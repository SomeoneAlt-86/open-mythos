'use strict';

const { openDatabase, insertTargets } = require('./db');
const { runAgenticLoop } = require('./loop');

async function run(prompt) {
  return runAgenticLoop({
    prompt,
    config: { workDir: process.cwd(), approvalMode: 'safe' },
  });
}

function buildThreatModelFilters({ id, repo_name, repo_path } = {}) {
  const hasAnyFilter =
    (id !== undefined && id !== null) ||
    (typeof repo_name === 'string' && repo_name.trim()) ||
    (typeof repo_path === 'string' && repo_path.trim());

  if (!hasAnyFilter) {
    throw new Error('At least one of id, repo_name, or repo_path is required.');
  }

  const conditions = [];
  const params = {};

  if (id !== undefined && id !== null) {
    conditions.push('id = @id');
    params.id = id;
  }
  if (typeof repo_name === 'string' && repo_name.trim()) {
    conditions.push('repo_name = @repo_name');
    params.repo_name = repo_name.trim();
  }
  if (typeof repo_path === 'string' && repo_path.trim()) {
    conditions.push('repo_path = @repo_path');
    params.repo_path = repo_path.trim();
  }

  return { conditions, params };
}

function pull_threat_model_row(filters = {}) {
  const { conditions, params } = buildThreatModelFilters(filters);
  const sql = `
    SELECT id, repo_name, repo_path, threat_model, created_at
    FROM threat_models
    WHERE ${conditions.join(' AND ')}
    ORDER BY created_at DESC, id DESC
    LIMIT 1
  `;

  const db = openDatabase();
  try {
    const row = db.prepare(sql).get(params);
    if (!row) {
      throw new Error('No threat model found for the provided filters.');
    }
    return row;
  } finally {
    db.close();
  }
}

function pull_threat_model(filters = {}) {
  const row = pull_threat_model_row(filters);
  const threatModelText = String(row.threat_model ?? '');
  console.log(threatModelText);
  return threatModelText;
}

function pull_existing_targets_json({ threat_model_id, repo_name, repo_path }) {
  const db = openDatabase();
  try {
    const row = db.prepare(`
      SELECT targets_json
      FROM targets
      WHERE threat_model_id = @threat_model_id
         OR (repo_name = @repo_name AND repo_path = @repo_path)
      ORDER BY created_at DESC, id DESC
      LIMIT 1
    `).get({
      threat_model_id,
      repo_name,
      repo_path,
    });

    if (!row) return '';
    return String(row.targets_json ?? '').trim();
  } finally {
    db.close();
  }
}

function buildCrafterPrompt(threatModelText, existingTargetsJson) {
  const existingTargetsSection = existingTargetsJson
    ? `
## EXISTING TARGETS (DO NOT REPEAT)
The following targets were already identified. Exclude them from your output.
Do not return the same path/function pair again.

${existingTargetsJson}
`
    : '';

  return `
You are a security researcher and your goal is to find vulnerabilities.
You are given the following threat model for the given repository:

${threatModelText}

## GOALS
- Use shell search tools like ripgrep (rg), grep, find, or ctags.
- Find sources, sinks, and identify the most likely vulnerability targets in the codebase.
- Targets can include likely vulnerable functions, high-risk code blocks, or high-risk files.
${existingTargetsSection}

## OUTPUT FORMAT
Return ONLY valid JSON with this shape:
{
  "targets": [
    {
      "path": "relative/or/absolute/path",
      "function": "functionName or N/A",
      "reason": "short security-focused justification"
    }
  ]
}
`;
}

function extractJsonCandidate(text) {
  const raw = String(text || '').trim();
  if (!raw) return '';

  const fenced = raw.match(/```(?:json)?\s*\n([\s\S]*?)\n```/i);
  if (fenced) return fenced[1].trim();

  const firstObj = raw.indexOf('{');
  const lastObj = raw.lastIndexOf('}');
  if (firstObj >= 0 && lastObj > firstObj) return raw.slice(firstObj, lastObj + 1).trim();

  const firstArr = raw.indexOf('[');
  const lastArr = raw.lastIndexOf(']');
  if (firstArr >= 0 && lastArr > firstArr) return raw.slice(firstArr, lastArr + 1).trim();

  return raw;
}

function parseTargetsJson(modelOutput) {
  const candidate = extractJsonCandidate(modelOutput);
  let parsed;
  try {
    parsed = JSON.parse(candidate);
  } catch (err) {
    throw new Error(`Model output is not valid JSON: ${err.message}`);
  }

  const targets = Array.isArray(parsed) ? parsed : parsed.targets;
  if (!Array.isArray(targets)) {
    throw new Error('JSON must be an array or an object containing a `targets` array.');
  }

  for (let i = 0; i < targets.length; i += 1) {
    const t = targets[i];
    if (!t || typeof t !== 'object') {
      throw new Error(`targets[${i}] must be an object.`);
    }
    if (typeof t.path !== 'string' || !t.path.trim()) {
      throw new Error(`targets[${i}].path must be a non-empty string.`);
    }
    if (typeof t.function !== 'string' || !t.function.trim()) {
      throw new Error(`targets[${i}].function must be a non-empty string.`);
    }
    if (typeof t.reason !== 'string' || !t.reason.trim()) {
      throw new Error(`targets[${i}].reason must be a non-empty string.`);
    }
  }

  return JSON.stringify({ targets }, null, 2);
}

function parseTargetsArray(jsonText) {
  if (!jsonText || !String(jsonText).trim()) return [];
  const candidate = extractJsonCandidate(jsonText);
  const parsed = JSON.parse(candidate);
  const targets = Array.isArray(parsed) ? parsed : parsed.targets;
  if (!Array.isArray(targets)) return [];
  return targets.filter((t) => t && typeof t === 'object');
}

function mergeTargets(existingTargetsJson, newTargetsJson) {
  const existing = parseTargetsArray(existingTargetsJson);
  const incoming = parseTargetsArray(newTargetsJson);
  const seen = new Set();
  const merged = [];

  const add = (t) => {
    const pathVal = String(t.path || '').trim();
    const fnVal = String(t.function || '').trim();
    const reasonVal = String(t.reason || '').trim();
    if (!pathVal || !fnVal || !reasonVal) return;

    const key = `${pathVal}::${fnVal}`;
    if (seen.has(key)) return;
    seen.add(key);
    merged.push({
      path: pathVal,
      function: fnVal,
      reason: reasonVal,
    });
  };

  for (const t of existing) add(t);
  for (const t of incoming) add(t);

  return JSON.stringify({ targets: merged }, null, 2);
}

async function main(filters = {}) {
  const threatModelRow = pull_threat_model_row(filters);
  const threatModelText = String(threatModelRow.threat_model ?? '');
  if (!threatModelText.trim()) {
    throw new Error('Threat model content is empty.');
  }

  const existingTargetsJson = pull_existing_targets_json({
    threat_model_id: threatModelRow.id,
    repo_name: threatModelRow.repo_name,
    repo_path: threatModelRow.repo_path,
  });

  const prompt = buildCrafterPrompt(threatModelText, existingTargetsJson);
  const modelOutput = await run(prompt);
  const newTargetsJson = parseTargetsJson(modelOutput);
  const targetsJson = mergeTargets(existingTargetsJson, newTargetsJson);

  const db = openDatabase();
  try {
    const targetsId = insertTargets(db, {
      threat_model_id: threatModelRow.id,
      repo_name: threatModelRow.repo_name,
      repo_path: threatModelRow.repo_path,
      targets_json: targetsJson,
    });

    const count = JSON.parse(targetsJson).targets.length;
    console.log(
      `Stored targets id=${targetsId} threat_model_id=${threatModelRow.id} repo=${threatModelRow.repo_name} count=${count}`
    );
    return { id: targetsId, threat_model_id: threatModelRow.id, count };
  } finally {
    db.close();
  }
}

function parseCliArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--id') {
      out.id = Number.parseInt(argv[i + 1], 10);
      i += 1;
    } else if (arg === '--repo-name') {
      out.repo_name = argv[i + 1];
      i += 1;
    } else if (arg === '--repo-path') {
      out.repo_path = argv[i + 1];
      i += 1;
    }
  }
  return out;
}

module.exports = {
  main,
  mergeTargets,
  parseTargetsJson,
  pull_existing_targets_json,
  pull_threat_model,
  pull_threat_model_row,
};

if (require.main === module) {
  const args = parseCliArgs(process.argv.slice(2));
  main(args).catch(console.error);
}
