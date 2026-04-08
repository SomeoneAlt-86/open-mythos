'use strict';

const crypto = require('crypto');
const {
  insertFindings,
  markTargetsScanned,
  openDatabase,
  pullUnscannedTargets,
} = require('./db');
const { runAgenticLoop } = require('./loop');

async function run(prompt) {
  return runAgenticLoop({
    prompt,
    config: { workDir: process.cwd(), approvalMode: 'safe' },
  });
}

function extractJsonCandidate(text) {
  const raw = String(text || '').trim();
  if (!raw) return '';

  const fenced = raw.match(/```(?:json)?\s*\n([\s\S]*?)\n```/i);
  if (fenced) return fenced[1].trim();

  const firstObj = raw.indexOf('{');
  const lastObj = raw.lastIndexOf('}');
  if (firstObj >= 0 && lastObj > firstObj) return raw.slice(firstObj, lastObj + 1).trim();

  return raw;
}

function buildResearchPrompt(threatModel, targets) {
  const targetsJson = JSON.stringify(
    targets.map((t) => ({
      target_item_id: t.id,
      path: t.path,
      function: t.function,
      reason: t.reason,
    })),
    null,
    2
  );

  return `
You are a security researcher. Analyze only the provided targets and report likely vulnerabilities.

## Threat Model
${threatModel}

## Target Queue
${targetsJson}

## Rules
- Focus only on these target_item_id values.
- If no issue is found for a target, skip it.
- Keep findings precise and evidence-backed.

## OUTPUT FORMAT
Return ONLY valid JSON:
{
  "findings": [
    {
      "target_item_id": 123,
      "title": "Short finding title",
      "severity": "low|medium|high|critical",
      "confidence": "low|medium|high",
      "description": "What is wrong and why",
      "evidence": "Code-level evidence",
      "impact": "Security impact",
      "recommendation": "How to fix"
    }
  ]
}
`;
}

function normalizeEnum(value, allowed, fallback = null) {
  const v = String(value || '').trim().toLowerCase();
  if (!v) return fallback;
  return allowed.includes(v) ? v : fallback;
}

function findingHash(normalized) {
  const payload = [
    normalized.target_item_id,
    normalized.title,
    normalized.description,
    normalized.evidence || '',
    normalized.impact || '',
    normalized.recommendation || '',
    normalized.severity || '',
    normalized.confidence || '',
  ].join('\n');

  return crypto.createHash('sha256').update(payload).digest('hex');
}

function parseFindingsJson(modelOutput, targets) {
  const candidate = extractJsonCandidate(modelOutput);
  let parsed;
  try {
    parsed = JSON.parse(candidate);
  } catch (err) {
    throw new Error(`Model output is not valid JSON: ${err.message}`);
  }

  const findings = Array.isArray(parsed) ? parsed : parsed.findings;
  if (!Array.isArray(findings)) {
    throw new Error('JSON must be an array or an object containing `findings` array.');
  }

  const targetsById = new Map(targets.map((t) => [t.id, t]));
  const normalized = [];

  for (let i = 0; i < findings.length; i += 1) {
    const f = findings[i];
    if (!f || typeof f !== 'object') continue;

    const targetItemId = Number.parseInt(f.target_item_id, 10);
    if (!targetsById.has(targetItemId)) continue;

    const title = String(f.title || '').trim();
    const description = String(f.description || '').trim();
    if (!title || !description) continue;

    const target = targetsById.get(targetItemId);
    const row = {
      threat_model_id: target.threat_model_id,
      target_item_id: target.id,
      repo_name: target.repo_name,
      repo_path: target.repo_path,
      path: target.path,
      function: target.function,
      severity: normalizeEnum(f.severity, ['low', 'medium', 'high', 'critical']),
      title,
      description,
      evidence: String(f.evidence || '').trim() || null,
      impact: String(f.impact || '').trim() || null,
      recommendation: String(f.recommendation || '').trim() || null,
      confidence: normalizeEnum(f.confidence, ['low', 'medium', 'high']),
      raw_json: JSON.stringify(f),
    };
    row.finding_hash = findingHash(row);
    normalized.push(row);
  }

  return normalized;
}

async function main(filters = {}) {
  const db = openDatabase();
  try {
    const targets = pullUnscannedTargets(db, {
      threat_model_id: filters.threat_model_id,
      repo_name: filters.repo_name,
      repo_path: filters.repo_path,
      limit: filters.limit,
    });

    if (!targets.length) {
      console.log('No unscanned targets found.');
      return {
        pulled_targets: 0,
        parsed_findings: 0,
        inserted_findings: 0,
        marked_scanned: 0,
      };
    }

    const threatModel = String(targets[0].threat_model || '').trim();
    if (!threatModel) {
      throw new Error(`Threat model text missing for threat_model_id=${targets[0].threat_model_id}`);
    }

    const prompt = buildResearchPrompt(threatModel, targets);
    const modelOutput = await run(prompt);
    const findings = parseFindingsJson(modelOutput, targets);

    const insertedFindings = insertFindings(db, findings);
    const markedScanned = markTargetsScanned(
      db,
      targets.map((t) => t.id)
    );

    const summary = {
      pulled_targets: targets.length,
      parsed_findings: findings.length,
      inserted_findings: insertedFindings,
      marked_scanned: markedScanned,
      threat_model_id: targets[0].threat_model_id,
      repo_name: targets[0].repo_name,
    };

    console.log(
      `Research complete threat_model_id=${summary.threat_model_id} repo=${summary.repo_name} pulled_targets=${summary.pulled_targets} parsed_findings=${summary.parsed_findings} inserted_findings=${summary.inserted_findings} marked_scanned=${summary.marked_scanned}`
    );
    return summary;
  } finally {
    db.close();
  }
}

function parseCliArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--threat-model-id') {
      out.threat_model_id = Number.parseInt(argv[i + 1], 10);
      i += 1;
    } else if (arg === '--repo-name') {
      out.repo_name = argv[i + 1];
      i += 1;
    } else if (arg === '--repo-path') {
      out.repo_path = argv[i + 1];
      i += 1;
    } else if (arg === '--limit') {
      out.limit = Number.parseInt(argv[i + 1], 10);
      i += 1;
    }
  }
  return out;
}

module.exports = {
  buildResearchPrompt,
  main,
  parseFindingsJson,
};

if (require.main === module) {
  const args = parseCliArgs(process.argv.slice(2));
  main(args).catch(console.error);
}
