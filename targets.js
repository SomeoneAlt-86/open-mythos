'use strict';

const { openDatabase } = require('./db');
const { runAgenticLoop } = require('./loop')

async function run(prompt) {
	const result = await runAgenticLoop({
		prompt,
		config: { workDir: process.cwd(), approvalMode: 'safe'},
	});
	return result;
}

function pull_threat_model({ id, repo_name, repo_path } = {}) {
  const hasAnyFilter =
    id !== undefined && id !== null
    || (typeof repo_name === 'string' && repo_name.trim())
    || (typeof repo_path === 'string' && repo_path.trim());

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

    const threatModelText = String(row.threat_model ?? '');
    //console.log(threatModelText);
    return threatModelText;
  } finally {
    db.close();
  }
}

module.exports = {
  pull_threat_model,
};

var t_m = pull_threat_model({ id: 1 });
console.log(t_m)

async function main() {
	const prompt = `
You are a security researcher and your goal is to find vulnerabilities
You are given the following threat model for the given repository -
${t_m}

## GOALS -
- using shell search tools like ripgrep (rg), grep, find, or ctags 
- find the entry points like Sources, sinks and identify the most likely targets in the codebase
- these targets can include likely vulnerable functions, high risk functions or code or entire code files 

## Output -
List the identified targets in json format containing path, function, reason 
`
	console.log(prompt)
}
main().catch(console.error)
