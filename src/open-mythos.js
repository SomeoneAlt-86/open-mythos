'use strict';

const path = require('path');
const { main: runRecon } = require('./recon');
const { main: runTargets } = require('./targets');
const { main: runResearch } = require('./research');
const { openDatabase } = require('./db');

function renameLatestThreatModelRepoName(repoPath, repoName) {
  if (!repoName || !String(repoName).trim()) return;

  const db = openDatabase();
  try {
    const latest = db.prepare(`
      SELECT id
      FROM threat_models
      WHERE repo_path = @repo_path
      ORDER BY created_at DESC, id DESC
      LIMIT 1
    `).get({ repo_path: repoPath });

    if (!latest) return;

    db.prepare(`
      UPDATE threat_models
      SET repo_name = @repo_name
      WHERE id = @id
    `).run({ id: latest.id, repo_name: String(repoName).trim() });
  } finally {
    db.close();
  }
}

async function runPipeline(options = {}) {
  const repoPath = path.resolve(options.repoPath || process.cwd());
  const repoName = options.repoName ? String(options.repoName).trim() : '';
  const maxCycles = Number.isInteger(options.maxCycles)
    ? Math.max(1, options.maxCycles)
    : 100;
  const researchLimit = Number.isInteger(options.researchLimit)
    ? Math.max(1, options.researchLimit)
    : undefined;

  process.chdir(repoPath);

  await runRecon();

  if (repoName) {
    renameLatestThreatModelRepoName(repoPath, repoName);
  }

  let cycles = 0;
  while (cycles < maxCycles) {
    cycles += 1;

    const targetsResult = await runTargets({ repo_path: repoPath });
    const researchResult = await runResearch({
      repo_path: repoPath,
      limit: researchLimit,
    });

    const insertedTargets = Number(targetsResult?.target_items_inserted || 0);
    const pulledTargets = Number(researchResult?.pulled_targets || 0);

    if (insertedTargets === 0 && pulledTargets === 0) break;
  }

  return {
    repo_path: repoPath,
    repo_name: repoName || path.basename(repoPath),
    cycles,
  };
}

module.exports = {
  runPipeline,
};
