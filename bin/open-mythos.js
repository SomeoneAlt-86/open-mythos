'use strict';

const path = require('path');
const { main: runRecon } = require('./recon');
const { main: runTargets } = require('./targets');
const { main: runResearch } = require('./research');

async function runPipeline(options = {}) {
  const repoPath = options.repoPath || process.cwd();
  const repoName = options.repoName || path.basename(repoPath);

  // ── Stage 1: Recon ──────────────────────────────────────────────────────────
  console.log('\n[open-mythos] Stage 1/3 — Recon: generating threat model...');
  await runRecon();
  console.log('[open-mythos] Recon complete.');

  // ── Stage 2: Targets ────────────────────────────────────────────────────────
  // targets.main() looks up the latest threat model for this repo and returns
  // { threat_model_id, parsed_count, target_items_inserted, total_for_threat_model }
  console.log('\n[open-mythos] Stage 2/3 — Targets: crafting target queue...');
  const targetsResult = await runTargets({ repo_name: repoName, repo_path: repoPath });
  console.log('[open-mythos] Targets complete.', targetsResult);

  // ── Stage 3: Research ───────────────────────────────────────────────────────
  // Pin research to the exact threat_model_id produced above so it never
  // accidentally picks up targets from an older run.
  console.log('\n[open-mythos] Stage 3/3 — Research: scanning targets...');
  const researchResult = await runResearch({ threat_model_id: targetsResult.threat_model_id });
  console.log('[open-mythos] Research complete.', researchResult);

  return {
    repo_name: repoName,
    repo_path: repoPath,
    threat_model_id: targetsResult.threat_model_id,
    targets: targetsResult,
    research: researchResult,
  };
}

// ── CLI entry point ────────────────────────────────────────────────────────────
if (require.main === module) {
  runPipeline().catch((err) => {
    console.error('[open-mythos] Pipeline failed:', err.message);
    process.exit(1);
  });
}

module.exports = { runPipeline };
