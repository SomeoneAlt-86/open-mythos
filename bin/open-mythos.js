#!/usr/bin/env node
'use strict';

const { program } = require('commander');
const path = require('path');
const { version, description } = require('../package.json');

program
  .name('open-mythos')
  .description(description)
  .version(version);

// ── run ───────────────────────────────────────────────────────────────────────
program
  .command('run')
  .description('Run the full pipeline: recon → targets → research')
  .option('--repo-path <path>', 'Path to the repository (default: cwd)')
  .option('--repo-name <n>', 'Override repository name')
  .action(async (opts) => {
    const { runPipeline } = require('../src');
    await runPipeline({
      repoPath: opts.repoPath ? path.resolve(opts.repoPath) : process.cwd(),
      repoName: opts.repoName,
    }).catch(fatal);
  });

// ── recon ─────────────────────────────────────────────────────────────────────
program
  .command('recon')
  .description('Stage 1 — generate threat model for a repository')
  .option('--repo-path <path>', 'Path to the repository (default: cwd)')
  .action(async (opts) => {
    if (opts.repoPath) process.chdir(path.resolve(opts.repoPath));
    const { runRecon } = require('../src');
    await runRecon().catch(fatal);
  });

// ── targets ───────────────────────────────────────────────────────────────────
program
  .command('targets')
  .description('Stage 2 — craft target queue from an existing threat model')
  .option('--id <n>',           'Threat model ID', parseIntOpt)
  .option('--repo-name <n>',    'Filter by repository name')
  .option('--repo-path <path>', 'Filter by repository path')
  .action(async (opts) => {
    const { runTargets } = require('../src');
    await runTargets({
      id:        opts.id,
      repo_name: opts.repoName,
      repo_path: opts.repoPath,
    }).catch(fatal);
  });

// ── research ──────────────────────────────────────────────────────────────────
program
  .command('research')
  .description('Stage 3 — scan unscanned targets and store findings')
  .option('--threat-model-id <n>', 'Pin to a specific threat model ID', parseIntOpt)
  .option('--repo-name <n>',       'Filter by repository name')
  .option('--repo-path <path>',    'Filter by repository path')
  .option('--limit <n>',           'Max targets to pull per batch (default: 20)', parseIntOpt)
  .action(async (opts) => {
    const { runResearch } = require('../src');
    await runResearch({
      threat_model_id: opts.threatModelId,
      repo_name:       opts.repoName,
      repo_path:       opts.repoPath,
      limit:           opts.limit,
    }).catch(fatal);
  });

// ── serve ─────────────────────────────────────────────────────────────────────
program
  .command('serve')
  .description('Start the read-only dashboard on localhost')
  .option('--port <n>', 'Port to listen on (default: 7331)', parseIntOpt)
  .action((opts) => {
    const { startServer } = require('../src');
    startServer(opts.port);
  });

// ── db ────────────────────────────────────────────────────────────────────────
const dbCmd = program
  .command('db')
  .description('Database utilities');

dbCmd
  .command('path')
  .description('Print the resolved database file path')
  .action(() => {
    const { DEFAULT_DB_PATH } = require('../src');
    console.log(process.env.OPEN_MYTHOS_DB_PATH || DEFAULT_DB_PATH);
  });

dbCmd
  .command('list')
  .description('List all repositories in the database')
  .action(() => {
    const { openDatabase } = require('../src');
    const database = openDatabase();
    try {
      const rows = database.prepare(`
        SELECT repo_name, repo_path,
               COUNT(DISTINCT id) AS threat_models,
               MAX(created_at)    AS last_run
        FROM threat_models
        GROUP BY repo_name, repo_path
        ORDER BY last_run DESC
      `).all();
      if (!rows.length) { console.log('No repositories found.'); return; }
      for (const r of rows) {
        console.log(`  ${r.repo_name}  (${r.threat_models} model${r.threat_models > 1 ? 's' : ''})  last: ${r.last_run}`);
        console.log(`    ${r.repo_path}`);
      }
    } finally {
      database.close();
    }
  });

// ── helpers ───────────────────────────────────────────────────────────────────
function parseIntOpt(value) {
  const n = Number.parseInt(value, 10);
  if (Number.isNaN(n)) throw new Error(`Expected an integer, got: ${value}`);
  return n;
}

function fatal(err) {
  console.error(`\nError: ${err.message}`);
  process.exit(1);
}

program.parseAsync(process.argv);
