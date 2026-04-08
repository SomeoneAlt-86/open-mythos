#!/usr/bin/env node
'use strict';

const { runPipeline } = require('./open-mythos');
const recon = require('./recon');
const targets = require('./targets');
const research = require('./research');
const { startDashboard } = require('./server');

function printHelp() {
  console.log(`
open-mythos <command> [options]

Commands:
  pipeline                          Run recon -> targets -> research
  recon                             Run only threat-model generation
  targets [--id N|--repo-name N|--repo-path P]
                                    Generate targets for latest matching threat model
  research [--threat-model-id N|--repo-name N|--repo-path P] [--limit N]
                                    Process queued targets into findings
  dashboard [--port N] [--host H]   Start local dashboard server
  help                              Show this help

Environment:
  OPENAI_API_KEY or OPENROUTER_API_KEY (required for model calls)
  OPENAI_BASE_URL (optional)
  OPEN_MYTHOS_DB_PATH (optional, override SQLite path)
`);
}

function parseFlags(argv) {
  const out = {};

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = argv[i + 1];

    if (!arg.startsWith('--')) {
      continue;
    }

    if (arg === '--id') {
      out.id = Number.parseInt(next, 10);
      i += 1;
    } else if (arg === '--repo-name') {
      out.repo_name = next;
      i += 1;
    } else if (arg === '--repo-path') {
      out.repo_path = next;
      i += 1;
    } else if (arg === '--threat-model-id') {
      out.threat_model_id = Number.parseInt(next, 10);
      i += 1;
    } else if (arg === '--limit') {
      out.limit = Number.parseInt(next, 10);
      i += 1;
    } else if (arg === '--port') {
      out.port = Number.parseInt(next, 10);
      i += 1;
    } else if (arg === '--host') {
      out.host = next;
      i += 1;
    }
  }

  return out;
}

async function main() {
  const [, , cmdRaw, ...rest] = process.argv;
  const cmd = cmdRaw || 'pipeline';
  const flags = parseFlags(rest);

  if (cmd === 'help' || cmd === '--help' || cmd === '-h') {
    printHelp();
    return;
  }

  if (cmd === 'pipeline') {
    await runPipeline();
    return;
  }

  if (cmd === 'recon') {
    await recon.main();
    return;
  }

  if (cmd === 'targets') {
    await targets.main({
      id: flags.id,
      repo_name: flags.repo_name,
      repo_path: flags.repo_path,
    });
    return;
  }

  if (cmd === 'research') {
    await research.main({
      threat_model_id: flags.threat_model_id,
      repo_name: flags.repo_name,
      repo_path: flags.repo_path,
      limit: flags.limit,
    });
    return;
  }

  if (cmd === 'dashboard') {
    startDashboard({ port: flags.port, host: flags.host });
    return;
  }

  console.error(`[open-mythos] Unknown command: ${cmd}`);
  printHelp();
  process.exitCode = 1;
}

main().catch((err) => {
  console.error('[open-mythos] Error:', err.message);
  process.exit(1);
});
