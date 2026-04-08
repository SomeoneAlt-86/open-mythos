# Open-Mythos

Automated LLM-assisted vulnerability discovery pipeline.
<img width="1916" height="935" alt="Screenshot_20260408_192816" src="https://github.com/user-attachments/assets/ad7939ab-4a50-43e2-820b-1819d14216e2" />

## Prerequisites

- Node.js >= 18
- An API key in your environment:
  - `OPENAI_API_KEY`, or
  - `OPENROUTER_API_KEY`

## Installation

```bash
npm install -g open-mythos
```

## Quickstart

Run these 3 commands in the repository you want to analyze:

```bash
open-mythos recon
open-mythos targets --repo-name "$(basename "$PWD")"
open-mythos research --repo-name "$(basename "$PWD")" --limit 20
```

What this does:
- `recon` creates and stores a threat model.
- `targets` creates a deduplicated target queue from that threat model.
- `research` scans unscanned targets and stores findings.

Optional dashboard:

```bash
open-mythos serve --port 7331
```

Then open `http://localhost:7331`.

## Full CLI Reference

### Global

- `open-mythos --help` Show CLI help
- `open-mythos --version` Show installed version

### `run`

Run full pipeline (`recon -> targets -> research`).

```bash
open-mythos run [--repo-path <path>] [--repo-name <name>]
```

Flags:
- `--repo-path <path>` Path to target repository (default: current directory)
- `--repo-name <name>` Override detected repository name

### `recon`

Generate a threat model for a repository and store it in SQLite.

```bash
open-mythos recon [--repo-path <path>]
```

Flags:
- `--repo-path <path>` Path to target repository (default: current directory)

### `targets`

Generate target queue items from an existing threat model.

```bash
open-mythos targets [--id <n>] [--repo-name <name>] [--repo-path <path>]
```

Flags:
- `--id <n>` Threat model ID
- `--repo-name <name>` Filter by repository name
- `--repo-path <path>` Filter by repository path

Note: at least one filter is required (`--id`, `--repo-name`, or `--repo-path`).

### `research`

Scan unscanned targets and store normalized findings.

```bash
open-mythos research [--threat-model-id <n>] [--repo-name <name>] [--repo-path <path>] [--limit <n>]
```

Flags:
- `--threat-model-id <n>` Pin research to a specific threat model
- `--repo-name <name>` Filter by repository name
- `--repo-path <path>` Filter by repository path
- `--limit <n>` Max targets pulled per batch (default: `20`)

### `serve`

Start read-only dashboard.

```bash
open-mythos serve [--port <n>]
```

Flags:
- `--port <n>` Dashboard port (default: `7331`)

### `db`

Database utilities.

```bash
open-mythos db path
open-mythos db list
```

Subcommands:
- `db path` Print resolved SQLite database path
- `db list` List repositories present in database

## Environment Variables

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `OPENAI_API_KEY` | Conditionally | _(none)_ | API key for LLM calls (either this or `OPENROUTER_API_KEY` must be set). |
| `OPENROUTER_API_KEY` | Conditionally | _(none)_ | Alternate API key for OpenRouter-compatible endpoint. |
| `OPENAI_BASE_URL` | No | `https://openrouter.ai/api/v1` | Base URL for OpenAI-compatible API. |
| `DEUS_MODEL` | No | `openai/gpt-4.1-mini` | Model identifier used by the agentic loop. |
| `DEUS_MAX_ITER` | No | `60` | Max iterations in the agentic loop. |
| `DEUS_TEMPERATURE` | No | `0.2` | Sampling temperature for model calls. |
| `DEUS_APPROVAL_MODE` | No | `safe` | Approval mode passed to loop config. |
| `DEUS_TRUNCATE_THRESHOLD` | No | `40` | Message-history truncation threshold. |
| `DEUS_TRUNCATE_KEEP_RECENT` | No | `10` | Number of recent turns to keep when truncating. |
| `OPEN_MYTHOS_DB_PATH` | No | `src/data/open-mythos.sqlite` | SQLite file path. |
| `DASHBOARD_PORT` | No | `7331` | Port used by dashboard server. |

## Contributing

1. Fork and clone the repository.
2. Install dependencies:

```bash
npm install
```

3. Set environment variables (copy from `.env.example` if needed).
4. Run tests:

```bash
npm test
```

5. Validate CLI behavior locally:

```bash
node bin/open-mythos.js --help
```

6. Open a pull request with:
- clear problem statement
- focused change set
- test or validation notes
