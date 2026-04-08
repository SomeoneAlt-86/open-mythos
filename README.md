# Open-Mythos

Open-Mythos is an LLM-assisted vulnerability discovery pipeline with three stages: recon, target crafting, and research.

## Install

```bash
npm install open-mythos
```

## CLI Usage

```bash
open-mythos pipeline
open-mythos recon
open-mythos targets --repo-name my-repo
open-mythos research --repo-name my-repo --limit 20
open-mythos dashboard --port 7331
```

Default command:

```bash
open-mythos
```

This runs `pipeline` (recon -> targets -> research).

## Environment

- `OPENAI_API_KEY` or `OPENROUTER_API_KEY` (required for model calls)
- `OPENAI_BASE_URL` (optional override)
- `OPEN_MYTHOS_DB_PATH` (optional SQLite override)
- `DASHBOARD_PORT` (optional, used by `dashboard`)

## Database Location

By default, Open-Mythos stores SQLite data in platform user data directories:

- Linux: `~/.local/share/open-mythos/open-mythos.sqlite`
- macOS: `~/Library/Application Support/open-mythos/open-mythos.sqlite`
- Windows: `%APPDATA%\\open-mythos\\open-mythos.sqlite`

Set `OPEN_MYTHOS_DB_PATH` if you want a project-local or custom location.

## Programmatic Usage

```js
const { runPipeline } = require('open-mythos');

runPipeline().catch(console.error);
```

For lower-level APIs:

```js
const { recon, targets, research, db, loop, server } = require('open-mythos');
```

## Stages

1. Recon
- Builds a repo-specific threat model and stores it in SQLite.

2. Targets
- Generates high-risk target candidates from the threat model.
- Deduplicates by `(threat_model_id, path, function)`.

3. Research
- Pulls unscanned targets.
- Produces normalized findings JSON.
- Marks processed targets as scanned.

## Dashboard

Run:

```bash
open-mythos dashboard
```

Then open `http://127.0.0.1:7331`.

## Release Checklist (npm)

```bash
npm run pack:check
npm publish --access public
```

The package is configured with a strict `"files"` allowlist so runtime artifacts like local SQLite data are not published.
