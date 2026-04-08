# Open-Mythos

Open-Mythos is an automated LLM-assisted vulnerability discovery pipeline built around staged static-analysis workflows.

## Architecture Overview

The system runs in three logical stages:

1. Recon stage
- Generates a repository-specific threat model from source context.
- Persists threat model records in SQLite with repository metadata.

2. Target-crafting stage
- Uses the threat model to identify likely vulnerability targets (`path` / `function` / `reason`).
- Pulls existing targets and instructs the model to avoid repeating prior findings.
- Inserts only new unique targets into the target queue.

3. Research stage
- Pulls queued targets where `scanned = 0`.
- Builds a focused investigation prompt from queued targets plus threat model context.
- Parses model findings JSON and stores normalized findings.
- Marks processed targets as scanned to prevent reprocessing.

## Data Model (High Level)

SQLite is the system of record. Core entities:

- `threat_models`
- One row per generated threat model for a repo snapshot/context.

- `target_items`
- Normalized queue of targets linked to a `threat_model_id`.
- Includes `scanned` state for downstream processing.
- Unique key prevents duplicate targets for the same threat model.

- `findings`
- Normalized vulnerability findings linked to both `threat_model_id` and `target_item_id`.
- Deduped by `(target_item_id, finding_hash)`.

## Pipeline Behavior

- Target insert semantics are insert-only for new unique items.
- Existing target conflicts are ignored, not overwritten.

- Research queue semantics:
- Only unscanned targets are selected (`scanned = 0`).
- Once processed, targets are marked scanned (`scanned = 1`).

- Findings semantics:
- Parsed from strict JSON output.
- Validated and normalized before database insert.

## Execution Flow

Typical lifecycle:

1. Generate threat model for a repository.
2. Generate or extend target queue from that threat model.
3. Run research batches on unscanned targets.
4. Repeat target/research cycles until coverage is sufficient.

## Runtime Requirements

- Node.js runtime.
- SQLite via `better-sqlite3`.
- OpenAI-compatible API credentials in environment:
- `OPENAI_API_KEY` or `OPENROUTER_API_KEY`
- Optional `OPENAI_BASE_URL`

## Minimal Loop Usage

```js
const { runAgenticLoop } = require('./loop');

async function main() {
  const result = await runAgenticLoop({
    prompt: 'Analyze this repo and propose fixes for failing tests',
    config: { workDir: process.cwd(), approvalMode: 'safe' },
  });
  console.log(result);
}

main().catch(console.error);
```
