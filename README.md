# Open-Mythos

### Main agent loop - loop.js
Minimal usage 
```
const { runAgenticLoop } = require('./loop');

async function main() {
  const result = await runAgenticLoop({
    prompt: 'Analyze this repo and propose fixes for failing tests',
    config: {workDir: process.cwd(), approvalMode: 'safe'},
    })
  console.log(result);
}

main().catch(console.error);
