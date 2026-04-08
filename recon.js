const {runAgenticLoop} = require('./loop');

async function main() {
	const result = await runAgenticLoop({
		prompt: 'List all the files in the directory',
		config: {workDir: process.cwd(), approvalMode: 'safe'},
	})
	console.log(result);
}

main().catch(console.error);
