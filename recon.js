const {runAgenticLoop} = require('./loop');

async function run(prompt) {
	const result = await runAgenticLoop({
		prompt: prompt,
		config: {workDir: process.cwd(), approvalMode: 'safe'},
	})
	return result
}

prompt = `
You are an autonomous security analysis agent operating on a large code repository.

Your goal is to **systematically identify high-risk areas for vulnerabilities using static analysis principles**, not to randomly scan code.

You MUST follow the workflow strictly and produce the required artifacts.

---

# PHASE 1 — Identify Project Type

Analyze the repository structure and determine the type of project.

Possible categories include (but are not limited to):

- Browser engine
- Operating system kernel
- Networking stack
- Compiler / interpreter
- Android / mobile app
- Electron / desktop app
- Backend service
- Cryptographic library

## Actions:

- Inspect directory structure
- Check build systems (CMake, GN, Bazel, Makefiles, Gradle, etc.)
- Identify primary languages (C, C++, Rust, Java, JS, etc.)
- Look for keywords (renderer, kernel, ipc, syscall, parser, etc.)

## Output:

Clearly state:

- Project type
- Primary languages
- High-level architecture (if inferable)

---

# PHASE 2 — Generate Threat Model

Create a **custom threat model tailored to this specific repository**.

## You MUST:

- Avoid generic templates
- Base reasoning on actual repo structure and components

## Identify:

### 1. Attack Surfaces

Examples:

- File parsers (images, media, configs)
- Network input handling
- IPC / message passing
- System call interfaces
- UI / event handling (if relevant)

### 2. Trust Boundaries

Examples:

- User input → internal processing
- Sandbox → privileged process
- Client → server
- Userland → kernel

### 3. High-Risk Components

Based on:

- Complexity
- Input handling
- Memory management
- Privilege level

### 4. Expected Vulnerability Classes

Tailor to project type:

Examples:

- Memory corruption (overflow, UAF)
- Type confusion
- Integer overflow
- Deserialization bugs
- Race conditions / TOCTOU
- Logic bugs (auth bypass, state issues)

---

## OUTPUT -> **THE OUTPUT MUST BE LIKE THE STRUCTURE GIVEN BELOW**
Structure EXACTLY as follows:

"""
# Threat Model

## Project Classification
...

## Architecture Overview
...

## Attack Surfaces
- ...

## Trust Boundaries
- ...

## High-Risk Components
- ...

## Expected Vulnerability Classes
- ...

## Priority Attack Paths
(Explicit source → sink flows)
- Source → ... → Sink
- ...
"""

`

run(prompt).catch(console.error())
