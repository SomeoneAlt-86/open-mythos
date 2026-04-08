'use strict';

const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const readline = require('readline');
const { promisify } = require('util');

const execAsync = promisify(exec);

const Colors = {
  RESET: '\x1b[0m',
  DIM: '\x1b[2m',
  CYAN: '\x1b[36m',
  GREEN: '\x1b[32m',
  YELLOW: '\x1b[33m',
};

const SYSTEM_TEMPLATE = [
  'You are Deus, a pragmatic coding agent operating like Codex CLI.',
  'Working directory: {work_dir}',
  'Deus repository workspace: {repo_dir}',
  '',
  'Core behavior:',
  '- Start with fast discovery (Glob/Grep/Read), then execute edits and verification.',
  '- Prefer surgical edits when possible.',
  '- Maintain TODO state for multi-step work.',
  '- Run tests/lints after code changes.',
  '- Ask user only when blocked or when tradeoffs require explicit choice.',
  '- Finish with Finish(summary) only when the task is truly done.',
  '',
  'Output behavior:',
  '- Be concise and action-oriented.',
  '- Avoid long narratives.',
].join('\n');

const DANGEROUS_BASH_PATTERNS = [
  /\brm\s+-rf\b/i,
  /\bmkfs\b/i,
  /\bdd\b/i,
  /\bshutdown\b/i,
  /\breboot\b/i,
  /:\s*\(\s*\)\s*\{/i,
  /\bchmod\s+-R\s+777\b/i,
];

function clip(text, limit = 8000) {
  if (text.length <= limit) return text;
  return `${text.slice(0, limit)}\n... [truncated ${text.length - limit} chars]`;
}

function relpathDisplay(targetPath, root) {
  try {
    return path.relative(path.resolve(root), path.resolve(targetPath));
  } catch {
    return targetPath;
  }
}

function normalizeRepoName(name) {
  const trimmed = String(name || '').trim().toLowerCase();
  if (!trimmed) throw new Error('Repository name cannot be empty');
  if (trimmed === '.' || trimmed === '..') throw new Error('Invalid repository name');
  if (trimmed.includes('/') || trimmed.includes('\\')) {
    throw new Error('Repository name must not contain path separators');
  }
  const cleaned = trimmed.replace(/[^a-z0-9._-]+/g, '-').replace(/-{2,}/g, '-').replace(/^-+|-+$/g, '');
  if (!cleaned) throw new Error('Repository name resolved to empty after normalization');
  return cleaned;
}

function buildTools() {
  return [
    {
      type: 'function',
      function: {
        name: 'Bash',
        description: 'Run a shell command in working directory. Avoid interactive commands.',
        parameters: {
          type: 'object',
          properties: {
            command: { type: 'string' },
            timeout: { type: 'integer', description: 'seconds, default 30' },
          },
          required: ['command'],
        },
      },
    },
    {
      type: 'function',
      function: {
        name: 'Read',
        description: 'Read a file as text.',
        parameters: {
          type: 'object',
          properties: {
            path: { type: 'string' },
            start_line: { type: 'integer' },
            end_line: { type: 'integer' },
          },
          required: ['path'],
        },
      },
    },
    {
      type: 'function',
      function: {
        name: 'Write',
        description: 'Write full file contents. Creates parent directory if needed.',
        parameters: {
          type: 'object',
          properties: {
            path: { type: 'string' },
            content: { type: 'string' },
          },
          required: ['path', 'content'],
        },
      },
    },
    {
      type: 'function',
      function: {
        name: 'Edit',
        description: 'Targeted replacement. old_str must match exactly and uniquely.',
        parameters: {
          type: 'object',
          properties: {
            path: { type: 'string' },
            old_str: { type: 'string' },
            new_str: { type: 'string' },
          },
          required: ['path', 'old_str', 'new_str'],
        },
      },
    },
    {
      type: 'function',
      function: {
        name: 'Glob',
        description: 'List files matching a glob pattern.',
        parameters: {
          type: 'object',
          properties: {
            pattern: { type: 'string' },
            path: { type: 'string' },
          },
          required: ['pattern'],
        },
      },
    },
    {
      type: 'function',
      function: {
        name: 'Grep',
        description: 'Regex search over files; returns file:line:match.',
        parameters: {
          type: 'object',
          properties: {
            pattern: { type: 'string' },
            path: { type: 'string' },
            glob: { type: 'string' },
          },
          required: ['pattern'],
        },
      },
    },
    {
      type: 'function',
      function: {
        name: 'WebFetch',
        description: 'Fetch URL and return readable text.',
        parameters: {
          type: 'object',
          properties: {
            url: { type: 'string' },
            max_chars: { type: 'integer' },
          },
          required: ['url'],
        },
      },
    },
    {
      type: 'function',
      function: {
        name: 'TodoWrite',
        description: 'Manage todo list. operations: add, complete, delete, list',
        parameters: {
          type: 'object',
          properties: {
            operation: { type: 'string', enum: ['add', 'complete', 'delete', 'list'] },
            text: { type: 'string' },
            id: { type: 'integer' },
          },
          required: ['operation'],
        },
      },
    },
    {
      type: 'function',
      function: {
        name: 'AskUser',
        description: 'Ask user for clarification and wait.',
        parameters: {
          type: 'object',
          properties: { question: { type: 'string' } },
          required: ['question'],
        },
      },
    },
    {
      type: 'function',
      function: {
        name: 'Finish',
        description: 'Mark task completed and provide summary.',
        parameters: {
          type: 'object',
          properties: { summary: { type: 'string' } },
          required: ['summary'],
        },
      },
    },
  ];
}

class DeusLoop {
  constructor(client, config = {}, runtime = {}) {
    this.client = client;
    this.config = config;
    this.useColor = runtime.useColor !== false;
    this.logger = runtime.logger === undefined ? console : runtime.logger;
    this.confirmCommand = runtime.confirmCommand;
    this.askUserHandler = runtime.askUser;
    this.tools = buildTools();
    this.state = {
      todos: [],
      nextTodoId: 1,
    };

    this.icons = {
      Bash: '⚡',
      Read: '📖',
      Write: '✍',
      Edit: '🔧',
      Glob: '🔍',
      Grep: '🔎',
      WebFetch: '🌐',
      TodoWrite: '📋',
      AskUser: '❓',
      Finish: '✅',
    };

    this.messages = [
      {
        role: 'system',
        content: SYSTEM_TEMPLATE
          .replace('{work_dir}', String(config.workDir))
          .replace('{repo_dir}', String(config.repoDir)),
      },
    ];
  }

  log(...args) {
    if (this.logger && typeof this.logger.log === 'function') {
      this.logger.log(...args);
    }
  }

  c(color, text) {
    if (!this.useColor) return text;
    return `${color}${text}${Colors.RESET}`;
  }

  resolvePath(filePath) {
    if (path.isAbsolute(filePath)) return filePath;
    return path.join(this.config.workDir, filePath);
  }

  requiresConfirmation(command) {
    if (this.config.approvalMode === 'never') return false;
    if (this.config.approvalMode === 'always') return true;
    return DANGEROUS_BASH_PATTERNS.some((pattern) => pattern.test(command));
  }

  askLine(question) {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });

    return new Promise((resolve) => {
      rl.question(question, (answer) => {
        rl.close();
        resolve(answer);
      });
    });
  }

  async confirm(promptText) {
    if (typeof this.confirmCommand === 'function') {
      return Boolean(await this.confirmCommand(promptText));
    }

    while (true) {
      const answer = (await this.askLine(`${promptText} [y/N]: `)).trim().toLowerCase();
      if (answer === 'y' || answer === 'yes') return true;
      if (answer === '' || answer === 'n' || answer === 'no') return false;
      this.log('Please enter y or n.');
    }
  }

  async toolBash(command, timeout = 30) {
    if (this.requiresConfirmation(command)) {
      const ok = await this.confirm(`Approve shell command? ${command}`);
      if (!ok) return 'ERROR: command denied by user';
    }

    const started = Date.now();
    try {
      const { stdout, stderr } = await execAsync(command, {
        cwd: this.config.workDir,
        timeout: timeout * 1000,
        maxBuffer: 1024 * 1024 * 8,
        shell: true,
      });

      const took = (Date.now() - started) / 1000;
      const body = [`exit_code=0 elapsed=${took.toFixed(2)}s`];
      if (stdout && stdout.trim()) body.push(`stdout:\n${stdout.trim()}`);
      if (stderr && stderr.trim()) body.push(`stderr:\n${stderr.trim()}`);
      return clip(body.join('\n\n'), 12000);
    } catch (err) {
      const took = (Date.now() - started) / 1000;
      if (err && err.killed) return `ERROR: timed out after ${timeout}s`;

      const code = typeof err.code === 'number' ? err.code : 'unknown';
      const body = [`exit_code=${code} elapsed=${took.toFixed(2)}s`];
      if (err.stdout && String(err.stdout).trim()) body.push(`stdout:\n${String(err.stdout).trim()}`);
      if (err.stderr && String(err.stderr).trim()) body.push(`stderr:\n${String(err.stderr).trim()}`);
      if (body.length === 1 && err.message) body.push(`stderr:\n${err.message}`);
      return clip(body.join('\n\n'), 12000);
    }
  }

  toolRead(filePath, startLine, endLine) {
    const resolved = this.resolvePath(filePath);
    if (!fs.existsSync(resolved)) return `ERROR: ${filePath} not found`;
    if (fs.statSync(resolved).isDirectory()) return `ERROR: ${filePath} is a directory`;

    const lines = fs.readFileSync(resolved, 'utf8').split(/(?<=\n)/);
    let selected = lines;
    if (startLine !== undefined || endLine !== undefined) {
      const s = Math.max((startLine || 1) - 1, 0);
      const e = endLine !== undefined ? endLine : lines.length;
      selected = lines.slice(s, e);
    }
    return clip(selected.join(''), 12000);
  }

  toolWrite(filePath, content) {
    const resolved = this.resolvePath(filePath);
    fs.mkdirSync(path.dirname(resolved), { recursive: true });

    let old = '';
    if (fs.existsSync(resolved) && fs.statSync(resolved).isFile()) {
      old = fs.readFileSync(resolved, 'utf8');
    }

    fs.writeFileSync(resolved, content, 'utf8');

    const oldLines = old ? old.split(/\r?\n/).length : 0;
    const newLines = content ? content.split(/\r?\n/).length : 0;
    return `Wrote ${relpathDisplay(resolved, this.config.workDir)} (${content.length} bytes, lines ${oldLines}->${newLines})`;
  }

  toolEdit(filePath, oldStr, newStr) {
    const resolved = this.resolvePath(filePath);
    if (!fs.existsSync(resolved)) return `ERROR: ${filePath} not found`;
    if (fs.statSync(resolved).isDirectory()) return `ERROR: ${filePath} is a directory`;

    const content = fs.readFileSync(resolved, 'utf8');
    const count = content.split(oldStr).length - 1;
    if (count === 0) return 'ERROR: old_str not found';
    if (count > 1) return `ERROR: old_str found ${count} times`;

    fs.writeFileSync(resolved, content.replace(oldStr, newStr), 'utf8');
    return `Edited ${relpathDisplay(resolved, this.config.workDir)} (1 replacement)`;
  }

  walkFiles(baseDir, out) {
    const entries = fs.readdirSync(baseDir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(baseDir, entry.name);
      if (entry.isDirectory()) {
        this.walkFiles(fullPath, out);
      } else if (entry.isFile()) {
        out.push(fullPath);
      }
    }
  }

  globToRegex(globPattern) {
    let p = globPattern.replace(/\\/g, '/');
    p = p.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    p = p.replace(/\*\*/g, '__DOUBLE_STAR__');
    p = p.replace(/\*/g, '[^/]*');
    p = p.replace(/\?/g, '.');
    p = p.replace(/__DOUBLE_STAR__/g, '.*');
    return new RegExp(`^${p}$`);
  }

  toolGlob(pattern, globPath) {
    const base = globPath ? this.resolvePath(globPath) : this.config.workDir;
    if (!fs.existsSync(base)) return `ERROR: path not found: ${globPath}`;
    if (!fs.statSync(base).isDirectory()) return `ERROR: path is not a directory: ${globPath}`;

    const files = [];
    this.walkFiles(base, files);

    const rx = this.globToRegex(pattern);
    const matches = [];

    for (const file of files) {
      const relToBase = path.relative(base, file).replace(/\\/g, '/');
      if (rx.test(relToBase)) {
        matches.push(relpathDisplay(file, this.config.workDir));
      }
    }

    if (matches.length === 0) return 'No matches';
    matches.sort();
    return clip(matches.slice(0, 300).join('\n'), 12000);
  }

  toolGrep(pattern, grepPath, globPattern) {
    const target = grepPath ? this.resolvePath(grepPath) : this.config.workDir;
    if (!fs.existsSync(target)) return `ERROR: path not found: ${grepPath}`;

    let files = [];
    if (fs.statSync(target).isFile()) {
      files = [target];
    } else {
      this.walkFiles(target, files);
      if (globPattern) {
        const globRx = this.globToRegex(globPattern);
        files = files.filter((f) => globRx.test(path.relative(target, f).replace(/\\/g, '/')));
      }
    }

    let rx;
    try {
      rx = new RegExp(pattern);
    } catch (err) {
      return `ERROR: invalid regex pattern: ${err.message}`;
    }

    const results = [];
    const maxFiles = Math.min(files.length, 1200);

    for (let i = 0; i < maxFiles; i += 1) {
      const file = files[i];
      try {
        const lines = fs.readFileSync(file, 'utf8').split(/\r?\n/);
        for (let lineNo = 0; lineNo < lines.length; lineNo += 1) {
          if (rx.test(lines[lineNo])) {
            results.push(`${relpathDisplay(file, this.config.workDir)}:${lineNo + 1}: ${lines[lineNo].trim()}`);
            if (results.length >= 300) break;
          }
        }
      } catch {
        // ignore unreadable files
      }
      if (results.length >= 300) break;
    }

    return results.length ? results.join('\n') : 'No matches';
  }

  async toolWebFetch(url, maxChars = 8000) {
    try {
      const response = await fetch(url, {
        headers: { 'User-Agent': 'deus-agent/1.0' },
      });
      const html = await response.text();

      const withoutScriptStyle = html
        .replace(/<script[\s\S]*?<\/script>/gi, ' ')
        .replace(/<style[\s\S]*?<\/style>/gi, ' ')
        .replace(/<nav[\s\S]*?<\/nav>/gi, ' ')
        .replace(/<footer[\s\S]*?<\/footer>/gi, ' ');

      const text = withoutScriptStyle
        .replace(/<[^>]+>/g, ' ')
        .replace(/\s+/g, ' ')
        .trim();

      return clip(text, maxChars);
    } catch (err) {
      return `ERROR: ${err.message}`;
    }
  }

  toolTodoWrite(operation, text, id) {
    if (operation === 'add') {
      if (!text) return 'ERROR: text is required for add';
      const tid = this.state.nextTodoId;
      this.state.nextTodoId += 1;
      this.state.todos.push({ id: tid, text, done: false });
      return `Added todo ${tid}: ${text}`;
    }

    if (operation === 'complete') {
      if (id === undefined || id === null) return 'ERROR: id is required for complete';
      const todo = this.state.todos.find((t) => t.id === id);
      if (!todo) return `ERROR: todo ${id} not found`;
      todo.done = true;
      return `Completed todo ${id}`;
    }

    if (operation === 'delete') {
      if (id === undefined || id === null) return 'ERROR: id is required for delete';
      const before = this.state.todos.length;
      this.state.todos = this.state.todos.filter((t) => t.id !== id);
      if (this.state.todos.length === before) return `ERROR: todo ${id} not found`;
      return `Deleted todo ${id}`;
    }

    if (operation === 'list') {
      if (!this.state.todos.length) return 'No todos';
      return this.state.todos
        .map((t) => `[${t.done ? 'x' : ' '}] ${t.id}. ${t.text}`)
        .join('\n');
    }

    return `ERROR: unknown operation '${operation}'`;
  }

  async toolAskUser(question) {
    if (typeof this.askUserHandler === 'function') {
      return String(await this.askUserHandler(question));
    }

    this.log(this.c(Colors.YELLOW, `\nAgent asks: ${question}`));
    return (await this.askLine('Your answer: ')).trim();
  }

  toolFinish(summary) {
    return { __finish__: true, summary };
  }

  async summarize(messages) {
    if (!messages.length) return '';

    const prompt = [
      'Summarize the prior conversation context for future continuation.',
      'Keep decisions, constraints, attempted actions, tool outcomes, and unresolved work.',
      'Use compact bullet points.',
    ].join(' ');

    try {
      const response = await this.client.chat.completions.create({
        model: this.config.model,
        messages: [
          { role: 'system', content: prompt },
          { role: 'user', content: clip(JSON.stringify(messages), 20000) },
        ],
        temperature: 0,
      });

      return String(response.choices?.[0]?.message?.content || '').trim();
    } catch (err) {
      return `Summary unavailable (${err.message})`;
    }
  }

  tailStartIndex() {
    const keep = Math.max(1, this.config.truncateKeepRecent);
    let start = Math.max(1, this.messages.length - keep);

    while (start < this.messages.length) {
      const role = this.messages[start]?.role;
      if (role === 'tool') {
        start += 1;
        continue;
      }
      if (role === 'assistant' && this.messages[start]?.tool_calls) {
        start += 1;
        continue;
      }
      break;
    }

    return Math.min(start, this.messages.length);
  }

  async maybeTruncate() {
    const threshold = Math.max(3, this.config.truncateThreshold);
    if (this.messages.length <= threshold) return;

    const tailStart = this.tailStartIndex();
    const middle = this.messages.slice(1, tailStart);
    if (!middle.length) return;

    const summary = await this.summarize(middle);
    this.messages = [
      this.messages[0],
      { role: 'user', content: `[prior context summary]\n${summary}` },
      ...this.messages.slice(tailStart),
    ];
  }

  async dispatch(name, args) {
    const dispatchMap = {
      Bash: (a) => this.toolBash(a.command, a.timeout),
      Read: (a) => this.toolRead(a.path, a.start_line, a.end_line),
      Write: (a) => this.toolWrite(a.path, a.content),
      Edit: (a) => this.toolEdit(a.path, a.old_str, a.new_str),
      Glob: (a) => this.toolGlob(a.pattern, a.path),
      Grep: (a) => this.toolGrep(a.pattern, a.path, a.glob),
      WebFetch: (a) => this.toolWebFetch(a.url, a.max_chars),
      TodoWrite: (a) => this.toolTodoWrite(a.operation, a.text, a.id),
      AskUser: (a) => this.toolAskUser(a.question),
      Finish: (a) => this.toolFinish(a.summary),
    };

    if (!dispatchMap[name]) return [`ERROR: unknown tool '${name}'`, false];

    const brief = args.command || args.path || args.pattern || args.url || args.question || '';
    const icon = this.icons[name] || '🔧';
    this.log(this.c(Colors.DIM, `  ${icon} ${name} ${String(brief).slice(0, 90)}`));

    try {
      const result = await dispatchMap[name](args);
      if (result && typeof result === 'object' && result.__finish__) {
        return [String(result.summary), true];
      }
      return [String(result), false];
    } catch (err) {
      return [`ERROR: invalid arguments for tool '${name}': ${err.message}`, false];
    }
  }

  async runTurn(userInput) {
    this.messages.push({ role: 'user', content: userInput });
    await this.maybeTruncate();

    for (let i = 1; i <= this.config.maxIter; i += 1) {
      this.log(this.c(Colors.DIM, `\n[${i}/${this.config.maxIter}] thinking...`));

      const response = await this.client.chat.completions.create({
        model: this.config.model,
        messages: this.messages,
        tools: this.tools,
        tool_choice: 'auto',
        temperature: this.config.temperature,
      });

      const choice = response.choices?.[0] || {};
      const msg = choice.message || {};
      const reason = choice.finish_reason;

      this.messages.push({
        role: msg.role || 'assistant',
        content: msg.content || '',
        tool_calls: msg.tool_calls || undefined,
      });
      await this.maybeTruncate();

      if (msg.content) {
        this.log(this.c(Colors.CYAN, `assistant> ${String(msg.content).trim()}`));
      }

      if (reason === 'stop' && !(msg.tool_calls && msg.tool_calls.length)) {
        return msg.content ? String(msg.content).trim() : 'Done.';
      }

      if (!msg.tool_calls || !msg.tool_calls.length) {
        return msg.content ? String(msg.content).trim() : 'No tool calls returned.';
      }

      const toolResults = [];

      for (const tc of msg.tool_calls) {
        const name = tc.function?.name;
        let args;
        try {
          args = JSON.parse(tc.function?.arguments || '{}');
        } catch (err) {
          const result = `ERROR: bad tool args JSON: ${err.message}`;
          toolResults.push({ role: 'tool', tool_call_id: tc.id, content: clip(result, 8000) });
          continue;
        }

        const [result, done] = await this.dispatch(name, args);

        toolResults.push({
          role: 'tool',
          tool_call_id: tc.id,
          content: clip(result, 8000),
        });

        if (done) {
          this.log(this.c(Colors.GREEN, `\nFinished: ${result}`));
          this.messages.push(...toolResults);
          await this.maybeTruncate();
          return result;
        }
      }

      this.messages.push(...toolResults);
      await this.maybeTruncate();
    }

    const maxMsg = `Stopped after max iterations (${this.config.maxIter}).`;
    this.log(this.c(Colors.YELLOW, maxMsg));
    return maxMsg;
  }

  async runPrompt(prompt) {
    return this.runTurn(prompt);
  }
}

function buildClient(options = {}) {
  let OpenAI;
  try {
    OpenAI = require('openai');
  } catch {
    throw new Error('Missing dependency: openai. Install it with `npm install openai`.');
  }

  const baseURL = options.baseURL || process.env.OPENAI_BASE_URL || 'https://openrouter.ai/api/v1';
  const apiKey = options.apiKey || process.env.OPENAI_API_KEY || process.env.OPENROUTER_API_KEY;
  if (!apiKey) {
    throw new Error('Missing API key. Set OPENAI_API_KEY or OPENROUTER_API_KEY in your environment.');
  }

  return new OpenAI({ baseURL, apiKey });
}

function buildDefaultConfig(overrides = {}) {
  const workDir = overrides.workDir || process.cwd();
  const appDir = overrides.appDir || __dirname;
  const rawRepoName = overrides.repoName || path.basename(workDir);
  const repoName = normalizeRepoName(rawRepoName);
  const repoDir = overrides.repoDir || path.join(appDir, 'repos', repoName);

  fs.mkdirSync(repoDir, { recursive: true });

  return {
    model: overrides.model || process.env.DEUS_MODEL || 'openai/gpt-4.1-mini',
    maxIter: overrides.maxIter ?? Number.parseInt(process.env.DEUS_MAX_ITER || '60', 10),
    temperature: overrides.temperature ?? Number.parseFloat(process.env.DEUS_TEMPERATURE || '0.2'),
    approvalMode: overrides.approvalMode || process.env.DEUS_APPROVAL_MODE || 'safe',
    truncateThreshold: overrides.truncateThreshold ?? Number.parseInt(process.env.DEUS_TRUNCATE_THRESHOLD || '40', 10),
    truncateKeepRecent: overrides.truncateKeepRecent ?? Number.parseInt(process.env.DEUS_TRUNCATE_KEEP_RECENT || '10', 10),
    workDir,
    appDir,
    repoName,
    repoDir,
  };
}

function validateConfig(config) {
  if (!['safe', 'always', 'never'].includes(config.approvalMode)) {
    throw new Error(`Invalid approvalMode '${config.approvalMode}' (expected safe|always|never)`);
  }
}

function createLoop(options = {}) {
  const client = options.client || buildClient(options.clientOptions || {});
  const config = buildDefaultConfig(options.config || {});
  validateConfig(config);

  return new DeusLoop(client, config, {
    useColor: options.useColor,
    logger: options.logger,
    confirmCommand: options.confirmCommand,
    askUser: options.askUser,
  });
}

async function runAgenticLoop(options = {}) {
  const prompt = options.prompt;
  if (typeof prompt !== 'string' || !prompt.trim()) {
    throw new Error('runAgenticLoop requires a non-empty `prompt` string.');
  }

  const loop = createLoop(options);
  return loop.runPrompt(prompt);
}

module.exports = {
  DeusLoop,
  buildClient,
  buildDefaultConfig,
  createLoop,
  runAgenticLoop,
  normalizeRepoName,
};
