'use strict';

const http = require('http');
const path = require('path');
const { openDatabase } = require('./db');

const PORT = process.env.DASHBOARD_PORT || 7331;

// ── DB queries ────────────────────────────────────────────────────────────────

function getRepos(db) {
  return db.prepare(`
    SELECT DISTINCT repo_name, repo_path,
           COUNT(DISTINCT tm.id) AS threat_model_count,
           MAX(tm.created_at)    AS last_run
    FROM threat_models tm
    GROUP BY repo_name, repo_path
    ORDER BY last_run DESC
  `).all();
}

function getLatestThreatModel(db, repoName) {
  return db.prepare(`
    SELECT id, repo_name, repo_path, threat_model, created_at
    FROM threat_models
    WHERE repo_name = ?
    ORDER BY created_at DESC, id DESC
    LIMIT 1
  `).get(repoName);
}

function getTargetStats(db, threatModelId) {
  return db.prepare(`
    SELECT
      COUNT(*)                          AS total,
      SUM(CASE WHEN scanned = 1 THEN 1 ELSE 0 END) AS scanned,
      SUM(CASE WHEN scanned = 0 THEN 1 ELSE 0 END) AS pending
    FROM target_items
    WHERE threat_model_id = ?
  `).get(threatModelId);
}

function getTargets(db, threatModelId) {
  return db.prepare(`
    SELECT ti.id, ti.path, ti.function, ti.reason, ti.scanned,
           COUNT(f.id) AS finding_count
    FROM target_items ti
    LEFT JOIN findings f ON f.target_item_id = ti.id
    WHERE ti.threat_model_id = ?
    GROUP BY ti.id
    ORDER BY finding_count DESC, ti.id ASC
  `).all(threatModelId);
}

function getFindings(db, threatModelId) {
  return db.prepare(`
    SELECT f.id, f.path, f.function, f.severity, f.title,
           f.description, f.evidence, f.impact, f.recommendation,
           f.confidence, f.created_at
    FROM findings f
    WHERE f.threat_model_id = ?
    ORDER BY
      CASE f.severity
        WHEN 'critical' THEN 1
        WHEN 'high'     THEN 2
        WHEN 'medium'   THEN 3
        WHEN 'low'      THEN 4
        ELSE 5
      END,
      f.created_at DESC
  `).all(threatModelId);
}

function getFindingStats(db, threatModelId) {
  return db.prepare(`
    SELECT
      COUNT(*) AS total,
      SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) AS critical,
      SUM(CASE WHEN severity = 'high'     THEN 1 ELSE 0 END) AS high,
      SUM(CASE WHEN severity = 'medium'   THEN 1 ELSE 0 END) AS medium,
      SUM(CASE WHEN severity = 'low'      THEN 1 ELSE 0 END) AS low
    FROM findings
    WHERE threat_model_id = ?
  `).get(threatModelId);
}

// ── HTML generation ───────────────────────────────────────────────────────────

function esc(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

const SEVERITY_CLASS = {
  critical: 'sev-critical',
  high: 'sev-high',
  medium: 'sev-medium',
  low: 'sev-low',
};

const CONFIDENCE_CLASS = {
  high: 'conf-high',
  medium: 'conf-medium',
  low: 'conf-low',
};

function renderCSS() {
  return `
    @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Barlow+Condensed:wght@300;400;600;700&family=Barlow:wght@300;400;500&display=swap');

    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    :root {
      --bg-void:      #040608;
      --bg-base:      #080c10;
      --bg-panel:     #0d1318;
      --bg-raised:    #111820;
      --bg-hover:     #16202a;
      --border:       #1c2a36;
      --border-bright:#243545;
      --amber:        #e8a020;
      --amber-dim:    #7a500f;
      --amber-glow:   rgba(232,160,32,0.12);
      --green:        #22c55e;
      --green-dim:    #14532d;
      --green-glow:   rgba(34,197,94,0.10);
      --red:          #ef4444;
      --red-dim:      #7f1d1d;
      --red-glow:     rgba(239,68,68,0.12);
      --orange:       #f97316;
      --orange-dim:   #7c2d12;
      --yellow:       #eab308;
      --yellow-dim:   #713f12;
      --blue:         #38bdf8;
      --blue-dim:     #0c4a6e;
      --text-primary: #c8d8e8;
      --text-sec:     #6a8299;
      --text-dim:     #384f62;
      --text-mono:    #9db8cc;
      --font-display: 'Barlow Condensed', sans-serif;
      --font-body:    'Barlow', sans-serif;
      --font-mono:    'Share Tech Mono', monospace;
    }

    html { scroll-behavior: smooth; }

    body {
      background: var(--bg-void);
      color: var(--text-primary);
      font-family: var(--font-body);
      font-size: 14px;
      line-height: 1.6;
      min-height: 100vh;
      background-image:
        linear-gradient(rgba(232,160,32,0.015) 1px, transparent 1px),
        linear-gradient(90deg, rgba(232,160,32,0.015) 1px, transparent 1px);
      background-size: 48px 48px;
    }

    /* ── TOPBAR ── */
    .topbar {
      position: sticky; top: 0; z-index: 100;
      background: rgba(4,6,8,0.96);
      border-bottom: 1px solid var(--border);
      backdrop-filter: blur(12px);
      padding: 0 24px;
      height: 52px;
      display: flex; align-items: center; gap: 16px;
    }
    .topbar-logo {
      font-family: var(--font-display);
      font-size: 18px; font-weight: 700; letter-spacing: 0.15em;
      color: var(--amber);
      text-transform: uppercase;
      display: flex; align-items: center; gap: 10px;
    }
    .topbar-logo::before {
      content: '';
      display: inline-block; width: 8px; height: 8px;
      background: var(--amber);
      clip-path: polygon(50% 0%, 100% 50%, 50% 100%, 0% 50%);
      animation: pulse-diamond 2.4s ease-in-out infinite;
    }
    @keyframes pulse-diamond {
      0%,100% { opacity: 1; transform: scale(1); }
      50%      { opacity: 0.4; transform: scale(0.7); }
    }
    .topbar-sep { color: var(--border-bright); margin: 0 4px; }
    .topbar-repo {
      font-family: var(--font-mono); font-size: 13px;
      color: var(--text-sec);
    }
    .topbar-right { margin-left: auto; display: flex; align-items: center; gap: 20px; }
    .topbar-clock {
      font-family: var(--font-mono); font-size: 12px;
      color: var(--text-dim); letter-spacing: 0.05em;
    }
    .back-link {
      font-family: var(--font-display); font-size: 12px; font-weight: 600;
      letter-spacing: 0.12em; text-transform: uppercase;
      color: var(--text-sec); text-decoration: none;
      border: 1px solid var(--border); padding: 4px 12px;
      transition: all 0.15s;
    }
    .back-link:hover { color: var(--amber); border-color: var(--amber-dim); }

    /* ── LAYOUT ── */
    .container { max-width: 1440px; margin: 0 auto; padding: 0 24px 60px; }

    /* ── PAGE HEADER ── */
    .page-header {
      padding: 32px 0 24px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 28px;
    }
    .page-header-label {
      font-family: var(--font-mono); font-size: 11px;
      color: var(--amber); letter-spacing: 0.2em; text-transform: uppercase;
      margin-bottom: 6px;
    }
    .page-header-title {
      font-family: var(--font-display); font-size: 36px; font-weight: 700;
      letter-spacing: 0.04em; line-height: 1;
      color: var(--text-primary);
    }
    .page-header-meta {
      margin-top: 8px;
      font-family: var(--font-mono); font-size: 12px; color: var(--text-sec);
      display: flex; gap: 24px; flex-wrap: wrap;
    }
    .page-header-meta span { display: flex; align-items: center; gap: 6px; }
    .page-header-meta span::before {
      content: ''; display: inline-block;
      width: 4px; height: 4px; border-radius: 50%;
      background: var(--amber-dim);
    }

    /* ── STAT BAR ── */
    .stat-bar {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 1px;
      background: var(--border);
      border: 1px solid var(--border);
      margin-bottom: 28px;
    }
    .stat-cell {
      background: var(--bg-panel);
      padding: 16px 20px;
      display: flex; flex-direction: column; gap: 4px;
    }
    .stat-cell-label {
      font-family: var(--font-mono); font-size: 10px;
      color: var(--text-dim); letter-spacing: 0.15em; text-transform: uppercase;
    }
    .stat-cell-value {
      font-family: var(--font-display); font-size: 28px; font-weight: 700;
      line-height: 1;
    }
    .stat-cell-value.v-critical { color: var(--red); }
    .stat-cell-value.v-high     { color: var(--orange); }
    .stat-cell-value.v-medium   { color: var(--yellow); }
    .stat-cell-value.v-low      { color: var(--blue); }
    .stat-cell-value.v-total    { color: var(--text-primary); }
    .stat-cell-value.v-scanned  { color: var(--green); }
    .stat-cell-value.v-pending  { color: var(--amber); }

    /* ── SECTION ── */
    .section { margin-bottom: 36px; }
    .section-head {
      display: flex; align-items: center; gap: 12px;
      padding-bottom: 10px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 16px;
    }
    .section-title {
      font-family: var(--font-display); font-size: 15px; font-weight: 600;
      letter-spacing: 0.12em; text-transform: uppercase;
      color: var(--text-sec);
    }
    .section-count {
      font-family: var(--font-mono); font-size: 11px;
      color: var(--amber); background: var(--amber-glow);
      border: 1px solid var(--amber-dim);
      padding: 1px 8px; letter-spacing: 0.05em;
    }
    .section-line {
      flex: 1; height: 1px;
      background: linear-gradient(90deg, var(--border), transparent);
    }

    /* ── THREAT MODEL PANEL ── */
    .threat-panel {
      background: var(--bg-panel);
      border: 1px solid var(--border);
      padding: 24px 28px;
      position: relative; overflow: hidden;
    }
    .threat-panel::before {
      content: '';
      position: absolute; top: 0; left: 0;
      width: 3px; height: 100%;
      background: var(--amber);
    }
    .threat-model-text {
      font-family: var(--font-mono); font-size: 12.5px;
      color: var(--text-mono); line-height: 1.8;
      white-space: pre-wrap; word-break: break-word;
      max-height: 420px; overflow-y: auto;
    }
    .threat-model-text::-webkit-scrollbar { width: 4px; }
    .threat-model-text::-webkit-scrollbar-track { background: transparent; }
    .threat-model-text::-webkit-scrollbar-thumb { background: var(--border-bright); }

    /* render markdown headings inside threat model */
    .threat-model-text .tm-h1 {
      font-family: var(--font-display); font-size: 16px; font-weight: 700;
      color: var(--amber); letter-spacing: 0.08em;
      display: block; margin: 14px 0 4px;
    }
    .threat-model-text .tm-h2 {
      font-family: var(--font-display); font-size: 13px; font-weight: 600;
      color: var(--text-sec); letter-spacing: 0.06em;
      display: block; margin: 10px 0 2px;
    }

    /* ── TARGETS TABLE ── */
    .targets-table { width: 100%; border-collapse: collapse; }
    .targets-table thead tr {
      background: var(--bg-raised);
      border-bottom: 1px solid var(--border-bright);
    }
    .targets-table th {
      font-family: var(--font-mono); font-size: 10px; font-weight: 400;
      letter-spacing: 0.15em; text-transform: uppercase;
      color: var(--text-dim); text-align: left;
      padding: 10px 14px;
    }
    .targets-table td {
      padding: 10px 14px;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }
    .targets-table tbody tr { background: var(--bg-panel); }
    .targets-table tbody tr:hover { background: var(--bg-hover); }
    .cell-path {
      font-family: var(--font-mono); font-size: 11.5px;
      color: var(--blue); word-break: break-all;
    }
    .cell-fn {
      font-family: var(--font-mono); font-size: 11.5px;
      color: var(--amber);
    }
    .cell-reason { font-size: 12.5px; color: var(--text-sec); }
    .badge-scanned {
      font-family: var(--font-mono); font-size: 10px;
      letter-spacing: 0.08em; text-transform: uppercase;
      padding: 2px 8px; border: 1px solid;
      display: inline-block;
    }
    .badge-scanned.done  { color: var(--green); border-color: var(--green-dim); background: var(--green-glow); }
    .badge-scanned.pend  { color: var(--amber); border-color: var(--amber-dim); background: var(--amber-glow); }
    .findings-bubble {
      font-family: var(--font-mono); font-size: 10px;
      color: var(--red); background: var(--red-glow);
      border: 1px solid var(--red-dim);
      padding: 1px 7px; display: inline-block;
    }
    .findings-bubble.zero { color: var(--text-dim); background: none; border-color: var(--border); }

    /* ── FINDINGS ── */
    .findings-list { display: flex; flex-direction: column; gap: 12px; }
    .finding-card {
      background: var(--bg-panel);
      border: 1px solid var(--border);
      border-left: 3px solid;
      position: relative; overflow: hidden;
    }
    .finding-card.sev-critical { border-left-color: var(--red); }
    .finding-card.sev-high     { border-left-color: var(--orange); }
    .finding-card.sev-medium   { border-left-color: var(--yellow); }
    .finding-card.sev-low      { border-left-color: var(--blue); }

    .finding-header {
      display: flex; align-items: flex-start; gap: 12px;
      padding: 14px 18px;
      border-bottom: 1px solid var(--border);
      cursor: pointer;
      user-select: none;
    }
    .finding-header:hover { background: var(--bg-hover); }

    .finding-severity {
      font-family: var(--font-mono); font-size: 10px; font-weight: 700;
      letter-spacing: 0.15em; text-transform: uppercase;
      padding: 3px 10px; border: 1px solid; flex-shrink: 0; margin-top: 1px;
    }
    .sev-critical .finding-severity { color: var(--red);    border-color: var(--red-dim);    background: var(--red-glow); }
    .sev-high     .finding-severity { color: var(--orange); border-color: var(--orange-dim); background: rgba(249,115,22,0.10); }
    .sev-medium   .finding-severity { color: var(--yellow); border-color: var(--yellow-dim); background: rgba(234,179,8,0.10); }
    .sev-low      .finding-severity { color: var(--blue);   border-color: var(--blue-dim);   background: rgba(56,189,248,0.08); }

    .finding-title-block { flex: 1; }
    .finding-title {
      font-family: var(--font-display); font-size: 16px; font-weight: 600;
      letter-spacing: 0.03em; color: var(--text-primary); line-height: 1.2;
    }
    .finding-loc {
      margin-top: 4px;
      font-family: var(--font-mono); font-size: 11px;
      color: var(--text-dim);
    }
    .finding-loc .loc-path { color: var(--blue); }
    .finding-loc .loc-fn   { color: var(--amber); margin-left: 8px; }

    .finding-meta {
      display: flex; align-items: center; gap: 10px; flex-shrink: 0;
    }
    .conf-badge {
      font-family: var(--font-mono); font-size: 10px;
      letter-spacing: 0.1em; text-transform: uppercase;
      padding: 2px 8px; border: 1px solid;
    }
    .conf-high   { color: var(--green);  border-color: var(--green-dim);  background: var(--green-glow); }
    .conf-medium { color: var(--amber);  border-color: var(--amber-dim);  background: var(--amber-glow); }
    .conf-low    { color: var(--text-dim); border-color: var(--border);   background: none; }

    .chevron {
      font-size: 12px; color: var(--text-dim);
      transition: transform 0.2s; flex-shrink: 0;
    }
    .finding-card.open .chevron { transform: rotate(90deg); }

    .finding-body {
      display: none; padding: 18px 20px;
    }
    .finding-card.open .finding-body { display: block; }

    .finding-fields { display: flex; flex-direction: column; gap: 14px; }
    .finding-field-label {
      font-family: var(--font-mono); font-size: 10px;
      letter-spacing: 0.15em; text-transform: uppercase;
      color: var(--text-dim); margin-bottom: 4px;
    }
    .finding-field-value {
      font-size: 13px; color: var(--text-sec); line-height: 1.65;
    }
    .finding-field-value.mono {
      font-family: var(--font-mono); font-size: 11.5px;
      background: var(--bg-base); border: 1px solid var(--border);
      padding: 10px 14px; color: var(--text-mono);
      white-space: pre-wrap; word-break: break-word;
    }
    .rec-block {
      background: var(--green-glow);
      border: 1px solid var(--green-dim);
      padding: 10px 14px;
      font-size: 13px; color: var(--text-sec); line-height: 1.65;
    }

    /* ── INDEX PAGE ── */
    .repo-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 1px; background: var(--border); }
    .repo-card {
      background: var(--bg-panel);
      padding: 20px 22px;
      text-decoration: none;
      display: block;
      position: relative; overflow: hidden;
      transition: background 0.15s;
    }
    .repo-card::after {
      content: '';
      position: absolute; bottom: 0; left: 0; right: 0;
      height: 2px;
      background: linear-gradient(90deg, var(--amber), transparent);
      transform: scaleX(0); transform-origin: left;
      transition: transform 0.25s;
    }
    .repo-card:hover { background: var(--bg-hover); }
    .repo-card:hover::after { transform: scaleX(1); }
    .repo-card-name {
      font-family: var(--font-display); font-size: 20px; font-weight: 700;
      color: var(--text-primary); letter-spacing: 0.04em; margin-bottom: 4px;
    }
    .repo-card-path {
      font-family: var(--font-mono); font-size: 10.5px;
      color: var(--text-dim); margin-bottom: 14px;
      word-break: break-all;
    }
    .repo-card-stats {
      display: flex; gap: 16px;
      font-family: var(--font-mono); font-size: 11px;
    }
    .repo-card-stats span { color: var(--text-sec); }
    .repo-card-stats span strong { color: var(--amber); }
    .repo-card-date {
      margin-top: 10px;
      font-family: var(--font-mono); font-size: 10px; color: var(--text-dim);
    }
    .empty-state {
      padding: 60px 24px; text-align: center;
      font-family: var(--font-mono); font-size: 13px; color: var(--text-dim);
    }
    .empty-state strong { display: block; font-size: 18px; color: var(--text-sec); margin-bottom: 8px; }

    /* ── SCROLLBAR ── */
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: var(--bg-void); }
    ::-webkit-scrollbar-thumb { background: var(--border-bright); }

    /* ── ANIMATIONS ── */
    @keyframes fadeSlideIn {
      from { opacity: 0; transform: translateY(10px); }
      to   { opacity: 1; transform: translateY(0); }
    }
    .anim { animation: fadeSlideIn 0.3s ease both; }
    .anim-d1 { animation-delay: 0.05s; }
    .anim-d2 { animation-delay: 0.10s; }
    .anim-d3 { animation-delay: 0.15s; }
    .anim-d4 { animation-delay: 0.20s; }
  `;
}

function renderTopbar(repoName) {
  const backLink = repoName
    ? `<a class="back-link" href="/">◀ ALL REPOS</a>`
    : '';
  const repoLabel = repoName
    ? `<span class="topbar-sep">/</span><span class="topbar-repo">${esc(repoName)}</span>`
    : '';
  return `
    <div class="topbar">
      <div class="topbar-logo">OPEN-MYTHOS${repoLabel}</div>
      <div class="topbar-right">
        <div class="topbar-clock" id="clock"></div>
        ${backLink}
      </div>
    </div>
    <script>
      (function() {
        function tick() {
          const el = document.getElementById('clock');
          if (el) el.textContent = new Date().toISOString().replace('T',' ').slice(0,19) + ' UTC';
        }
        tick(); setInterval(tick, 1000);
      })();
    </script>
  `;
}

function renderBase(title, repoName, bodyContent) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${esc(title)} — Open-Mythos</title>
  <style>${renderCSS()}</style>
</head>
<body>
  ${renderTopbar(repoName)}
  <div class="container">
    ${bodyContent}
  </div>
  <script>
    // accordion
    document.addEventListener('click', function(e) {
      const header = e.target.closest('.finding-header');
      if (!header) return;
      header.closest('.finding-card').classList.toggle('open');
    });
  </script>
</body>
</html>`;
}

// ── Pages ─────────────────────────────────────────────────────────────────────

function renderIndexPage(repos) {
  let body = `
    <div class="page-header anim">
      <div class="page-header-label">Intelligence Platform</div>
      <div class="page-header-title">Repository Index</div>
      <div class="page-header-meta">
        <span>${repos.length} repositor${repos.length === 1 ? 'y' : 'ies'} tracked</span>
      </div>
    </div>
  `;

  if (!repos.length) {
    body += `<div class="empty-state"><strong>No repositories found</strong>Run the pipeline first to populate the database.</div>`;
  } else {
    body += `<div class="repo-grid anim anim-d1">`;
    for (const repo of repos) {
      body += `
        <a class="repo-card" href="/repo/${encodeURIComponent(repo.repo_name)}">
          <div class="repo-card-name">${esc(repo.repo_name)}</div>
          <div class="repo-card-path">${esc(repo.repo_path)}</div>
          <div class="repo-card-stats">
            <span>Runs <strong>${repo.threat_model_count}</strong></span>
          </div>
          <div class="repo-card-date">Last run: ${esc(repo.last_run)}</div>
        </a>
      `;
    }
    body += `</div>`;
  }

  return renderBase('Repository Index', null, body);
}

function renderThreatModelText(raw) {
  // Lightly render markdown headings into styled spans
  const lines = raw.split('\n').map((line) => {
    if (/^# /.test(line))  return `<span class="tm-h1">${esc(line.slice(2))}</span>`;
    if (/^## /.test(line)) return `<span class="tm-h2">${esc(line.slice(3))}</span>`;
    return esc(line);
  });
  return lines.join('\n');
}

function renderRepoPage(tm, targetStats, targets, findingStats, findings) {
  const repoName = tm.repo_name;

  // ── stat bar ──
  const statBar = `
    <div class="stat-bar anim anim-d1">
      <div class="stat-cell">
        <div class="stat-cell-label">Critical</div>
        <div class="stat-cell-value v-critical">${findingStats.critical ?? 0}</div>
      </div>
      <div class="stat-cell">
        <div class="stat-cell-label">High</div>
        <div class="stat-cell-value v-high">${findingStats.high ?? 0}</div>
      </div>
      <div class="stat-cell">
        <div class="stat-cell-label">Medium</div>
        <div class="stat-cell-value v-medium">${findingStats.medium ?? 0}</div>
      </div>
      <div class="stat-cell">
        <div class="stat-cell-label">Low</div>
        <div class="stat-cell-value v-low">${findingStats.low ?? 0}</div>
      </div>
      <div class="stat-cell">
        <div class="stat-cell-label">Total Findings</div>
        <div class="stat-cell-value v-total">${findingStats.total ?? 0}</div>
      </div>
      <div class="stat-cell">
        <div class="stat-cell-label">Targets</div>
        <div class="stat-cell-value v-total">${targetStats.total ?? 0}</div>
      </div>
      <div class="stat-cell">
        <div class="stat-cell-label">Scanned</div>
        <div class="stat-cell-value v-scanned">${targetStats.scanned ?? 0}</div>
      </div>
      <div class="stat-cell">
        <div class="stat-cell-label">Pending</div>
        <div class="stat-cell-value v-pending">${targetStats.pending ?? 0}</div>
      </div>
    </div>
  `;

  // ── threat model ──
  const threatSection = `
    <div class="section anim anim-d2">
      <div class="section-head">
        <div class="section-title">Threat Model</div>
        <div class="section-count">ID ${tm.id}</div>
        <div class="section-line"></div>
        <span style="font-family:var(--font-mono);font-size:10px;color:var(--text-dim)">${esc(tm.created_at)}</span>
      </div>
      <div class="threat-panel">
        <div class="threat-model-text">${renderThreatModelText(tm.threat_model)}</div>
      </div>
    </div>
  `;

  // ── findings ──
  let findingsHtml = '';
  if (!findings.length) {
    findingsHtml = `<div class="empty-state"><strong>No findings yet</strong>Run the research stage to populate findings.</div>`;
  } else {
    findingsHtml = `<div class="findings-list">`;
    for (const f of findings) {
      const sevClass = SEVERITY_CLASS[f.severity] || '';
      const confClass = CONFIDENCE_CLASS[f.confidence] || '';
      findingsHtml += `
        <div class="finding-card ${esc(sevClass)}">
          <div class="finding-header">
            <div class="finding-severity">${esc((f.severity || 'n/a').toUpperCase())}</div>
            <div class="finding-title-block">
              <div class="finding-title">${esc(f.title)}</div>
              <div class="finding-loc">
                <span class="loc-path">${esc(f.path)}</span>
                <span class="loc-fn">fn: ${esc(f.function)}</span>
              </div>
            </div>
            <div class="finding-meta">
              ${f.confidence ? `<div class="conf-badge ${esc(confClass)}">${esc(f.confidence.toUpperCase())} CONF</div>` : ''}
              <div class="chevron">▶</div>
            </div>
          </div>
          <div class="finding-body">
            <div class="finding-fields">
              <div>
                <div class="finding-field-label">Description</div>
                <div class="finding-field-value">${esc(f.description)}</div>
              </div>
              ${f.evidence ? `
              <div>
                <div class="finding-field-label">Evidence</div>
                <div class="finding-field-value mono">${esc(f.evidence)}</div>
              </div>` : ''}
              ${f.impact ? `
              <div>
                <div class="finding-field-label">Impact</div>
                <div class="finding-field-value">${esc(f.impact)}</div>
              </div>` : ''}
              ${f.recommendation ? `
              <div>
                <div class="finding-field-label">Recommendation</div>
                <div class="rec-block">${esc(f.recommendation)}</div>
              </div>` : ''}
              <div style="font-family:var(--font-mono);font-size:10px;color:var(--text-dim)">
                Logged: ${esc(f.created_at)}
              </div>
            </div>
          </div>
        </div>
      `;
    }
    findingsHtml += `</div>`;
  }

  const findingsSection = `
    <div class="section anim anim-d3">
      <div class="section-head">
        <div class="section-title">Findings</div>
        <div class="section-count">${findings.length}</div>
        <div class="section-line"></div>
      </div>
      ${findingsHtml}
    </div>
  `;

  // ── targets table ──
  let targetsRows = '';
  for (const t of targets) {
    const scannedBadge = t.scanned
      ? `<span class="badge-scanned done">SCANNED</span>`
      : `<span class="badge-scanned pend">PENDING</span>`;
    const fc = t.finding_count > 0
      ? `<span class="findings-bubble">${t.finding_count} finding${t.finding_count > 1 ? 's' : ''}</span>`
      : `<span class="findings-bubble zero">0</span>`;
    targetsRows += `
      <tr>
        <td class="cell-path">${esc(t.path)}</td>
        <td class="cell-fn">${esc(t.function)}</td>
        <td class="cell-reason">${esc(t.reason)}</td>
        <td>${scannedBadge}</td>
        <td>${fc}</td>
      </tr>
    `;
  }

  const targetsSection = `
    <div class="section anim anim-d4">
      <div class="section-head">
        <div class="section-title">Target Queue</div>
        <div class="section-count">${targets.length}</div>
        <div class="section-line"></div>
      </div>
      <div style="overflow-x:auto">
        <table class="targets-table">
          <thead>
            <tr>
              <th>Path</th>
              <th>Function</th>
              <th>Reason</th>
              <th>Status</th>
              <th>Findings</th>
            </tr>
          </thead>
          <tbody>${targetsRows}</tbody>
        </table>
      </div>
    </div>
  `;

  const pageHeader = `
    <div class="page-header anim">
      <div class="page-header-label">Repository Analysis</div>
      <div class="page-header-title">${esc(repoName)}</div>
      <div class="page-header-meta">
        <span>${esc(tm.repo_path)}</span>
        <span>Threat Model ${tm.id}</span>
        <span>Generated ${esc(tm.created_at)}</span>
      </div>
    </div>
  `;

  return renderBase(repoName, repoName, pageHeader + statBar + findingsSection + threatSection + targetsSection);
}

function render404(msg) {
  return renderBase('Not Found', null, `<div class="empty-state" style="margin-top:80px"><strong>404</strong>${esc(msg)}</div>`);
}

// ── Request handler ───────────────────────────────────────────────────────────

function handleRequest(req, res) {
  const url = new URL(req.url, `http://localhost`);
  const pathname = url.pathname;

  let db;
  try {
    db = openDatabase();
  } catch (err) {
    res.writeHead(500, { 'Content-Type': 'text/plain' });
    res.end('Database error: ' + err.message);
    return;
  }

  try {
    if (pathname === '/' || pathname === '') {
      const repos = getRepos(db);
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(renderIndexPage(repos));
      return;
    }

    const repoMatch = pathname.match(/^\/repo\/([^/]+)$/);
    if (repoMatch) {
      const repoName = decodeURIComponent(repoMatch[1]);
      const tm = getLatestThreatModel(db, repoName);
      if (!tm) {
        res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(render404(`No threat model found for repository "${repoName}"`));
        return;
      }

      const targetStats  = getTargetStats(db, tm.id);
      const targets      = getTargets(db, tm.id);
      const findingStats = getFindingStats(db, tm.id);
      const findings     = getFindings(db, tm.id);

      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(renderRepoPage(tm, targetStats, targets, findingStats, findings));
      return;
    }

    res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(render404('Page not found.'));
  } catch (err) {
    res.writeHead(500, { 'Content-Type': 'text/plain' });
    res.end('Internal error: ' + err.message);
  } finally {
    db.close();
  }
}

// ── Start ─────────────────────────────────────────────────────────────────────

const server = http.createServer(handleRequest);
server.listen(PORT, '127.0.0.1', () => {
  console.log(`[open-mythos] Dashboard running at http://127.0.0.1:${PORT}`);
  console.log(`[open-mythos] Press Ctrl+C to stop.`);
});
