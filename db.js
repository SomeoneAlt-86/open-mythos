'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

function defaultDataDir() {
  if (process.platform === 'win32') {
    return process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming');
  }
  if (process.platform === 'darwin') {
    return path.join(os.homedir(), 'Library', 'Application Support');
  }

  return process.env.XDG_DATA_HOME || path.join(os.homedir(), '.local', 'share');
}

const DEFAULT_DB_PATH = path.join(defaultDataDir(), 'open-mythos', 'open-mythos.sqlite');

function ensureParentDir(filePath) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
}

function loadSqliteDriver() {
  try {
    return require('better-sqlite3');
  } catch {
    throw new Error('Missing dependency: better-sqlite3. Install it with `npm install better-sqlite3`.');
  }
}

function initSchema(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS threat_models (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      repo_name TEXT NOT NULL,
      repo_path TEXT NOT NULL,
      threat_model TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_threat_models_repo_name
      ON threat_models (repo_name);

    CREATE INDEX IF NOT EXISTS idx_threat_models_created_at
      ON threat_models (created_at);
  `);

  const existingColumns = db.prepare('PRAGMA table_info(target_items)').all().map((c) => c.name);
  const hasLegacyTargetItems = existingColumns.includes('targets_id');

  if (hasLegacyTargetItems) {
    db.exec(`
      ALTER TABLE target_items RENAME TO target_items_legacy;

      CREATE TABLE target_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        threat_model_id INTEGER NOT NULL,
        repo_name TEXT NOT NULL,
        repo_path TEXT NOT NULL,
        path TEXT NOT NULL,
        function TEXT NOT NULL,
        reason TEXT NOT NULL,
        scanned INT NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        FOREIGN KEY(threat_model_id) REFERENCES threat_models(id),
        UNIQUE(threat_model_id, path, function)
      );

      INSERT OR IGNORE INTO target_items (
        threat_model_id, repo_name, repo_path, path, function, reason, scanned, created_at
      )
      SELECT
        threat_model_id,
        repo_name,
        repo_path,
        path,
        function,
        reason,
        COALESCE(scanned, 0),
        COALESCE(created_at, datetime('now'))
      FROM target_items_legacy;

      DROP TABLE target_items_legacy;
    `);
  } else {
    db.exec(`
      CREATE TABLE IF NOT EXISTS target_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        threat_model_id INTEGER NOT NULL,
        repo_name TEXT NOT NULL,
        repo_path TEXT NOT NULL,
        path TEXT NOT NULL,
        function TEXT NOT NULL,
        reason TEXT NOT NULL,
        scanned INT NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        FOREIGN KEY(threat_model_id) REFERENCES threat_models(id),
        UNIQUE(threat_model_id, path, function)
      );
    `);
  }

  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_target_items_threat_model_id
      ON target_items (threat_model_id);

    CREATE INDEX IF NOT EXISTS idx_target_items_repo_name_created_at
      ON target_items (repo_name, created_at);

    CREATE INDEX IF NOT EXISTS idx_target_items_scanned_threat_model
      ON target_items (scanned, threat_model_id);
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS findings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      threat_model_id INTEGER NOT NULL,
      target_item_id INTEGER NOT NULL,
      repo_name TEXT NOT NULL,
      repo_path TEXT NOT NULL,
      path TEXT NOT NULL,
      function TEXT NOT NULL,
      severity TEXT,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      evidence TEXT,
      impact TEXT,
      recommendation TEXT,
      confidence TEXT,
      finding_hash TEXT NOT NULL,
      raw_json TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY(threat_model_id) REFERENCES threat_models(id),
      FOREIGN KEY(target_item_id) REFERENCES target_items(id),
      UNIQUE(target_item_id, finding_hash)
    );

    CREATE INDEX IF NOT EXISTS idx_findings_threat_model_id
      ON findings (threat_model_id);

    CREATE INDEX IF NOT EXISTS idx_findings_target_item_id
      ON findings (target_item_id);

    CREATE INDEX IF NOT EXISTS idx_findings_repo_name_created_at
      ON findings (repo_name, created_at);
  `);
}

function openDatabase(dbPath = process.env.OPEN_MYTHOS_DB_PATH || DEFAULT_DB_PATH) {
  const Database = loadSqliteDriver();
  ensureParentDir(dbPath);

  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  initSchema(db);
  return db;
}

function insertThreatModel(db, payload) {
  const stmt = db.prepare(`
    INSERT INTO threat_models (repo_name, repo_path, threat_model)
    VALUES (@repo_name, @repo_path, @threat_model)
  `);
  const result = stmt.run(payload);
  return result.lastInsertRowid;
}

function insertNewTargetItems(db, payload) {
  const { threat_model_id, repo_name, repo_path, targets } = payload;
  if (!Array.isArray(targets)) {
    throw new Error('insertNewTargetItems requires `targets` to be an array.');
  }

  const stmt = db.prepare(`
    INSERT INTO target_items (
      threat_model_id, repo_name, repo_path, path, function, reason, scanned
    ) VALUES (
      @threat_model_id, @repo_name, @repo_path, @path, @function, @reason, @scanned
    )
    ON CONFLICT(threat_model_id, path, function) DO NOTHING
  `);

  const tx = db.transaction((rows) => {
    let changed = 0;
    for (const t of rows) {
      const result = stmt.run({
        threat_model_id,
        repo_name,
        repo_path,
        path: t.path,
        function: t.function,
        reason: t.reason,
        scanned: Number.isInteger(t.scanned) ? t.scanned : 0,
      });
      changed += result.changes || 0;
    }
    return changed;
  });

  return tx(targets);
}

function pullUnscannedTargets(db, filters = {}) {
  const limit = Number.isInteger(filters.limit) ? Math.max(1, filters.limit) : 20;
  const where = ['ti.scanned = 0'];
  const params = { limit };

  if (filters.threat_model_id !== undefined && filters.threat_model_id !== null) {
    where.push('ti.threat_model_id = @threat_model_id');
    params.threat_model_id = filters.threat_model_id;
  }
  if (typeof filters.repo_name === 'string' && filters.repo_name.trim()) {
    where.push('ti.repo_name = @repo_name');
    params.repo_name = filters.repo_name.trim();
  }
  if (typeof filters.repo_path === 'string' && filters.repo_path.trim()) {
    where.push('ti.repo_path = @repo_path');
    params.repo_path = filters.repo_path.trim();
  }

  const baseWhere = where.join(' AND ');
  const rows = db.prepare(`
    WITH next_tm AS (
      SELECT ti.threat_model_id
      FROM target_items ti
      WHERE ${baseWhere}
      ORDER BY ti.id ASC
      LIMIT 1
    )
    SELECT
      ti.id,
      ti.threat_model_id,
      ti.repo_name,
      ti.repo_path,
      ti.path,
      ti.function,
      ti.reason,
      ti.scanned,
      tm.threat_model
    FROM target_items ti
    JOIN threat_models tm ON tm.id = ti.threat_model_id
    WHERE ti.scanned = 0
      AND ti.threat_model_id = (SELECT threat_model_id FROM next_tm)
      ${typeof filters.repo_name === 'string' && filters.repo_name.trim() ? 'AND ti.repo_name = @repo_name' : ''}
      ${typeof filters.repo_path === 'string' && filters.repo_path.trim() ? 'AND ti.repo_path = @repo_path' : ''}
    ORDER BY ti.id ASC
    LIMIT @limit
  `).all(params);

  return rows;
}

function insertFindings(db, findings) {
  if (!Array.isArray(findings)) {
    throw new Error('insertFindings requires an array.');
  }

  const stmt = db.prepare(`
    INSERT INTO findings (
      threat_model_id, target_item_id, repo_name, repo_path, path, function,
      severity, title, description, evidence, impact, recommendation, confidence,
      finding_hash, raw_json
    ) VALUES (
      @threat_model_id, @target_item_id, @repo_name, @repo_path, @path, @function,
      @severity, @title, @description, @evidence, @impact, @recommendation, @confidence,
      @finding_hash, @raw_json
    )
    ON CONFLICT(target_item_id, finding_hash) DO NOTHING
  `);

  const tx = db.transaction((rows) => {
    let inserted = 0;
    for (const row of rows) {
      const result = stmt.run(row);
      inserted += result.changes || 0;
    }
    return inserted;
  });

  return tx(findings);
}

function markTargetsScanned(db, targetItemIds) {
  if (!Array.isArray(targetItemIds) || targetItemIds.length === 0) {
    return 0;
  }

  const stmt = db.prepare('UPDATE target_items SET scanned = 1 WHERE id = ?');
  const tx = db.transaction((ids) => {
    let updated = 0;
    for (const id of ids) {
      const result = stmt.run(id);
      updated += result.changes || 0;
    }
    return updated;
  });
  return tx(targetItemIds);
}

module.exports = {
  DEFAULT_DB_PATH,
  initSchema,
  insertFindings,
  insertNewTargetItems,
  insertThreatModel,
  markTargetsScanned,
  openDatabase,
  pullUnscannedTargets,
};
