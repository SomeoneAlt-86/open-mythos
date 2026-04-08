'use strict';

const fs = require('fs');
const path = require('path');

const DEFAULT_DB_PATH = path.join(__dirname, 'data', 'open-mythos.sqlite');

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

module.exports = {
  DEFAULT_DB_PATH,
  initSchema,
  insertNewTargetItems,
  insertThreatModel,
  openDatabase,
};
