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

    CREATE TABLE IF NOT EXISTS targets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      threat_model_id INTEGER NOT NULL,
      repo_name TEXT NOT NULL,
      repo_path TEXT NOT NULL,
      targets_json TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY(threat_model_id) REFERENCES threat_models(id)
    );

    CREATE INDEX IF NOT EXISTS idx_targets_threat_model_id
      ON targets (threat_model_id);

    CREATE INDEX IF NOT EXISTS idx_targets_repo_name_created_at
      ON targets (repo_name, created_at);
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

function insertTargets(db, payload) {
  const stmt = db.prepare(`
    INSERT INTO targets (threat_model_id, repo_name, repo_path, targets_json)
    VALUES (@threat_model_id, @repo_name, @repo_path, @targets_json)
  `);
  const result = stmt.run(payload);
  return result.lastInsertRowid;
}

module.exports = {
  DEFAULT_DB_PATH,
  initSchema,
  insertTargets,
  insertThreatModel,
  openDatabase,
};
