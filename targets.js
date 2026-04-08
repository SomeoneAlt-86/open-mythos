const Database = require('better-sqlite3');
const db = new Database('data/open-mythos.sqlite');

const rows = db.prepare('SELECT * FROM threat_models').all();
console.log(rows)
