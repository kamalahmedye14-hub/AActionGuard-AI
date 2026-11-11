import Database from 'better-sqlite3';
import path from 'node:path';
import fs from 'node:fs';
const dataDir = path.resolve(process.cwd(), 'data');
fs.mkdirSync(dataDir,{recursive:true});
export const db = new Database(path.join(dataDir,'actionguard.sqlite'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS audit_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 event TEXT NOT NULL,
 outcome TEXT NOT NULL,
 rule TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS policies (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 action TEXT NOT NULL CHECK(action IN ('ALLOW','BLOCK','REDACT','REVIEW')),
 priority INTEGER NOT NULL,
 enabled INTEGER NOT NULL DEFAULT 1
);
`);
const count = db.prepare('SELECT COUNT(*) as n FROM policies').get() as {n:number};
if(count.n===0){
 const insert=db.prepare('INSERT INTO policies(name,action,priority) VALUES(?,?,?)');
 insert.run('Credential pattern detected','BLOCK',10);
 insert.run('Personal data pattern detected','REDACT',20);
 insert.run('No matching security rule','REVIEW',100);
}
