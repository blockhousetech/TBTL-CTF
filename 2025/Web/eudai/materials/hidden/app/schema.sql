CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS credentials (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ctype TEXT NOT NULL,
  owner_user_id INTEGER NOT NULL,
  claims_json TEXT NOT NULL,
  issuer_kid TEXT NOT NULL,
  issued_at TEXT NOT NULL,
  salts_json TEXT NOT NULL,
  digests_json TEXT NOT NULL,
  FOREIGN KEY(owner_user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS presentations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  encoded TEXT NOT NULL,
  owner_user_id INTEGER,
  created_at TEXT NOT NULL,
  FOREIGN KEY(owner_user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_presentations_owner ON presentations(owner_user_id);
