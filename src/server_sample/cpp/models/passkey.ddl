CREATE TABLE passkey (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user TEXT NOT NULL,
    credential_id TEXT NOT NULL,
    user_handle TEXT NOT NULL,
    public_key TEXT NOT NULL,
    alg INTEGER NOT NULL,
    sign_count INTEGER NOT NULL,
    transports TEXT,
    backup_eligible INTEGER,
    backed_up INTEGER,
    aaguid TEXT,
    name TEXT,
    last_used_at TEXT,
    created_at TEXT NOT NULL DEFAULT (DATETIME('now', 'localtime')),
    updated_at TEXT NOT NULL DEFAULT (DATETIME('now', 'localtime')))
;

CREATE TABLE passkey_challenge (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    challenge TEXT NOT NULL,
    purpose TEXT NOT NULL,
    user TEXT,
    user_handle TEXT,
    expire TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (DATETIME('now', 'localtime')))
;

CREATE TABLE session (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user TEXT NOT NULL,
    skey TEXT NOT NULL,
    expire TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (DATETIME('now', 'localtime')))
;

CREATE TABLE account (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user TEXT NOT NULL,
    status TEXT NOT NULL,
    approved_by TEXT,
    approved_at TEXT,
    created_at TEXT)
;
