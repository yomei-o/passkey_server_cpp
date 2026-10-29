CREATE TABLE tenant (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    guid TEXT NOT NULL,
    name TEXT NOT NULL,
    created_by TEXT,
    created_at TEXT)
;

CREATE TABLE tenant_member (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    user TEXT NOT NULL,
    status TEXT NOT NULL,
    role TEXT,
    approved_by TEXT,
    approved_at TEXT,
    created_at TEXT)
;
