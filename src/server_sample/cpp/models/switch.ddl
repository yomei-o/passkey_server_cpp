CREATE TABLE switch_state (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    value INTEGER NOT NULL,
    updated_by TEXT,
    updated_at TEXT)
;
