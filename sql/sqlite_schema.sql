CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY,
    designation TEXT NOT NULL,
    status TEXT DEFAULT 'ACTIVE',
    last_sync DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS swarm_memory (
    id TEXT PRIMARY KEY,
    agent_id TEXT REFERENCES agents(id),
    embedding BLOB,
    context TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
