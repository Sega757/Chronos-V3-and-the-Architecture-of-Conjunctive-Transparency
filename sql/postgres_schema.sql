CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS agents (
    id UUID PRIMARY KEY,
    designation VARCHAR(255) NOT NULL,
    status VARCHAR(50) DEFAULT 'ACTIVE',
    last_sync TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS swarm_memory (
    id UUID PRIMARY KEY,
    agent_id UUID REFERENCES agents(id),
    embedding VECTOR(768),
    context TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Vector similarity search index
CREATE INDEX ON swarm_memory USING hnsw (embedding vector_l2_ops);

-- Index on foreign key agent_id to optimize agent memory lookups and joins from O(N) to O(log N)
CREATE INDEX IF NOT EXISTS idx_swarm_memory_agent_id ON swarm_memory (agent_id);
