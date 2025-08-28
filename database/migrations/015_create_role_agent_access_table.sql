-- 015_create_role_agent_access_table.sql
-- Create table to control which roles can access which agents

CREATE TABLE IF NOT EXISTS role_agent_access (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    role_id INTEGER NOT NULL,
    agent_id INTEGER NOT NULL,
    access_level VARCHAR(20) NOT NULL DEFAULT 'read_only', -- 'read_only', 'full_access', 'no_access'
    created_at DATETIME DEFAULT (datetime('now', 'localtime')),
    updated_at DATETIME DEFAULT (datetime('now', 'localtime')),
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE,
    UNIQUE(role_id, agent_id) -- Prevent duplicate role-agent mappings
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_role_agent_access_role_id ON role_agent_access(role_id);
CREATE INDEX IF NOT EXISTS idx_role_agent_access_agent_id ON role_agent_access(agent_id);
CREATE INDEX IF NOT EXISTS idx_role_agent_access_level ON role_agent_access(access_level);

-- Add default access levels for existing roles
-- SuperAdministrador gets full access to all agents
INSERT OR IGNORE INTO role_agent_access (role_id, agent_id, access_level)
SELECT r.id, a.id, 'full_access'
FROM roles r, agents a
WHERE LOWER(r.name) = 'superadministrador';

-- Other roles get read_only access by default (can be customized later)
INSERT OR IGNORE INTO role_agent_access (role_id, agent_id, access_level)
SELECT r.id, a.id, 'read_only'
FROM roles r, agents a
WHERE LOWER(r.name) != 'superadministrador';
