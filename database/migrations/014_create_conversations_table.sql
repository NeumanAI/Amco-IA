-- Migración 014: Crear tabla de conversaciones para historial dinámico
-- Fecha: $(date)

-- Crear tabla de conversaciones
CREATE TABLE IF NOT EXISTS conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT UNIQUE NOT NULL,
    title TEXT NOT NULL,
    agent_id INTEGER NOT NULL,
    user_id INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    message_count INTEGER DEFAULT 0,
    FOREIGN KEY (agent_id) REFERENCES agents (id),
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- Crear índices para optimizar consultas
CREATE INDEX IF NOT EXISTS ix_conversations_session_id ON conversations (session_id);
CREATE INDEX IF NOT EXISTS ix_conversations_user_id ON conversations (user_id);
CREATE INDEX IF NOT EXISTS ix_conversations_updated_at ON conversations (updated_at);
CREATE INDEX IF NOT EXISTS ix_conversations_agent_id ON conversations (agent_id);

-- Migrar datos existentes (crear conversaciones para sessions existentes en queries)
INSERT INTO conversations (session_id, title, agent_id, user_id, created_at, updated_at, message_count)
SELECT 
    q.session_id,
    CASE 
        WHEN LENGTH(MIN(q.query_text)) > 50 THEN SUBSTR(MIN(q.query_text), 1, 50) || '...'
        ELSE MIN(q.query_text)
    END as title,
    q.agent_id,
    NULL as user_id, -- Por ahora NULL, se puede actualizar después
    MIN(q.created_at) as created_at,
    MAX(q.created_at) as updated_at,
    COUNT(*) as message_count
FROM queries q
WHERE q.session_id IS NOT NULL 
  AND q.session_id != ''
  AND q.query_text IS NOT NULL
  AND q.query_text != ''
GROUP BY q.session_id, q.agent_id;

SELECT 'Migración 014 (Crear tabla conversations y migrar datos existentes) ejecutada exitosamente.' AS status;
