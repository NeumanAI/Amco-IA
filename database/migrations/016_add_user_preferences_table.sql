-- 016_add_user_preferences_table.sql
-- Create table for user preferences and settings

CREATE TABLE IF NOT EXISTS user_preferences (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    preference_key VARCHAR(100) NOT NULL,
    preference_value TEXT,
    category VARCHAR(50) DEFAULT 'general',
    created_at DATETIME DEFAULT (datetime('now', 'localtime')),
    updated_at DATETIME DEFAULT (datetime('now', 'localtime')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(user_id, preference_key) -- One preference per user per key
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_user_preferences_user_id ON user_preferences(user_id);
CREATE INDEX IF NOT EXISTS idx_user_preferences_key ON user_preferences(preference_key);
CREATE INDEX IF NOT EXISTS idx_user_preferences_category ON user_preferences(category);

-- Add default preferences for existing users
INSERT OR IGNORE INTO user_preferences (user_id, preference_key, preference_value, category)
SELECT id, 'theme', 'light', 'ui'
FROM users;

INSERT OR IGNORE INTO user_preferences (user_id, preference_key, preference_value, category)
SELECT id, 'language', 'es', 'ui'
FROM users;

INSERT OR IGNORE INTO user_preferences (user_id, preference_key, preference_value, category)
SELECT id, 'timezone', 'America/Bogota', 'general'
FROM users;
