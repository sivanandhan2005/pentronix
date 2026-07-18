-- Pentronix SQLite Database Schema
-- All tables use INTEGER PRIMARY KEY (rowid alias) for performance.
-- Timestamps are stored as ISO-8601 text (UTC).

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA synchronous = NORMAL;

-- ── Sessions ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sessions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT    NOT NULL UNIQUE,
    start_time  TEXT    NOT NULL,
    end_time    TEXT,
    summary     TEXT,
    target      TEXT
);

-- ── Commands (tool executions) ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS commands (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id          TEXT    NOT NULL REFERENCES sessions(session_id),
    raw_input           TEXT    NOT NULL,
    understood_command  TEXT,
    intent              TEXT,
    tool_used           TEXT,
    command_run         TEXT,
    output              TEXT,
    ai_summary          TEXT,
    risk_level          TEXT    DEFAULT 'LOW',
    timestamp           TEXT    NOT NULL,
    duration_seconds    REAL,
    success             INTEGER DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_commands_session ON commands(session_id);
CREATE INDEX IF NOT EXISTS idx_commands_timestamp ON commands(timestamp);

-- ── Targets ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS targets (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_or_domain        TEXT    NOT NULL UNIQUE,
    first_seen          TEXT    NOT NULL,
    last_seen           TEXT    NOT NULL,
    open_ports          TEXT    DEFAULT '[]',
    services            TEXT    DEFAULT '[]',
    vulnerabilities     TEXT    DEFAULT '[]',
    os_detected         TEXT,
    notes               TEXT
);

CREATE INDEX IF NOT EXISTS idx_targets_ip ON targets(ip_or_domain);

-- ── Tool Registry ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tool_registry (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL UNIQUE,
    path            TEXT,
    version         TEXT,
    category        TEXT,
    purpose         TEXT,
    common_commands TEXT    DEFAULT '[]',
    found           INTEGER DEFAULT 0,
    last_scanned    TEXT
);

-- ── Preferences ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS preferences (
    key     TEXT PRIMARY KEY,
    value   TEXT
);

-- ── Scan Results (detailed per-port data) ────────────────────────────────────
CREATE TABLE IF NOT EXISTS scan_results (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    command_id  INTEGER NOT NULL REFERENCES commands(id),
    target      TEXT    NOT NULL,
    port        INTEGER,
    protocol    TEXT,
    state       TEXT,
    service     TEXT,
    version     TEXT,
    extra       TEXT    DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_scan_results_target ON scan_results(target);

-- ── Conversations (full message history) ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS conversations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT    NOT NULL REFERENCES sessions(session_id),
    role        TEXT    NOT NULL,   -- 'user', 'assistant', 'tool'
    content     TEXT    NOT NULL,
    tool_name   TEXT,               -- populated when role='tool'
    timestamp   TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_conversations_session ON conversations(session_id);

-- ── Agent Steps (think/act/observe log) ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS agent_steps (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT    NOT NULL REFERENCES sessions(session_id),
    step_type   TEXT    NOT NULL,   -- 'think', 'tool_call', 'tool_result', 'response'
    tool_name   TEXT,
    tool_args   TEXT,               -- JSON string
    result      TEXT,
    timestamp   TEXT    NOT NULL,
    duration_ms INTEGER
);

CREATE INDEX IF NOT EXISTS idx_agent_steps_session ON agent_steps(session_id);

-- ── Learned Knowledge (from internet research) ──────────────────────────────
CREATE TABLE IF NOT EXISTS learned_knowledge (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    topic       TEXT    NOT NULL,
    content     TEXT    NOT NULL,
    sources     TEXT    DEFAULT '[]',   -- JSON array of URLs
    learned_at  TEXT    NOT NULL,
    times_used  INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_knowledge_topic ON learned_knowledge(topic);

-- ── Installed Tools (agent-installed) ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS installed_tools (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL UNIQUE,
    install_command TEXT    NOT NULL,
    installed_at    TEXT    NOT NULL,
    installed_by    TEXT    DEFAULT 'agent'   -- 'agent' or 'system'
);
