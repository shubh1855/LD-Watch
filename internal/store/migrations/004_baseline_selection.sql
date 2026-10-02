CREATE TABLE baseline_active (
    exe TEXT NOT NULL,
    environment_key TEXT NOT NULL,
    baseline_id INTEGER NOT NULL REFERENCES baseline_versions(id),
    PRIMARY KEY(exe, environment_key)
);

CREATE TABLE baseline_learning_cursors (
    exe TEXT NOT NULL,
    environment_key TEXT NOT NULL,
    event_id INTEGER NOT NULL CHECK(event_id >= 0),
    PRIMARY KEY(exe, environment_key)
);

CREATE TABLE baseline_candidate_policies (
    exe TEXT NOT NULL,
    environment_key TEXT NOT NULL,
    entry_type TEXT NOT NULL CHECK(entry_type IN ('LOAD','SYMBOL_PROVIDER')),
    identity TEXT NOT NULL,
    symbol TEXT NOT NULL DEFAULT '',
    optional INTEGER NOT NULL CHECK(optional IN (0,1)),
    PRIMARY KEY(exe,environment_key,entry_type,identity,symbol)
);
