CREATE TABLE IF NOT EXISTS argus.users (
    id uuid,
    email text,
    password_hash text,
    created_at timestamp,
    updated_at timestamp,
    PRIMARY KEY (id, created_at)
) WITH CLUSTERING ORDER BY (created_at DESC);

CREATE TABLE IF NOT EXISTS argus.api_keys (
    id uuid,
    user_id uuid,
    name text,
    key_hash text,
    created_at timestamp,
    last_used_at timestamp,
    expires_at timestamp,
    is_active boolean,
    PRIMARY KEY (id, created_at)
) WITH CLUSTERING ORDER BY (created_at DESC);

CREATE TABLE IF NOT EXISTS argus.applications (
    id uuid,
    user_id uuid,
    name text,
    description text,
    key_hash text,
    created_at timestamp,
    updated_at timestamp,
    PRIMARY KEY (id, created_at)
) WITH CLUSTERING ORDER BY (created_at DESC);

CREATE TABLE IF NOT EXISTS argus.logs (
    application_id uuid,
    timestamp timestamp,
    log_id uuid,
    user_id uuid,
    log_level text,
    message text,
    PRIMARY KEY ((application_id), timestamp, log_id)
) WITH CLUSTERING ORDER BY (timestamp DESC);

CREATE TABLE IF NOT EXISTS argus.log_frequencies (
    application_id uuid,
    interval_start timestamp,
    interval_end timestamp,
    log_count int,
    PRIMARY KEY ((application_id), interval_start)
) WITH CLUSTERING ORDER BY (interval_start DESC);
