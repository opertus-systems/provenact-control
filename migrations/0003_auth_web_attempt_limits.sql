CREATE TABLE IF NOT EXISTS auth_register_attempts (
    key text NOT NULL,
    ts timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS auth_register_attempts_key_ts_idx
    ON auth_register_attempts (key, ts);

CREATE TABLE IF NOT EXISTS auth_login_attempts (
    key text NOT NULL,
    ts timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS auth_login_attempts_key_ts_idx
    ON auth_login_attempts (key, ts);
