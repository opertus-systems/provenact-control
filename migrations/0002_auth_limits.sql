CREATE TABLE IF NOT EXISTS bridge_token_replays (
    jti text PRIMARY KEY,
    exp_at timestamptz NOT NULL,
    seen_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_bridge_token_replays_exp_at ON bridge_token_replays (exp_at);

CREATE TABLE IF NOT EXISTS api_request_events (
    id bigserial PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    ts timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_api_request_events_user_ts ON api_request_events (user_id, ts);
