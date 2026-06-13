-- ©AngelaMos | 2026
-- 0003_indexes.sql

-- +goose Up
-- +goose StatementBegin
CREATE INDEX idx_tokens_created_ip      ON tokens(created_ip);
CREATE INDEX idx_tokens_created_fp      ON tokens(created_fp);
CREATE INDEX idx_tokens_created_at      ON tokens(created_at DESC);
CREATE INDEX idx_tokens_type            ON tokens(type);
CREATE INDEX idx_tokens_trigger_count
    ON tokens(trigger_count DESC) WHERE trigger_count > 0;

CREATE INDEX idx_events_token_triggered ON events(token_id, triggered_at DESC);
CREATE INDEX idx_events_source_ip       ON events(source_ip);
CREATE INDEX idx_events_notify_pending
    ON events(notify_status) WHERE notify_status = 'pending';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_events_notify_pending;
DROP INDEX IF EXISTS idx_events_source_ip;
DROP INDEX IF EXISTS idx_events_token_triggered;
DROP INDEX IF EXISTS idx_tokens_trigger_count;
DROP INDEX IF EXISTS idx_tokens_type;
DROP INDEX IF EXISTS idx_tokens_created_at;
DROP INDEX IF EXISTS idx_tokens_created_fp;
DROP INDEX IF EXISTS idx_tokens_created_ip;
-- +goose StatementEnd
