-- ©AngelaMos | 2026
-- 0002_create_events.sql

-- +goose Up
-- +goose StatementBegin
CREATE TABLE events (
    id              BIGSERIAL    PRIMARY KEY,
    token_id        VARCHAR(12)  NOT NULL REFERENCES tokens(id) ON DELETE CASCADE,
    triggered_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    source_ip       INET         NOT NULL,
    user_agent      TEXT,
    referer         TEXT,

    geo_country     CHAR(2),
    geo_region      VARCHAR(64),
    geo_city        VARCHAR(64),
    geo_asn         INT,
    geo_asn_org     VARCHAR(128),

    extra           JSONB        NOT NULL DEFAULT '{}'::jsonb,

    notify_status   VARCHAR(16)  NOT NULL DEFAULT 'pending',
    notified_at     TIMESTAMPTZ,

    CONSTRAINT chk_notify_status CHECK (
        notify_status IN ('pending', 'sent', 'failed', 'deduped')
    )
);
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS events;
