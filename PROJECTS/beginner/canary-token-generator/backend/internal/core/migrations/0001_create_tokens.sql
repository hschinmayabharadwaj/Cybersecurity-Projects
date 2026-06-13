-- ©AngelaMos | 2026
-- 0001_create_tokens.sql

-- +goose Up
-- +goose StatementBegin
CREATE TABLE tokens (
    id              VARCHAR(12)  PRIMARY KEY,
    manage_id       UUID         UNIQUE NOT NULL,
    type            VARCHAR(32)  NOT NULL,
    memo            TEXT         NOT NULL DEFAULT '',
    filename        TEXT,

    alert_channel   VARCHAR(16)  NOT NULL,
    telegram_bot    TEXT,
    telegram_chat   TEXT,
    webhook_url     TEXT,

    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    created_ip      INET         NOT NULL,
    created_fp      CHAR(16)     NOT NULL,
    enabled         BOOLEAN      NOT NULL DEFAULT TRUE,

    trigger_count   BIGINT       NOT NULL DEFAULT 0,
    last_triggered  TIMESTAMPTZ,

    metadata        JSONB        NOT NULL DEFAULT '{}'::jsonb,

    CONSTRAINT chk_type CHECK (type IN
        ('webbug', 'slowredirect', 'docx', 'pdf', 'kubeconfig', 'envfile', 'mysql')),
    CONSTRAINT chk_channel CHECK (alert_channel IN ('telegram', 'webhook')),
    CONSTRAINT chk_telegram_complete CHECK (
        alert_channel <> 'telegram' OR
        (telegram_bot IS NOT NULL AND telegram_chat IS NOT NULL)
    ),
    CONSTRAINT chk_webhook_complete CHECK (
        alert_channel <> 'webhook' OR webhook_url IS NOT NULL
    )
);
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS tokens;
