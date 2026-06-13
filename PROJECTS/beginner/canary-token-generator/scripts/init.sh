#!/usr/bin/env bash
# =============================================================================
# ©AngelaMos | 2026
# init.sh
# =============================================================================
# Idempotent setup helper.
#   1. Copies .env.example -> .env if .env is missing
#   2. Generates POSTGRES_PASSWORD and OPERATOR_TOKEN if their values are blank
#   3. Downloads GeoLite2-City.mmdb when MAXMIND_ACCOUNT_ID + MAXMIND_LICENSE_KEY are set
#
# Safe to run repeatedly: skips already-set values and existing mmdb.
# =============================================================================

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$DIR/.env"
EXAMPLE_FILE="$DIR/.env.example"
DATA_DIR="$DIR/data"
MMDB_PATH="$DATA_DIR/GeoLite2-City.mmdb"

# ── ensure .env exists ────────────────────────────────────────────────────────
if [[ ! -f "$ENV_FILE" ]]; then
    if [[ ! -f "$EXAMPLE_FILE" ]]; then
        echo "Error: $EXAMPLE_FILE missing — cannot bootstrap .env" >&2
        exit 1
    fi
    cp "$EXAMPLE_FILE" "$ENV_FILE"
    echo "  created .env from .env.example"
fi

# ── secret generator ──────────────────────────────────────────────────────────
gen_secret() {
    local key="$1"
    local current
    current="$(grep -E "^${key}=" "$ENV_FILE" | head -1 | cut -d= -f2- || true)"

    if [[ -z "$current" ]]; then
        local newval
        newval="$(openssl rand -hex 32)"
        if grep -qE "^${key}=" "$ENV_FILE"; then
            sed -i "s|^${key}=.*|${key}=${newval}|" "$ENV_FILE"
        else
            printf '\n%s=%s\n' "$key" "$newval" >> "$ENV_FILE"
        fi
        echo "  generated $key"
    else
        echo "  $key already set, skipping"
    fi
}

gen_secret POSTGRES_PASSWORD
gen_secret OPERATOR_TOKEN

# ── geoip database ────────────────────────────────────────────────────────────
ACCT="$(grep -E "^MAXMIND_ACCOUNT_ID=" "$ENV_FILE" | head -1 | cut -d= -f2- || true)"
KEY="$(grep -E "^MAXMIND_LICENSE_KEY=" "$ENV_FILE" | head -1 | cut -d= -f2- || true)"

if [[ -n "$ACCT" && -n "$KEY" ]]; then
    if [[ ! -f "$MMDB_PATH" ]]; then
        mkdir -p "$DATA_DIR"
        echo "  downloading GeoLite2-City.mmdb from MaxMind..."
        tmp_dir="$(mktemp -d)"
        trap 'rm -rf "$tmp_dir"' EXIT
        if curl -sSf -u "$ACCT:$KEY" \
            "https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz" \
            -o "$tmp_dir/geolite.tar.gz"; then
            tar -xzf "$tmp_dir/geolite.tar.gz" -C "$tmp_dir" --strip-components=1 \
                "*/GeoLite2-City.mmdb"
            mv "$tmp_dir/GeoLite2-City.mmdb" "$MMDB_PATH"
            echo "  GeoLite2-City.mmdb downloaded to $MMDB_PATH"
        else
            echo "  Warning: GeoLite2 download failed (check MAXMIND_ACCOUNT_ID and MAXMIND_LICENSE_KEY)" >&2
        fi
    else
        echo "  GeoLite2-City.mmdb already present, skipping"
    fi
else
    echo "  MaxMind credentials not set in .env — geolocation will be disabled"
fi

# ── done ──────────────────────────────────────────────────────────────────────
echo ""
echo "Setup complete. Edit .env to set PUBLIC_BASE_URL + Turnstile keys, then 'just up'."
