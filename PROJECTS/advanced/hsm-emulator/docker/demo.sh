#!/usr/bin/env bash
# ©AngelaMos | 2026
# demo.sh

set -euo pipefail

MOD="${HSM_MODULE:-/hsm/lib/libhsm.so.0.1.0}"
SO_PIN=12345678
PIN=1234
WORK="$(mktemp -d)"
mkdir -p "$(dirname "$ANGELAMOS_HSM_TOKEN")" "$(dirname "$ANGELAMOS_HSM_OBJECTS")"

line() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }

line "AngelaMos HSM — PKCS#11 module loaded by OpenSC pkcs11-tool"
pkcs11-tool --module "$MOD" --init-token --label angelamos --so-pin "$SO_PIN" >/dev/null
pkcs11-tool --module "$MOD" --init-pin --so-pin "$SO_PIN" --pin "$PIN" >/dev/null
pkcs11-tool --module "$MOD" -I

line "Supported mechanisms"
pkcs11-tool --module "$MOD" -M

line "RSA-2048 — generate, sign (SHA256-RSA-PKCS), verify"
pkcs11-tool --module "$MOD" --login --pin "$PIN" --keypairgen --key-type RSA:2048 --label rsa --id 01 2>/dev/null
printf 'invoice #42 total $1000' > "$WORK/msg"
pkcs11-tool --module "$MOD" --login --pin "$PIN" --sign --mechanism SHA256-RSA-PKCS --id 01 -i "$WORK/msg" -o "$WORK/rsa.sig" 2>/dev/null
pkcs11-tool --module "$MOD" --login --pin "$PIN" --verify --mechanism SHA256-RSA-PKCS --id 01 -i "$WORK/msg" --signature-file "$WORK/rsa.sig"

line "EC P-256 — generate, sign (ECDSA-SHA256), verify"
pkcs11-tool --module "$MOD" --login --pin "$PIN" --keypairgen --key-type EC:prime256v1 --label ec --id 02 2>/dev/null
pkcs11-tool --module "$MOD" --login --pin "$PIN" --sign --mechanism ECDSA-SHA256 --id 02 -i "$WORK/msg" -o "$WORK/ec.sig" 2>/dev/null
pkcs11-tool --module "$MOD" --login --pin "$PIN" --verify --mechanism ECDSA-SHA256 --id 02 -i "$WORK/msg" --signature-file "$WORK/ec.sig"

line "AES-256 — generate, encrypt (AES-CBC), decrypt, compare"
pkcs11-tool --module "$MOD" --login --pin "$PIN" --keygen --key-type AES:32 --label aes --id 03 2>/dev/null
printf '0123456789ABCDEF' > "$WORK/pt"
IV=000102030405060708090a0b0c0d0e0f
pkcs11-tool --module "$MOD" --login --pin "$PIN" --encrypt --mechanism AES-CBC --id 03 --iv "$IV" -i "$WORK/pt" -o "$WORK/ct" 2>/dev/null
pkcs11-tool --module "$MOD" --login --pin "$PIN" --decrypt --mechanism AES-CBC --id 03 --iv "$IV" -i "$WORK/ct" -o "$WORK/dec" 2>/dev/null
if cmp -s "$WORK/pt" "$WORK/dec"; then
    echo "AES-CBC round-trip: plaintext recovered OK"
else
    echo "AES-CBC round-trip: MISMATCH" && exit 1
fi

line "Token objects (private material sealed at rest under Argon2id(User-PIN))"
pkcs11-tool --module "$MOD" --login --pin "$PIN" -O

line "Demo complete — RSA + ECDSA signatures verified, AES-CBC round-trip OK"
