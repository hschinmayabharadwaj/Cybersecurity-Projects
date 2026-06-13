#!/usr/bin/env bash
# ©AngelaMos | 2026
# install.sh

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
DIM='\033[2m'
NC='\033[0m'

info()  { printf "${CYAN}▸${NC} %s\n" "$1"; }
ok()    { printf "${GREEN}✓${NC} %s\n" "$1"; }
warn()  { printf "${YELLOW}!${NC} %s\n" "$1"; }
fail()  { printf "${RED}✗${NC} %s\n" "$1"; exit 1; }

MIN_ZIG="0.16.0"

banner() {
    printf "\n"
    printf "${CYAN}"
    cat <<'EOF'
  ██╗  ██╗███████╗███╗   ███╗
  ██║  ██║██╔════╝████╗ ████║
  ███████║███████╗██╔████╔██║
  ██╔══██║╚════██║██║╚██╔╝██║
  ██║  ██║███████║██║ ╚═╝ ██║
  ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝
EOF
    printf "${NC}"
    printf "  ${DIM}hsm emulator installer — pkcs#11 v2.40 module in zig${NC}\n"
    printf "\n"
}

check_zig() {
    if ! command -v zig &>/dev/null; then
        fail "Zig is not installed. Get 0.16.0 at https://ziglang.org/download/"
    fi

    local ver
    ver=$(zig version)

    if ! printf '%s\n%s\n' "$MIN_ZIG" "$ver" \
        | sort -V | head -n1 | grep -qx "$MIN_ZIG"; then
        fail "Zig $MIN_ZIG+ required (found $ver). This project tracks 0.16 idioms."
    fi

    ok "Zig $ver"
}

check_opensc() {
    if ! command -v pkcs11-tool &>/dev/null; then
        fail "OpenSC (pkcs11-tool) not found. Install: sudo apt install opensc"
    fi
    ok "OpenSC pkcs11-tool$(dpkg -l opensc 2>/dev/null | awk '/^ii/{print " "$3}')"

    if [ -e /usr/lib/x86_64-linux-gnu/pkcs11-spy.so ]; then
        ok "pkcs11-spy.so present (call tracing via 'just spy')"
    else
        warn "pkcs11-spy.so not found (optional; ships with opensc-pkcs11)"
    fi
}

check_openssl() {
    if command -v openssl &>/dev/null; then
        ok "$(openssl version | cut -d' ' -f1-2) (libcrypto for RSA, M5)"
    else
        warn "OpenSSL not found (needed later for the RSA milestone). Install: sudo apt install libssl-dev"
    fi
}

check_just() {
    if command -v just &>/dev/null; then
        ok "just $(just --version 2>/dev/null | cut -d' ' -f2)"
    else
        info "just not found (optional). Install: curl -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin"
    fi
}

build_module() {
    info "Building the Cryptoki module (ReleaseSafe)..."
    zig build --release=safe
    local so
    so=$(find zig-out/lib -name 'libhsm.so.*' -type f | head -1)
    [ -n "$so" ] || fail "Build produced no libhsm.so"
    ok "Built $so ($(du -h "$so" | cut -f1))"
}

run_tests() {
    info "Running ABI cross-check and unit tests..."
    if zig build test --release=safe >/dev/null 2>&1; then
        ok "All tests passed (ck.zig matches OASIS v2.40 headers)"
    else
        fail "Tests failed. Run 'zig build test --summary all' for details."
    fi

    info "Running the dlopen smoke test..."
    if zig build smoke --release=safe 2>&1 | grep -q "smoke: OK"; then
        ok "Smoke test passed (module loads and drives the ABI)"
    else
        fail "Smoke test failed. Run 'zig build smoke' for details."
    fi
}

verify_load() {
    info "Verifying the module loads under OpenSC..."
    if pkcs11-tool --module zig-out/lib/libhsm.so -L >/dev/null 2>&1; then
        ok "pkcs11-tool loaded the module and enumerated the slot"
    else
        fail "pkcs11-tool could not load the module."
    fi
}

main() {
    banner

    info "Checking dependencies..."
    check_zig
    check_opensc
    check_openssl
    check_just

    printf "\n"

    build_module
    run_tests
    verify_load

    printf "\n"
    ok "Setup complete"
    printf "\n"
    printf "  ${DIM}List the slot:${NC}      pkcs11-tool --module zig-out/lib/libhsm.so -L\n"
    printf "  ${DIM}List mechanisms:${NC}    pkcs11-tool --module zig-out/lib/libhsm.so -M\n"
    printf "  ${DIM}Trace every call:${NC}   just spy -L\n"
    printf "  ${DIM}All commands:${NC}       just\n"
    printf "\n"
}

main "$@"
