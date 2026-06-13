# =============================================================================
# ©AngelaMos | 2026
# justfile
# =============================================================================

set dotenv-load
set export
set shell := ["bash", "-uc"]

project    := file_name(justfile_directory())
version    := `git describe --tags --always 2>/dev/null || echo "dev"`
module     := justfile_directory() / "zig-out/lib/libhsm.so"
spy        := "/usr/lib/x86_64-linux-gnu/pkcs11-spy.so"
image      := "angelamos-hsm:latest"

# =============================================================================
# Default
# =============================================================================

default:
    @just --list --unsorted

# =============================================================================
# Build
# =============================================================================

[group('build')]
build:
    zig build

[group('build')]
debug:
    zig build -Doptimize=Debug

[group('build')]
release:
    zig build -Doptimize=ReleaseSafe

# =============================================================================
# Test
# =============================================================================

[group('test')]
test:
    zig build test

[group('test')]
test-verbose:
    zig build test --summary all

[group('test')]
smoke:
    zig build smoke

# =============================================================================
# Lint and Format
# =============================================================================

[group('lint')]
fmt:
    zig fmt build.zig build.zig.zon src tests examples

[group('lint')]
fmt-check:
    zig fmt --check build.zig build.zig.zon src tests examples

# =============================================================================
# PKCS#11 (drive the built module with OpenSC pkcs11-tool)
# =============================================================================

[group('pkcs11')]
inspect: build
    pkcs11-tool --module {{module}} -I

[group('pkcs11')]
slots: build
    pkcs11-tool --module {{module}} -L

[group('pkcs11')]
mechs: build
    pkcs11-tool --module {{module}} -M

[group('pkcs11')]
spy *ARGS: build
    PKCS11SPY={{module}} pkcs11-tool --module {{spy}} {{ARGS}}

# =============================================================================
# Docker (build the image, then run the end-to-end pkcs11-tool demo)
# =============================================================================

[group('docker')]
docker-build:
    docker build -t {{image}} .

[group('docker')]
docker-demo: docker-build
    docker run --rm {{image}}

# =============================================================================
# CI / Quality
# =============================================================================

[group('ci')]
ci: fmt-check test smoke

# =============================================================================
# Utilities
# =============================================================================

[group('util')]
info:
    @echo "Project: {{project}}"
    @echo "Version: {{version}}"
    @echo "Module:  {{module}}"
    @echo "OS:      {{os()}} ({{arch()}})"
    @zig version | xargs -I{} echo "Zig:     {}"

[group('util')]
clean:
    -rm -rf zig-out
    -rm -rf .zig-cache
    @echo "Build artifacts cleaned"
