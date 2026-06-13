# ©AngelaMos | 2026
# Dockerfile

FROM debian:bookworm-slim AS builder

ARG ZIG_VERSION=0.16.0
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl xz-utils libssl-dev libc6-dev \
    && rm -rf /var/lib/apt/lists/*
RUN curl -fSL "https://ziglang.org/download/${ZIG_VERSION}/zig-x86_64-linux-${ZIG_VERSION}.tar.xz" \
        -o /tmp/zig.tar.xz \
    && mkdir -p /opt/zig \
    && tar -xJf /tmp/zig.tar.xz -C /opt/zig --strip-components=1 \
    && rm /tmp/zig.tar.xz
ENV PATH="/opt/zig:${PATH}"

WORKDIR /src
COPY build.zig build.zig.zon pkcs11.map ./
COPY src ./src
COPY vendor ./vendor
COPY examples ./examples
COPY tests ./tests
RUN zig build --release=safe

FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        opensc libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /hsm
COPY --from=builder /src/zig-out/lib/ /hsm/lib/
COPY docker/demo.sh /hsm/demo.sh
RUN chmod +x /hsm/demo.sh

ENV HSM_MODULE=/hsm/lib/libhsm.so.0.1.0 \
    ANGELAMOS_HSM_TOKEN=/hsm/state/token \
    ANGELAMOS_HSM_OBJECTS=/hsm/state/objects

ENTRYPOINT ["/hsm/demo.sh"]
