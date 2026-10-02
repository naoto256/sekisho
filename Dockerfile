# syntax=docker/dockerfile:1.7
#
# Multi-stage build for the Sekisho identity-aware proxy.
#
#   builder: rust:1.95-bookworm — builds the workspace in --release.
#   runtime: gcr.io/distroless/cc-debian12:nonroot — minimal cc base
#            with the dynamic loader, glibc, and CA certs.
#
# The builder image's Rust channel must match rust-toolchain.toml at the
# repo root; bump together. Built images expose the proxy on 443/80 and
# the management API on 9443. The container runs as the `nonroot` user
# (uid 65532) baked into the distroless base — no shell, no package
# manager, no setuid binaries inside the image.

# ---- builder ----------------------------------------------------------------
FROM --platform=$BUILDPLATFORM rust:1.95-bookworm AS builder

# Cargo registry / git / target are mounted as cache to keep CI rebuilds fast.
WORKDIR /src

# Pre-cache the dependency graph by copying just the manifests and a
# stub main, so unrelated source edits don't re-download crates.io.
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
COPY vendor/ ./vendor/

# Build all binaries, then stamp `cap_net_bind_service` onto sekishod
# so the runtime stage's nonroot user (uid 65532) can bind 80 / 443
# without needing `--cap-add NET_BIND_SERVICE` at run time. The
# distroless runtime image has no `setcap` tool, so the file
# capability has to be applied here in the builder stage; BuildKit's
# COPY preserves xattrs across stages. sekisho-webui (9444) and
# sekisho-cli need no capabilities — leave those alone.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --release --workspace --locked && \
    apt-get update -qq && apt-get install -y --no-install-recommends libcap2-bin >/dev/null && \
    mkdir -p /out && \
    cp target/release/sekishod      /out/sekishod && \
    cp target/release/sekisho-cli   /out/sekisho-cli && \
    cp target/release/sekisho-webui /out/sekisho-webui && \
    setcap cap_net_bind_service=+ep /out/sekishod && \
    rm -rf /var/lib/apt/lists/*

# ---- runtime ----------------------------------------------------------------
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

LABEL org.opencontainers.image.title="sekisho"
LABEL org.opencontainers.image.description="Sekisho identity-aware proxy"
LABEL org.opencontainers.image.source="https://github.com/naoto256/sekisho"
LABEL org.opencontainers.image.licenses="MIT OR Apache-2.0"

# Binaries land under /usr/bin to match the .deb layout, so docs and
# operator muscle memory survive the deb -> docker move.
COPY --from=builder /out/sekishod      /usr/bin/sekishod
COPY --from=builder /out/sekisho-cli   /usr/bin/sekisho-cli
COPY --from=builder /out/sekisho-webui /usr/bin/sekisho-webui

# State directory expected by sekishod (instance config DB and DEK ring
# blobs). Mount a volume here to persist across
# container restarts. distroless's `nonroot` user is uid/gid 65532; the
# directory is created in the build with that ownership.
USER nonroot
WORKDIR /var/lib/sekisho
VOLUME ["/var/lib/sekisho"]

# The local-auth control socket defaults to /run/sekisho/control.sock,
# which only works when systemd's `RuntimeDirectory=sekisho` has
# pre-created the directory with the right ownership (deb path). In a
# container nonroot can't create /run/sekisho, so re-home the socket
# inside the writable state volume. Operators who don't use local-auth
# can blank this with `-e SEKISHO_CONTROL_SOCKET=`.
ENV SEKISHO_CONTROL_SOCKET=/var/lib/sekisho/control.sock

# 443: TLS proxy listener
#  80: ACME HTTP-01 + plaintext-redirect listener
# 9443: management API (sekisho-cli / sekisho-webui talk to this)
EXPOSE 443 80 9443

# distroless has no shell, so HEALTHCHECK uses the in-tree --healthz
# probe, which exits 0 on a /readyz HTTP 200 and 1 otherwise. The probe
# reaches the loopback-only management port from inside the container.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["/usr/bin/sekisho-cli", "--healthz", "https://127.0.0.1:9443"]

ENTRYPOINT ["/usr/bin/sekishod"]
