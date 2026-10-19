# MCP-Shield (Rust) — tool-layer defense.
# Multi-stage: compile a release binary, then a slim runtime that also has
# python3 (to run the fixture MCP server) so the rug-pull demo runs in-container.
#
# The build context is the REPOSITORY ROOT, not this directory: the Secret
# Boundary is a path dependency that lives in ../../crates, and cargo resolves
# a path dependency relative to the manifest that declares it. The crate is
# therefore copied to the sibling path the dependency names.

FROM rust:1.86-slim AS build
# reqwest's `rustls` feature pulls in aws-lc-rs, which compiles a bundled C
# library and therefore needs a C compiler and cmake. The slim Rust image has
# neither, and the build fails without them. Only the builder stage needs
# them; the runtime stage ships just the statically linked binary.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential cmake \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src/mcp-shield
COPY mcp-shield/Cargo.toml mcp-shield/Cargo.lock ./
COPY mcp-shield/src ./src
# Sibling of the manifest, matching the `../crates/pbm-secret-boundary` path
# dependency declared in Cargo.toml.
COPY crates /src/crates
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 bash curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /src/mcp-shield/target/release/mcp-shield /usr/local/bin/mcp-shield
COPY mcp-shield/fixtures ./fixtures
# Let fixtures/run_demo.sh use the prebuilt binary and invoke `python`.
ENV MCP_SHIELD_BIN=/usr/local/bin/mcp-shield
RUN ln -sf /usr/bin/python3 /usr/local/bin/python \
    && useradd --system --uid 10001 --create-home monolith \
    && mkdir -p /var/lib/monolith \
    && chown -R monolith:monolith /app /var/lib/monolith
# The default Compose command runs the resident outbox drainer. Proxy sessions
# are still invoked on demand with `docker compose exec`.
USER monolith
CMD ["mcp-shield", "--drain-outbox"]
