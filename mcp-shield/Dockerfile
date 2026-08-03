# MCP-Shield (Rust) — tool-layer defense.
# Multi-stage: compile a release binary, then a slim runtime that also has
# python3 (to run the fixture MCP server) so the rug-pull demo runs in-container.

FROM rust:1.86-slim AS build
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 bash curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app/target/release/mcp-shield /usr/local/bin/mcp-shield
COPY fixtures ./fixtures
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
