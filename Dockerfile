# syntax=docker/dockerfile:1.7
#
# Image de la passerelle Tor / I2P / VPN.
#
# Trois étapes : le bundle Vue, le binaire Rust, puis une image d'exécution
# minimale. Le front est construit sur l'architecture de la machine de build
# (`$BUILDPLATFORM`), ce qui évite d'émuler Node lors d'un build ARM64.

# --- Étape 1 : construction de l'interface web ------------------------------
FROM --platform=$BUILDPLATFORM node:22-alpine AS ui

WORKDIR /ui
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

# --- Étape 2 : construction du binaire --------------------------------------
FROM rust:1.94-slim-bookworm AS build

WORKDIR /src

# Les dépendances sont compilées à partir d'un binaire factice : tant que
# Cargo.toml et Cargo.lock ne changent pas, cette couche reste en cache.
# `build.rs` crée `web/dist` au passage, ce qui suffit à rust-embed.
COPY Cargo.toml Cargo.lock build.rs ./
RUN mkdir -p src \
    && echo 'fn main() {}' > src/main.rs \
    && cargo build --release --locked \
    && rm -rf src

COPY src ./src
COPY --from=ui /ui/dist ./web/dist
# Cargo se fie à l'horodatage : sans ce `touch`, le binaire factice serait gardé.
RUN touch src/main.rs && cargo build --release --locked

# --- Étape 3 : image d'exécution --------------------------------------------
FROM debian:bookworm-slim

# `ca-certificates` sert aux sondes de santé en HTTPS, `curl` au HEALTHCHECK.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# La passerelle n'a besoin d'aucun privilège : elle n'écoute que sur des ports
# non réservés. Le volume de données doit appartenir à cet utilisateur.
RUN useradd --system --uid 1000 --create-home --home-dir /home/tiv tiv

COPY --from=build /src/target/release/tiv-gateway /usr/local/bin/tiv-gateway

RUN mkdir -p /data && chown tiv:tiv /data
VOLUME ["/data"]

USER tiv
WORKDIR /data

ENV TIV_CONFIG=/data/config.toml \
    TIV_LOG=info

# 8080 interface d'administration · 1080 SOCKS5 · 8118 proxy HTTP
EXPOSE 8080 1080 8118

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS --noproxy '*' http://127.0.0.1:8080/api/session || exit 1

ENTRYPOINT ["/usr/local/bin/tiv-gateway"]
