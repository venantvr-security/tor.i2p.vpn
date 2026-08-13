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
#
# Le compilateur tourne sur l'architecture de la machine de build et produit du
# code pour l'architecture cible. Émuler tout un build Rust sous QEMU coûterait
# une demi-heure là où la compilation croisée prend une minute et demie.
FROM --platform=$BUILDPLATFORM rust:1.94-slim-bookworm AS build

ARG TARGETARCH
ARG BUILDARCH

WORKDIR /src

# Choisit la cible Rust et, lorsque les architectures diffèrent, installe
# l'éditeur de liens et les en-têtes de la libc correspondante. `cc-rs` déduit
# seul le compilateur C à partir du triplet, il n'y a donc rien d'autre à lui
# indiquer pour les dépendances qui embarquent du C, comme `ring`.
RUN set -eux; \
    case "$TARGETARCH" in \
      amd64) target='x86_64-unknown-linux-gnu'; \
             linker='x86_64-linux-gnu-gcc'; \
             packages='gcc-x86-64-linux-gnu libc6-dev-amd64-cross' ;; \
      arm64) target='aarch64-unknown-linux-gnu'; \
             linker='aarch64-linux-gnu-gcc'; \
             packages='gcc-aarch64-linux-gnu libc6-dev-arm64-cross' ;; \
      *) echo "architecture cible non prise en charge : $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    echo "export CARGO_BUILD_TARGET=$target" > /build-env; \
    if [ "$TARGETARCH" != "$BUILDARCH" ]; then \
      apt-get update; \
      apt-get install -y --no-install-recommends $packages; \
      rm -rf /var/lib/apt/lists/*; \
      variable=$(echo "$target" | tr 'a-z-' 'A-Z_'); \
      echo "export CARGO_TARGET_${variable}_LINKER=$linker" >> /build-env; \
    fi; \
    rustup target add "$target"

# Les dépendances sont compilées à partir d'un binaire factice : tant que
# Cargo.toml et Cargo.lock ne changent pas, cette couche reste en cache.
# `build.rs` crée `web/dist` au passage, ce qui suffit à rust-embed.
COPY Cargo.toml Cargo.lock build.rs ./
RUN set -eux; \
    . /build-env; \
    mkdir -p src; \
    echo 'fn main() {}' > src/main.rs; \
    cargo build --release --locked; \
    rm -rf src

COPY src ./src
COPY --from=ui /ui/dist ./web/dist
# Cargo se fie à l'horodatage : sans ce `touch`, le binaire factice serait gardé.
# Le binaire est ensuite déposé à un chemin fixe, `COPY` ne sachant pas
# interpoler le triplet de la cible.
RUN set -eux; \
    . /build-env; \
    touch src/main.rs; \
    cargo build --release --locked; \
    cp "target/$CARGO_BUILD_TARGET/release/tiv-gateway" /tiv-gateway

# --- Étape 3 : image d'exécution --------------------------------------------
#
# Sans `--platform`, cette étape est bâtie pour l'architecture cible. Seules des
# commandes triviales y tournent — installation de paquets, création d'un
# utilisateur — donc l'émulation éventuelle ne coûte que quelques secondes.
FROM debian:bookworm-slim

# Rattache le paquet publié à son dépôt d'origine dans l'interface GitHub.
LABEL org.opencontainers.image.source="https://github.com/venantvr-security/tor.i2p.vpn" \
      org.opencontainers.image.title="Passerelle Tor / I2P" \
      org.opencontainers.image.description="Proxy SOCKS5 et HTTP routant .onion vers Tor et .i2p vers I2P, avec interface web de configuration et de supervision" \
      org.opencontainers.image.licenses="MIT"

# `ca-certificates` sert aux sondes de santé en HTTPS, `curl` au HEALTHCHECK.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# La passerelle n'a besoin d'aucun privilège : elle n'écoute que sur des ports
# non réservés. Le volume de données doit appartenir à cet utilisateur.
RUN useradd --system --uid 1000 --create-home --home-dir /home/tiv tiv

COPY --from=build /tiv-gateway /usr/local/bin/tiv-gateway

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
