# Three-stage build:
#
#   1. golang:1.23-alpine    compiles the panel binary
#   2. alpine                 downloads and unpacks the Xray release, then
#                            strips it to the binary we actually need
#   3. alpine                 the runtime image: panel binary + xray binary +
#                            ca-certificates (for outbound TLS) + nobody user
#
# The runtime image is intentionally alpine rather than scratch because we
# now run Xray as a subprocess and need a working /tmp, /proc and a non-root
# user. The image is still small: alpine + the two binaries + ca-certificates
# is well under 50 MB.

FROM golang:1.23-alpine AS build

# ca-certificates is copied into the final image so outbound TLS works if the
# panel ever needs it. Nothing else from this stage ships.
RUN apk add --no-cache ca-certificates

WORKDIR /src

# go.mod first: this layer caches unless the module definition changes.
COPY go.mod ./
RUN go mod download

COPY . .

# Fail the build rather than the deploy if anything regressed.
RUN go vet ./... && go test ./...

# CGO off keeps the binary fully static; -trimpath drops local paths from it.
RUN CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags="-s -w" \
      -o /panel .

# ----- stage 2: fetch Xray --------------------------------------------------
#
# We download a pinned Xray release and unpack just the binary. Pinning is
# deliberate: a future Xray release could change config syntax and silently
# break deploys, so we upgrade explicitly.
FROM alpine:3.20 AS xray

ARG XRAY_VERSION=1.8.24

# curl/unzip are pulled just for this stage and do not reach the runtime.
RUN apk add --no-cache curl unzip

WORKDIR /tmp
RUN curl -fsSL -o xray.zip \
      "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-linux-64.zip" \
      && echo "Pinned Xray release v${XRAY_VERSION}" \
      && unzip -o xray.zip xray -d /out \
      && rm xray.zip \
      && /out/xray version

# ----- stage 3: runtime -----------------------------------------------------
FROM alpine:3.20

# ca-certificates is required so the panel can dial HTTPS endpoints (the
# /api/diagnose probe, the sync agent on a VPS, etc.).
# tzdata is small and lets the panel log local times in addition to UTC.
# tor: the panel runs one Tor instance per country (50 in total), each
# pinned to its country via ExitNodes. The alpine 'tor' package bundles
# the geoip files (/usr/share/tor/geoip, geoip6) that Tor needs to map
# country codes to IP ranges; without them, ExitNodes {cc} silently
# falls back to "any exit" and every location would egress through the
# same country (the bug we are fixing). Note: there is no separate
# 'tor-geoipdb' package in alpine -- the files ship with 'tor' itself.
RUN apk add --no-cache ca-certificates tzdata tor

# Xray binary from stage 2, panel binary from stage 1.
COPY --from=xray /out/xray /usr/local/bin/xray
COPY --from=build /panel /panel

# DATA_DIR should point at a mounted volume in production. Container
# filesystems are wiped on redeploy, so without a volume every user is lost
# when the service rebuilds.
#
# SELF_HOSTED_PROXY defaults to true: the panel runs an in-process Xray and
# serves WebSocket traffic on the same port as the panel UI. Set to "false"
# to use the original architecture where the panel only generates config for
# a separate VPS.
#
# TOR_LOCATIONS controls which Tor instances are started.
#   - "DE,US,TR,FR,AE" (default): the 5 Tor-pinned locations. NL
#     is NOT in this list because it exits directly through the
#     container's own IP (the Location table marks it Direct=true).
#     Each Tor instance uses ~110 MB RSS, so 5 instances need ~550 MB --
#     fits in Railway's trial plan (~953 MB RAM) with headroom.
#   - "all": starts a Tor instance for every non-direct location.
#   - "DE,US,...": any comma-separated list of country codes.
#
# PORT defaults to 8080 -- Railway injects its own PORT env at runtime, which
# overrides this default via the envOr() helper in main.go.
ENV PORT=8080 \
    DATA_DIR=/data \
    SELF_HOSTED_PROXY=true \
    XRAY_BIN=/usr/local/bin/xray \
    XRAY_CONF=/tmp/xray-config.json \
    TOR_BIN=/usr/bin/tor \
    TOR_BASE_DIR=/tmp/tor-ml \
    TOR_GEOIP_DIR=/usr/share/tor \
    TOR_LOCATIONS=DE,US,TR,FR,AE

# /data is where the panel persists its JSON state. Mount a Railway volume
# here to keep users across redeploys. XRAY_CONF lives under /data so the
# config file is writable by the panel process.
RUN mkdir -p /data /tmp && \
    chown -R nobody:nobody /data /tmp && \
    chmod 1777 /tmp

# Run as nobody. The panel binds a high port (8080) and Xray binds loopback
# ports only, so root is not needed.
USER nobody

# NOTE: do not declare VOLUME here. Railway rejects Dockerfile VOLUME
# directives ("docker VOLUME is not supported, use Railway Volumes"). To
# persist state across redeploys, create a Railway volume in the dashboard
# and mount it at /data.

EXPOSE 8080

ENTRYPOINT ["/panel"]
