# Two-stage build producing a single static binary on an empty base image.
#
# The panel has no external Go dependencies and the UI is compiled in via
# go:embed, so the runtime image needs nothing but the binary itself. That keeps
# the deployed image in single-digit megabytes and removes the entire OS package
# surface from the attack surface.

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

FROM scratch

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /panel /panel

# DATA_DIR should point at a mounted volume in production. Container
# filesystems are wiped on redeploy, so without a volume every user is lost
# when the service rebuilds.
ENV PORT=8080 \
    DATA_DIR=/data

EXPOSE 8080

ENTRYPOINT ["/panel"]
