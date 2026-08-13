# ============================================================================
# MCP Security Gateway — multi-stage build
#
# Stage 1 (builder):  compiles a fully static, CGO-free binary.
# Stage 2 (runtime):  gcr.io/distroless/static-debian12 — no shell, no
#                     package manager, non-root by default, ~15MB.
#
# Build:  docker build -f build/Dockerfile -t mcp-gateway:v5 .
# Run:    docker run -d -p 9090:9090 -v $(pwd)/policy.yaml:/etc/mcp-gateway/policy.yaml:ro mcp-gateway:v5
# ============================================================================

FROM golang:1.23-alpine AS builder

# go.sum/go.mod are separate from source so dependency downloads are cached
# across source-only changes.
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0 produces a fully static binary (required for distroless/scratch
# images, which contain no libc). -trimpath removes local build paths from the
# binary metadata; -ldflags strips debug info.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath \
    -ldflags="-s -w -X main.Version=v5" \
    -o /out/mcp-gateway \
    ./cmd/mcp-gateway

# Optional smoke test of the built artifact inside the builder (static link check).
RUN ldd /out/mcp-gateway 2>&1 | grep -qi "not a dynamic executable" && echo "static binary confirmed"

# ----------------------------------------------------------------------------
# Runtime: distroless/static — contains only the binary + CA certificates.
FROM gcr.io/distroless/static-debian12:nonroot

LABEL maintainer="mcp-gateway-team"
LABEL org.opencontainers.image.title="MCP Security Gateway"
LABEL org.opencontainers.image.description="Zero-trust security sidecar for Model Context Protocol agents"

COPY --from=builder /out/mcp-gateway /mcp-gateway

# Non-root execution (distroless static default UID 65532:65532).
USER nonroot:nonroot

# Ports: gateway proxy + (optional) console, matching the default flags.
EXPOSE 9090 9091

ENTRYPOINT ["/mcp-gateway"]
