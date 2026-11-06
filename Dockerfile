# Stage 1: Build standalone binary with pure-Go (zero CGO)
FROM golang:1.24-alpine AS builder

WORKDIR /src

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source tree and compile statically
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/samlguard ./cmd/samlguard

# Stage 2: Minimal runtime image
FROM alpine:3.20

# Install runtime dependencies for health checks and certificate trust
RUN apk --no-cache add ca-certificates tzdata wget \
    && addgroup -S -g 10001 samlguard \
    && adduser -S -u 10001 -G samlguard -h /app samlguard \
    && mkdir -p /data /configs /app/cert \
    && chown -R samlguard:samlguard /data /configs /app

WORKDIR /app
COPY --from=builder /bin/samlguard /app/samlguard

USER samlguard:samlguard

# Default persistent volumes for SQLite and external YAML configuration
VOLUME ["/data", "/configs"]

# Expose HTTP and HTTPS default ports
EXPOSE 8080 8443

HEALTHCHECK --interval=15s --timeout=5s --retries=3 --start-period=5s \
    CMD wget -q --spider http://localhost:8080/health || exit 1

ENTRYPOINT ["/app/samlguard"]

