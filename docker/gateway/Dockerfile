FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /gateway ./cmd/gateway

FROM gcr.io/distroless/static:nonroot

COPY --from=builder /gateway /gateway
COPY --from=builder /app/configs /configs
COPY --from=builder /app/web /web

EXPOSE 8080

USER nonroot:nonroot

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD ["/gateway", "--health-check"] || exit 1

ENTRYPOINT ["/gateway"]
