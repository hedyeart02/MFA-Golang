FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /session ./cmd/session

FROM gcr.io/distroless/static:nonroot

COPY --from=builder /session /session
COPY --from=builder /app/configs /configs

EXPOSE 8083

USER nonroot:nonroot

ENTRYPOINT ["/session"]
