FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /mfa ./cmd/mfa

FROM gcr.io/distroless/static:nonroot

COPY --from=builder /mfa /mfa
COPY --from=builder /app/configs /configs

EXPOSE 8082

USER nonroot:nonroot

ENTRYPOINT ["/mfa"]
