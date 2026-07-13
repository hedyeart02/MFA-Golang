# SAMLGuard

**Enterprise Lightweight SAML 2.0 MFA Gateway Microservices**

SAMLGuard is a production-grade, lightweight SAML 2.0 MFA Gateway that acts as a Proxy Identity Provider (Proxy IdP) between SAML Service Providers and upstream Identity Providers.

## Features

- **SAML 2.0 Proxy IdP** — Intercepts SAML authentication, enforces MFA, and re-signs assertions
- **Multi-Factor Authentication** — TOTP, Email OTP, SMS OTP, Backup Codes, Trusted Devices
- **Microservices Architecture** — 5 independently deployable services
- **Enterprise Security** — XML signature validation, replay detection, encrypted secrets, secure sessions
- **Production Ready** — Docker, Nginx reverse proxy, CI/CD, structured logging, graceful shutdown

## Architecture

```
Browser → Service Provider (ITA) → SAMLGuard Gateway → Upstream IdP (Entra/ADFS/Keycloak)
                                       ↓
                              Auth | MFA | Session | Audit
```

| Service   | Port | Description                              |
|-----------|------|------------------------------------------|
| Gateway   | 8080 | SAML proxy, orchestration, MFA challenge |
| Auth      | 8081 | SAML validation, assertion generation    |
| MFA       | 8082 | TOTP, Email/SMS OTP, backup codes        |
| Session   | 8083 | JWT sessions, idle/absolute timeout      |
| Audit     | 8084 | Structured event logging                 |

## Quick Start

### Prerequisites

- Go 1.24+
- Docker & Docker Compose
- OpenSSL

### Development Setup

```bash
# Clone and setup
git clone https://github.com/your-org/samlguard.git
cd samlguard

# Generate certificates and install dependencies
bash scripts/setup.sh

# Run all services
go run ./cmd/gateway &
go run ./cmd/auth &
go run ./cmd/mfa &
go run ./cmd/session &
go run ./cmd/audit &
```

### Docker Deployment

```bash
# Generate certificates
bash scripts/generate-certs.sh

# Set encryption key
export MFA_ENCRYPTION_KEY=$(cat cert/mfa-encryption.key)

# Start all services
docker-compose up --build -d

# Check health
curl https://localhost/health
```

## Configuration

All services are configured via `configs/config.yaml`, environment variables (`SAMLGUARD_*` prefix), or Docker secrets.

See [Configuration Guide](docs/configuration.md) for details.

## API Endpoints

| Service | Method | Path          | Description                |
|---------|--------|---------------|----------------------------|
| Gateway | GET    | /login        | Initiate SAML login        |
| Gateway | POST   | /acs          | SAML Assertion Consumer    |
| Gateway | GET    | /metadata     | Proxy IdP SAML metadata    |
| Gateway | GET    | /logout       | Session logout             |
| Gateway | GET    | /health       | Health check               |
| Auth    | POST   | /api/v1/validate  | Validate SAML response |
| Auth    | POST   | /api/v1/assertion | Generate new assertion |
| MFA     | POST   | /api/v1/enroll    | Enroll in MFA          |
| MFA     | POST   | /api/v1/request   | Send MFA challenge     |
| MFA     | POST   | /api/v1/verify    | Verify MFA code        |
| Session | GET    | /api/v1/session   | Get session info       |
| Session | DELETE | /api/v1/session   | Revoke session         |
| Audit   | GET    | /api/v1/logs      | Query audit logs       |
| Audit   | GET    | /api/v1/events    | List event types       |

## Testing

```bash
# Run all tests
go test ./... -v

# With race detection
go test ./... -race

# With coverage
go test ./... -coverprofile=coverage.out
go tool cover -func=coverage.out
```

## Technology Stack

| Component    | Technology                    |
|-------------|-------------------------------|
| Language     | Go 1.24                       |
| HTTP         | Gin                           |
| ORM          | GORM                          |
| Database     | SQLite (pure Go driver)       |
| SAML         | crewjam/saml                  |
| JWT          | golang-jwt                    |
| OTP          | pquerna/otp                   |
| Config       | Viper                         |
| Logging      | Zap                           |
| Container    | Docker + Docker Compose       |
| Proxy        | Nginx                         |
| CI/CD        | GitHub Actions                |

## Documentation

- [Architecture Guide](docs/architecture.md)
- [API Documentation](docs/api.md)
- [Configuration Guide](docs/configuration.md)
- [Deployment Guide](docs/deployment.md)
- [Security Guide](docs/security.md)
- [Troubleshooting Guide](docs/troubleshooting.md)

## License

Enterprise proprietary. All rights reserved.
