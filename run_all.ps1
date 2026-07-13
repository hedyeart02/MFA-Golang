$ErrorActionPreference = "Stop"

$goPath = "C:\Program Files\Go\bin\go.exe"
$binDir = ".\bin"

Write-Host "Creating directories..."
New-Item -ItemType Directory -Force -Path "data" | Out-Null
New-Item -ItemType Directory -Force -Path $binDir | Out-Null

Write-Host "Building microservices (compiling once for instant subsequent runs)..."
& $goPath build -o "$binDir\audit.exe" ./cmd/audit
& $goPath build -o "$binDir\session.exe" ./cmd/session
& $goPath build -o "$binDir\mfa.exe" ./cmd/mfa
& $goPath build -o "$binDir\auth.exe" ./cmd/auth
& $goPath build -o "$binDir\gateway.exe" ./cmd/gateway

Write-Host "Setting environment variables..."
$env:MFA_ENCRYPTION_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

Write-Host "Starting Audit Service (Port 18084)..."
$env:SAMLGUARD_DATABASE_PATH = "./data/audit.db"
Start-Process -NoNewWindow -FilePath "$binDir\audit.exe"

Write-Host "Starting Session Service (Port 18083)..."
$env:SAMLGUARD_DATABASE_PATH = "./data/session.db"
Start-Process -NoNewWindow -FilePath "$binDir\session.exe"

Write-Host "Starting MFA Service (Port 18082)..."
$env:SAMLGUARD_DATABASE_PATH = "./data/mfa.db"
Start-Process -NoNewWindow -FilePath "$binDir\mfa.exe"

Write-Host "Starting Auth Service (Port 18081)..."
$env:SAMLGUARD_DATABASE_PATH = "./data/auth.db"
Start-Process -NoNewWindow -FilePath "$binDir\auth.exe"

Write-Host "Starting Gateway Service (Port 18080)..."
Write-Host "Press Ctrl+C to stop the gateway (other services will continue running in background)."
Remove-Item env:SAMLGUARD_DATABASE_PATH -ErrorAction SilentlyContinue
& "$binDir\gateway.exe"
