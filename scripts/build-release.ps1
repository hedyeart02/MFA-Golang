<#
.SYNOPSIS
    Automated Cross-Platform Release Packaging for SAMLGuard
.DESCRIPTION
    Builds standalone, pure-Go binaries (CGO=0) for Windows AMD64, Linux AMD64,
    and Linux ARM64, structures release directories with configs, scripts and docs,
    and creates .zip and .tar.gz distribution archives with SHA-256 checksums.
#>
param(
    [string]$Version = "1.0.2"
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$ProjectRoot = Resolve-Path "$PSScriptRoot\.."
Set-Location $ProjectRoot

$DistDir = "$ProjectRoot\dist"
if (Test-Path $DistDir) {
    Remove-Item -Recurse -Force $DistDir
}
New-Item -ItemType Directory -Force -Path $DistDir | Out-Null

$Targets = @(
    @{ OS = "windows"; Arch = "amd64"; Binary = "samlguard.exe"; ArchiveType = "zip" },
    @{ OS = "linux"; Arch = "amd64"; Binary = "samlguard"; ArchiveType = "tar.gz" },
    @{ OS = "linux"; Arch = "arm64"; Binary = "samlguard"; ArchiveType = "tar.gz" }
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Building SAMLGuard Release v$Version (Pure-Go / CGO=0)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$ChecksumEntries = @()

foreach ($t in $Targets) {
    $osName = $t.OS
    $archName = $t.Arch
    $binName = $t.Binary
    $pkgName = "samlguard-v$Version-$osName-$archName"
    $stageDir = "$DistDir\staging\$pkgName"

    Write-Host "`n==> Compiling for $osName/$archName..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Force -Path "$stageDir\bin" | Out-Null
    New-Item -ItemType Directory -Force -Path "$stageDir\configs" | Out-Null
    New-Item -ItemType Directory -Force -Path "$stageDir\cert" | Out-Null
    New-Item -ItemType Directory -Force -Path "$stageDir\data" | Out-Null
    New-Item -ItemType Directory -Force -Path "$stageDir\scripts" | Out-Null

    $outBin = "$stageDir\bin\$binName"
    $env:GOOS = $osName
    $env:GOARCH = $archName
    $env:CGO_ENABLED = "0"

    go build -ldflags="-s -w -X main.Version=v$Version" -o $outBin ./cmd/samlguard
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed building binary for $osName/$archName"
        exit $LASTEXITCODE
    }

    # Copy configurations
    Copy-Item "$ProjectRoot\configs\config.yaml.example" "$stageDir\configs\config.yaml.example"
    if (Test-Path "$ProjectRoot\configs\default.yaml") {
        Copy-Item "$ProjectRoot\configs\default.yaml" "$stageDir\configs\default.yaml"
    }

    # Placeholders for certs & data
    New-Item -ItemType File -Force -Path "$stageDir\cert\.gitkeep" | Out-Null
    New-Item -ItemType File -Force -Path "$stageDir\data\.gitkeep" | Out-Null

    # Platform-specific scripts & docs
    if ($osName -eq "windows") {
        New-Item -ItemType Directory -Force -Path "$stageDir\scripts\windows" | Out-Null
        Copy-Item "$ProjectRoot\scripts\windows\*" "$stageDir\scripts\windows\"
    }
    else {
        New-Item -ItemType Directory -Force -Path "$stageDir\scripts\linux" | Out-Null
        Copy-Item "$ProjectRoot\scripts\linux\*" "$stageDir\scripts\linux\"
    }

    # Package README
    $readmeContent = @"
# SAMLGuard v$Version ($osName-$archName)

Standalone, platform-independent SAML MFA Reverse Proxy Gateway.

## Quick Start

### 1. Configuration
Copy ``configs/config.yaml.example`` to ``configs/config.yaml`` and edit with your settings.
External SAML endpoints in production must use HTTPS.

### 2. Execution
Run directly from terminal or command prompt:
```
./bin/$binName -config ./configs/config.yaml
```

### 3. Service Installation
- Linux: Use ``scripts/linux/install.sh`` (registers systemd service)
- Windows: Use ``scripts/windows/install-service.ps1`` (registers Windows Service)

Documentation: https://github.com/hedyeart02/MFA-Golang
"@
    Set-Content -Path "$stageDir\README.md" -Value $readmeContent

    # Create archive
    $archivePath = ""
    if ($t.ArchiveType -eq "zip") {
        $archivePath = "$DistDir\$pkgName.zip"
        Write-Host "==> Creating ZIP archive: $archivePath" -ForegroundColor Green
        Compress-Archive -Path "$stageDir\*" -DestinationPath $archivePath -Force
    }
    else {
        $archivePath = "$DistDir\$pkgName.tar.gz"
        Write-Host "==> Creating TAR.GZ archive: $archivePath" -ForegroundColor Green
        # Use tar utility available in modern Windows / PowerShell
        tar -czf $archivePath -C "$DistDir\staging" $pkgName
    }

    # Compute SHA256 checksum
    $hash = (Get-FileHash -Algorithm SHA256 -Path $archivePath).Hash.ToLower()
    $archiveFilename = Split-Path -Leaf $archivePath
    $ChecksumEntries += "$hash  $archiveFilename"
    Write-Host "    SHA256: $hash"
}

# Clean staging directory
Remove-Item -Recurse -Force "$DistDir\staging"

# Write Checksums
$checksumPath = "$DistDir\checksums.txt"
$ChecksumEntries | Out-File -FilePath $checksumPath -Encoding utf8
Write-Host "`n==> Release packages successfully created in: $DistDir" -ForegroundColor Green
Get-ChildItem $DistDir | Select-Object Name, Length
