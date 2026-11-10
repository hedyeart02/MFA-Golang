<#
.SYNOPSIS
    Installs SAMLGuard as a background service on Windows.
.DESCRIPTION
    Creates standard installation directories in Program Files and ProgramData,
    copies the binary and template configuration, and registers the service.
.PARAMETER BinarySource
    Path to the compiled samlguard.exe binary (default: .\bin\samlguard.exe)
#>
param(
    [string]$BinarySource = ".\bin\samlguard.exe"
)

# Enforce Administrator privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be executed in an elevated PowerShell session (Run as Administrator)."
    exit 1
}

if (-not (Test-Path $BinarySource)) {
    Write-Error "Binary not found at $BinarySource"
    exit 1
}

$InstallDir = "$env:ProgramFiles\SAMLGuard"
$DataDir = "$env:ProgramData\SAMLGuard"
$CertDir = "$DataDir\cert"
$DbDir = "$DataDir\data"
$ServiceExe = "$InstallDir\samlguard.exe"
$ConfigFile = "$DataDir\config.yaml"

Write-Host "==> Creating directories..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
New-Item -ItemType Directory -Force -Path $CertDir | Out-Null
New-Item -ItemType Directory -Force -Path $DbDir | Out-Null

Write-Host "==> Installing binary to $ServiceExe..." -ForegroundColor Cyan
Copy-Item -Path $BinarySource -Destination $ServiceExe -Force

Write-Host "==> Setting up configuration in $ConfigFile..." -ForegroundColor Cyan
if (-not (Test-Path $ConfigFile)) {
    if (Test-Path ".\configs\config.yaml.example") {
        Copy-Item -Path ".\configs\config.yaml.example" -Destination $ConfigFile
    } elseif (Test-Path ".\configs\config.yaml") {
        Copy-Item -Path ".\configs\config.yaml" -Destination $ConfigFile
    }
}

Write-Host "==> Applying security ACLs..." -ForegroundColor Cyan
# Restrict configuration and database permissions to SYSTEM and Administrators
$acl = Get-Acl $DataDir
$acl.SetAccessRuleProtection($true, $false)
$adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.AddAccessRule($adminRule)
$acl.AddAccessRule($systemRule)
Set-Acl -Path $DataDir -AclObject $acl

$ServiceName = "SAMLGuard"
Write-Host "==> Registering native Windows Service '$ServiceName'..." -ForegroundColor Cyan

# Check if service already exists
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "    Stopping existing service..."
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    & sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

# Register native Windows service with SCM
$binPath = "`"$ServiceExe`" -config `"$ConfigFile`""
$created = $false
try {
    New-Service -Name $ServiceName `
        -BinaryPathName $binPath `
        -DisplayName "SAMLGuard MFA Gateway" `
        -StartupType Automatic `
        -Description "SAML MFA Reverse Proxy Gateway for IT Advisor and enterprise IdPs" `
        -DependsOn "Tcpip" -ErrorAction Stop | Out-Null
    $created = $true
} catch {
    Write-Host "    Falling back to sc.exe create..." -ForegroundColor Yellow
    & sc.exe create $ServiceName binPath= $binPath start= auto DisplayName= "SAMLGuard MFA Gateway" depend= Tcpip | Out-Null
    & sc.exe description $ServiceName "SAML MFA Reverse Proxy Gateway for IT Advisor and enterprise IdPs" | Out-Null
    $created = $true
}

# Configure service failure recovery actions (restart after 5 seconds on 1st, 2nd, and subsequent crashes)
& sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null
& sc.exe failureflag $ServiceName 1 | Out-Null

Write-Host "==> Installation complete!" -ForegroundColor Green
Write-Host "    Executable:     $ServiceExe"
Write-Host "    Configuration:  $ConfigFile"
Write-Host "    Database:       $DbDir\samlguard.db"
Write-Host "    To start:       Start-Service -Name $ServiceName"
Write-Host "    To stop:        Stop-Service -Name $ServiceName"

