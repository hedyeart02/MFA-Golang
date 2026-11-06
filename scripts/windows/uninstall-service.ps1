<#
.SYNOPSIS
    Uninstalls the SAMLGuard service on Windows.
#>
param(
    [switch]$PurgeData
)

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be executed in an elevated PowerShell session (Run as Administrator)."
    exit 1
}

$ServiceName = "SAMLGuard"
$InstallDir = "$env:ProgramFiles\SAMLGuard"
$DataDir = "$env:ProgramData\SAMLGuard"

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "==> Stopping service $ServiceName..." -ForegroundColor Cyan
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    Write-Host "==> Removing service registration from Windows SCM..." -ForegroundColor Cyan
    & sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
} else {
    Write-Host "    Service $ServiceName is not registered in Windows SCM." -ForegroundColor Yellow
}

Write-Host "==> Removing application binary..." -ForegroundColor Cyan
if (Test-Path $InstallDir) {
    Remove-Item -Recurse -Force $InstallDir
}

if ($PurgeData) {
    Write-Host "==> Purging configuration and database ($DataDir)..." -ForegroundColor Yellow
    if (Test-Path $DataDir) {
        Remove-Item -Recurse -Force $DataDir
    }
} else {
    Write-Host "    Configuration and database preserved at $DataDir (use -PurgeData to delete)."
}

Write-Host "==> SAMLGuard service uninstalled successfully." -ForegroundColor Green

