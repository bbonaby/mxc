# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# build-mxc-service.ps1 — one-command build/rebuild/reinstall loop for
# the Tier 2 mxc-service prototype.
#
# Usage:
#   .\scripts\build-mxc-service.ps1                 # build MSI only
#   .\scripts\build-mxc-service.ps1 -Install        # also (re)install on local machine (requires elevation)
#   .\scripts\build-mxc-service.ps1 -Install -Verify  # then run `mxc-net version` to confirm IPC
#
# Each invocation bumps the MSI ProductVersion to the current
# yyMM.dd.HHmm so MajorUpgrade always upgrades cleanly in the dev loop.

[CmdletBinding()]
param(
    [switch]$Install,
    [switch]$Verify,
    [switch]$SkipCargo
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path "$PSScriptRoot\..").Path
$srcDir = Join-Path $repoRoot 'src'
$installerDir = Join-Path $repoRoot 'installer\mxc-service-msi'
$wxsFile = Join-Path $installerDir 'Package.wxs'

# ---------------------------------------------------------------------------
# 1. cargo build --release
# ---------------------------------------------------------------------------
if (-not $SkipCargo) {
    Write-Host "==> cargo build --release -p mxc_service -p mxc_service_client" -ForegroundColor Cyan
    Push-Location $srcDir
    try {
        cargo build --release -p mxc_service -p mxc_service_client
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed ($LASTEXITCODE)" }
    } finally {
        Pop-Location
    }
}

# ---------------------------------------------------------------------------
# 2. locate the built binaries
# ---------------------------------------------------------------------------
$targetDir = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $srcDir 'target' }
$releaseCandidates = @(
    (Join-Path $targetDir 'release'),
    (Join-Path $targetDir 'amd64fre\release')
)
$releaseDir = $releaseCandidates | Where-Object { Test-Path (Join-Path $_ 'mxc-service.exe') } | Select-Object -First 1
if (-not $releaseDir) {
    throw "Could not find mxc-service.exe under $($releaseCandidates -join ' OR ')"
}
Write-Host "    Using release binaries in $releaseDir" -ForegroundColor DarkGray

# ---------------------------------------------------------------------------
# 3. wix build
# ---------------------------------------------------------------------------
$ts = Get-Date
$minutesOfDay = $ts.Hour * 60 + $ts.Minute
$productVersion = "{0}.{1}.{2}" -f ($ts.Year - 2000), $ts.Month, ($ts.Day * 1440 + $minutesOfDay)
Write-Host "==> wix build (ProductVersion=$productVersion)" -ForegroundColor Cyan
$msiOut = Join-Path $installerDir 'mxc-service.msi'
& wix build $wxsFile `
    -arch x64 `
    -define "ServiceBinaryDir=$releaseDir" `
    -define "ProductVersion=$productVersion" `
    -out $msiOut
if ($LASTEXITCODE -ne 0) { throw "wix build failed ($LASTEXITCODE)" }
Write-Host "    -> $msiOut" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 4. optional install/upgrade on local machine
# ---------------------------------------------------------------------------
if ($Install) {
    Write-Host "==> msiexec /i $msiOut /qn" -ForegroundColor Cyan
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Warning "Not elevated; install will likely fail. Re-run from an admin shell."
    }
    $logPath = Join-Path $env:TEMP "mxc-service-install.log"
    $p = Start-Process msiexec.exe -ArgumentList @('/i', $msiOut, '/qn', '/L*v', $logPath) -PassThru -Wait
    Write-Host "    msiexec exit code: $($p.ExitCode); log: $logPath" -ForegroundColor DarkGray
    if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) {
        throw "MSI install failed with code $($p.ExitCode). See $logPath."
    }
    Write-Host "    Service status:" -ForegroundColor DarkGray
    Get-Service mxc-service -ErrorAction SilentlyContinue | Format-Table -AutoSize
}

# ---------------------------------------------------------------------------
# 5. optional smoke test via mxc-net
# ---------------------------------------------------------------------------
if ($Verify) {
    $mxcNet = Join-Path 'C:\Program Files\Microsoft\MXC Service' 'mxc-net.exe'
    if (-not (Test-Path $mxcNet)) { $mxcNet = Join-Path $releaseDir 'mxc-net.exe' }
    Write-Host "==> $mxcNet version" -ForegroundColor Cyan
    & $mxcNet version
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "mxc-net version failed; service may not have started, or IPC pipe is not yet up."
    }
}

Write-Host "Done." -ForegroundColor Green
