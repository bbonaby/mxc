# Test wxc-exec JSON network policy: block 8.8.8.8 / allow 1.1.1.1
# Must run elevated (firewall enforcement needs admin).
$ErrorActionPreference = 'Continue'
$root = 'C:\test\mxc-tier2\extracted'
$wxc  = Join-Path $root 'wxc-exec.exe'
$cfg  = Join-Path $root 'block_8888.json'
if (-not (Test-Path $wxc)) { throw "wxc-exec.exe not found at $wxc" }
if (-not (Test-Path $cfg)) { throw "config not found at $cfg" }
Write-Host "=== wxc-exec.exe size: $((Get-Item $wxc).Length) bytes ==="
Write-Host "=== Running wxc-exec with block-8.8.8.8 policy ==="
& $wxc --debug $cfg
Write-Host ""
Write-Host "=== wxc-exec exit: $LASTEXITCODE ==="
