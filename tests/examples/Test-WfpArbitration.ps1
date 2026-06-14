# Tier 2 WFP arbitration empirical test.
#
# Question (open since the AC<->AC loopback investigation):
# Do MXC's user-mode PERMIT filters at FWPM_LAYER_ALE_AUTH_CONNECT_V4
# dominate the system-origin filter 71655 that blocks AC<->AC loopback
# by default?
#
# Methodology:
#   1. Without broker policy: wxc-exec runs a containerized curl to
#      loopback IP/port that has no listener. Expected outcome with
#      filter 71655 winning: BLOCKED at ALE layer => connect() returns
#      WSAECONNREFUSED *or* WSAETIMEDOUT depending on layer (block at
#      ALE often surfaces as ICMP-unreachable -> WSAECONNREFUSED on
#      loopback, but the TCP packet never leaves the box).
#   2. With broker permit installed: wxc-exec config has defaultPolicy
#      = block and an allowedHosts list containing 127.0.0.0/8. The
#      broker translates allowedHosts -> Rule { verb: Allow, addr:
#      127.0.0.1 } at the same ALE layer with higher weight.
#   3. Compare connect() return between the two runs.
#   4. Capture netsh wfp trace during run #2 and grep for our policy
#      filter to confirm it's the winning filter.

[CmdletBinding()]
param(
    [string] $WxcExec = 'C:\mxc-rpc\wxc-exec.exe',
    [int]    $Port    = 19443
)

$ErrorActionPreference = 'Continue'

function New-Config {
    param([string]$Path, [string]$DefaultPolicy, [string[]]$BlockedHosts, [string[]]$AllowedHosts)
    $cfg = @{
        version          = '0.4.0-alpha'
        containerId      = 'WfpArbTest'
        containment      = 'processcontainer'
        process          = @{
            commandLine = "curl.exe --max-time 4 -sS -o NUL -w STATUS=%{http_code}_ERR=%{errormsg}_TIME=%{time_total} http://127.0.0.1:$Port"
            cwd         = 'C:\Windows'
            timeout     = 15000
        }
        processContainer = @{ capabilities = @('internetClient', 'privateNetworkClientServer') }
        network          = @{ enforcementMode = 'firewall'; defaultPolicy = $DefaultPolicy }
        lifecycle        = @{ destroy_on_exit = $true }
    }
    if ($BlockedHosts) { $cfg.network.blockedHosts = $BlockedHosts }
    if ($AllowedHosts) { $cfg.network.allowedHosts = $AllowedHosts }
    $cfg | ConvertTo-Json -Depth 6 | Set-Content -Path $Path -Encoding ascii
}

$baselineCfg = 'C:\mxc-rpc\arb-baseline.json'
$permitCfg   = 'C:\mxc-rpc\arb-permit.json'

# Baseline: default=allow, no overrides => broker is NOT invoked.
# Outcome is governed entirely by stock Windows policy (filter 71655).
New-Config -Path $baselineCfg -DefaultPolicy 'allow' -BlockedHosts @() -AllowedHosts @()

# Test: default=block + allowedHosts=loopback => broker installs PERMIT
# at ALE_AUTH_CONNECT_V4 scoped to this AC's SID for 127.0.0.0/8.
New-Config -Path $permitCfg -DefaultPolicy 'block' -BlockedHosts @() -AllowedHosts @('127.0.0.0/8')

function Invoke-Run {
    param([string]$Cfg, [string]$Label)
    Write-Host "`n=== $Label ===" -ForegroundColor Cyan
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $out = & $WxcExec $Cfg 2>&1 | Out-String
    $sw.Stop()
    Write-Host $out
    Write-Host "elapsed: $($sw.Elapsed.TotalSeconds.ToString('0.00'))s"
}

Write-Host '== Stage 1: baseline (default=allow, no broker) =='
Invoke-Run -Cfg $baselineCfg -Label 'BASELINE allow-all'

Write-Host '== Stage 2: broker permit (default=block + allow 127.0.0.0/8) =='
# Start wfp capture
$capFile = 'C:\mxc-rpc\wfp-arb.etl'
netsh wfp capture start file=$capFile 2>&1 | Out-Null
try {
    Invoke-Run -Cfg $permitCfg -Label 'BROKER-permit 127.0.0.0/8'
} finally {
    netsh wfp capture stop 2>&1 | Out-Null
}

Write-Host "`nWFP capture saved to $capFile"
if (Test-Path $capFile) {
    # Convert to XML and search for our policy GUID.
    $xmlFile = 'C:\mxc-rpc\wfp-arb.xml'
    netsh wfp show netevents file=$xmlFile 2>&1 | Out-Null
    if (Test-Path $xmlFile) {
        $matches = Select-String -Path $xmlFile -Pattern '71655|MxcPolicy|FWPM_LAYER_ALE_AUTH_CONNECT|filterId' -SimpleMatch | Select-Object -First 30
        Write-Host '--- relevant lines in netevents.xml ---'
        $matches | ForEach-Object { Write-Host $_.Line }
    }
}

Write-Host ''
Write-Host '=== Interpretation ==='
Write-Host 'BASELINE should surface STATUS=000 + WSAECONNREFUSED quickly (no listener'
Write-Host 'on port 19443; ALE_AUTH_CONNECT_V4 permits the SYN, RST comes back).'
Write-Host ''
Write-Host 'BROKER-permit: if MXC filter dominates filter 71655, same outcome'
Write-Host '(STATUS=000 + ECONNREFUSED). If filter 71655 wins, outcome would be a'
Write-Host 'silent drop -> WSAETIMEDOUT after 4s.'
