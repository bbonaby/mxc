# Tier 2 WFP arbitration AC<->AC test.
#
# Two wxc-exec invocations:
#   1. SERVER container: defaultPolicy=allow, runs ac-tcp-listener.exe
#      binding 127.0.0.1:19443. Must be allowed to listen.
#   2. CLIENT container: tries `curl http://127.0.0.1:19443`. Three
#      scenarios, each measuring connect outcome:
#         a) defaultPolicy=allow, no broker        -> baseline
#         b) defaultPolicy=block, no allowedHosts   -> broker blocks
#         c) defaultPolicy=block, allow 127.0.0.0/8 -> broker permits
#
# Filter 71655 is a system-origin block at ALE_AUTH_CONNECT for AC<->AC
# loopback. If our user-mode PERMITs dominate it, scenario (c) succeeds
# (HTTP 200). If 71655 wins, scenario (c) is a silent drop (timeout).

[CmdletBinding()]
param(
    [string] $WxcExec  = 'C:\mxc-rpc\wxc-exec.exe',
    [string] $Listener = 'C:\mxc-rpc\ac-tcp-listener.exe',
    [int]    $Port     = 19443
)

$ErrorActionPreference = 'Continue'

function New-ClientConfig {
    param([string]$Path, [string]$DefaultPolicy, [string[]]$AllowedHosts)
    $cfg = @{
        version          = '0.4.0-alpha'
        containerId      = 'ArbClient'
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
    if ($AllowedHosts) { $cfg.network.allowedHosts = $AllowedHosts }
    $cfg | ConvertTo-Json -Depth 6 | Set-Content -Path $Path -Encoding ascii
}

function New-ServerConfig {
    param([string]$Path)
    $cfg = @{
        version          = '0.4.0-alpha'
        containerId      = 'ArbServer'
        containment      = 'processcontainer'
        process          = @{
            commandLine = "$Listener $Port"
            cwd         = 'C:\mxc-rpc'
            timeout     = 30000
        }
        processContainer = @{ capabilities = @('internetClient', 'privateNetworkClientServer') }
        network          = @{ enforcementMode = 'firewall'; defaultPolicy = 'allow' }
        lifecycle        = @{ destroy_on_exit = $true }
    }
    $cfg | ConvertTo-Json -Depth 6 | Set-Content -Path $Path -Encoding ascii
}

$serverCfg   = 'C:\mxc-rpc\arb-server.json'
$baselineCfg = 'C:\mxc-rpc\arb-client-allow.json'
$blockedCfg  = 'C:\mxc-rpc\arb-client-block.json'
$permitCfg   = 'C:\mxc-rpc\arb-client-permit.json'

New-ServerConfig -Path $serverCfg
New-ClientConfig -Path $baselineCfg -DefaultPolicy 'allow' -AllowedHosts @()
New-ClientConfig -Path $blockedCfg  -DefaultPolicy 'block' -AllowedHosts @()
New-ClientConfig -Path $permitCfg   -DefaultPolicy 'block' -AllowedHosts @('127.0.0.0/8')

function Invoke-Scenario {
    param([string]$Label, [string]$ClientCfg)
    Write-Host "`n=== $Label ===" -ForegroundColor Cyan

    $serverJob = Start-Job -ScriptBlock {
        param($wxc, $cfg)
        & $wxc $cfg 2>&1
    } -ArgumentList $WxcExec, $serverCfg
    Start-Sleep -Milliseconds 600

    $sw = [Diagnostics.Stopwatch]::StartNew()
    $clientOut = & $WxcExec $ClientCfg 2>&1 | Out-String
    $sw.Stop()
    Write-Host "  client: $($clientOut.Trim())"
    Write-Host "  elapsed: $($sw.Elapsed.TotalSeconds.ToString('0.00'))s"

    Start-Sleep -Milliseconds 200
    Stop-Job $serverJob -ErrorAction SilentlyContinue
    $serverOut = Receive-Job $serverJob -ErrorAction SilentlyContinue
    Remove-Job $serverJob -Force -ErrorAction SilentlyContinue
    if ($serverOut) {
        Write-Host "  server: $($serverOut | Out-String).Trim()"
    }
}

Invoke-Scenario -Label 'A) default=allow, no broker (control)' -ClientCfg $baselineCfg
Invoke-Scenario -Label 'B) default=block, no allow (broker BLOCKS loopback)' -ClientCfg $blockedCfg
Invoke-Scenario -Label 'C) default=block + allow 127.0.0.0/8 (broker PERMITS loopback)' -ClientCfg $permitCfg

Write-Host ''
Write-Host '=== INTERPRETATION ===' -ForegroundColor Yellow
Write-Host 'A: should HTTP 200 if AC<->AC loopback is *not* blocked by 71655 here,'
Write-Host '   or fail with timeout if 71655 dominates by default.'
Write-Host 'B: broker installs Block-default + no overrides. SYN must be dropped.'
Write-Host '   Expect timeout / ECONNREFUSED depending on which layer drops it.'
Write-Host 'C: the empirical test for the open question. If MXC permit dominates'
Write-Host '   71655, expect HTTP 200. If 71655 dominates, expect timeout.'
