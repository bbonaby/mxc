# Tier 2 end-to-end test using only wxc-exec + mxc-service + mxc-diagnostic-console.
#
# Validates the §4 broker path with NO mxc-net.exe step: wxc-exec discovers the
# broker via the network manager, marshals blockedHosts through the IPC pipe, and
# the service installs WFP filters scoped to the AppContainer SID.
#
# Recommended layout: run mxc-diagnostic-console.exe in another elevated window
# first; this script's output will appear there too (broker emits via the diag
# pipe). Then run this script (does NOT need elevation; wxc-exec runs as the
# user, the broker does the privileged work).

[CmdletBinding()]
param(
    [string] $WxcExec    = (Join-Path $PSScriptRoot '..\..\extracted\wxc-exec.exe' | Resolve-Path -ErrorAction SilentlyContinue),
    [string] $ConfigDir  = $PSScriptRoot,
    [string] $TargetHost = '8.8.8.8',
    [string] $ControlHost = '1.1.1.1'
)

if (-not $WxcExec -or -not (Test-Path $WxcExec)) {
    $WxcExec = Read-Host 'Path to wxc-exec.exe'
}

function Invoke-WxcCurl {
    param([string]$ConfigPath, [string]$Label)
    Write-Host "`n=== $Label ===" -ForegroundColor Cyan
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    & $WxcExec $ConfigPath 2>&1 | Out-String | ForEach-Object { $_.TrimEnd() } | Write-Host
    $sw.Stop()
    Write-Host "elapsed: $($sw.Elapsed.TotalSeconds.ToString('0.00'))s" -ForegroundColor DarkGray
}

# Two configs that share defaultPolicy=allow + enforcementMode=firewall.
# Difference: one has blockedHosts:[$TargetHost], the other has no host list.
# The broker path is only triggered when host lists are non-empty.

$blockCfg   = Join-Path $ConfigDir 'block_8888_hostlist.json'
$controlCfg = Join-Path $ConfigDir 'curl_1111_baseline.json'

if (-not (Test-Path $controlCfg)) {
    @{
        version          = '0.4.0-alpha'
        containerId      = 'MxcBrokerControlTest'
        containment      = 'processcontainer'
        process          = @{
            commandLine = "curl.exe --max-time 5 -sS -o NUL -w HTTP=%{http_code}_TIME=%{time_total}_ERR=%{errormsg} http://$ControlHost"
            cwd         = 'C:\Windows'
            timeout     = 30000
        }
        processContainer = @{ capabilities = @('internetClient') }
        network          = @{ enforcementMode = 'firewall'; defaultPolicy = 'allow' }
        lifecycle        = @{ destroy_on_exit = $true }
    } | ConvertTo-Json -Depth 6 | Set-Content -Path $controlCfg -Encoding ascii
}

Invoke-WxcCurl -ConfigPath $controlCfg -Label "CONTROL: curl http://$ControlHost (no host list - direct curl)"
Invoke-WxcCurl -ConfigPath $blockCfg   -Label "BLOCKED: curl http://$TargetHost (broker installs WFP block via blockedHosts)"

Write-Host ''
Write-Host 'Look at mxc-diagnostic-console for broker events: AddPolicy / filters_installed / RemovePolicy.' -ForegroundColor Yellow
