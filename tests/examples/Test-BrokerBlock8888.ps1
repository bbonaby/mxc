# Tier 2 end-to-end: PowerShell driver + wxc-exec + mxc-net broker
#
# 1. Pre-create AppContainer profile "MxcBlock8888Test" and derive its SID.
# 2. Call mxc-net add via the §4.1 restricted-LocalService broker to install
#    a WFP block:any:8.8.8.8 filter bound to that SID.
# 3. Launch ping (8.8.8.8 then 1.1.1.1) inside the AC via wxc-exec.exe.
# 4. Expected: ping 8.8.8.8 -> blocked, ping 1.1.1.1 -> reply.
# 5. Cleanup: mxc-net remove + delete AC profile.
#
# Must run elevated.

$ErrorActionPreference = 'Stop'
$root = 'C:\test\mxc-tier2\extracted'
$wxc  = Join-Path $root 'wxc-exec.exe'
$net  = 'C:\Program Files\Microsoft\MXC Service\mxc-net.exe'
$cfg  = Join-Path $root 'block_8888_broker.json'
$containerName = 'MxcBlock8888Test'

foreach ($p in @($wxc, $net, $cfg)) {
    if (-not (Test-Path $p)) { throw "missing: $p" }
}

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class AC {
    [DllImport("userenv.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern int DeriveAppContainerSidFromAppContainerName(
        string name, out IntPtr sid);
    [DllImport("userenv.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern int CreateAppContainerProfile(
        string name, string display, string desc,
        IntPtr caps, int capCount, out IntPtr sid);
    [DllImport("userenv.dll", CharSet=CharSet.Unicode)]
    public static extern int DeleteAppContainerProfile(string name);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool ConvertSidToStringSidW(IntPtr sid, out IntPtr stringSid);
    [DllImport("kernel32.dll")]
    public static extern IntPtr LocalFree(IntPtr p);
    [DllImport("advapi32.dll")]
    public static extern IntPtr FreeSid(IntPtr sid);
}
'@ -ErrorAction SilentlyContinue

function Get-AcSidString([string]$name) {
    $sidPtr = [IntPtr]::Zero
    $hr = [AC]::CreateAppContainerProfile($name, $name, "MXC tier 2 block test", [IntPtr]::Zero, 0, [ref]$sidPtr)
    if ($hr -ne 0 -and $sidPtr -eq [IntPtr]::Zero) {
        $hr = [AC]::DeriveAppContainerSidFromAppContainerName($name, [ref]$sidPtr)
        if ($hr -ne 0) { throw "Derive failed: 0x$($hr.ToString('X8'))" }
    }
    try {
        $strPtr = [IntPtr]::Zero
        if (-not [AC]::ConvertSidToStringSidW($sidPtr, [ref]$strPtr)) {
            throw "ConvertSidToStringSidW failed"
        }
        try   { return [Runtime.InteropServices.Marshal]::PtrToStringUni($strPtr) }
        finally { [AC]::LocalFree($strPtr) | Out-Null }
    } finally { [AC]::FreeSid($sidPtr) | Out-Null }
}

Write-Host "=== 1. Derive AppContainer SID for '$containerName' ==="
$sid = Get-AcSidString $containerName
Write-Host "    SID = $sid"

Write-Host ""
Write-Host "=== 2. Install broker WFP block via mxc-net (via restricted-LocalService) ==="
$addOut = & $net --json add $sid --default allow --rule 'block:any:8.8.8.8::' 2>&1
Write-Host $addOut
$policyId = $null
try {
    $parsed = $addOut | ConvertFrom-Json
    $policyId = $parsed.policy_id
} catch { }
if (-not $policyId) { Write-Host "    (couldn't parse policy_id; cleanup will be best-effort)" }
else { Write-Host "    policy_id = $policyId" }

Write-Host ""
Write-Host "=== 3a. Launch ping 8.8.8.8 in AC (broker BLOCKS) ==="
try {
    & $wxc $cfg
    Write-Host "[wxc-exec ping-8888 exit: $LASTEXITCODE]"

    Write-Host ""
    Write-Host "=== 3b. Launch ping 1.1.1.1 in AC (broker ALLOWS) ==="
    # Patch the JSON in place for the second target
    $tmpCfg = Join-Path $env:TEMP 'block_8888_broker_1111.json'
    (Get-Content $cfg -Raw).Replace('http://8.8.8.8', 'http://1.1.1.1') | Set-Content $tmpCfg
    & $wxc $tmpCfg
    Write-Host "[wxc-exec ping-1111 exit: $LASTEXITCODE]"
    Remove-Item $tmpCfg -ErrorAction SilentlyContinue
} finally {
    Write-Host ""
    Write-Host "=== 4. Cleanup ==="
    if ($policyId) {
        & $net remove $policyId 2>&1 | Write-Host
    }
    [AC]::DeleteAppContainerProfile($containerName) | Out-Null
    Write-Host "    profile '$containerName' deleted"
}
