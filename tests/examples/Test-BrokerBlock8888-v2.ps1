$ErrorActionPreference = 'Continue'
$root = 'C:\test\mxc-tier2\extracted'
$wxc  = Join-Path $root 'wxc-exec.exe'
$net  = 'C:\Program Files\Microsoft\MXC Service\mxc-net.exe'
$cfg8 = Join-Path $root 'block_8888_broker.json'
$cfg1 = Join-Path $root 'block_8888_broker_1111.json'
$containerName = 'MxcBlock8888Test'

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class AC2 {
    [DllImport("userenv.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern int DeriveAppContainerSidFromAppContainerName(string name, out IntPtr sid);
    [DllImport("userenv.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern int CreateAppContainerProfile(string name, string display, string desc, IntPtr caps, int capCount, out IntPtr sid);
    [DllImport("userenv.dll", CharSet=CharSet.Unicode)]
    public static extern int DeleteAppContainerProfile(string name);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool ConvertSidToStringSidW(IntPtr sid, out IntPtr stringSid);
    [DllImport("kernel32.dll")] public static extern IntPtr LocalFree(IntPtr p);
    [DllImport("advapi32.dll")] public static extern IntPtr FreeSid(IntPtr sid);
}
'@ -ErrorAction SilentlyContinue

$sidPtr = [IntPtr]::Zero
$null = [AC2]::CreateAppContainerProfile($containerName, $containerName, "tier2 test", [IntPtr]::Zero, 0, [ref]$sidPtr)
if ($sidPtr -eq [IntPtr]::Zero) {
    $null = [AC2]::DeriveAppContainerSidFromAppContainerName($containerName, [ref]$sidPtr)
}
$strPtr = [IntPtr]::Zero
[void][AC2]::ConvertSidToStringSidW($sidPtr, [ref]$strPtr)
$sid = [Runtime.InteropServices.Marshal]::PtrToStringUni($strPtr)
[AC2]::LocalFree($strPtr) | Out-Null
[AC2]::FreeSid($sidPtr) | Out-Null
Write-Host "AC SID: $sid"
Write-Host ""

# Step A: NO broker filter -- curl both should work
Write-Host "============================================================"
Write-Host "A. BASELINE (no broker filter): expect both 1.1.1.1 + 8.8.8.8 reachable"
Write-Host "============================================================"
Write-Host "[curl 1.1.1.1 from AC]"
$out = & $wxc $cfg1 2>&1 | Out-String
Write-Host $out.Trim()
Write-Host "[curl 8.8.8.8 from AC]"
$out = & $wxc $cfg8 2>&1 | Out-String
Write-Host $out.Trim()
Write-Host ""

# Step B: install broker block for 8.8.8.8 -- expect only 1.1.1.1 reachable
Write-Host "============================================================"
Write-Host "B. WITH broker block:8.8.8.8 -- expect 1.1.1.1 OK, 8.8.8.8 BLOCKED"
Write-Host "============================================================"
$addOut = & $net --json add $sid --default allow --rule 'block:any:8.8.8.8::' 2>&1 | Out-String
Write-Host "mxc-net add: $($addOut.Trim())"
$policyId = $null
try { $policyId = ($addOut | ConvertFrom-Json).policy_id } catch {}
try {
    Write-Host "[curl 1.1.1.1 from AC]"
    $out = & $wxc $cfg1 2>&1 | Out-String
    Write-Host $out.Trim()
    Write-Host "[curl 8.8.8.8 from AC]"
    $out = & $wxc $cfg8 2>&1 | Out-String
    Write-Host $out.Trim()
} finally {
    Write-Host ""
    Write-Host "Cleanup:"
    if ($policyId) { & $net remove $policyId 2>&1 | Out-String | Write-Host }
    [AC2]::DeleteAppContainerProfile($containerName) | Out-Null
    Write-Host "  profile '$containerName' deleted"
}
