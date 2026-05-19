# ============================================================
# Invoke-PatchAudit.ps1
# Windows patch & vulnerability posture (Red Team view)
# ============================================================
# What it does:
#   - Lists installed hotfixes, age of latest patch
#   - Pending reboot detection
#   - WU service state + WU/WSUS policy (incl. HTTP WSUS = WSUSpect)
#   - Update history via COM Microsoft.Update.Session
#   - Hardcoded checklist of top exploited CVEs (late 2025 + 2026)
#     compared against last patch date → likely vulnerable / patched
#   - .NET Framework / .NET 5+ versions
#
# Usage:
#   .\Invoke-PatchAudit.ps1
#   .\Invoke-PatchAudit.ps1 -NoUpdateHistory   # skip COM (slow)
#   .\Invoke-PatchAudit.ps1 -NoPendingCheck    # skip WU online search
# ============================================================

[CmdletBinding()]
param(
    [switch]$NoUpdateHistory,
    [switch]$NoPendingCheck
)

# --- Helpers ---
function Write-Section($t) {
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor DarkCyan
    Write-Host "  $t" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor DarkCyan
}
function Write-Sub($t)   { Write-Host ""; Write-Host "  --- $t ---" -ForegroundColor Magenta }
function Write-KV($k,$v,$c='White') {
    Write-Host ("  {0,-32}" -f $k) -ForegroundColor Gray -NoNewline
    Write-Host $v -ForegroundColor $c
}
function Write-Good($m) { Write-Host "  [+] $m" -ForegroundColor Green }
function Write-Bad($m)  { Write-Host "  [-] $m" -ForegroundColor Red }
function Write-Warn($m) { Write-Host "  [!] $m" -ForegroundColor Yellow }
function Write-Info($m) { Write-Host "  [*] $m" -ForegroundColor DarkGray }

$findings = New-Object System.Collections.Generic.List[string]

Write-Section "WINDOWS PATCH & VULNERABILITY AUDIT"

# ============================================================
# [1] INSTALLED HOTFIXES + LAST PATCH AGE
# ============================================================
Write-Sub "[1] Installed hotfixes"
$lastPatchDate = $null
try {
    $hf = Get-HotFix -EA Stop | Sort-Object InstalledOn -Descending
    Write-KV "Total hotfixes (Get-HotFix)" $hf.Count
    Write-Host ""
    Write-Host "  Most recent 10:" -ForegroundColor Gray
    $hf | Select-Object -First 10 | ForEach-Object {
        Write-Host ("    {0,-12} {1,-14} {2}" -f $_.HotFixID, $_.Description, $_.InstalledOn)
    }
    # Resolve last patch date (DateTime, not localized string)
    $lastHF = $hf | Where-Object { $_.InstalledOn } | Select-Object -First 1
    if ($lastHF) {
        # InstalledOn may come as string depending on culture
        if ($lastHF.InstalledOn -is [datetime]) {
            $lastPatchDate = $lastHF.InstalledOn
        } else {
            try { $lastPatchDate = [datetime]::Parse($lastHF.InstalledOn) } catch {}
        }
    }
} catch { Write-Info "Get-HotFix failed: $_" }

if ($lastPatchDate) {
    $age = ((Get-Date) - $lastPatchDate).Days
    $col = if ($age -gt 60) {'Red'} elseif ($age -gt 30) {'Yellow'} else {'Green'}
    Write-Host ""
    Write-KV "Last patch installed" "$($lastPatchDate.ToString('yyyy-MM-dd')) ($age days ago)" $col
    if ($age -gt 60) { $findings.Add("Last patch $age days old — likely unpatched against recent CVEs") }
}

# ============================================================
# [2] PENDING REBOOT
# ============================================================
Write-Sub "[2] Pending reboot"
$pending = $false; $reasons = @()
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $pending=$true; $reasons+='CBS' }
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $pending=$true; $reasons+='WU' }
try {
    $pfr = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -EA SilentlyContinue).PendingFileRenameOperations
    if ($pfr) { $pending=$true; $reasons+='PendingRename' }
} catch {}
if ($pending) {
    Write-Warn "Reboot pending ($($reasons -join ', '))"
    Write-Info "After reboot, host applies queued patches → your foothold may evaporate"
    $findings.Add("Reboot pending — patches queued, get persistence or hurry")
} else { Write-Good "No reboot pending" }

# ============================================================
# [3] WU SERVICES
# ============================================================
Write-Sub "[3] Windows Update services"
$wuSvcs = @('wuauserv','BITS','UsoSvc','WaaSMedicSvc','TrustedInstaller')
foreach ($s in $wuSvcs) {
    try {
        $svc = Get-Service $s -EA Stop
        $col = if ($svc.Status -eq 'Running') {'Green'} elseif ($svc.StartType -eq 'Disabled') {'Red'} else {'Yellow'}
        Write-KV $s "$($svc.Status) ($($svc.StartType))" $col
        if ($svc.StartType -eq 'Disabled' -and $s -eq 'wuauserv') {
            $findings.Add("wuauserv DISABLED — host doesn't receive Windows updates")
        }
    } catch { Write-KV $s "Not installed" 'DarkGray' }
}

# ============================================================
# [4] WU / WSUS POLICY (huge red team angle)
# ============================================================
Write-Sub "[4] WU / WSUS policy"
try {
    $wu = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -EA SilentlyContinue
    $au = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -EA SilentlyContinue
    if ($wu) {
        Write-KV "WUServer"        $wu.WUServer
        Write-KV "WUStatusServer"  $wu.WUStatusServer
        Write-KV "TargetGroup"     $wu.TargetGroup
        if ($wu.WUServer -match '^http://') {
            Write-Bad "WSUS over HTTP detected → WSUSpect candidate (MITM update injection)"
            $findings.Add("WSUS server uses HTTP ($($wu.WUServer)) — vulnerable to WSUSpect")
        }
        if ($wu.DeferFeatureUpdatesPeriodInDays)  { Write-KV "DeferFeatureUpdates"  "$($wu.DeferFeatureUpdatesPeriodInDays) days" 'Yellow' }
        if ($wu.DeferQualityUpdatesPeriodInDays)  { Write-KV "DeferQualityUpdates"  "$($wu.DeferQualityUpdatesPeriodInDays) days" 'Yellow' }
        if ($wu.PauseQualityUpdatesStartTime)     { Write-KV "PauseQualityUpdates" $wu.PauseQualityUpdatesStartTime 'Red' }
    } else { Write-Info "No WindowsUpdate GPO key — using Microsoft Update directly" }
    if ($au) {
        $auMap = @{2='Notify download';3='Auto download, notify install';4='Auto download and install';5='Allow user choice'}
        Write-KV "AUOptions" ("{0} ({1})" -f $au.AUOptions, $auMap[[int]$au.AUOptions])
        Write-KV "NoAutoUpdate" $au.NoAutoUpdate ($(if ($au.NoAutoUpdate -eq 1) {'Red'} else {'Green'}))
        if ($au.NoAutoUpdate -eq 1) { $findings.Add("NoAutoUpdate=1 — auto-updates disabled by policy") }
    }
} catch { Write-Info "WU policy keys not readable" }

# ============================================================
# [5] UPDATE HISTORY (COM Microsoft.Update.Session)
# ============================================================
if (-not $NoUpdateHistory) {
    Write-Sub "[5] Update history (COM Microsoft.Update.Session)"
    try {
        $session  = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $count    = $searcher.GetTotalHistoryCount()
        if ($count -gt 0) {
            $take = [Math]::Min(25, $count)
            $hist = $searcher.QueryHistory(0, $take)
            $resultMap = @{0='NotStarted';1='InProgress';2='Succeeded';3='SucceededWErr';4='FAILED';5='Aborted'}
            $opMap     = @{1='Install';2='Uninstall'}
            $succ = 0; $fail = 0
            Write-Host "  Last $take entries:" -ForegroundColor Gray
            foreach ($e in $hist) {
                $r = $resultMap[[int]$e.ResultCode]
                $o = $opMap[[int]$e.Operation]
                $col = switch ($e.ResultCode) { 2{'DarkGray'} 4{'Red'} 5{'Red'} default{'Yellow'} }
                if ($e.ResultCode -eq 2) { $succ++ } else { $fail++ }
                $title = if ($e.Title.Length -gt 80) { $e.Title.Substring(0,80) + '…' } else { $e.Title }
                Write-Host ("    {0:yyyy-MM-dd}  {1,-12}  {2,-9}  {3}" -f $e.Date, $r, $o, $title) -ForegroundColor $col
            }
            Write-Host ""
            Write-KV "Success / Failed (recent $take)" "$succ / $fail" ($(if ($fail -gt 5) {'Red'} else {'White'}))
            if ($fail -gt 5) { $findings.Add("$fail failed/aborted updates recently — patching is broken on this host") }
            # Most recent succeeded install date
            $lastOk = $hist | Where-Object { $_.ResultCode -eq 2 -and $_.Operation -eq 1 } | Sort-Object Date -Descending | Select-Object -First 1
            if ($lastOk) {
                Write-KV "Most recent successful install" $lastOk.Date.ToString('yyyy-MM-dd')
                # Override last patch date if newer than Get-HotFix
                if (-not $lastPatchDate -or $lastOk.Date -gt $lastPatchDate) { $lastPatchDate = $lastOk.Date }
            }
        }
    } catch { Write-Info "COM update history failed: $_" }
} else { Write-Info "Update history skipped (-NoUpdateHistory)" }

# ============================================================
# [6] PENDING UPDATES (COM search — hits WU/WSUS)
# ============================================================
if (-not $NoPendingCheck) {
    Write-Sub "[6] Pending updates (queries WU/WSUS — network call)"
    try {
        if (-not $session)  { $session  = New-Object -ComObject Microsoft.Update.Session }
        if (-not $searcher) { $searcher = $session.CreateUpdateSearcher() }
        $res = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
        if ($res.Updates.Count -gt 0) {
            Write-Warn "$($res.Updates.Count) pending updates:"
            foreach ($u in $res.Updates) {
                $sev = $u.MsrcSeverity
                $col = switch ($sev) { 'Critical'{'Red'} 'Important'{'Yellow'} default{'White'} }
                $kbs = ($u.KBArticleIDs | ForEach-Object { "KB$_" }) -join ','
                $title = if ($u.Title.Length -gt 80) { $u.Title.Substring(0,80)+'…' } else { $u.Title }
                Write-Host ("    [{0,-9}] {1}  {2}" -f $sev, $kbs, $title) -ForegroundColor $col
            }
            $findings.Add("$($res.Updates.Count) updates pending install")
        } else { Write-Good "No pending updates" }
    } catch { Write-Info "Pending check failed (no network / WSUS down?): $_" }
} else { Write-Info "Pending check skipped (-NoPendingCheck)" }

# ============================================================
# [7] CVE CHECKLIST — top exploited 2025/2026
# ============================================================
Write-Sub "[7] CVE checklist (top exploited 2025-2026)"

# Hardcoded list. PatchMonth = 'YYYY-MM' when Microsoft released the fix.
# Heuristic: if the host's last successful patch date >= end of PatchMonth,
# the host is likely patched against this CVE.
$KnownCVEs = @(
    [PSCustomObject]@{ CVE='CVE-2025-59230'; PatchMonth='2025-10'; Component='RasMan';                                   Type='LPE→SYSTEM';   Notes='Zero-day, CISA KEV. RasMan service abuse.' }
    [PSCustomObject]@{ CVE='CVE-2025-24990'; PatchMonth='2025-10'; Component='Agere Modem ltmdm64.sys';                   Type='LPE→Admin';    Notes='Zero-day, CISA KEV. MS removed driver entirely.' }
    [PSCustomObject]@{ CVE='CVE-2025-59287'; PatchMonth='2025-10'; Component='WSUS server';                               Type='RCE unauth';    Notes='Wormable between WSUS hosts. If host IS WSUS server.' }
    [PSCustomObject]@{ CVE='CVE-2025-62215'; PatchMonth='2025-11'; Component='Windows Kernel race condition';             Type='LPE→SYSTEM';   Notes='Zero-day, in the wild.' }
    [PSCustomObject]@{ CVE='CVE-2025-60710'; PatchMonth='2025-11'; Component='Host Process for Windows Tasks';            Type='LPE→SYSTEM';   Notes='Link-following. Added to CISA KEV Apr 2026.' }
    [PSCustomObject]@{ CVE='CVE-2025-62221'; PatchMonth='2025-12'; Component='Cloud Files Mini Filter Driver';            Type='LPE→SYSTEM';   Notes='Zero-day, CISA KEV. Driver always present.' }
    [PSCustomObject]@{ CVE='CVE-2025-62458'; PatchMonth='2025-12'; Component='Win32k';                                    Type='LPE→SYSTEM';   Notes='“Exploitation More Likely”. 9th Win32k LPE of 2025.' }
    [PSCustomObject]@{ CVE='CVE-2025-54100'; PatchMonth='2025-12'; Component='PowerShell URL parsing';                    Type='RCE';           Notes='Social-eng vector; needs user to run PS snippet.' }
    [PSCustomObject]@{ CVE='CVE-2026-21510'; PatchMonth='2026-02'; Component='Windows Shell / SmartScreen';               Type='SFB';           Notes='Zero-day, CISA KEV. Bypass MoTW prompts.' }
    [PSCustomObject]@{ CVE='CVE-2026-21513'; PatchMonth='2026-02'; Component='MSHTML Framework';                          Type='SFB';           Notes='Zero-day, CISA KEV. Phishing payload delivery.' }
    [PSCustomObject]@{ CVE='CVE-2026-21514'; PatchMonth='2026-02'; Component='Microsoft Word';                            Type='SFB';           Notes='Zero-day, CISA KEV. Document-based.' }
    [PSCustomObject]@{ CVE='CVE-2026-21519'; PatchMonth='2026-02'; Component='Desktop Window Manager (DWM)';              Type='LPE→SYSTEM';   Notes='Zero-day, CISA KEV. Type confusion.' }
    [PSCustomObject]@{ CVE='CVE-2026-21533'; PatchMonth='2026-02'; Component='Remote Desktop Services';                   Type='LPE';           Notes='Zero-day, CISA KEV.' }
    [PSCustomObject]@{ CVE='CVE-2026-32201'; PatchMonth='2026-04'; Component='SharePoint Server';                         Type='Spoofing';      Notes='Zero-day, exploited. If host IS SharePoint.' }
    [PSCustomObject]@{ CVE='CVE-2026-33825'; PatchMonth='2026-04'; Component='Microsoft Defender (BlueHammer)';           Type='LPE→SYSTEM';   Notes='Pub disclosed before patch. PoC available.' }
)

Write-Host ""
Write-Host "  Verdict logic: if last installed patch ≥ end of patch month → assumed patched." -ForegroundColor DarkGray
Write-Host "                  Otherwise → likely VULNERABLE (operator should confirm)." -ForegroundColor DarkGray
Write-Host ""

$vulnCount = 0
foreach ($cve in $KnownCVEs) {
    $patchMonthStart = [datetime]::ParseExact($cve.PatchMonth + '-01','yyyy-MM-dd',$null)
    $patchMonthEnd   = $patchMonthStart.AddMonths(1).AddDays(-1)
    if (-not $lastPatchDate) {
        $verdict = 'UNKNOWN'; $col = 'DarkGray'
    } elseif ($lastPatchDate -ge $patchMonthEnd) {
        $verdict = 'patched'; $col = 'DarkGray'
    } else {
        $verdict = 'VULNERABLE'; $col = 'Red'; $vulnCount++
    }
    Write-Host ("    {0,-16} [{1,-10}] {2,-7} {3}" -f $cve.CVE, $verdict, $cve.Type, $cve.Component) -ForegroundColor $col
    if ($verdict -eq 'VULNERABLE') {
        Write-Host ("        → $($cve.Notes)") -ForegroundColor Yellow
    }
}
if ($vulnCount -gt 0) { $findings.Add("$vulnCount known-exploited CVEs likely NOT patched") }

# ============================================================
# [8] .NET versions installed
# ============================================================
Write-Sub "[8] .NET versions"
# .NET Framework 4.x
try {
    $rel = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -EA Stop).Release
    $netVer = switch ($rel) {
        {$_ -ge 533320} { '4.8.1' ; break }
        {$_ -ge 528040} { '4.8'   ; break }
        {$_ -ge 461808} { '4.7.2' ; break }
        {$_ -ge 461308} { '4.7.1' ; break }
        {$_ -ge 460798} { '4.7'   ; break }
        {$_ -ge 394802} { '4.6.2' ; break }
        {$_ -ge 393295} { '4.6'   ; break }
        {$_ -ge 379893} { '4.5.2' ; break }
        default         { "<4.5.2 (release=$rel)" }
    }
    $col = if ($netVer -match '^4\.[78]') {'Green'} else {'Yellow'}
    Write-KV ".NET Framework 4.x" "$netVer (release $rel)" $col
    Write-Info ".NET 4.8+ supports AMSI on assembly load + CLR ETW provider"
} catch { Write-Info ".NET Framework 4.x not detected" }

# .NET 5+ (Core)
try {
    $dn = Get-ChildItem 'HKLM:\SOFTWARE\dotnet\Setup\InstalledVersions' -EA Stop
    foreach ($arch in $dn) {
        $sharedHost = Get-ItemProperty (Join-Path $arch.PSPath 'sharedhost') -EA SilentlyContinue
        if ($sharedHost.Version) {
            Write-KV "  .NET ($($arch.PSChildName))" $sharedHost.Version 'White'
        }
    }
} catch { Write-Info ".NET 5+ runtime not detected via registry" }

# pwsh / dotnet CLI presence
foreach ($exe in 'dotnet','pwsh') {
    $p = Get-Command $exe -EA SilentlyContinue
    if ($p) { Write-KV "$exe.exe" $p.Source 'Yellow' }
}

# ============================================================
# SUMMARY
# ============================================================
Write-Host ""
Write-Host ("=" * 60) -ForegroundColor DarkYellow
Write-Host "  PATCH AUDIT FINDINGS" -ForegroundColor Yellow
Write-Host ("=" * 60) -ForegroundColor DarkYellow
if ($findings.Count -eq 0) {
    Write-Host "  (no notable findings — host appears well patched)" -ForegroundColor DarkGray
} else {
    $i = 1
    foreach ($f in $findings) {
        Write-Host ("  [{0:D2}] {1}" -f $i, $f) -ForegroundColor Yellow
        $i++
    }
}
Write-Host ""
