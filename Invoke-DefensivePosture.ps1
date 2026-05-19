# ============================================================
# [MODULE 4] Detection / Logging / Identity Posture (Red Team)
# Version: 2.0
#   - Console (color) + structured object output (pipeable)
#   - I18N-safe auditpol via subcategory GUIDs
#   - I18N-safe cmdkey parsing
#   - Tamper Protection via Get-MpComputerStatus
#   - Full coverage restored (spooler, WSH, DPAPI, .cip, etc.)
# Usage:
#   .\Invoke-DefensivePosture.ps1                       # console output, returns object
#   .\Invoke-DefensivePosture.ps1 | ConvertTo-Json -Depth 6 > posture.json
#   $r = .\Invoke-DefensivePosture.ps1 ; $r.HighValueFindings
# ============================================================

# --- Estado global ---
$script:ReportData = [ordered]@{
    ScanTime          = (Get-Date -Format 'o')
    Hostname          = $env:COMPUTERNAME
    User              = "$env:USERDOMAIN\$env:USERNAME"
    PrivilegeLevel    = $null
    Sections          = [ordered]@{}
    HighValueFindings = New-Object System.Collections.Generic.List[string]
}
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$IsSystem = ([Security.Principal.WindowsIdentity]::GetCurrent()).IsSystem
$script:ReportData.PrivilegeLevel = if ($IsSystem) {'SYSTEM'} elseif ($IsAdmin) {'ADMIN'} else {'USER'}

# --- Helpers ---
function Write-Section($t) {
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor DarkCyan
    Write-Host "  $t"     -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor DarkCyan
}
function Write-Sub($t)  { Write-Host ""; Write-Host "  --- $t ---" -ForegroundColor Magenta }
function Write-Good($m) { Write-Host "  [+] $m" -ForegroundColor Green }
function Write-Bad($m)  { Write-Host "  [-] $m" -ForegroundColor Red }
function Write-Warn($m) { Write-Host "  [!] $m" -ForegroundColor Yellow }
function Write-Info($m) { Write-Host "  [*] $m" -ForegroundColor DarkGray }

function Save-Data {
    param([string]$Section, [string]$Key, $Value)
    if (-not $script:ReportData.Sections.Contains($Section)) {
        $script:ReportData.Sections[$Section] = [ordered]@{}
    }
    $script:ReportData.Sections[$Section][$Key] = $Value
}
# Imprime K:V y guarda en el objeto
function Show-KV {
    param([string]$Section, [string]$Key, $Value, [string]$Color = 'White')
    Save-Data $Section $Key $Value
    Write-Host ("  {0,-38} " -f $Key) -ForegroundColor Gray -NoNewline
    Write-Host $Value -ForegroundColor $Color
}
function Add-Finding([string]$Text) {
    [void]$script:ReportData.HighValueFindings.Add($Text)
}

# --- I18N: detectar "no auditado" en varios idiomas ---
$NoAuditPatterns = @(
    'No Auditing','Sin auditor','Pas d''audit','Keine Über','Nessun audit',
    'Não auditad','감사 안 함','監査なし','审核','审计','Ingen overvågning'
)
function Test-AuditOn([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    foreach ($p in $NoAuditPatterns) { if ($Value -like "*$p*") { return $false } }
    return $true
}

Write-Section "DETECTION / LOGGING / IDENTITY POSTURE"
Write-Info "Privilege: $($script:ReportData.PrivilegeLevel)$(if (-not $IsAdmin) {' — some checks will be skipped'})"

# ============================================================
# [1/12] SYSMON
# ============================================================
Write-Sub "[1/12] Sysmon"
$sysmonFound = $false
$sysmonInfo = @()
$svcRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services'
foreach ($name in @('Sysmon','Sysmon64','SysmonDrv')) {
    if (Test-Path "$svcRoot\$name") {
        $sysmonFound = $true
        $data  = Get-ItemProperty "$svcRoot\$name" -EA SilentlyContinue
        $state = (Get-Service $name -EA SilentlyContinue).Status
        Show-KV 'Sysmon' "Service[$name]" "$state  path=$($data.ImagePath)" 'Yellow'
        $sysmonInfo += [PSCustomObject]@{ Name=$name; State="$state"; Path=$data.ImagePath }
    }
}
# Sysmon renombrado: driver con altitude 385201
try {
    $altHits = Get-ChildItem $svcRoot -EA SilentlyContinue | ForEach-Object {
        $p = Join-Path $_.PSPath 'Instances'
        if (Test-Path $p) {
            $def = (Get-ItemProperty $p -EA SilentlyContinue).DefaultInstance
            if ($def) {
                $alt = (Get-ItemProperty (Join-Path $p $def) -EA SilentlyContinue).Altitude
                if ($alt -eq '385201') { $_.PSChildName }
            }
        }
    }
    if ($altHits) {
        $sysmonFound = $true
        foreach ($h in $altHits) { Write-Warn "Possible renamed Sysmon driver: $h (altitude 385201)" }
        Save-Data 'Sysmon' 'RenamedDriverCandidates' $altHits
    }
} catch {}

Save-Data 'Sysmon' 'Detected' $sysmonFound
Save-Data 'Sysmon' 'Services' $sysmonInfo
if ($sysmonFound) {
    Add-Finding 'Sysmon present — assume cmdline, hashes, network connects and image-loads are logged'
    if ($IsAdmin) {
        try {
            $cfg = Get-ItemProperty "$svcRoot\SysmonDrv\Parameters" -EA Stop
            if ($cfg.ConfigHash) { Show-KV 'Sysmon' 'ConfigHash' $cfg.ConfigHash 'Yellow' }
            if ($cfg.Rules)      { Show-KV 'Sysmon' 'RulesBlobBytes' $cfg.Rules.Length 'Yellow' }
        } catch {}
    }
} else { Write-Good "No Sysmon service/driver detected" }

# ============================================================
# [2/12] AUDIT POLICY (vía GUIDs — locale-independent)
# ============================================================
Write-Sub "[2/12] Audit Policy"

# Command-line en 4688 (registry, locale-independent)
try {
    $cmdAudit = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -EA Stop).ProcessCreationIncludeCmdLine_Enabled
    $val = [int]$cmdAudit
    Show-KV 'AuditPolicy' 'ProcessCreationCmdline_4688' $val ($(if ($val -eq 1) {'Red'} else {'Green'}))
    if ($val -eq 1) { Add-Finding '4688 includes command line — every process exec logs full cmdline' }
} catch { Show-KV 'AuditPolicy' 'ProcessCreationCmdline_4688' 'Not configured' 'Green' }

# Force advanced audit policy
try {
    $force = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -EA Stop).SCENoApplyLegacyAuditPolicy
    Show-KV 'AuditPolicy' 'ForceAdvancedAuditPolicy' ([int]$force)
} catch {}

# Subcategorías clave por GUID (mismo en cualquier idioma)
$auditSubcats = [ordered]@{
    'ProcessCreation'                    = '{0CCE922B-69AE-11D9-BED3-505054503030}'
    'ProcessTermination'                 = '{0CCE922C-69AE-11D9-BED3-505054503030}'
    'Logon'                              = '{0CCE9215-69AE-11D9-BED3-505054503030}'
    'Logoff'                             = '{0CCE9216-69AE-11D9-BED3-505054503030}'
    'SpecialLogon'                       = '{0CCE921B-69AE-11D9-BED3-505054503030}'
    'SensitivePrivilegeUse'              = '{0CCE9228-69AE-11D9-BED3-505054503030}'
    'CredentialValidation'               = '{0CCE923F-69AE-11D9-BED3-505054503030}'
    'KerberosAuthenticationService'      = '{0CCE9242-69AE-11D9-BED3-505054503030}'
    'KerberosServiceTicketOperations'    = '{0CCE9240-69AE-11D9-BED3-505054503030}'
    'OtherObjectAccessEvents'            = '{0CCE9227-69AE-11D9-BED3-505054503030}'
    'FileSystem'                         = '{0CCE921D-69AE-11D9-BED3-505054503030}'
    'Registry'                           = '{0CCE921E-69AE-11D9-BED3-505054503030}'
    'AuditPolicyChange'                  = '{0CCE922F-69AE-11D9-BED3-505054503030}'
    'AuthenticationPolicyChange'         = '{0CCE9230-69AE-11D9-BED3-505054503030}'
}
if ($IsAdmin) {
    $subResults = [ordered]@{}
    foreach ($kv in $auditSubcats.GetEnumerator()) {
        try {
            # /r → CSV; saltar header localizado y forzar nombres de columna
            $csv = (auditpol /get /subcategory:"$($kv.Value)" /r 2>$null) |
                Select-Object -Skip 1 |
                ConvertFrom-Csv -Header 'm','t','sc','scg','inc','exc'
            $inclusion = ($csv | Select-Object -First 1).inc
            $on = Test-AuditOn $inclusion
            $subResults[$kv.Key] = @{ Raw = $inclusion; Audited = $on }
            $color = if ($on) { 'Yellow' } else { 'DarkGray' }
            Show-KV 'AuditPolicy' $kv.Key "$inclusion" $color
        } catch {
            $subResults[$kv.Key] = @{ Raw = $null; Audited = $null; Error = "$_" }
        }
    }
    Save-Data 'AuditPolicy' 'Subcategories' $subResults
    $onCount = ($subResults.Values | Where-Object { $_.Audited }).Count
    if ($onCount -ge 6) { Add-Finding "Heavy auditing: $onCount/$($subResults.Count) critical subcategories audited" }
} else {
    Write-Info "auditpol subcategory enumeration requires admin"
}

# ============================================================
# [3/12] WINDOWS EVENT FORWARDING (WEF → SIEM)
# ============================================================
Write-Sub "[3/12] Event Forwarding (WEF)"
$wefTargets = @()
foreach ($k in @(
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager',
    'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager'
)) {
    if (Test-Path $k) {
        $vals = Get-ItemProperty $k -EA SilentlyContinue
        if ($vals) {
            $vals.PSObject.Properties | Where-Object { $_.Name -match '^\d+$' } | ForEach-Object {
                Show-KV 'WEF' "Target[$($_.Name)]" $_.Value 'Yellow'
                $wefTargets += $_.Value
            }
        }
    }
}
Save-Data 'WEF' 'Targets' $wefTargets
if ($wefTargets.Count -gt 0) { Add-Finding 'WEF forwarders configured — logs leave the host to a collector' }
else                          { Write-Good "No WEF forwarder configured" }
$wec = Get-Service Wecsvc -EA SilentlyContinue
if ($wec) { Show-KV 'WEF' 'WecSvc' "$($wec.Status)" $(if ($wec.Status -eq 'Running') {'Yellow'} else {'DarkGray'}) }

# ============================================================
# [4/12] ETW SESSIONS DE INTERÉS
# ============================================================
Write-Sub "[4/12] ETW telemetry sessions"
$etwAll = @(); $etwHit = @()
try {
    $lines = (logman query -ets 2>$null) | Where-Object { $_ -match '^\S' -and $_ -notmatch '^Data Collector|^---|^The command|^$|^Name' }
    $needles = @('Defender','Sense','DiagTrack','EventLog-Security','MDE','CrowdStrike','SentinelOne','Cylance','CarbonBlack','Tanium','ATP','Threat','Falcon','Elastic','Sysmon')
    foreach ($line in $lines) {
        $name = ($line -split '\s{2,}')[0]
        if (-not $name) { continue }
        $etwAll += $name
        foreach ($n in $needles) {
            if ($name -match $n) {
                Write-Host "    $name" -ForegroundColor Yellow
                $etwHit += $name
                break
            }
        }
    }
    Save-Data 'ETW' 'AllSessions' $etwAll
    Save-Data 'ETW' 'NotableSessions' $etwHit
    Write-Info "Note: Microsoft-Windows-PowerShell ETW provider is always exposed"
} catch { Write-Info "logman not available" }

# ============================================================
# [5/12] LSA / LSASS / CREDS POLICY
# ============================================================
Write-Sub "[5/12] LSA / LSASS Protection"
try {
    $lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -EA Stop
    $rap = [int]($lsa.RunAsPPL | ForEach-Object { if ($null -eq $_) { 0 } else { $_ } })
    Show-KV 'LSA' 'RunAsPPL'             $rap                                  ($(if ($rap -ge 1) {'Red'} else {'Green'}))
    if ($rap -ge 1) { Add-Finding 'LSASS as PPL — classic mimikatz read blocked (need driver/CVE bypass)' }

    Show-KV 'LSA' 'LmCompatibilityLevel'  ([int]$lsa.LmCompatibilityLevel)
    Show-KV 'LSA' 'LimitBlankPasswordUse' ([int]$lsa.LimitBlankPasswordUse)
    Show-KV 'LSA' 'RestrictAnonymous'     ([int]$lsa.RestrictAnonymous)
    Show-KV 'LSA' 'RestrictAnonymousSAM'  ([int]$lsa.RestrictAnonymousSAM)
    $cg = [int]($lsa.LsaCfgFlags | ForEach-Object { if ($null -eq $_) { 0 } else { $_ } })
    Show-KV 'LSA' 'LsaCfgFlags(CredGuard)' $cg                                  ($(if ($cg -ge 1) {'Red'} else {'Green'}))
    if ($cg -ge 1) { Add-Finding 'Credential Guard enabled — TGT/NTLM hashes isolated in VTL1' }
    Show-KV 'LSA' 'DisableRestrictedAdmin' ([int]$lsa.DisableRestrictedAdmin)
} catch { Write-Info "Cannot read HKLM\...\Lsa: $_" }

# WDigest
try {
    $wd = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -EA Stop).UseLogonCredential
    $v = [int]($wd | ForEach-Object { if ($null -eq $_) { 0 } else { $_ } })
    Show-KV 'LSA' 'WDigest_UseLogonCredential' $v ($(if ($v -eq 1) {'Red'} else {'Green'}))
    if ($v -eq 1) { Add-Finding 'WDigest cleartext enabled — plaintext creds in LSASS' }
} catch { Show-KV 'LSA' 'WDigest_UseLogonCredential' '0 (default)' 'Green' }

# Cached logons
try {
    $c = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -EA Stop).CachedLogonsCount
    Show-KV 'LSA' 'CachedLogonsCount' $c
    if ([int]$c -gt 0) { Write-Info "Cached domain creds (MSCACHE) extractable offline with SYSTEM" }
} catch {}

# ============================================================
# [6/12] UAC (completo)
# ============================================================
Write-Sub "[6/12] UAC configuration"
try {
    $u = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -EA Stop
    $eLua  = [int]$u.EnableLUA
    $cpa   = [int]$u.ConsentPromptBehaviorAdmin
    $cpu   = [int]$u.ConsentPromptBehaviorUser
    $latfp = [int]$u.LocalAccountTokenFilterPolicy
    Show-KV 'UAC' 'EnableLUA'                       $eLua  ($(if ($eLua  -eq 0) {'Red'} else {'Green'}))
    Show-KV 'UAC' 'ConsentPromptBehaviorAdmin'      $cpa   ($(switch ($cpa) {0{'Red'}1{'Yellow'}2{'Yellow'}5{'Green'}default{'White'}}))
    Show-KV 'UAC' 'ConsentPromptBehaviorUser'       $cpu
    Show-KV 'UAC' 'PromptOnSecureDesktop'           ([int]$u.PromptOnSecureDesktop)
    Show-KV 'UAC' 'FilterAdministratorToken'        ([int]$u.FilterAdministratorToken)
    Show-KV 'UAC' 'LocalAccountTokenFilterPolicy'   $latfp ($(if ($latfp -eq 1) {'Red'} else {'Green'}))
    Show-KV 'UAC' 'EnableInstallerDetection'        ([int]$u.EnableInstallerDetection)

    if ($eLua -eq 0)              { Add-Finding 'UAC disabled (EnableLUA=0) — admins get full token immediately' }
    if ($latfp -eq 1)             { Add-Finding 'LocalAccountTokenFilterPolicy=1 — remote local-admin gets full token (lateral via SMB/PSExec)' }
    if ($cpa -eq 0 -and $eLua -eq 1) { Add-Finding "UAC 'Elevate without prompting' — silent auto-elevation for admins" }
} catch { Write-Info "Cannot read UAC policy: $_" }

# ============================================================
# [7/12] NTLM + SMB
# ============================================================
Write-Sub "[7/12] NTLM restrictions & SMB"
$ntlmMap = @{ 0='Allow all'; 1='Audit all'; 2='Deny all' }
try {
    $msv  = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -EA Stop
    $send = [int]$msv.RestrictSendingNTLMTraffic
    $recv = [int]$msv.RestrictReceivingNTLMTraffic
    $aud  = [int]$msv.AuditReceivingNTLMTraffic
    Show-KV 'NTLM_SMB' 'RestrictSendingNTLMTraffic'   "$send ($($ntlmMap[$send]))"   ($(switch ($send) {0{'Green'}1{'Yellow'}2{'Red'}default{'White'}}))
    Show-KV 'NTLM_SMB' 'RestrictReceivingNTLMTraffic' "$recv ($($ntlmMap[$recv]))"   ($(switch ($recv) {0{'Green'}1{'Yellow'}2{'Red'}default{'White'}}))
    Show-KV 'NTLM_SMB' 'AuditReceivingNTLMTraffic'    $aud
    Show-KV 'NTLM_SMB' 'NTLMMinClientSec'             ('0x{0:X}' -f [int]$msv.NTLMMinClientSec)
    Show-KV 'NTLM_SMB' 'NTLMMinServerSec'             ('0x{0:X}' -f [int]$msv.NTLMMinServerSec)
    if ($recv -eq 1) { Add-Finding 'NTLM incoming is AUDITED (events 8001-8004)' }
    if ($recv -eq 2) { Add-Finding 'NTLM incoming BLOCKED — relay/coerce useless against this host' }
} catch { Write-Info "MSV1_0 keys not readable" }

try {
    $smb = Get-SmbServerConfiguration -EA Stop
    Show-KV 'NTLM_SMB' 'SMB_RequireSigning'  $smb.RequireSecuritySignature ($(if ($smb.RequireSecuritySignature) {'Green'} else {'Red'}))
    Show-KV 'NTLM_SMB' 'SMB_EnableSigning'   $smb.EnableSecuritySignature
    Show-KV 'NTLM_SMB' 'SMBv1Enabled'        $smb.EnableSMB1Protocol        ($(if ($smb.EnableSMB1Protocol)        {'Red'}   else {'Green'}))
    if (-not $smb.RequireSecuritySignature) { Add-Finding 'SMB signing NOT required — relay attacks viable' }
} catch {}

# ============================================================
# [8/12] LAPS (legacy + Windows LAPS nuevo)
# ============================================================
Write-Sub "[8/12] LAPS"
$lapsModern = $false; $lapsLegacy = $false
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config') {
    $lapsModern = $true
    Write-Warn "Windows LAPS (modern) configured"
    try {
        $lc = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config' -EA Stop
        Show-KV 'LAPS' 'BackupDirectory'         $lc.BackupDirectory   # 0=Disabled,1=AAD,2=AD
        Show-KV 'LAPS' 'AdministratorAccountName' $lc.AdministratorAccountName
        Show-KV 'LAPS' 'PasswordAgeDays'          $lc.PasswordAgeDays
    } catch {}
}
foreach ($svc in 'LapsSvc','laps') {
    $s = Get-Service $svc -EA SilentlyContinue
    if ($s) { Show-KV 'LAPS' "Service[$svc]" "$($s.Status)" 'Yellow'; $lapsModern = $true }
}
if (Test-Path "$env:WINDIR\System32\AdmPwd.dll") {
    $lapsLegacy = $true
    Write-Warn "Legacy LAPS (AdmPwd.dll) present"
}
if (Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd') {
    $lapsLegacy = $true
    Write-Warn "Legacy LAPS policy key present"
}
Save-Data 'LAPS' 'ModernConfigured' $lapsModern
Save-Data 'LAPS' 'LegacyInstalled'  $lapsLegacy
if ($lapsModern -or $lapsLegacy) { Add-Finding 'LAPS deployed — local admin password unique & rotated' }
else                              { Write-Good "No LAPS detected — local admin password may be reused across hosts" }

# ============================================================
# [9/12] SAVED CREDS / DPAPI / VAULT
# ============================================================
Write-Sub "[9/12] Saved credentials"
# cmdkey (I18N: Target / Destino / Ziel / Cible / Destinazione)
try {
    $ck = cmdkey /list 2>$null
    $entries = $ck | Where-Object { $_ -match '^\s*(Target|Destino|Ziel|Cible|Destinazione|Bestemming|Alvo|目标|ターゲット)\s*:' }
    Show-KV 'SavedCredentials' 'CmdKeyEntries' ($entries.Count)
    if ($entries) {
        Write-Warn "Saved credentials via cmdkey:"
        $entries | ForEach-Object { Write-Host "    $_" -ForegroundColor Yellow }
        Add-Finding 'Credential Manager has saved entries — try dpapi::cred / vault::list'
    } else { Write-Good "No saved credentials via cmdkey" }
} catch {}

# DPAPI master keys
$mkRoot = "$env:APPDATA\Microsoft\Protect"
$dpapiInfo = @()
if (Test-Path $mkRoot) {
    foreach ($sidDir in (Get-ChildItem $mkRoot -Directory -EA SilentlyContinue)) {
        $keys = Get-ChildItem $sidDir.FullName -EA SilentlyContinue | Where-Object { $_.Name -match '^[a-f0-9-]{36}$' }
        if ($keys) {
            $dpapiInfo += [PSCustomObject]@{ SID = $sidDir.Name; MasterKeys = $keys.Count }
            Show-KV 'SavedCredentials' "DPAPI[$($sidDir.Name)]" "$($keys.Count) masterkey(s)" 'Yellow'
        }
    }
}
Save-Data 'SavedCredentials' 'DPAPIMasterKeys' $dpapiInfo

# Credential blobs
$credDir = "$env:APPDATA\Microsoft\Credentials"
if (Test-Path $credDir) {
    $cf = Get-ChildItem $credDir -Force -EA SilentlyContinue
    if ($cf) { Show-KV 'SavedCredentials' 'CredentialBlobs' "$($cf.Count) file(s) at $credDir" 'Yellow' }
}
$vaultDir = "$env:LOCALAPPDATA\Microsoft\Vault"
if (Test-Path $vaultDir) {
    $vf = Get-ChildItem $vaultDir -Force -Recurse -EA SilentlyContinue | Where-Object { -not $_.PSIsContainer }
    Show-KV 'SavedCredentials' 'VaultFiles' "$($vf.Count) file(s) at $vaultDir" 'Yellow'
}

# ============================================================
# [10/12] DEFENDER STATUS + TAMPER PROTECTION
# ============================================================
Write-Sub "[10/12] Defender Real-Time & Tamper Protection"
try {
    $mp = Get-MpComputerStatus -EA Stop
    Show-KV 'Defender' 'AntivirusEnabled'           $mp.AntivirusEnabled        ($(if ($mp.AntivirusEnabled)        {'Yellow'} else {'Green'}))
    Show-KV 'Defender' 'RealTimeProtectionEnabled'  $mp.RealTimeProtectionEnabled ($(if ($mp.RealTimeProtectionEnabled) {'Yellow'} else {'Green'}))
    Show-KV 'Defender' 'BehaviorMonitorEnabled'     $mp.BehaviorMonitorEnabled
    Show-KV 'Defender' 'IsTamperProtected'          $mp.IsTamperProtected        ($(if ($mp.IsTamperProtected)        {'Yellow'} else {'Green'}))
    Show-KV 'Defender' 'TamperProtectionSource'     $mp.TamperProtectionSource
    Show-KV 'Defender' 'AMRunningMode'              $mp.AMRunningMode
    if (-not $mp.RealTimeProtectionEnabled) { Add-Finding 'Defender Real-Time Protection DISABLED' }
    if ($mp.IsTamperProtected)              { Add-Finding "Defender Tamper Protection ON (source: $($mp.TamperProtectionSource)) — registry/policy tampering will be blocked" }
    if ($mp.AMRunningMode -match 'Passive|EDR Block') { Add-Finding "Defender in $($mp.AMRunningMode) mode — primary AV is something else" }
} catch { Write-Info "Get-MpComputerStatus failed (3rd-party AV?): $_" }

# ============================================================
# [11/12] WDAC / Device Guard / VBS
# ============================================================
Write-Sub "[11/12] WDAC / Device Guard / VBS"
try {
    $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -EA Stop
    $vbs   = [int]$dg.VirtualizationBasedSecurityStatus     # 0=Off,1=Configured,2=Running
    $ciSt  = [int]$dg.CodeIntegrityPolicyEnforcementStatus  # 0=Off,1=Audit,2=Enforced
    $umci  = [int]$dg.UsermodeCodeIntegrityPolicyEnforcementStatus
    $svcs  = ($dg.SecurityServicesRunning -join ',')        # 1=CG,2=HVCI,3=SBCG,4=SMM
    Show-KV 'WDAC' 'VBS_Status'                       $vbs   ($(if ($vbs  -eq 2) {'Yellow'} else {'DarkGray'}))
    Show-KV 'WDAC' 'SecurityServicesRunning'          $svcs
    Show-KV 'WDAC' 'CodeIntegrityPolicyEnforcement'   $ciSt  ($(if ($ciSt -eq 2) {'Red'} elseif ($ciSt -eq 1) {'Yellow'} else {'Green'}))
    Show-KV 'WDAC' 'UMCI_PolicyEnforcement'           $umci  ($(if ($umci -eq 2) {'Red'} elseif ($umci -eq 1) {'Yellow'} else {'Green'}))
    if ($umci -eq 2) { Add-Finding 'UMCI enforced — PowerShell will run in Constrained Language Mode' }
    if ($ciSt -eq 2) { Add-Finding 'WDAC Kernel CI ENFORCED — only signed/allowed binaries can load' }
} catch { Write-Info "Win32_DeviceGuard not available" }

# .cip files en disco
$ciDir = "$env:WINDIR\System32\CodeIntegrity\CiPolicies\Active"
if (Test-Path $ciDir) {
    $pols = Get-ChildItem $ciDir -Filter *.cip -EA SilentlyContinue
    if ($pols) {
        $list = $pols | ForEach-Object { @{ Name=$_.Name; Bytes=$_.Length } }
        Save-Data 'WDAC' 'ActivePolicyFiles' $list
        Write-Warn "WDAC active policy files:"
        $pols | ForEach-Object { Write-Host "    $($_.Name)  ($($_.Length) bytes)" -ForegroundColor Yellow }
        Add-Finding 'WDAC supplemental policies present on disk — binary allow-listing in force'
    }
}

# ============================================================
# [12/12] Misc priv-esc / lateral surface
# ============================================================
Write-Sub "[12/12] Misc priv-esc & lateral surface"
# AlwaysInstallElevated
$aieHKLM = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -EA SilentlyContinue).AlwaysInstallElevated
$aieHKCU = (Get-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -EA SilentlyContinue).AlwaysInstallElevated
$aieL = [int]($aieHKLM | ForEach-Object { if ($null -eq $_) { 0 } else { $_ } })
$aieU = [int]($aieHKCU | ForEach-Object { if ($null -eq $_) { 0 } else { $_ } })
Show-KV 'PrivEsc' 'AlwaysInstallElevated_HKLM' $aieL ($(if ($aieL -eq 1) {'Red'} else {'Green'}))
Show-KV 'PrivEsc' 'AlwaysInstallElevated_HKCU' $aieU ($(if ($aieU -eq 1) {'Red'} else {'Green'}))
if ($aieL -eq 1 -and $aieU -eq 1) {
    Write-Bad "AlwaysInstallElevated set in BOTH hives → trivial SYSTEM via .msi"
    Add-Finding 'AlwaysInstallElevated=1 in HKLM+HKCU — SYSTEM via malicious MSI'
}

# Print Spooler (PrintNightmare / coerce surface)
$ps = Get-Service Spooler -EA SilentlyContinue
if ($ps) {
    Show-KV 'PrivEsc' 'PrintSpooler' "$($ps.Status) ($($ps.StartType))" ($(if ($ps.Status -eq 'Running') {'Yellow'} else {'Green'}))
    if ($ps.Status -eq 'Running') { Add-Finding 'Print Spooler running — coerce (PetitPotam-like) & driver-load surface' }
}

# WSH
try {
    $wsh = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' -EA SilentlyContinue).Enabled
    Show-KV 'PrivEsc' 'WSH_Enabled' $(if ($null -eq $wsh) {'default (on)'} else {$wsh})
} catch {}

# amsi.dll cargado en este proceso PS
$amsi = [System.Diagnostics.Process]::GetCurrentProcess().Modules | Where-Object { $_.ModuleName -ieq 'amsi.dll' }
Save-Data 'PrivEsc' 'AmsiLoadedInThisProcess' [bool]$amsi
if ($amsi) { Write-Warn "amsi.dll loaded in this PS process: $($amsi.FileName)" }
else        { Write-Good "amsi.dll NOT loaded in this process" }

# ============================================================
# SUMMARY
# ============================================================
Write-Host ""
Write-Host ("=" * 60) -ForegroundColor DarkYellow
Write-Host "  HIGH-VALUE FINDINGS" -ForegroundColor Yellow
Write-Host ("=" * 60) -ForegroundColor DarkYellow
if ($script:ReportData.HighValueFindings.Count -eq 0) {
    Write-Host "  (no notable findings flagged)" -ForegroundColor DarkGray
} else {
    $i = 1
    foreach ($f in $script:ReportData.HighValueFindings) {
        Write-Host ("  [{0:D2}] {1}" -f $i, $f) -ForegroundColor Yellow
        $i++
    }
}
Write-Host ""

# --- Return structured object ---
[PSCustomObject]$script:ReportData
