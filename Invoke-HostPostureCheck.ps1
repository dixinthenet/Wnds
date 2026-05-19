# ============================================================
# [MODULE] Detection / Logging / Identity Posture (Red Team / Audit)
# Version: 2.0 (Improved & Production Ready)
# ============================================================

function Write-Section($Title) {
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor DarkCyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor DarkCyan
}

function Write-Sub($Title) {
    Write-Host ""
    Write-Host "  --- $Title ---" -ForegroundColor Magenta
}

function Write-KV($Key, $Value, $Color = "White") {
    Write-Host ("  {0,-38}" -f $Key) -ForegroundColor Gray -NoNewline
    Write-Host $Value -ForegroundColor $Color
}

function Write-Good($Msg) { Write-Host "  [+] $Msg" -ForegroundColor Green }
function Write-Bad($Msg)  { Write-Host "  [-] $Msg" -ForegroundColor Red }
function Write-Warn($Msg) { Write-Host "  [!] $Msg" -ForegroundColor Yellow }
function Write-Info($Msg) { Write-Host "  [*] $Msg" -ForegroundColor DarkGray }

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$findings = New-Object System.Collections.Generic.List[string]

Write-Section "DETECTION / LOGGING / IDENTITY POSTURE"
Write-Info ("Privilege: " + $(if ($IsAdmin) {'ADMIN'} else {'NON-ADMIN — some checks will be skipped'}))

# ============================================================
# [1/10] SYSMON (Optimized - No slow WMI service scanning)
# ============================================================
Write-Sub "[1/10] Sysmon"
$sysmonFound = $false

# 1. Fast Registry Check for Sysmon Service
$sysmonRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services"
$potentialSysmonSvcs = @("Sysmon", "Sysmon64", "SysmonDrv")

foreach ($svcName in $potentialSysmonSvcs) {
    if (Test-Path "$sysmonRegPath\$svcName") {
        $sysmonFound = $true
        $svcData = Get-ItemProperty "$sysmonRegPath\$svcName" -ErrorAction SilentlyContinue
        $svcStatus = (Get-Service $svcName -ErrorAction SilentlyContinue).Status
        Write-KV "Service ($svcName)" "$svcStatus  Path=$($svcData.ImagePath)" 'Yellow'
    }
}

# 2. Driver Altitude (Sysmon default: 385201) - Stealth check
try {
    $instanceKeys = Get-ChildItem "$sysmonRegPath" -ErrorAction SilentlyContinue | ForEach-Object {
        $p = Join-Path $_.PSPath 'Instances'
        if (Test-Path $p) {
            $defInst = (Get-ItemProperty $p -ErrorAction SilentlyContinue).DefaultInstance
            if ($defInst) {
                $instKey = Join-Path $p $defInst
                $altitude = (Get-ItemProperty $instKey -ErrorAction SilentlyContinue).Altitude
                if ($altitude -eq '385201') {
                    [PSCustomObject]@{ Service = $_.PSChildName; Altitude = $altitude }
                }
            }
        }
    }
    foreach ($a in $instanceKeys) {
        $sysmonFound = $true
        Write-Warn "Possible renamed Sysmon driver: $($a.Service) (altitude 385201)"
    }
} catch {}

if ($sysmonFound) {
    $findings.Add("Sysmon detected — assume command-line, hash, network and image-load logging")
    if ($IsAdmin) {
        try {
            $cfg = Get-ItemProperty "$sysmonRegPath\SysmonDrv\Parameters" -ErrorAction SilentlyContinue
            if ($cfg -and $cfg.ConfigHash) { Write-KV "ConfigHash" $cfg.ConfigHash 'Yellow' }
            if ($cfg -and $cfg.Rules)      { Write-KV "Rules blob size" "$($cfg.Rules.Length) bytes" 'Yellow' }
        } catch {}
    }
} else {
    Write-Good "No Sysmon service/driver detected"
}

# ============================================================
# [2/10] AUDIT POLICY + COMMAND-LINE LOGGING (I18N Compliant)
# ============================================================
Write-Sub "[2/10] Audit Policy"
if ($IsAdmin) {
    try {
        # Support for both English and Spanish headers dynamically
        $auditRaw = auditpol /get /category:* /r 2>$null
        $audit = $auditRaw | ConvertFrom-Csv

        if ($audit) {
            # Detect header names dynamically to avoid I18N crash
            $firstRow = $audit
            $subcatField = ($firstRow.PSObject.Properties | Where-Object { $_.Name -match 'Subcategory|Subcategor' }).Name
            $settingField = ($firstRow.PSObject.Properties | Where-Object { $_.Name -match 'Setting|Configuraci' }).Name

            if ($subcatField -and $settingField) {
                $enabled = $audit | Where-Object { $_."$settingField" -match 'Success|Failure|Éxito|Error' }
                Write-KV "Total subcategories audited" $enabled.Count ($(if ($enabled.Count -gt 30) {'Red'} else {'Green'}))
                
                # Critical Subcategories (Regex maps both EN and ES patterns)
                $critRegex = "Process Creation|Creación de procesos|Process Termination|Finalización de procesos|Logon|Inicio de sesión|Logoff|Cierre de sesión|Privilege Use|Uso de privilegios|Credential Validation|Validación de credenciales|Audit Policy Change|Cambio de política de auditoría|File System|Sistema de archivos|Registry|Registro"
                
                foreach ($row in $audit) {
                    if ($row."$subcatField" -match $critRegex) {
                        $val = $row."$settingField"
                        $col = if ($val -match 'Success and Failure|Éxito y errores') {'Red'} elseif ($val -match 'Success|Failure|Éxito|Error') {'Yellow'} else {'DarkGray'}
                        Write-KV "  $($row."$subcatField")" $val $col
                    }
                }
            } else {
                Write-Info "Could not parse auditpol columns dynamically. Raw count of lines: $($auditRaw.Count)"
            }
        }
    } catch { Write-Info "auditpol analysis failed: $_" }
} else {
    Write-Info "auditpol requires admin"
}

# Command-line in Event 4688
try {
    $cmdAudit = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled
    $displayVal = if ($null -eq $cmdAudit) { "Not configured" } else { $cmdAudit }
    $col = if ($cmdAudit -eq 1) {'Red'} else {'Green'}
    Write-KV "ProcessCreation Cmdline (4688)" $displayVal $col
    if ($cmdAudit -eq 1) { $findings.Add("4688 includes command line — every process exec logs full cmdline") }
} catch { Write-KV "ProcessCreation Cmdline (4688)" "Not configured / Error" 'Green' }

# ============================================================
# [3/10] WINDOWS EVENT FORWARDING (WEF → SIEM)
# ============================================================
Write-Sub "[3/10] Event Forwarding (WEF)"
$wefKeys = @(
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager',
    'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager'
)
$wefFound = $false
foreach ($k in $wefKeys) {
    if (Test-Path $k) {
        $vals = Get-ItemProperty $k -ErrorAction SilentlyContinue
        if ($vals) {
            $vals.PSObject.Properties | Where-Object { $_.Name -match '^\d+$' } | ForEach-Object {
                $wefFound = $true
                Write-KV "Forwarder target" $_.Value 'Yellow'
            }
        }
    }
}
if ($wefFound) {
    $findings.Add("WEF forwarding configured — logs are leaving the host")
} else {
    Write-Good "No WEF forwarder configured"
}
$wec = Get-Service Wecsvc -ErrorAction SilentlyContinue
if ($wec -and $wec.Status -eq 'Running') { Write-Warn "Wecsvc running — host might BE a WEF collector" }

# ============================================================
# [4/10] ETW TELEMETRY SESSIONS
# ============================================================
Write-Sub "[4/10] ETW telemetry sessions"
try {
    $traces = (logman query -ets 2>$null) | Where-Object { $_ -match '^\S' -and $_ -notmatch '^Data Collector|^---|^The command|^$|^Name' }
    $interesting = @('Defender','Sense','DiagTrack','EventLog-Security','MDE','CrowdStrike','SentinelOne','Cylance','CarbonBlack','Tanium','ATP','Threat')
    foreach ($line in $traces) {
        $name = ($line -split '\s{2,}')
        if (-not $name) { continue }
        $hit = $false
        foreach ($i in $interesting) { if ($name -match $i) { $hit = $true; break } }
        if ($hit) { Write-Host "    $name" -ForegroundColor Yellow }
    }
    Write-Info "Note: Microsoft-Windows-PowerShell ETW is always exposed (operational + analytic)"
} catch { Write-Info "logman not available" }

# ============================================================
# [5/10] LSA / LSASS PROTECTION & CREDENTIALS
# ============================================================
Write-Sub "[5/10] LSA / LSASS Protection"
try {
    $lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
    if ($lsa) {
        $rap = $lsa.RunAsPPL
        $col = if ($rap -eq 1 -or $rap -eq 2) {'Red'} else {'Green'}
        Write-KV "RunAsPPL (LSASS PPL)" $(if($null -eq $rap){"0 (Disabled)"}else{$rap}) $col
        if ($rap -ge 1) { $findings.Add("LSASS runs as PPL — classic mimikatz read blocked (need driver/CVE)") }
        
        Write-KV "LmCompatibilityLevel" $lsa.LmCompatibilityLevel
        Write-KV "LimitBlankPasswordUse" $lsa.LimitBlankPasswordUse
        Write-KV "RestrictAnonymous" $lsa.RestrictAnonymous
        Write-KV "RestrictAnonymousSAM" $lsa.RestrictAnonymousSAM
        
        $colCG = if ($lsa.LsaCfgFlags -ge 1) {'Red'} else {'Green'}
        Write-KV "LsaCfgFlags (CredGuard)" $(if($null -eq $lsa.LsaCfgFlags){"0 (Disabled)"}else{$lsa.LsaCfgFlags}) $colCG
        if ($lsa.LsaCfgFlags -ge 1) { $findings.Add("Credential Guard enabled — TGT/NTLM hashes isolated in VTL1") }
    }
} catch { Write-Info "Cannot read HKLM:\...\Lsa" }

# WDigest UseLogonCredential
try {
    $wd = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -ErrorAction SilentlyContinue).UseLogonCredential
    if ($wd -eq 1) {
        Write-Bad "WDigest UseLogonCredential = 1 (clear-text creds in LSASS — easy win)"
        $findings.Add("WDigest cleartext enabled — extract plaintext creds from LSASS")
    } else {
        Write-KV "WDigest UseLogonCredential" $(if($null -eq $wd){"0 (Default)"}else{$wd}) 'Green'
    }
} catch { Write-KV "WDigest UseLogonCredential" "Not set (default 0)" 'Green' }

# Cached logons
try {
    $cached = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue).CachedLogonsCount
    Write-KV "CachedLogonsCount" $cached
    if ($null -ne $cached -and [int]$cached -gt 0) { Write-Info "Cached domain creds (MSCACHE) may be extractable offline if SYSTEM" }
} catch {}

# ============================================================
# [6/10] UAC POLICY SAFEGUARDS
# ============================================================
Write-Sub "[6/10] UAC configuration"
try {
    $u = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue
    if ($u) {
        Write-KV "EnableLUA" $u.EnableLUA ($(if ($u.EnableLUA -eq 0) {'Red'} else {'Green'}))
        if ($u.EnableLUA -eq 0) { $findings.Add("UAC disabled (EnableLUA=0) — admins get full token immediately") }
        
        Write-KV "ConsentPromptBehaviorAdmin" $u.ConsentPromptBehaviorAdmin ($(
            switch ($u.ConsentPromptBehaviorAdmin) {
                0 {'Red'}   # No prompt — auto elevate
                1 {'Yellow'}
                2 {'Yellow'}
                5 {'Green'} # Default secure desktop
                default {'White'}
            }
        ))
        Write-KV "LocalAccountTokenFilterPolicy" $(if($null -eq $u.LocalAccountTokenFilterPolicy){0}else{$u.LocalAccountTokenFilterPolicy}) ($(if ($u.LocalAccountTokenFilterPolicy -eq 1) {'Red'} else {'Green'}))
        if ($u.LocalAccountTokenFilterPolicy -eq 1) {
            $findings.Add("LocalAccountTokenFilterPolicy=1 — remote local-admin gets full token (lateral via SMB/PSExec works)")
        }
        if ($u.ConsentPromptBehaviorAdmin -eq 0 -and $u.EnableLUA -eq 1) {
            $findings.Add("UAC in 'Elevate without prompting' — silent auto-elevation for admins")
        }
    }
} catch { Write-Info "Cannot read UAC policy keys" }

# ============================================================
# [7/10] NTLM RESTRICTIONS & SMB SIGNING
# ============================================================
Write-Sub "[7/10] NTLM restrictions & SMB"
try {
    $msv = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -ErrorAction SilentlyContinue
    if ($msv) {
        $send = $msv.RestrictSendingNTLMTraffic
        $recv = $msv.RestrictReceivingNTLMTraffic
        $sendMap = @{0='Allow all';1='Audit all';2='Deny all'}
        Write-KV "RestrictSendingNTLMTraffic"   ("{0}  ({1})" -f $send, $sendMap[[int]$send]) ($(if ($send -eq 2) {'Red'} elseif ($send -eq 1) {'Yellow'} else {'Green'}))
        Write-KV "RestrictReceivingNTLMTraffic" ("{0}  ({1})" -f $recv, $sendMap[[int]$recv]) ($(if ($recv -eq 2) {'Red'} elseif ($recv -eq 1) {'Yellow'} else {'Green'}))
        if ($recv -eq 1) { $findings.Add("NTLM auth attempts are AUDITED on this host (8001-8004 events)") }
        if ($recv -eq 2) { $findings.Add("Incoming NTLM is BLOCKED — relay/coerce useless against this host") }
    }
} catch { Write-Info "MSV1_0 NTLM keys not readable" }

try {
    $smb = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
    if ($smb) {
        Write-KV "SMB Signing Required"  $smb.RequireSecuritySignature ($(if ($smb.RequireSecuritySignature) {'Green'} else {'Red'}))
        Write-KV "SMBv1 Enabled"         $smb.EnableSMB1Protocol ($(if ($smb.EnableSMB1Protocol) {'Red'} else {'Green'}))
        if (-not $smb.RequireSecuritySignature) { $findings.Add("SMB signing NOT required — relay attacks viable") }
    }
} catch {}

# ============================================================
# [8/10] LAPS (Legacy & Modern Windows LAPS)
# ============================================================
Write-Sub "[8/10] LAPS"
$lapsFound = $false

if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config' -PathType Container) {
    $lapsFound = $true
    Write-Warn "Windows LAPS (modern native) configured"
    try {
        $lc = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config' -ErrorAction SilentlyContinue
        Write-KV "  BackupDirectory" $lc.BackupDirectory
        Write-KV "  AdministratorAccountName" $lc.AdministratorAccountName
    } catch {}
}
foreach ($svc in @('LapsSvc','laps')) {
    $s = Get-Service $svc -ErrorAction SilentlyContinue
    if ($s) { $lapsFound = $true; Write-KV "Service $svc" "$($s.Status)" 'Yellow' }
}
if (Test-Path "$env:WINDIR\System32\AdmPwd.dll") { $lapsFound = $true; Write-Warn "Legacy LAPS (AdmPwd.dll) installed" }

if (-not $lapsFound) { 
    Write-Good "No LAPS detected — local admin password may be reused across hosts" 
} else { 
    $findings.Add("LAPS deployed — local admin password is unique & rotated") 
}

# ============================================================
# [9/10] SAVED CREDENTIALS & STORED DATA SITES
# ============================================================
Write-Sub "[9/10] Saved credentials (Contextual User check)"
try {
    $ck = cmdkey /list 2>$null
    $entries = $ck | Where-Object { $_ -match 'Target:|Destino:' }
    if ($entries) {
        Write-Warn "Saved credentials in Credential Manager (Current User Context):"
        $entries | ForEach-Object { Write-Host "    $($_.Trim())" -ForegroundColor Yellow }
        $findings.Add("Credential Manager has saved entries for current context user")
    } else { Write-Good "No saved credentials via cmdkey for this user context" }
} catch {}

# Check presence of DPAPI / Vault files across profiles if Admin
if ($IsAdmin) {
    $profileDirs = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue
    $totalVaults = 0
    foreach ($p in $profileDirs) {
        if (Test-Path "$($p.FullName)\AppData\Local\Microsoft\Vault") { $totalVaults++ }
    }
    if ($totalVaults -gt 0) { Write-KV "User Profiles with Vault Data" $totalVaults 'Yellow' }
}

# ============================================================
# [10/10] AlwaysInstallElevated & PRIV-ESC SURFACE
# ============================================================
Write-Sub "[10/10] AlwaysInstallElevated + misc surface"
$aieHKLM = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -ErrorAction SilentlyContinue).AlwaysInstallElevated
$aieHKCU = (Get-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -ErrorAction SilentlyContinue).AlwaysInstallElevated
Write-KV "AlwaysInstallElevated HKLM" $(if($null -eq $aieHKLM){0}else{$aieHKLM}) ($(if ($aieHKLM -eq 1) {'Red'} else {'Green'}))
Write-KV "AlwaysInstallElevated HKCU" $(if($null -eq $aieHKCU){0}else{$aieHKCU}) ($(if ($aieHKCU -eq 1) {'Red'} else {'Green'}))
if ($aieHKLM -eq 1 -and $aieHKCU -eq 1) {
    Write-Bad "AlwaysInstallElevated set in BOTH hives → trivial SYSTEM via .msi"
    $findings.Add("AlwaysInstallElevated=1 in HKLM+HKCU — SYSTEM via malicious MSI")
}

$ciDir = "$env:WINDIR\System32\CodeIntegrity\CiPolicies\Active"
if (Test-Path $ciDir) {
    $pols = Get-ChildItem $ciDir -Filter *.cip -ErrorAction SilentlyContinue
    if ($pols) {
        Write-Warn "WDAC active policies on disk:"
        $pols | ForEach-Object { Write-Host "    $($_.Name) ($($_.Length) bytes)" -ForegroundColor Yellow }
        $findings.Add("WDAC supplemental policies active — binary allow-listing in force")
    }
}

$ps = Get-Service Spooler -ErrorAction SilentlyContinue
if ($ps) {
    $col = if ($ps.Status -eq 'Running') {'Yellow'} else {'Green'}
    Write-KV "Print Spooler" "$($ps.Status) ($($ps.StartType))" $col
}

# ============================================================
# SUMMARY OF HIGH-VALUE FINDINGS
# ============================================================
Write-Host ""
Write-Host ("=" * 60) -ForegroundColor DarkYellow
Write-Host "  HIGH-VALUE FINDINGS SUMMARY" -ForegroundColor Yellow
Write-Host ("=" * 60) -ForegroundColor DarkYellow
if ($findings.Count -eq 0) {
    Write-Host "  (no notable findings flagged)" -ForegroundColor DarkGray
} else {
    $i = 1
    foreach ($f in $findings) {
        Write-Host ("  [{0:D2}] {1}" -f $i, $f) -ForegroundColor Yellow
        $i++
    }
}
Write-Host ""
