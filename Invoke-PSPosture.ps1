# ============================================================
# Invoke-PSPosture.ps1
# PowerShell Security Posture (Red Team view)
# ============================================================
# Enumerates:
#   - PS version, host, language mode, execution policy
#   - PS profiles (autoruns), PSv2 downgrade, PowerShell 7 separate engine
#   - Logging: ScriptBlock / Module / Transcription (PS 5.1 + PS 7)
#   - AMSI providers + DLL signature (MS vs 3rd-party)
#   - WDAC / Device Guard / VBS / AppLocker
#   - JEA endpoints, WinRM listeners, CredSSP delegation
#   - PSReadLine history (creds leak)
#   - (Optional) AMSI bypass state via AmsiUtils reflection
#
# Usage:
#   .\Invoke-PSPosture.ps1
#   .\Invoke-PSPosture.ps1 -CheckAmsiBypass    # OPSEC-sensitive
# ============================================================

param(
    # Si $true, intenta leer System.Management.Automation.AmsiUtils.amsiInitFailed
    # OJO: acceder a AmsiUtils via reflection es el patrón inicial de bypasses
    # conocidos. Algunos EDR tienen firmas para esa secuencia. Solo lectura,
    # pero úsalo solo si ya estás "quemado" o en un lab.
    [switch]$CheckAmsiBypass
)

# --- Helpers de output ---
function Write-Section($Title) {
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor DarkCyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor DarkCyan
}
function Write-KV($Key, $Value, $Color = "White") {
    Write-Host ("  {0,-34}" -f $Key) -ForegroundColor Gray -NoNewline
    Write-Host $Value -ForegroundColor $Color
}
function Write-Good($Msg) { Write-Host "  [+] $Msg" -ForegroundColor Green }
function Write-Bad($Msg)  { Write-Host "  [-] $Msg" -ForegroundColor Red }
function Write-Warn($Msg) { Write-Host "  [!] $Msg" -ForegroundColor Yellow }
function Write-Info($Msg) { Write-Host "  [*] $Msg" -ForegroundColor DarkGray }

Write-Section "POWERSHELL SECURITY POSTURE"

# --- PS version + Host ---
Write-KV "PS Version"          $PSVersionTable.PSVersion
Write-KV "PS Edition"          $PSVersionTable.PSEdition
Write-KV "CLR Version"         $PSVersionTable.CLRVersion
Write-KV "Host"                $Host.Name
Write-KV "Host Version"        $Host.Version
Write-KV "Process"             "$([System.Diagnostics.Process]::GetCurrentProcess().ProcessName) (PID $PID)"
Write-KV "Process Arch"        $env:PROCESSOR_ARCHITECTURE
Write-KV "Is64BitProcess"      ([Environment]::Is64BitProcess)

# --- PowerShell profile scripts (autoruns) ---
Write-Host ""
Write-Host "  PowerShell profile scripts (autoruns):" -ForegroundColor Cyan
$profilePaths = [ordered]@{
    'AllUsersAllHosts'       = $PROFILE.AllUsersAllHosts
    'AllUsersCurrentHost'    = $PROFILE.AllUsersCurrentHost
    'CurrentUserAllHosts'    = $PROFILE.CurrentUserAllHosts
    'CurrentUserCurrentHost' = $PROFILE.CurrentUserCurrentHost
}
foreach ($kv in $profilePaths.GetEnumerator()) {
    if (Test-Path $kv.Value) {
        $item = Get-Item $kv.Value -Force
        Write-KV $kv.Key "$($kv.Value)  ($($item.Length) bytes)" 'Red'
        Write-Warn "$($kv.Key) profile exists — code runs on every PS start (persistence vector AND defender trap)"
        try {
            $preview = Get-Content $kv.Value -TotalCount 5 -EA Stop
            $preview | ForEach-Object { Write-Host "      | $_" -ForegroundColor DarkGray }
            if ((Get-Content $kv.Value).Count -gt 5) { Write-Host "      | ..." -ForegroundColor DarkGray }
        } catch {}
    } else {
        Write-KV $kv.Key "(not present)" 'Green'
    }
}

# --- LANGUAGE MODE (lo más importante) ---
Write-Host ""
$lm = $ExecutionContext.SessionState.LanguageMode
$lmColor = switch ($lm) {
    'FullLanguage'        { 'Green' }
    'ConstrainedLanguage' { 'Red'   }
    'RestrictedLanguage'  { 'Red'   }
    'NoLanguage'          { 'Red'   }
    default               { 'Yellow' }
}
Write-KV "LANGUAGE MODE" $lm $lmColor
if ($lm -ne 'FullLanguage') {
    Write-Bad  "Not in FullLanguage — Add-Type, .NET reflection, COM, etc. will be blocked"
    Write-Info "Common bypasses: PSv2 downgrade, AppLocker DLL hijack, custom runspaces, COM hijack"
} else {
    Write-Good "FullLanguage — no language restrictions in this session"
}

# Env var que históricamente fuerza CLM (legacy)
if ($env:__PSLockdownPolicy) {
    Write-Warn "__PSLockdownPolicy env var is set: $env:__PSLockdownPolicy"
}

# --- Execution Policy por scope ---
Write-Host ""
Write-Host "  ExecutionPolicy by scope:" -ForegroundColor Cyan
try {
    Get-ExecutionPolicy -List | ForEach-Object {
        $col = switch ($_.ExecutionPolicy) {
            'Unrestricted' { 'Green' }
            'Bypass'       { 'Green' }
            'RemoteSigned' { 'Yellow' }
            'AllSigned'    { 'Red' }
            'Restricted'   { 'Red' }
            'Undefined'    { 'DarkGray' }
            default        { 'White' }
        }
        Write-Host ("    {0,-18} {1}" -f $_.Scope, $_.ExecutionPolicy) -ForegroundColor $col
    }
} catch { Write-Info "Get-ExecutionPolicy not available" }
Write-Info "ExecutionPolicy is NOT a security boundary — bypassable: -ep bypass, -enc, piping into PS, IEX, .ps1 → cmdlets, etc."

# --- PSv2 engine availability (downgrade attack para evadir AMSI/logging) ---
Write-Host ""
Write-Host "  PowerShell v2 engine availability:" -ForegroundColor Cyan
try {
    $psv2Path = 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine'
    if (Test-Path $psv2Path) {
        $v2 = Get-ItemProperty $psv2Path -EA Stop
        Write-KV "  Registry PowerShellVersion" $v2.PowerShellVersion
        Write-Warn "PSv2 engine registered — possible downgrade target (PSv2 has no AMSI, no ScriptBlock logging)"
    }
    if (Get-Command Get-WindowsOptionalFeature -EA SilentlyContinue) {
        try {
            $feat = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -EA Stop
            $col = if ($feat.State -eq 'Enabled') { 'Red' } else { 'Green' }
            Write-KV "  PSv2 feature state" $feat.State $col
        } catch { Write-Info "  Need admin to query optional features" }
    }
} catch { Write-Info "PSv2 info not available" }

# --- PowerShell 7 (pwsh) — separate engine with independent policies ---
Write-Host ""
Write-Host "  PowerShell 7 / pwsh:" -ForegroundColor Cyan
$ps7Found = $false
$ps7Locations = @(
    "$env:ProgramFiles\PowerShell\7\pwsh.exe",
    "${env:ProgramFiles(x86)}\PowerShell\7\pwsh.exe"
)
foreach ($p in $ps7Locations) {
    if (Test-Path $p) {
        $ps7Found = $true
        try {
            $ver = (Get-Item $p).VersionInfo.ProductVersion
            Write-KV "pwsh.exe" "$p (v$ver)" 'Yellow'
        } catch { Write-KV "pwsh.exe" $p 'Yellow' }
    }
}
try {
    $inst = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\PowerShellCore\InstalledVersions' -EA Stop
    foreach ($i in $inst) {
        $sv = (Get-ItemProperty $i.PSPath -EA SilentlyContinue).SemanticVersion
        if ($sv) { Write-Host "    Registered: $sv" -ForegroundColor White; $ps7Found = $true }
    }
} catch {}

if ($ps7Found) {
    Write-Warn "PowerShell 7 installed — has its OWN logging/AMSI policies, INDEPENDENT from PS 5.1"
    foreach ($k in 'ScriptBlockLogging','ModuleLogging','Transcription') {
        $path = "HKLM:\SOFTWARE\Policies\Microsoft\PowerShellCore\$k"
        if (Test-Path $path) {
            $val = Get-ItemProperty $path -EA SilentlyContinue
            $field = switch ($k) {
                'ScriptBlockLogging' { 'EnableScriptBlockLogging' }
                'ModuleLogging'      { 'EnableModuleLogging' }
                'Transcription'      { 'EnableTranscripting' }
            }
            $on = ($val.$field -eq 1)
            Write-KV "  PS7 $k" $on ($(if ($on) {'Red'} else {'Green'}))
        } else {
            Write-KV "  PS7 $k" "Not configured" 'Green'
        }
    }
    Write-Info "Tip: if PS 5.1 has logging ON and PS 7 doesn't → 'pwsh -c <stuff>' is a free pass"
} else {
    Write-Good "PowerShell 7 not installed — only PS 5.1 to deal with"
}

# --- LOGGING (PS 5.1): ScriptBlock / Module / Transcription ---
Write-Host ""
Write-Host "  PowerShell 5.1 Logging (HKLM policies):" -ForegroundColor Cyan

# ScriptBlock Logging
try {
    $sbl = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -EA Stop
    $on = ($sbl.EnableScriptBlockLogging -eq 1)
    Write-KV "ScriptBlockLogging" $on ($(if($on){'Red'}else{'Green'}))
    if ($sbl.EnableScriptBlockInvocationLogging -eq 1) {
        Write-Bad "ScriptBlock INVOCATION logging is ON (every script-block start/stop logged → 4105/4106)"
    }
} catch { Write-KV "ScriptBlockLogging" "Not configured" 'Green' }

# Module Logging
try {
    $ml = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -EA Stop
    $on = ($ml.EnableModuleLogging -eq 1)
    Write-KV "ModuleLogging" $on ($(if($on){'Red'}else{'Green'}))
    if ($on) {
        try {
            $mods = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' -EA Stop
            $names = $mods.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | Select-Object -Expand Name
            Write-Host "    Logged modules: $($names -join ', ')" -ForegroundColor Yellow
        } catch {}
    }
} catch { Write-KV "ModuleLogging" "Not configured" 'Green' }

# Transcription
try {
    $tr = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -EA Stop
    $on = ($tr.EnableTranscripting -eq 1)
    Write-KV "Transcription" $on ($(if($on){'Red'}else{'Green'}))
    if ($on) {
        Write-Host "    OutputDirectory: $($tr.OutputDirectory)" -ForegroundColor Yellow
        Write-Host "    InvocationHeader: $($tr.EnableInvocationHeader)" -ForegroundColor Yellow
    }
} catch { Write-KV "Transcription" "Not configured" 'Green' }

# HKCU overrides
foreach ($k in 'ScriptBlockLogging','ModuleLogging','Transcription') {
    if (Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\$k") {
        Write-Warn "HKCU policy present for $k (user-level override)"
    }
}

# --- AMSI Providers + signature (MS vs 3rd-party AV/EDR) ---
Write-Host ""
Write-Host "  AMSI Providers registered:" -ForegroundColor Cyan
try {
    $provs = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers' -EA Stop
    if (-not $provs) { Write-Info "No AMSI providers registered (unusual)" }
    foreach ($p in $provs) {
        $clsid = Split-Path $p.Name -Leaf
        $name = $null; $dll = $null
        try { $name = (Get-Item "HKLM:\SOFTWARE\Classes\CLSID\$clsid" -EA Stop).GetValue('') } catch {}
        try { $dll  = (Get-Item "HKLM:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32" -EA Stop).GetValue('') } catch {}
        Write-Host ("    {0}" -f $clsid) -ForegroundColor Yellow
        Write-Host ("      Name:   {0}" -f $name) -ForegroundColor White
        Write-Host ("      DLL:    {0}" -f $dll)  -ForegroundColor White
        # Signature check
        if ($dll) {
            $dllExpanded = [Environment]::ExpandEnvironmentVariables($dll)
            if (Test-Path $dllExpanded) {
                try {
                    $sig = Get-AuthenticodeSignature $dllExpanded -EA SilentlyContinue
                    $subject = $sig.SignerCertificate.Subject
                    $isMS = $subject -match 'Microsoft (Windows|Corporation)'
                    $sigCol = if ($isMS) {'DarkGray'} else {'Yellow'}
                    Write-Host ("      Signer: {0}" -f $subject) -ForegroundColor $sigCol
                    if (-not $isMS) {
                        Write-Warn "      → 3rd-party AMSI provider (AV/EDR vendor hook)"
                    }
                } catch {}
            }
        }
    }
} catch { Write-Info "Cannot enumerate AMSI providers" }

# Si amsi.dll está cargado en este proceso
$amsiLoaded = [System.Diagnostics.Process]::GetCurrentProcess().Modules | Where-Object { $_.ModuleName -ieq 'amsi.dll' }
if ($amsiLoaded) {
    Write-Warn "amsi.dll is loaded in this PS process (path: $($amsiLoaded.FileName))"
} else {
    Write-Good "amsi.dll NOT loaded in this process"
}

# --- WDAC / Device Guard / VBS (fuerza CLM si UMCI está enforce) ---
Write-Host ""
Write-Host "  Device Guard / WDAC / VBS:" -ForegroundColor Cyan
try {
    $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -EA Stop
    Write-KV "VirtualizationBasedSecurityStatus" $dg.VirtualizationBasedSecurityStatus  # 0=Off,1=Configured,2=Running
    Write-KV "SecurityServicesRunning"           ($dg.SecurityServicesRunning -join ', ')  # 1=CG,2=HVCI,3=SBCG,4=SMM
    Write-KV "CodeIntegrityPolicyEnforcement"    $dg.CodeIntegrityPolicyEnforcementStatus # 0=Off,1=Audit,2=Enforced
    Write-KV "UMCI PolicyEnforcement"            $dg.UsermodeCodeIntegrityPolicyEnforcementStatus
    if ($dg.UsermodeCodeIntegrityPolicyEnforcementStatus -eq 2) {
        Write-Bad "UMCI ENFORCED → PowerShell will run in Constrained Language Mode"
    }
} catch { Write-Info "DeviceGuard WMI class not available" }

# --- AppLocker (también fuerza CLM si Allow rules en Scripts/DLL) ---
Write-Host ""
Write-Host "  AppLocker effective policy:" -ForegroundColor Cyan
try {
    $appS = Get-Service AppIDSvc -EA Stop
    Write-KV "AppIDSvc" "$($appS.Status) ($($appS.StartType))"
    $pol = [xml](Get-AppLockerPolicy -Effective -Xml -EA Stop)
    $coll = $pol.AppLockerPolicy.RuleCollection
    if ($coll) {
        foreach ($c in $coll) {
            $rules = ($c.FilePathRule.Count + $c.FilePublisherRule.Count + $c.FileHashRule.Count)
            $col = if ($c.EnforcementMode -eq 'Enabled') { 'Red' } elseif ($c.EnforcementMode -eq 'AuditOnly') { 'Yellow' } else { 'DarkGray' }
            Write-Host ("    {0,-12} {1,-10} rules={2}" -f $c.Type, $c.EnforcementMode, $rules) -ForegroundColor $col
        }
    } else { Write-Info "No effective AppLocker policy" }
} catch { Write-Info "AppLocker not configured or AppIDSvc not running" }

# --- JEA / Restricted endpoints (si entramos via remoting) ---
Write-Host ""
Write-Host "  PSSessionConfigurations (JEA endpoints):" -ForegroundColor Cyan
try {
    Get-PSSessionConfiguration -EA Stop | ForEach-Object {
        $col = if ($_.PSVersion -lt 5 -or $_.Permission -match 'Everyone|Users') { 'Yellow' } else { 'White' }
        Write-Host ("    {0,-40} PSv{1}  RunAs={2}" -f $_.Name, $_.PSVersion, $_.RunAsUser) -ForegroundColor $col
    }
} catch { Write-Info "Need admin (or remoting) to enumerate session configs" }

# --- WinRM config (listeners, auth, trusted hosts) ---
Write-Host ""
Write-Host "  WinRM configuration:" -ForegroundColor Cyan
$wr = Get-Service WinRM -EA SilentlyContinue
if ($wr) {
    $col = if ($wr.Status -eq 'Running') {'Yellow'} else {'DarkGray'}
    Write-KV "WinRM service" "$($wr.Status) ($($wr.StartType))" $col
    if ($wr.Status -eq 'Running') { Write-Info "Inbound remoting is up — host is a lateral movement target" }
}
# Listeners
try {
    $listeners = Get-ChildItem WSMan:\localhost\Listener -EA Stop
    foreach ($l in $listeners) {
        $cfg = Get-ChildItem $l.PSPath -EA SilentlyContinue
        $transport = ($cfg | Where-Object { $_.Name -eq 'Transport' }).Value
        $port      = ($cfg | Where-Object { $_.Name -eq 'Port' }).Value
        $col = if ($transport -eq 'HTTP') {'Yellow'} else {'White'}
        Write-KV "Listener" "$transport on port $port" $col
    }
} catch { Write-Info "WSMan listener enumeration failed" }
# Auth methods (server side)
try {
    $svcAuth = Get-ChildItem WSMan:\localhost\Service\Auth -EA Stop
    foreach ($a in $svcAuth) {
        $col = if ($a.Name -in @('Basic','CredSSP') -and $a.Value -eq 'true') { 'Red' } else { 'White' }
        Write-Host ("    Service Auth.{0,-12} = {1}" -f $a.Name, $a.Value) -ForegroundColor $col
    }
} catch {}
# TrustedHosts (client side — outbound)
try {
    $th = (Get-Item WSMan:\localhost\Client\TrustedHosts -EA Stop).Value
    if ($th) {
        Write-KV "TrustedHosts (client)" $th 'Red'
        Write-Warn "Outbound WinRM trusts these hosts — creds may flow to them"
    } else {
        Write-KV "TrustedHosts (client)" "(empty)" 'Green'
    }
} catch {}

# --- CredSSP / Credential Delegation (double-hop) ---
Write-Host ""
Write-Host "  CredSSP / credential delegation:" -ForegroundColor Cyan
try {
    $cred = Get-WSManCredSSP -EA Stop
    foreach ($line in ($cred -split "`n")) {
        if ($line.Trim()) { Write-Host "    $($line.Trim())" -ForegroundColor White }
    }
    if ($cred -match 'configured to allow delegating fresh credentials') {
        Write-Warn "CredSSP outbound delegation enabled — creds will be forwarded to allowed hosts"
    }
} catch { Write-Info "Get-WSManCredSSP failed: $_" }

# Registry: AllowFreshCredentials / AllowSavedCredentials / etc.
foreach ($name in 'AllowFreshCredentials','AllowFreshCredentialsWhenNTLMOnly','AllowSavedCredentials','AllowSavedCredentialsWhenNTLMOnly') {
    $k = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\$name"
    if (Test-Path $k) {
        $vals = Get-ItemProperty $k -EA SilentlyContinue
        $entries = $vals.PSObject.Properties | Where-Object { $_.Name -match '^\d+$' }
        if ($entries) {
            Write-Warn "$name has entries:"
            $entries | ForEach-Object { Write-Host "      [$($_.Name)] $($_.Value)" -ForegroundColor Yellow }
        }
    }
}

# --- PSReadLine history (CREDS LEAK!) ---
Write-Host ""
Write-Host "  PSReadLine history (potential creds!):" -ForegroundColor Cyan
try {
    $histPath = (Get-PSReadLineOption -EA Stop).HistorySavePath
    Write-KV "  HistorySavePath" $histPath
    if ($histPath -and (Test-Path $histPath)) {
        $size = (Get-Item $histPath).Length
        $lines = (Get-Content $histPath -EA SilentlyContinue).Count
        Write-KV "  History size" "$size bytes / $lines lines"
        $juicy = Select-String -Path $histPath -Pattern 'password|passwd|secret|token|apikey|api_key|convertto-secure|credential|-p ' -EA SilentlyContinue
        if ($juicy) {
            Write-Bad "Sensitive keywords found in PS history:"
            $juicy | Select-Object -First 10 | ForEach-Object {
                Write-Host "      L$($_.LineNumber): $($_.Line)" -ForegroundColor Yellow
            }
        }
    }
} catch { Write-Info "PSReadLine not loaded" }

# Otros historiales típicos
foreach ($p in @(
    "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
    "$env:USERPROFILE\.bash_history",
    "$env:USERPROFILE\.zsh_history"
)) {
    if (Test-Path $p) { Write-Info "Also present: $p" }
}

# --- AMSI bypass state (opt-in via -CheckAmsiBypass; OPSEC-sensible) ---
if ($CheckAmsiBypass) {
    Write-Host ""
    Write-Host "  AMSI bypass state (reflection on AmsiUtils — may trigger AV):" -ForegroundColor Yellow
    try {
        $type = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
        if ($type) {
            $field = $type.GetField('amsiInitFailed','NonPublic,Static')
            if ($field) {
                $failed = $field.GetValue($null)
                if ($failed) {
                    Write-Bad "amsiInitFailed = True → AMSI is ALREADY bypassed in this runspace"
                    Write-Info "Either a prior bypass in this session or a defender artifact"
                } else {
                    Write-Good "amsiInitFailed = False → AMSI intact in this runspace"
                }
            }
        }
    } catch { Write-Info "Could not read amsiInitFailed: $_" }
}

# --- Loaded modules / assemblies of interest ---
Write-Host ""
Write-Host "  Loaded assemblies of interest:" -ForegroundColor Cyan
$watch = @('System.Management.Automation','System.Reflection','Microsoft.PowerShell','amsi')
foreach ($a in [AppDomain]::CurrentDomain.GetAssemblies()) {
    foreach ($w in $watch) {
        if ($a.FullName -match $w) {
            Write-Host ("    {0}" -f $a.FullName.Split(',')[0]) -ForegroundColor DarkGray
            break
        }
    }
}
