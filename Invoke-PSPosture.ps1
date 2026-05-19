# ============================================================
# [MODULE] PowerShell Security Posture (Red Team view)
# ============================================================
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

# --- PSv2 disponibilidad (downgrade attack para evadir AMSI/logging) ---
Write-Host ""
Write-Host "  PowerShell v2 engine availability:" -ForegroundColor Cyan
try {
    $psv2Path = 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine'
    if (Test-Path $psv2Path) {
        $v2 = Get-ItemProperty $psv2Path -EA Stop
        Write-KV "  Registry PowerShellVersion" $v2.PowerShellVersion
        Write-Warn "PSv2 engine registered — possible downgrade target (PSv2 has no AMSI, no ScriptBlock logging)"
    }
    # Test sin lanzar proceso: ¿está la feature instalada?
    if (Get-Command Get-WindowsOptionalFeature -EA SilentlyContinue) {
        try {
            $feat = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -EA Stop
            $col = if ($feat.State -eq 'Enabled') { 'Red' } else { 'Green' }
            Write-KV "  PSv2 feature state" $feat.State $col
        } catch { Write-Info "  Need admin to query optional features" }
    }
} catch { Write-Info "PSv2 info not available" }

# --- LOGGING: ScriptBlock / Module / Transcription ---
Write-Host ""
Write-Host "  PowerShell Logging (HKLM policies):" -ForegroundColor Cyan

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

# También chequear HKCU (puede override en algunos casos)
foreach ($k in 'ScriptBlockLogging','ModuleLogging','Transcription') {
    if (Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\$k") {
        Write-Warn "HKCU policy present for $k (user-level override)"
    }
}

# --- AMSI Providers registrados ---
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
        Write-Host ("      Name: {0}" -f $name) -ForegroundColor White
        Write-Host ("      DLL:  {0}" -f $dll)  -ForegroundColor White
    }
} catch { Write-Info "Cannot enumerate AMSI providers" }

# Si amsi.dll está cargado en este proceso
$amsiLoaded = [System.Diagnostics.Process]::GetCurrentProcess().Modules | Where-Object { $_.ModuleName -ieq 'amsi.dll' }
if ($amsiLoaded) {
    Write-Warn "amsi.dll is loaded in this PS process (path: $($amsiLoaded.FileName))"
} else {
    Write-Good "amsi.dll NOT loaded in this process"
}

# --- WDAC / Device Guard (fuerza CLM si está activo en UMCI) ---
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
    Write-KV "AppIDSvc"  "$($appS.Status) ($($appS.StartType))"
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
        # Buscar palabras sensibles
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

# --- Loaded modules / assemblies sospechosas ---
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
