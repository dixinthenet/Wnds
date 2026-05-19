# ============================================================
# [MODULE] Microsoft Defender Status
# ============================================================
function Write-Section($Title) {
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor DarkCyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor DarkCyan
}
function Write-KV($Key, $Value, $Color = "White") {
    Write-Host ("  {0,-32}" -f $Key) -ForegroundColor Gray -NoNewline
    Write-Host $Value -ForegroundColor $Color
}
function Write-Status($Key, $Value, $GoodIsTrue = $true) {
    $color = if (($Value -eq $true -and $GoodIsTrue) -or ($Value -eq $false -and -not $GoodIsTrue)) { 'Red' } else { 'Green' }
    Write-KV $Key $Value $color
}

Write-Section "MICROSOFT DEFENDER STATUS"

# --- Servicios Defender ---
$defServices = @('WinDefend','WdNisSvc','SecurityHealthService','Sense','MDCoreSvc')
foreach ($s in $defServices) {
    try {
        $svc = Get-Service -Name $s -ErrorAction Stop
        $color = if ($svc.Status -eq 'Running') { 'Green' } elseif ($svc.Status -eq 'Stopped') { 'Yellow' } else { 'Gray' }
        Write-KV $s "$($svc.Status) ($($svc.StartType))" $color
    } catch {
        Write-KV $s "Not installed" 'DarkGray'
    }
}
# Sense = Microsoft Defender for Endpoint (EDR)
if ((Get-Service Sense -EA SilentlyContinue).Status -eq 'Running') {
    Write-Host "  [!] Defender for Endpoint (Sense / MDE) is ACTIVE — EDR running" -ForegroundColor Yellow
}

# --- Get-MpComputerStatus ---
Write-Host ""
try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    Write-KV "AntivirusEnabled"             $mp.AntivirusEnabled
    Write-KV "AMServiceEnabled"             $mp.AMServiceEnabled
    Write-KV "RealTimeProtectionEnabled"    $mp.RealTimeProtectionEnabled
    Write-KV "BehaviorMonitorEnabled"       $mp.BehaviorMonitorEnabled
    Write-KV "IoavProtectionEnabled"        $mp.IoavProtectionEnabled
    Write-KV "OnAccessProtectionEnabled"    $mp.OnAccessProtectionEnabled
    Write-KV "NISEnabled (network)"         $mp.NISEnabled
    Write-KV "IsTamperProtected"            $mp.IsTamperProtected
    Write-KV "AMRunningMode"                $mp.AMRunningMode
    Write-Host ""
    Write-KV "AntivirusSignatureVersion"    $mp.AntivirusSignatureVersion
    Write-KV "AntivirusSignatureAge (days)" $mp.AntivirusSignatureAge
    Write-KV "EngineVersion"                $mp.AMEngineVersion
    Write-KV "ProductVersion"               $mp.AMProductVersion
    if ($mp.AntivirusSignatureAge -gt 7) {
        Write-Host "  [!] Signatures are $($mp.AntivirusSignatureAge) days old — possibly air-gapped or update broken" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  [-] Get-MpComputerStatus failed: $_" -ForegroundColor Red
}

# --- Get-MpPreference (exclusiones + ASR + cloud) ---
Write-Host ""
Write-Host "  Defender Preferences:" -ForegroundColor Cyan
try {
    $pref = Get-MpPreference -ErrorAction Stop

    Write-KV "DisableRealtimeMonitoring"    $pref.DisableRealtimeMonitoring
    Write-KV "DisableBehaviorMonitoring"    $pref.DisableBehaviorMonitoring
    Write-KV "DisableScriptScanning"        $pref.DisableScriptScanning
    Write-KV "DisableIOAVProtection"        $pref.DisableIOAVProtection
    Write-KV "DisableArchiveScanning"       $pref.DisableArchiveScanning
    Write-KV "MAPSReporting (cloud)"        $pref.MAPSReporting          # 0=Off,1=Basic,2=Advanced
    Write-KV "SubmitSamplesConsent"         $pref.SubmitSamplesConsent   # 0=Always prompt,1=Send safe,2=Never,3=Send all
    Write-KV "CloudBlockLevel"              $pref.CloudBlockLevel
    Write-KV "PUAProtection"                $pref.PUAProtection

    # --- EXCLUSIONES (oro puro para red team) ---
    Write-Host ""
    Write-Host "  EXCLUSIONS:" -ForegroundColor Yellow
    if ($pref.ExclusionPath)      { Write-Host "    Paths:"      -ForegroundColor Yellow; $pref.ExclusionPath      | ForEach-Object { Write-Host "      $_" -ForegroundColor Green } }
    else                          { Write-Host "    Paths:      (none)" -ForegroundColor DarkGray }
    if ($pref.ExclusionProcess)   { Write-Host "    Processes:" -ForegroundColor Yellow; $pref.ExclusionProcess   | ForEach-Object { Write-Host "      $_" -ForegroundColor Green } }
    else                          { Write-Host "    Processes:  (none)" -ForegroundColor DarkGray }
    if ($pref.ExclusionExtension) { Write-Host "    Extensions:" -ForegroundColor Yellow; $pref.ExclusionExtension | ForEach-Object { Write-Host "      $_" -ForegroundColor Green } }
    else                          { Write-Host "    Extensions: (none)" -ForegroundColor DarkGray }
    if ($pref.ExclusionIpAddress) { Write-Host "    IPs:"       -ForegroundColor Yellow; $pref.ExclusionIpAddress | ForEach-Object { Write-Host "      $_" -ForegroundColor Green } }

    # --- ASR (Attack Surface Reduction) ---
    Write-Host ""
    Write-Host "  ASR Rules:" -ForegroundColor Cyan
    if ($pref.AttackSurfaceReductionRules_Ids -and $pref.AttackSurfaceReductionRules_Ids.Count -gt 0) {
        $asrMap = @{
            '0=Disabled'='Off'; '1=Block'='BLOCK'; '2=Audit'='Audit'; '5=NotConfigured'='NotCfg'; '6=Warn'='Warn'
        }
        for ($i=0; $i -lt $pref.AttackSurfaceReductionRules_Ids.Count; $i++) {
            $id = $pref.AttackSurfaceReductionRules_Ids[$i]
            $ac = $pref.AttackSurfaceReductionRules_Actions[$i]
            $label = switch ($ac) { 0{'Disabled'} 1{'BLOCK'} 2{'Audit'} 5{'NotConfigured'} 6{'Warn'} default{"Unknown($ac)"} }
            $color = switch ($ac) { 1{'Red'} 2{'Yellow'} default{'DarkGray'} }
            Write-Host ("    {0}  -> {1}" -f $id, $label) -ForegroundColor $color
        }
    } else { Write-Host "    (no ASR rules configured)" -ForegroundColor DarkGray }
} catch {
    Write-Host "  [-] Get-MpPreference failed (need admin?): $_" -ForegroundColor Red
}

# --- Threat history ---
Write-Host ""
Write-Host "  Recent threat detections (last 5):" -ForegroundColor Cyan
try {
    $threats = Get-MpThreatDetection -ErrorAction Stop | Sort-Object InitialDetectionTime -Descending | Select-Object -First 5
    if ($threats) {
        $threats | ForEach-Object { Write-Host ("    {0}  {1}" -f $_.InitialDetectionTime, $_.ThreatID) -ForegroundColor Yellow }
    } else { Write-Host "    (no threats logged)" -ForegroundColor DarkGray }
} catch { Write-Host "    Not available" -ForegroundColor DarkGray }

# --- AV de terceros / lo que el OS reporta al Security Center ---
Write-Host ""
Write-Host "  Registered AntiVirus products (SecurityCenter2):" -ForegroundColor Cyan
try {
    $avs = Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntivirusProduct -ErrorAction Stop
    if ($avs) {
        foreach ($av in $avs) {
            # productState bitfield: https://mspscripts.com/get-installed-antivirus-information-2/
            $state = '0x{0:X}' -f $av.productState
            Write-Host ("    {0,-40} state={1}  path={2}" -f $av.displayName, $state, $av.pathToSignedProductExe) -ForegroundColor White
        }
    } else { Write-Host "    (none registered)" -ForegroundColor DarkGray }
} catch { Write-Host "    SecurityCenter2 not available (server OS?)" -ForegroundColor DarkGray }
