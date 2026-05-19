# ============================================================
# [MODULE] Windows System Status
# ============================================================
function Write-Section($Title) {
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor DarkCyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor DarkCyan
}
function Write-KV($Key, $Value, $Color = "White") {
    Write-Host ("  {0,-28}" -f $Key) -ForegroundColor Gray -NoNewline
    Write-Host $Value -ForegroundColor $Color
}
function Write-Warn($Msg)  { Write-Host "  [!] $Msg" -ForegroundColor Yellow }
function Write-Bad($Msg)   { Write-Host "  [-] $Msg" -ForegroundColor Red }
function Write-Good($Msg)  { Write-Host "  [+] $Msg" -ForegroundColor Green }
function Write-Info($Msg)  { Write-Host "  [*] $Msg" -ForegroundColor DarkGray }

# --- Privilegios ---
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$IsSystem = ([Security.Principal.WindowsIdentity]::GetCurrent()).IsSystem

Write-Section "WINDOWS SYSTEM STATUS"

# --- Identidad del proceso ---
$ident = [Security.Principal.WindowsIdentity]::GetCurrent()
Write-KV "Current User"        $ident.Name
Write-KV "User SID"            $ident.User.Value
Write-KV "Integrity"           ($ident.Groups | Where-Object { $_.Value -match '^S-1-16-' } | ForEach-Object { $_.Translate([Security.Principal.NTAccount]).Value } | Select-Object -First 1)
if ($IsSystem)   { Write-Good "Running as SYSTEM" }
elseif ($IsAdmin){ Write-Good "Running as ADMIN (elevated)" }
else             { Write-Warn "Running as STANDARD USER (no elevation)" }

# --- OS Info ---
Write-Host ""
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    Write-KV "OS"               "$($os.Caption) ($($os.OSArchitecture))"
    Write-KV "Version / Build"  "$($os.Version) (Build $($os.BuildNumber))"
    # UBR (Update Build Revision) — nivel real de parche
    try {
        $ubr = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name UBR -ErrorAction Stop).UBR
        $dispVer = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name DisplayVersion -ErrorAction SilentlyContinue).DisplayVersion
        Write-KV "Display Version"  "$dispVer (UBR $ubr)"
    } catch {}
    Write-KV "Install Date"     $os.InstallDate
    Write-KV "Last Boot"        $os.LastBootUpTime
    $uptime = (Get-Date) - $os.LastBootUpTime
    Write-KV "Uptime"           ("{0}d {1}h {2}m" -f $uptime.Days, $uptime.Hours, $uptime.Minutes)
    Write-KV "Hostname"         $cs.Name
    Write-KV "Domain"           $cs.Domain
    Write-KV "Part of Domain"   $cs.PartOfDomain
    Write-KV "Manufacturer"     $cs.Manufacturer
    Write-KV "Model"            $cs.Model

    # VM / Físico
    $vmHints = @('VMware','VirtualBox','Virtual Machine','KVM','Xen','QEMU','Hyper-V','Parallels')
    $isVM = $false
    foreach ($h in $vmHints) {
        if ($cs.Manufacturer -match $h -or $cs.Model -match $h) { $isVM = $true; break }
    }
    if ($isVM) { Write-Warn "Likely VIRTUAL MACHINE (sandbox? VDI?)" }
    else       { Write-Info "Likely physical / unknown" }
} catch { Write-Bad "Failed to query OS info: $_" }

# --- CPU / RAM (señales de sandbox) ---
Write-Host ""
try {
    $cpu = Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object -First 1
    $mem = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
    Write-KV "CPU"              "$($cpu.Name)"
    Write-KV "CPU Cores"        "$($cpu.NumberOfCores) cores / $($cpu.NumberOfLogicalProcessors) logical"
    Write-KV "RAM (GB)"         $mem
    if ($cpu.NumberOfCores -lt 2) { Write-Warn "Single core — sandbox indicator" }
    if ($mem -lt 4)               { Write-Warn "Low RAM ($mem GB) — sandbox indicator" }
} catch {}

# --- Sesiones / usuarios logueados ---
Write-Host ""
Write-Host "  Logged-on users:" -ForegroundColor Gray
try {
    $sessions = quser 2>$null
    if ($sessions) { $sessions | ForEach-Object { Write-Host "    $_" -ForegroundColor White } }
    else { Write-Info "quser returned nothing" }
} catch { Write-Info "quser not available" }

# --- Pending reboot (útil: parche aplicado pero no efectivo aún) ---
Write-Host ""
$pending = $false
$reasons = @()
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $pending=$true; $reasons+='CBS' }
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $pending=$true; $reasons+='WU' }
try { if ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -EA SilentlyContinue).PendingFileRenameOperations) { $pending=$true; $reasons+='PendingRename' } } catch {}
if ($pending) { Write-Warn "Pending reboot ($($reasons -join ', '))" }
else          { Write-Info "No pending reboot" }

# --- Últimos hotfixes (visible para non-admin) ---
Write-Host ""
Write-Host "  Last 5 hotfixes:" -ForegroundColor Gray
try {
    Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending | Select-Object -First 5 |
        ForEach-Object { Write-Host ("    {0,-12} {1,-10} {2}" -f $_.HotFixID, $_.Description, $_.InstalledOn) }
} catch { Write-Info "Get-HotFix not available" }

# --- Antigüedad del último parche ---
try {
    $lastHF = Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending | Select-Object -First 1
    if ($lastHF.InstalledOn) {
        $days = ((Get-Date) - $lastHF.InstalledOn).Days
        if ($days -gt 60)      { Write-Bad  "Last patch is $days days old — likely unpatched vulns" }
        elseif ($days -gt 30)  { Write-Warn "Last patch is $days days old" }
        else                   { Write-Good "Last patch is $days days old" }
    }
} catch {}
