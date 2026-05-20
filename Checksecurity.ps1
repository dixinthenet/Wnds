<#
.SYNOPSIS
    Auditoria de seguridad de SOLO LECTURA para Windows Server 2025.

.DESCRIPTION
    Recorre las principales medidas de seguridad y contencion de WS2025 y
    reporta su estado: Activo / Inactivo / Parcial / No aplicable / Sin datos.
    NO modifica ninguna configuracion del sistema. Solo lee.

    Distingue entre servidor en dominio y standalone, ya que varias defensas
    (Credential Guard, VBS) solo se activan por defecto en equipos de dominio.

.NOTES
    Ejecutar en una consola de PowerShell ELEVADA (Administrador).
    Probado para Windows Server 2025. Algunos checks degradan con elegancia
    si falta un modulo o no hay permisos.

.OUTPUTS
    - Tabla en consola con codigo de color.
    - Informe HTML en el escritorio (o en la carpeta actual si falla).
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$ReportPath = (Join-Path ([Environment]::GetFolderPath('Desktop')) "Audit-WS2025-$(Get-Date -Format 'yyyyMMdd-HHmmss').html")
)

# ---------------------------------------------------------------------------
# Infraestructura del informe
# ---------------------------------------------------------------------------
$script:Results = New-Object System.Collections.Generic.List[object]

function Add-Result {
    param(
        [string]$Category,
        [string]$Check,
        [ValidateSet('Activo','Inactivo','Parcial','No aplicable','Sin datos')]
        [string]$Status,
        [string]$Detail = '',
        [string]$Default = ''   # Lo que se espera "por defecto" en WS2025
    )
    $script:Results.Add([pscustomobject]@{
        Categoria   = $Category
        Comprobacion= $Check
        Estado      = $Status
        Detalle     = $Detail
        PorDefecto  = $Default
    })
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-RegValue {
    param([string]$Path,[string]$Name)
    try { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name }
    catch { $null }
}

# ---------------------------------------------------------------------------
# Contexto del sistema
# ---------------------------------------------------------------------------
$isAdmin = Test-Admin
if (-not $isAdmin) {
    Write-Warning "No se esta ejecutando como Administrador. Varios checks daran 'Sin datos'."
}

try { $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop } catch { $cs = $null }
$inDomain = if ($cs) { [bool]$cs.PartOfDomain } else { $false }
try {
    $isDC = (Get-CimInstance Win32_OperatingSystem).ProductType -eq 2  # 2 = DC
} catch { $isDC = $false }

$os = try { (Get-CimInstance Win32_OperatingSystem).Caption } catch { 'Desconocido' }

Write-Host "`n=== Contexto ===" -ForegroundColor Cyan
Write-Host "SO            : $os"
Write-Host "Equipo        : $($env:COMPUTERNAME)"
Write-Host ("Rol           : {0}" -f $(if ($isDC) {'Controlador de dominio'} elseif ($inDomain) {'Miembro de dominio'} else {'Standalone / Grupo de trabajo'}))
Write-Host "Administrador : $isAdmin`n"

# ---------------------------------------------------------------------------
# 1. IDENTIDAD Y CREDENCIALES
# ---------------------------------------------------------------------------
$cat = 'Identidad y credenciales'

try {
    $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
    $running = @($dg.SecurityServicesRunning)

    # VBS
    $vbsStatus = $dg.VirtualizationBasedSecurityStatus  # 0 off, 1 enabled-not-running, 2 running
    $vbsState  = switch ($vbsStatus) { 2 {'Activo'} 1 {'Parcial'} default {'Inactivo'} }
    Add-Result $cat 'VBS (Virtualization-Based Security)' $vbsState "Status=$vbsStatus (2=corriendo)" 'Si, en HW compatible'

    # Credential Guard = servicio 1
    $cgState = if ($running -contains 1) {'Activo'} else {'Inactivo'}
    $cgDef = if ($inDomain -and -not $isDC) {'Si (dominio, no DC, HW compatible)'} else {'No (requiere dominio y no ser DC)'}
    Add-Result $cat 'Credential Guard' $cgState "ServiciosEnEjecucion=$($running -join ',')" $cgDef

    # HVCI = servicio 2
    $hvciState = if ($running -contains 2) {'Activo'} else {'Inactivo'}
    Add-Result $cat 'HVCI / Integridad de memoria' $hvciState "ServiciosEnEjecucion=$($running -join ',')" 'Si, en HW compatible'
}
catch {
    Add-Result $cat 'VBS / Credential Guard / HVCI' 'Sin datos' "No se pudo consultar Win32_DeviceGuard: $($_.Exception.Message)" 'Si, en HW compatible'
}

# LSASS protegido (RunAsPPL)
$ppl = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'
$pplState = if ($ppl -in 1,2) {'Activo'} elseif ($null -eq $ppl) {'Inactivo'} else {'Parcial'}
Add-Result $cat 'LSASS protegido (RunAsPPL)' $pplState "RunAsPPL=$ppl (1 o 2 = activo)" 'Parcial / recomendado forzar'

# LAPS
$lapsState = if (Get-Module -ListAvailable -Name LAPS -ErrorAction SilentlyContinue) {
    $pol = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS' 'BackupDirectory'
    if ($pol) {'Activo'} else {'Parcial'}
} else {'Inactivo'}
Add-Result $cat 'Windows LAPS (rotacion admin local)' $lapsState 'Modulo LAPS y politica BackupDirectory' 'No (opt-in)'

# ---------------------------------------------------------------------------
# 2. ACTIVE DIRECTORY (solo relevante en dominio)
# ---------------------------------------------------------------------------
$cat = 'Active Directory'
if ($inDomain -or $isDC) {
    $ldapEnforce = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' 'LDAPServerIntegrity'
    $ldapState = if ($ldapEnforce -ge 2) {'Activo'} elseif ($ldapEnforce -eq 1) {'Parcial'} else {'Sin datos'}
    Add-Result $cat 'Refuerzo de firma/cifrado LDAP' $ldapState "LDAPServerIntegrity=$ldapEnforce" 'Si (cifrado por defecto en WS2025)'

    # TLS 1.3 disponible para Schannel (afecta a LDAP over TLS). Solo es fiable en el DC.
    if ($isDC) {
        $tls13Srv = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' 'Enabled'
        # Ausencia de la clave => habilitado por defecto en WS2025
        $tls13State = if ($tls13Srv -eq 0) {'Inactivo'} else {'Activo'}
        Add-Result $cat 'TLS 1.3 en Schannel (LDAP over TLS)' $tls13State "Server\Enabled=$tls13Srv (vacio=default activo)" 'Si (soportado por defecto)'
    } else {
        Add-Result $cat 'TLS 1.3 en Schannel (LDAP over TLS)' 'No aplicable' 'Comprobacion relevante en el DC' 'Si en DC'
    }

    # Randomizacion de contrasena de cuenta de maquina: el DC la fuerza si esta el flag.
    if ($isDC) {
        $machRnd = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' 'RandomizeMachineAccountPassword'
        $machState = if ($machRnd -eq 1) {'Activo'} elseif ($null -eq $machRnd) {'Parcial'} else {'Inactivo'}
        Add-Result $cat 'Randomizacion contrasena cuenta de maquina' $machState "RandomizeMachineAccountPassword=$machRnd (vacio=comportamiento por defecto)" 'Si (por defecto en WS2025)'
    } else {
        Add-Result $cat 'Randomizacion contrasena cuenta de maquina' 'No aplicable' 'Politica gestionada en el DC' 'Si en DC'
    }

    # PKINIT / agilidad criptografica Kerberos (KDC). Solo en DC.
    if ($isDC) {
        $pkinit = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' 'PKINITHashAlgorithmConfiguration'
        $pkState = if ($null -ne $pkinit) {'Activo'} else {'Parcial'}
        Add-Result $cat 'Kerberos PKINIT - agilidad criptografica' $pkState "PKINITHashAlgorithmConfiguration=$pkinit (vacio=default WS2025)" 'Si (soportado por defecto)'
    } else {
        Add-Result $cat 'Kerberos PKINIT - agilidad criptografica' 'No aplicable' 'Configuracion del KDC (DC)' 'Si en DC'
    }
} else {
    Add-Result $cat 'Seguridad de AD (LDAP, Kerberos, etc.)' 'No aplicable' 'El equipo no esta unido a dominio' 'Si en dominio'
}

# ---------------------------------------------------------------------------
# 3. CONTROL DE APLICACIONES (CONTENCION)
# ---------------------------------------------------------------------------
$cat = 'Control de aplicaciones'

# AppLocker: servicio
try {
    $appid = Get-Service AppIDSvc -ErrorAction Stop
    $appidState = if ($appid.Status -eq 'Running') {'Activo'} else {'Inactivo'}
    Add-Result $cat 'AppLocker - servicio AppIDSvc' $appidState "Estado=$($appid.Status), Inicio=$($appid.StartType)" 'No (manual, sin reglas)'
} catch {
    Add-Result $cat 'AppLocker - servicio AppIDSvc' 'Sin datos' $_.Exception.Message 'No (manual)'
}

# AppLocker: hay reglas efectivas?
try {
    $alPol = Get-AppLockerPolicy -Effective -ErrorAction Stop
    $ruleCount = ($alPol.RuleCollections | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
    $enforced = $alPol.RuleCollections | Where-Object { $_.EnforcementMode -eq 'Enabled' }
    $alState = if ($ruleCount -gt 0 -and $enforced) {'Activo'} elseif ($ruleCount -gt 0) {'Parcial'} else {'Inactivo'}
    $alDetail = "Reglas=$ruleCount; Colecciones en enforcement=$($enforced.Count)"
    Add-Result $cat 'AppLocker - politica efectiva' $alState $alDetail 'No (opt-in)'
} catch {
    Add-Result $cat 'AppLocker - politica efectiva' 'Sin datos' 'No se pudo leer la politica AppLocker' 'No (opt-in)'
}

# WDAC / App Control
try {
    $ci = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
    $cfg = @($ci.CodeIntegrityPolicyEnforcementStatus)  # 0 off, 1 audit, 2 enforce
    $wdacState = switch ($ci.CodeIntegrityPolicyEnforcementStatus) { 2 {'Activo'} 1 {'Parcial'} default {'Inactivo'} }
    Add-Result $cat 'WDAC / App Control for Business' $wdacState "EnforcementStatus=$($ci.CodeIntegrityPolicyEnforcementStatus) (1=audit,2=enforce)" 'No (opt-in)'
} catch {
    Add-Result $cat 'WDAC / App Control for Business' 'Sin datos' 'No consultable' 'No (opt-in)'
}

# Constrained Language Mode (sesion actual)
$clm = $ExecutionContext.SessionState.LanguageMode
$clmState = if ($clm -eq 'ConstrainedLanguage') {'Activo'} else {'Inactivo'}
Add-Result $cat 'PowerShell Constrained Language Mode' $clmState "LanguageMode=$clm (sesion actual)" 'No (lo impone WDAC/AppLocker)'

# ---------------------------------------------------------------------------
# 4. ATTACK SURFACE REDUCTION + DEFENDER
# ---------------------------------------------------------------------------
$cat = 'Antimalware y ASR'
try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    Add-Result $cat 'Microsoft Defender - tiempo real' ($(if($mp.RealTimeProtectionEnabled){'Activo'}else{'Inactivo'})) "AV=$($mp.AntivirusEnabled)" 'Si'
    Add-Result $cat 'Microsoft Defender - AMSI' ($(if($mp.AMSIEnabled){'Activo'}else{'Inactivo'})) "AMSIEnabled=$($mp.AMSIEnabled)" 'Si'

    $pref = Get-MpPreference -ErrorAction Stop

    # Proteccion en la nube (MAPS): 0 deshabilitado, 1 basico, 2 avanzado
    $maps = $pref.MAPSReporting
    $mapsState = if ($maps -ge 1) {'Activo'} else {'Inactivo'}
    Add-Result $cat 'Defender - proteccion en la nube (MAPS)' $mapsState "MAPSReporting=$maps (0=off,1=basico,2=avanzado)" 'Si'

    # Envio de muestras: 0 siempre preguntar, 1 enviar seguras, 2 nunca, 3 enviar todas
    $samp = $pref.SubmitSamplesConsent
    $sampState = if ($samp -in 1,3) {'Activo'} elseif ($samp -eq 0) {'Parcial'} else {'Inactivo'}
    Add-Result $cat 'Defender - envio de muestras' $sampState "SubmitSamplesConsent=$samp (1/3=envia,0=pregunta,2=nunca)" 'Si'

    $asrIds = @($pref.AttackSurfaceReductionRules_Ids)
    $asrAct = @($pref.AttackSurfaceReductionRules_Actions)
    $blocking = 0
    for ($i=0; $i -lt $asrIds.Count; $i++) { if ($asrAct[$i] -eq 1) { $blocking++ } }
    $asrState = if ($blocking -gt 0) {'Activo'} elseif ($asrIds.Count -gt 0) {'Parcial'} else {'Inactivo'}
    Add-Result $cat 'Reglas ASR' $asrState "Configuradas=$($asrIds.Count); en bloqueo=$blocking" 'No (ninguna de fabrica)'
} catch {
    Add-Result $cat 'Microsoft Defender / ASR' 'Sin datos' "Modulo Defender no disponible: $($_.Exception.Message)" 'Si (Defender)'
}

# ---------------------------------------------------------------------------
# 5. POWERSHELL
# ---------------------------------------------------------------------------
$cat = 'PowerShell'

# PS 2.0 presente?
try {
    $v2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -ErrorAction Stop
    $v2State = if ($v2.State -eq 'Enabled') {'Inactivo'} else {'Activo'}  # Activo = bien (v2 fuera)
    Add-Result $cat 'PowerShell 2.0 retirado' $v2State "Estado de la caracteristica v2: $($v2.State)" 'Si (limpio); revisar si upgrade'
} catch {
    Add-Result $cat 'PowerShell 2.0 retirado' 'Sin datos' 'No se pudo consultar la caracteristica opcional' 'Si'
}

# Script Block Logging
$sbl = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
Add-Result $cat 'Script Block Logging' ($(if($sbl -eq 1){'Activo'}else{'Inactivo'})) "EnableScriptBlockLogging=$sbl" 'No (opt-in)'

# Module Logging
$ml = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging'
Add-Result $cat 'Module Logging' ($(if($ml -eq 1){'Activo'}else{'Inactivo'})) "EnableModuleLogging=$ml" 'No (opt-in)'

# Transcription
$tr = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 'EnableTranscripting'
Add-Result $cat 'Transcription' ($(if($tr -eq 1){'Activo'}else{'Inactivo'})) "EnableTranscripting=$tr" 'No (opt-in)'

# Protected Event Logging (cifrado de logs con certificado)
$pel = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging' 'EnableProtectedEventLogging'
Add-Result $cat 'Protected Event Logging' ($(if($pel -eq 1){'Activo'}else{'Inactivo'})) "EnableProtectedEventLogging=$pel" 'No (opt-in)'

# Execution Policy
$ep = try { Get-ExecutionPolicy -Scope LocalMachine } catch { 'Desconocido' }
Add-Result $cat 'Execution Policy (LocalMachine)' 'Parcial' "Valor=$ep (medida debil, no es control real)" 'RemoteSigned'

# JEA
try {
    $jea = Get-PSSessionConfiguration -ErrorAction Stop | Where-Object { $_.Name -notlike 'microsoft.*' }
    $jeaState = if ($jea) {'Activo'} else {'Inactivo'}
    Add-Result $cat 'JEA (endpoints restringidos)' $jeaState "Endpoints personalizados=$(@($jea).Count)" 'No (opt-in)'
} catch {
    Add-Result $cat 'JEA (endpoints restringidos)' 'Sin datos' 'No consultable' 'No (opt-in)'
}

# ---------------------------------------------------------------------------
# 6. RED Y PROTOCOLOS
# ---------------------------------------------------------------------------
$cat = 'Red y protocolos'

# SMB signing servidor
try {
    $smb = Get-SmbServerConfiguration -ErrorAction Stop
    $smbState = if ($smb.RequireSecuritySignature) {'Activo'} elseif ($smb.EnableSecuritySignature) {'Parcial'} else {'Inactivo'}
    Add-Result $cat 'SMB signing (servidor)' $smbState "Require=$($smb.RequireSecuritySignature); Enable=$($smb.EnableSecuritySignature)" 'Reforzado en WS2025'

    # SMB over QUIC (disponible tambien en Standard en WS2025)
    if ($null -ne $smb.PSObject.Properties['EnableSMBQUIC']) {
        $quic = $smb.EnableSMBQUIC
        $quicState = if ($quic) {'Activo'} else {'Inactivo'}
        Add-Result $cat 'SMB over QUIC' $quicState "EnableSMBQUIC=$quic" 'No (opt-in)'
    } else {
        Add-Result $cat 'SMB over QUIC' 'Sin datos' 'Propiedad EnableSMBQUIC no expuesta en esta build' 'No (opt-in)'
    }
} catch {
    Add-Result $cat 'SMB signing (servidor)' 'Sin datos' 'Modulo SMB no disponible' 'Reforzado'
}

# TLS hardening (Schannel): protocolos viejos deshabilitados
$schPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
$weakOn = @()
foreach ($proto in 'SSL 2.0','SSL 3.0','TLS 1.0','TLS 1.1') {
    $en = Get-RegValue "$schPath\$proto\Server" 'Enabled'
    $dbd = Get-RegValue "$schPath\$proto\Server" 'DisabledByDefault'
    # Se considera "apagado" si Enabled=0; si no hay clave, el SO decide (en WS2025 los viejos van capados)
    if ($en -ne 0 -and $en -ne $null) { $weakOn += $proto }
    elseif ($en -eq $null -and $dbd -ne 1) { } # sin clave: confiar en default seguro de WS2025
}
$tlsState = if ($weakOn.Count -eq 0) {'Activo'} else {'Parcial'}
$tlsDetail = if ($weakOn.Count -eq 0) {'Protocolos heredados no habilitados explicitamente'} else {"Habilitados aun: $($weakOn -join ', ')"}
Add-Result $cat 'TLS - protocolos heredados deshabilitados' $tlsState $tlsDetail 'Si (WS2025 capa los viejos)'

# TLS - clave RSA minima de servidor (WS2025 exige >= 2048). Comprobamos que no se haya rebajado.
$minRsa = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL' 'ClientMinKeyBitLength'
Add-Result $cat 'TLS - longitud minima de clave RSA' ($(if($null -eq $minRsa -or $minRsa -ge 2048){'Activo'}else{'Inactivo'})) "ClientMinKeyBitLength=$minRsa (vacio=default 2048 en WS2025)" 'Si (>=2048 por defecto)'


# SMB1
try {
    $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
    $smb1State = if ($smb1.State -eq 'Enabled') {'Inactivo'} else {'Activo'}  # Activo = bien (SMB1 fuera)
    Add-Result $cat 'SMB 1.0 deshabilitado' $smb1State "Estado caracteristica SMB1: $($smb1.State)" 'Si (fuera)'
} catch {
    Add-Result $cat 'SMB 1.0 deshabilitado' 'Sin datos' 'No consultable' 'Si (fuera)'
}

# Firewall
try {
    $fw = Get-NetFirewallProfile -ErrorAction Stop
    $allOn = ($fw | Where-Object { -not $_.Enabled } | Measure-Object).Count -eq 0
    $fwState = if ($allOn) {'Activo'} else {'Parcial'}
    Add-Result $cat 'Firewall de Windows (3 perfiles)' $fwState (($fw | ForEach-Object { "$($_.Name)=$($_.Enabled)" }) -join '; ') 'Si'
} catch {
    Add-Result $cat 'Firewall de Windows' 'Sin datos' 'No consultable' 'Si'
}

# OpenSSH server
try {
    $sshd = Get-Service sshd -ErrorAction Stop
    $sshState = if ($sshd.Status -eq 'Running') {'Activo'} else {'Inactivo'}
    Add-Result $cat 'OpenSSH server (sshd)' $sshState "Estado=$($sshd.Status), Inicio=$($sshd.StartType)" 'Instalado pero apagado'
} catch {
    Add-Result $cat 'OpenSSH server (sshd)' 'Inactivo' 'Servicio sshd no presente/instalado' 'Instalado pero apagado'
}

# ---------------------------------------------------------------------------
# 7. ARRANQUE Y PLATAFORMA
# ---------------------------------------------------------------------------
$cat = 'Arranque y plataforma'

# Secure Boot
try {
    $sb = Confirm-SecureBootUEFI -ErrorAction Stop
    Add-Result $cat 'Secure Boot' ($(if($sb){'Activo'}else{'Inactivo'})) "Confirm-SecureBootUEFI=$sb" 'Recomendado (firmware)'
} catch {
    Add-Result $cat 'Secure Boot' 'Sin datos' 'No UEFI o sin permisos' 'Recomendado'
}

# TPM
try {
    $tpm = Get-Tpm -ErrorAction Stop
    $tpmState = if ($tpm.TpmPresent -and $tpm.TpmReady) {'Activo'} elseif ($tpm.TpmPresent) {'Parcial'} else {'Inactivo'}
    Add-Result $cat 'TPM' $tpmState "Present=$($tpm.TpmPresent); Ready=$($tpm.TpmReady)" 'Depende de HW'
} catch {
    Add-Result $cat 'TPM' 'Sin datos' 'No consultable' 'Depende de HW'
}

# HVPT (Hypervisor-Enforced Paging Translation). Codigo 7 en las propiedades de DeviceGuard.
try {
    $dg2 = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
    $avail = @($dg2.AvailableSecurityProperties)
    $running2 = @($dg2.SecurityServicesRunning)
    if ($running2 -contains 7) {
        $hvptState = 'Activo'; $hvptDetail = 'Servicio 7 en ejecucion'
    } elseif ($avail -contains 7) {
        $hvptState = 'Parcial'; $hvptDetail = 'Disponible en HW pero no en ejecucion'
    } else {
        $hvptState = 'Inactivo'; $hvptDetail = 'No disponible (HW no compatible o desactivado)'
    }
    Add-Result $cat 'HVPT (Hypervisor-Enforced Paging Translation)' $hvptState $hvptDetail 'Solo en HW moderno'
} catch {
    Add-Result $cat 'HVPT (Hypervisor-Enforced Paging Translation)' 'Sin datos' 'No consultable' 'Solo en HW moderno'
}

# ---------------------------------------------------------------------------
# 8. GESTION / BASELINE
# ---------------------------------------------------------------------------
$cat = 'Gestion y baseline'
$osc = Get-Module -ListAvailable -Name Microsoft.OSConfig -ErrorAction SilentlyContinue
Add-Result $cat 'Modulo OSConfig presente' ($(if($osc){'Activo'}else{'Inactivo'})) "Instalado=$([bool]$osc)" 'No aplicado por defecto'

# OSConfig: hay realmente un baseline aplicado y cual es su cumplimiento (drift)?
if ($osc) {
    try {
        Import-Module Microsoft.OSConfig -ErrorAction Stop
        $applied = $false; $compliantTxt = ''
        foreach ($scn in 'SecurityBaseline/WS2025/MemberServer','SecurityBaseline/WS2025/DomainController','SecurityBaseline/WS2025/WorkgroupMember') {
            try {
                $st = Get-OSConfigDesiredConfiguration -Scenario $scn -ErrorAction Stop
                if ($st) { $applied = $true; $compliantTxt += "$scn: $($st.ComplianceStatus); " }
            } catch { }
        }
        if ($applied) {
            $baseState = if ($compliantTxt -match 'NonCompliant|Drift') {'Parcial'} else {'Activo'}
            Add-Result $cat 'OSConfig - baseline aplicado y cumplimiento' $baseState $compliantTxt 'No (opt-in)'
        } else {
            Add-Result $cat 'OSConfig - baseline aplicado y cumplimiento' 'Inactivo' 'Ningun escenario de baseline desplegado' 'No (opt-in)'
        }
    } catch {
        Add-Result $cat 'OSConfig - baseline aplicado y cumplimiento' 'Sin datos' "No se pudo evaluar: $($_.Exception.Message)" 'No (opt-in)'
    }
} else {
    Add-Result $cat 'OSConfig - baseline aplicado y cumplimiento' 'Inactivo' 'Modulo OSConfig no instalado' 'No (opt-in)'
}

# Hotpatch (requiere Azure Arc / suscripcion y habilitacion explicita)
$hp = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Quality Compat' 'HotPatchEnabled'
$hpAlt = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotPatch' 'Enabled'
$hpVal = if ($null -ne $hp) { $hp } else { $hpAlt }
$hpState = if ($hpVal -eq 1) {'Activo'} else {'Inactivo'}
Add-Result $cat 'Hotpatch (actualizaciones sin reinicio)' $hpState "Valor=$hpVal (requiere Azure Arc + habilitacion)" 'No (opt-in)'

# ---------------------------------------------------------------------------
# SALIDA EN CONSOLA
# ---------------------------------------------------------------------------
Write-Host "=== Resultados ===`n" -ForegroundColor Cyan
foreach ($r in $script:Results) {
    $color = switch ($r.Estado) {
        'Activo'        {'Green'}
        'Inactivo'      {'Red'}
        'Parcial'       {'Yellow'}
        'No aplicable'  {'DarkGray'}
        'Sin datos'     {'DarkYellow'}
        default         {'Gray'}
    }
    Write-Host ("[{0,-12}] {1,-26} | {2}" -f $r.Estado, $r.Categoria, $r.Comprobacion) -ForegroundColor $color
}

# Resumen
$summary = $script:Results | Group-Object Estado | Select-Object Name, Count
Write-Host "`n=== Resumen ===" -ForegroundColor Cyan
$summary | ForEach-Object { Write-Host ("{0,-14}: {1}" -f $_.Name, $_.Count) }

# ---------------------------------------------------------------------------
# INFORME HTML
# ---------------------------------------------------------------------------
$css = @"
<style>
 body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1f2937;}
 h1{font-size:20px;} h2{font-size:14px;color:#374151;margin-top:24px;}
 table{border-collapse:collapse;width:100%;margin-top:8px;font-size:13px;}
 th,td{border:1px solid #e5e7eb;padding:6px 10px;text-align:left;vertical-align:top;}
 th{background:#f3f4f6;}
 .Activo{color:#065f46;font-weight:600;} .Inactivo{color:#991b1b;font-weight:600;}
 .Parcial{color:#92400e;font-weight:600;} .Noaplicable{color:#6b7280;}
 .Sindatos{color:#a16207;}
 .meta{color:#6b7280;font-size:12px;}
</style>
"@

$rolText = if ($isDC) {'Controlador de dominio'} elseif ($inDomain) {'Miembro de dominio'} else {'Standalone / Grupo de trabajo'}
$rows = ($script:Results | ForEach-Object {
    $cls = ($_.Estado -replace ' ','')
    "<tr><td>$($_.Categoria)</td><td>$($_.Comprobacion)</td><td class='$cls'>$($_.Estado)</td><td>$([System.Web.HttpUtility]::HtmlEncode($_.Detalle))</td><td>$($_.PorDefecto)</td></tr>"
}) -join "`n"

$html = @"
<!DOCTYPE html><html><head><meta charset='utf-8'>$css<title>Auditoria WS2025</title></head><body>
<h1>Auditoria de seguridad - Windows Server 2025</h1>
<p class='meta'>Equipo: <b>$($env:COMPUTERNAME)</b> &middot; SO: $os &middot; Rol: <b>$rolText</b><br>
Fecha: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') &middot; Ejecutado como admin: $isAdmin</p>
<p class='meta'>Este informe es de solo lectura. No se modifico ninguna configuracion.</p>
<table>
<tr><th>Categoria</th><th>Comprobacion</th><th>Estado</th><th>Detalle</th><th>Esperado por defecto</th></tr>
$rows
</table>
</body></html>
"@

try { Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue } catch {}
try {
    $html | Out-File -FilePath $ReportPath -Encoding UTF8 -ErrorAction Stop
    Write-Host "`nInforme HTML generado en: $ReportPath" -ForegroundColor Cyan
} catch {
    $fallback = Join-Path (Get-Location) "Audit-WS2025.html"
    $html | Out-File -FilePath $fallback -Encoding UTF8
    Write-Host "`nInforme HTML generado en: $fallback" -ForegroundColor Cyan
}
