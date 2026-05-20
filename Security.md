Marco central: Security Baselines y OSConfig
Es la novedad más importante para hardening en WS2025. El baseline de Windows Server 2025 incluye más de 300 ajustes de seguridad y se despliega mediante OSConfig, con soporte para entornos on-premises y conectados por Azure Arc. Las baselines aportan GPOs preconfiguradas, ajustes de registro y configuraciones endurecidas para estandarizar la protección. La versión más reciente del baseline es la 2602 (febrero 2026). Microsoft LearnWindows Report
powershell# Instalar el módulo y aplicar el baseline
Install-Module -Name Microsoft.OSConfig -Scope AllUsers
Set-OSConfigDesiredConfiguration -Scenario SecurityBaseline/WS2025/MemberServer

# Verificar cumplimiento (drift)
Get-OSConfigDesiredConfiguration -Scenario SecurityBaseline/WS2025/MemberServer

# Quitar/revertir el escenario
Remove-OSConfigDesiredConfiguration -Scenario SecurityBaseline/WS2025/MemberServer
Escenarios típicos: MemberServer, DomainController, WorkgroupMember. Estándares de referencia alternativos: CIS Benchmarks (ya publicados para WS2025) y DISA STIGs.
Credential Guard (con VBS)
Protege credenciales (hashes NTLM, tickets Kerberos) contra pass-the-hash. A partir de Windows Server 2025 está habilitado por defecto en todos los sistemas elegibles que cumplen requisitos de hardware y licencia, por lo que normalmente solo intervienes para verificarlo o desactivarlo por compatibilidad. NinjaOne
powershell# Verificar (1 = Credential Guard corriendo; 2 = HVCI)
(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning
Conviene habilitarlo antes de unir el equipo al dominio; si se activa después, los secretos de usuario y equipo podrían ya estar comprometidos. Para activarlo manualmente si estuviera apagado, primero se asegura VBS/Hyper-V y luego: Lukas Blog
powershell# Activar VBS
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 1
Para desactivar (cuando NO usa UEFI lock — el modo por defecto): poner a 0 las claves de registro LsaCfgFlags en HKLM\SYSTEM\CurrentControlSet\Control\Lsa y en HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard, y reiniciar. Si está protegido con UEFI lock, hay que borrar la variable UEFI y confirmar en consola durante el arranque. Windows OS HubLevel
Nota importante: desde la actualización de abril (KB5055523), la función "Credential Guard protected machine accounts" está deshabilitada temporalmente en Windows Server 2025 por un problema con la rotación de contraseña de máquina vía Kerberos. microsoft
VBS / HVCI (Memory Integrity)
Base de Credential Guard y de la integridad de código.
powershell# Verificar: VBS activo y servicios disponibles vs corriendo
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | 
  Select VirtualizationBasedSecurityStatus, SecurityServicesConfigured, SecurityServicesRunning
VirtualizationBasedSecurityStatus = 2 significa habilitado y en ejecución. Activación/desactivación vía GPO en Configuración del equipo > Plantillas administrativas > Sistema > Device Guard > Activar la seguridad basada en virtualización.
WDAC (Application Control) y AppLocker
Control de qué binarios pueden ejecutarse. WDAC for Business y AppLocker son piezas clave del hardening de aplicaciones en WS2025. Windows Forum
powershell# Crear y aplicar una política WDAC
New-CIPolicy -FilePath .\policy.xml -Level Publisher -ScanPath C:\ -UserPEs
ConvertFrom-CIPolicy -XmlFilePath .\policy.xml -BinaryFilePath .\policy.cip
# Desplegar
CiTool --update-policy .\policy.cip
# Verificar políticas activas
CiTool --list-policies
# Eliminar una política por su ID
CiTool --remove-policy "<PolicyID>"
AppLocker se gestiona con el servicio AppIDSvc y el módulo Get-AppLockerPolicy / Set-AppLockerPolicy.
Reglas ASR (Attack Surface Reduction)
Bloquean vectores comunes de malware (macros, LSASS, etc.).
powershell# Verificar reglas y su estado (0=off,1=block,2=audit,6=warn)
Get-MpPreference | Select AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions

# Activar una regla en modo bloqueo
Add-MpPreference -AttackSurfaceReductionRules_Ids <GUID> -AttackSurfaceReductionRules_Actions Enabled

# Desactivar
Add-MpPreference -AttackSurfaceReductionRules_Ids <GUID> -AttackSurfaceReductionRules_Actions Disabled
SMB Hardening (signing + EPA)
WS2025 refuerza SMB contra ataques de relay. El firmado de servidor SMB se habilita con "Microsoft network server: Digitally sign communications (always)" y la protección extendida para autenticación (EPA) con "Server SPN target name validation level". Microsoft Community Hub
powershell# Verificar
Get-SmbServerConfiguration | Select RequireSecuritySignature, EnableSecuritySignature
# Activar firmado obligatorio
Set-SmbServerConfiguration -RequireSecuritySignature $true
# Desactivar
Set-SmbServerConfiguration -RequireSecuritySignature $false
Desde las actualizaciones de septiembre 2025 hay eventos de auditoría para comprobar la compatibilidad de clientes con el firmado SMB y EPA antes de forzarlo. Microsoft Community Hub
LAPS (rotación de contraseñas de admin local)
powershellGet-Command -Module LAPS         # verificar disponibilidad
Get-LapsADPassword <equipo> -AsPlainText   # leer
Reset-LapsPassword               # forzar rotación
Gestión por GPO/Intune en las políticas de Windows LAPS. El baseline 2602 también deshabilita el modo del comando sudo en servidores miembro y controladores de dominio para reducir el riesgo de bypass de UAC. Windows Report
Secure Boot, TPM y Measured Boot
Configura Measured Boot vía UEFI y TPM como base del hardening. IT Start
powershellConfirm-SecureBootUEFI      # True si Secure Boot activo
Get-Tpm                     # estado del TPM
Secure Boot y TPM se activan en el firmware UEFI; no se desactivan desde el SO.
Microsoft Defender Antivirus y Firewall
powershell# Defender
Get-MpComputerStatus | Select AntivirusEnabled, RealTimeProtectionEnabled
Set-MpPreference -DisableRealtimeMonitoring $false   # activar protección en tiempo real

# Firewall
Get-NetFirewallProfile | Select Name, Enabled
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

Medidas activas por defecto en WS2025 (si se cumplen requisitos)
Credential Guard — la novedad estrella. A partir de Windows Server 2025 está habilitado por defecto en sistemas unidos a dominio, que NO sean controladores de dominio, y que cumplan los requisitos de hardware. Esa activación por defecto enciende automáticamente VBS, se hace sin UEFI Lock (lo que permite desactivarlo en remoto si hace falta) y Secure Boot no es un requisito obligatorio para que VBS funcione, aunque sí recomendado. Microsoft LearnMicrosoft Learn
VBS (Virtualization-Based Security) — cuando Credential Guard se habilita, VBS se habilita automáticamente también. Thomasmarcussen
HVCI / Integridad de memoria — la Integridad de Código Protegida por Hipervisor (HVCI), también llamada integridad de memoria, está ahora habilitada por defecto en Windows Server 2025. Thomasmarcussen
Seguridad de Active Directory (si es DC o miembro de dominio) — todas las conexiones LDAP van cifradas por defecto, hay soporte de TLS 1.3 para LDAP, las contraseñas de cuentas de máquina se generan aleatoriamente por defecto, y los DC exigen conexiones cifradas al manejar atributos confidenciales. Mondoo
TLS más estricto — la autenticación de servidor TLS ahora requiere una longitud mínima de clave RSA de 2.048 bits. GitHub
OpenSSH (servidor) — el componente de servidor OpenSSH viene instalado por defecto, con una opción de un solo paso en Server Manager para habilitar o deshabilitar el servicio sshd.exe. (Más bien una capacidad de gestión, pero relevante para la superficie de exposición.) GitHub
Otras protecciones de plataforma presentes en la versión, aunque dependen de hardware moderno: HVPT (Hypervisor-Enforced Paging Translation) contra ataques write-what-where, y los enclaves VBS como entornos de ejecución aislados. Mondoo
El matiz crítico para un Standard standalone
Si tu servidor no está unido a un dominio, Credential Guard (y por tanto VBS por esa vía) no se activa por defecto — el default-on requiere domain-join y que no sea DC. Además, si Credential Guard fue desactivado explícitamente antes de actualizar a WS2025, la activación por defecto no sobrescribe ese ajuste y seguirá deshabilitado. Thomasmarcussen
Por tanto, en un Standard en grupo de trabajo conviene verificar y activar manualmente lo que necesites. Comprobación rápida del estado real:
powershell# Credential Guard / VBS en ejecución (1 = Cred Guard, 2 = HVCI)
(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning

# Estado global de VBS (2 = habilitado y corriendo)
(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).VirtualizationBasedSecurityStatus


1. Eliminación de PowerShell 2.0 (lo nuevo en WS2025)
El cambio más relevante. PowerShell 2.0 se retira de las imágenes de Windows Server 2025 a partir de septiembre de 2025 (KB 5065506). Importa por seguridad porque la v2 carece de integración con AMSI, de script block logging, de Constrained Language Mode y de JEA, y los atacantes la usaban como "downgrade attack": forzar una sesión al motor antiguo y menos protegido para evadir AMSI y el logging. Windows Forum + 2
Ojo: en instalaciones limpias de WS2025 ya no está; pero los sistemas actualizados in-place pueden conservar el componente hasta el reimaging. Verifica y elimínalo: Windows Forum
powershell# Verificar si la característica v2 sigue presente
Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2*
# Desactivar/eliminar el motor v2
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root
También conviene buscar invocaciones explícitas -Version 2 en tareas programadas, instaladores y repos de scripts.
2. Logging (lo más rentable para detección)
Tres niveles, todos vía GPO en Configuración del equipo > Plantillas administrativas > Componentes de Windows > Windows PowerShell:
powershell# Verificar Script Block Logging (1 = activo)
(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -EA SilentlyContinue).EnableScriptBlockLogging

# Activar Script Block Logging por registro
New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Force | Out-Null
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1

# Desactivar
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 0
Los eventos van al log Microsoft-Windows-PowerShell/Operational (Script Block = ID 4104). Los otros dos: Module Logging (qué cmdlets se ejecutan) y Transcription (transcripción completa a fichero, idealmente a un recurso de red protegido). Protected Event Logging cifra los logs con un certificado para que los secretos en tránsito no queden en claro.
3. AMSI (Anti-Malware Scan Interface)
Permite a Defender (o el AV) escanear el contenido del script en memoria, incluso ofuscado, justo antes de ejecutarse. Va integrado en PowerShell 5.1+ y se apoya en Defender. No se "activa" como tal; depende de que el AV esté operativo:
powershellGet-MpComputerStatus | Select AMSIEnabled, RealTimeProtectionEnabled
Si Defender está activo, AMSI lo está. Vigila intentos de bypass de AMSI en el script block logging — son un indicador típico de ataque.
4. Constrained Language Mode (CLM)
Limita PowerShell a un subconjunto seguro del lenguaje (bloquea llamadas a .NET arbitrario, COM, Add-Type, etc.), cortando la mayoría de payloads ofensivos.
powershell# Verificar el modo actual
$ExecutionContext.SessionState.LanguageMode   # FullLanguage o ConstrainedLanguage
Lo recomendable no es forzar CLM por la variable de entorno __PSLockdownPolicy (es trivial de eludir), sino dejar que WDAC/AppLocker en modo enforcement lo imponga automáticamente. Cuando hay una política WDAC activa, PowerShell entra en CLM solo. Esa es la forma robusta.
5. Execution Policy
Es una medida de conveniencia, no un control de seguridad real (se evade con -ExecutionPolicy Bypass o leyendo el script por stdin). Útil para evitar ejecuciones accidentales, no para frenar a un atacante.
powershellGet-ExecutionPolicy -List          # verificar por ámbito
Set-ExecutionPolicy AllSigned -Scope LocalMachine   # exigir scripts firmados
Set-ExecutionPolicy Restricted     # más restrictivo
AllSigned combinado con firma Authenticode de tus scripts (Set-AuthenticodeSignature) sí aporta valor.
6. JEA (Just Enough Administration)
Da a los administradores sesiones de PowerShell restringidas a un conjunto concreto de cmdlets, ejecutadas bajo una cuenta virtual con privilegios, sin entregar credenciales de admin completas. Reduce drásticamente el daño de una cuenta comprometida.
powershell# Ver endpoints de sesión registrados
Get-PSSessionConfiguration
# Registrar un endpoint JEA a partir de tu archivo de configuración
Register-PSSessionConfiguration -Name JEA_Operadores -Path .\jea.pssc
# Quitarlo
Unregister-PSSessionConfiguration -Name JEA_Operadores
Se define con un Role Capability File (.psrc) y un Session Configuration File (.pssc).
7. Remoting (WinRM) endurecido
powershell# Estado del servicio de remoting
Get-Service WinRM
Test-WSMan
# Desactivar remoting si el servidor no lo necesita
Disable-PSRemoting -Force
Si lo usas: fuerza HTTPS (no HTTP 5985 en claro), restringe por firewall a hosts de administración concretos, y limita quién pertenece al grupo Remote Management Users.
8. Migración a PowerShell 7.x
PowerShell 5.1 sigue siendo el motor base de Windows y tiene AMSI/logging/CLM. PowerShell 7.x está mantenido activamente y recibe correcciones de seguridad independientes del ciclo de Windows. Si despliegas 7.x, asegúrate de aplicarle también la configuración de logging (usa su propio espacio de configuración) para no perder telemetría.


AppLocker: qué es y por qué importa en PowerShell
AppLocker controla qué ejecutables, scripts, instaladores (MSI), DLLs y apps empaquetadas pueden ejecutarse, según reglas por editor (firma), ruta o hash. Su conexión con PowerShell es la clave: cuando AppLocker está en modo enforcement con reglas de script, fuerza a PowerShell a entrar en Constrained Language Mode automáticamente para el código no autorizado. Es la vía "ligera" de imponer CLM (la robusta sigue siendo WDAC, ver más abajo).
Verificar el estado
powershell# El servicio que aplica AppLocker (Application Identity)
Get-Service AppIDSvc

# Ver la política efectiva (local + GPO combinadas)
Get-AppLockerPolicy -Effective -Xml

# Solo la política local
Get-AppLockerPolicy -Local -Xml

# Probar si un fichero concreto se permitiría para un usuario
Get-AppLockerFileInformation -Path C:\ruta\script.ps1 |
  Test-AppLockerPolicy -PolicyObject (Get-AppLockerPolicy -Effective) -User Everyone
Dato crítico: AppLocker no aplica nada si el servicio AppIDSvc no está corriendo. Por defecto suele estar en arranque manual, así que aunque tengas reglas definidas, sin el servicio activo no hay protección.
powershell# Dejar AppIDSvc en automático y arrancarlo
Set-Service AppIDSvc -StartupType Automatic
Start-Service AppIDSvc
Nota: en versiones modernas AppIDSvc está protegido y a veces requiere configurarse vía GPO/tarea en lugar de Set-Service directo; si te da acceso denegado, hazlo desde la directiva.
Activar y configurar reglas
Lo más práctico es generar reglas por defecto (que permiten Windows y Program Files) y luego endurecer:
powershell# Generar reglas base automáticamente a partir del sistema
$pol = Get-AppLockerFileInformation -Directory C:\Windows\System32 -Recurse -FileType Exe |
  New-AppLockerPolicy -RuleType Publisher,Hash -User Everyone -Optimize

# Aplicar la política localmente
Set-AppLockerPolicy -PolicyObject $pol -Merge
Por GPO: Configuración del equipo > Directivas > Configuración de Windows > Configuración de seguridad > Directivas de control de aplicaciones > AppLocker. Ahí defines las cinco colecciones de reglas (Ejecutables, Scripts, Windows Installer, DLLs, Apps empaquetadas).
Modo auditoría primero (importantísimo)
Nunca despliegues AppLocker directo en enforcement: rompes el servidor. Empieza en Audit Only, que solo registra lo que se bloquearía, y revisas los logs:
powershell# Los eventos de AppLocker viven aquí:
#  Microsoft-Windows-AppLocker/EXE and DLL
#  Microsoft-Windows-AppLocker/MSI and Script
Get-WinEvent -LogName 'Microsoft-Windows-AppLocker/MSI and Script' -MaxEvents 50
IDs útiles: 8003/8006 = se permitiría pero violaría regla (modo auditoría); 8004/8007 = bloqueado (enforcement). Cuando los logs estén limpios, pasas a enforcement.
Desactivar
powershell# Vaciar toda la política local (crear XML vacío y aplicarlo)
$empty = [xml]'<AppLockerPolicy Version="1"></AppLockerPolicy>'
Set-AppLockerPolicy -XmlPolicy ($empty.OuterXml | Out-File temp.xml; "temp.xml")
# y opcionalmente detener el servicio
Stop-Service AppIDSvc
Por GPO basta con poner las colecciones de reglas en "No configurado" o quitar el enforcement.
AppLocker vs WDAC — cuál usar
Microsoft posiciona WDAC (App Control for Business) como el control estratégico y recomendado, y AppLocker como complemento. Diferencias prácticas:
AppLocker es más fácil y rápido de desplegar, se gestiona por usuario/grupo, pero es menos resistente a un atacante con privilegios de administrador local (puede pararse manipulando el servicio). WDAC se aplica a nivel de kernel, es mucho más difícil de evadir incluso con admin, y también impone CLM en PowerShell, pero es más complejo de mantener. El patrón recomendado por Microsoft es WDAC como capa principal + AppLocker para refinar por usuario donde WDAC no llega.
Para un Standard standalone donde quieres algo funcional rápido, AppLocker en enforcement con reglas de script ya te da el CLM y bloquea binarios no firmados. Para máxima robustez, WDAC.
¿Quieres que incluya AppLocker (servicio + política efectiva + lectura de los logs de bloqueo) en ese script de auditoría que te ofrecí, para que el informe cubra también el control de aplicaciones?

Identidad y credenciales
Credential Guard — Por defecto SÍ, pero solo si: hardware compatible + unido a dominio + no es DC. Standalone → NO.
VBS (Virtualization-Based Security) — Por defecto SÍ cuando se activa Credential Guard (lo enciende automáticamente). Standalone → NO de forma automática.
HVCI / Integridad de memoria — Por defecto SÍ en sistemas compatibles.
LSASS protegido (RunAsPPL) — Por defecto parcial; conviene forzarlo. No siempre activo en standalone.
LAPS (rotación de admin local) — Por defecto NO. Hay que configurarlo (GPO/Intune).
Contraseñas aleatorias de cuenta de máquina (AD) — Por defecto SÍ en entorno de dominio.
Active Directory (si es DC o miembro)
Cifrado LDAP obligatorio — Por defecto SÍ.
TLS 1.3 para LDAP over TLS — Por defecto SÍ (soportado).
Conexiones cifradas para atributos confidenciales — Por defecto SÍ.
Kerberos PKINIT con agilidad criptográfica — Por defecto SÍ.
Control de aplicaciones (containment)
AppLocker — Por defecto NO. Servicio AppIDSvc en manual, sin reglas. Requiere configuración + enforcement.
WDAC / App Control for Business — Por defecto NO. Opt-in total.
Constrained Language Mode — Por defecto NO activo; se impone automáticamente cuando AppLocker/WDAC están en enforcement.
Reglas ASR (Attack Surface Reduction) — Por defecto NO (ninguna regla activa de fábrica). Hay que habilitarlas una a una.
PowerShell
PowerShell 2.0 retirado — Por defecto SÍ en instalaciones limpias. In-place upgrade puede conservarlo → verificar.
AMSI — Por defecto SÍ (si Defender está activo, que lo está).
Script Block Logging — Por defecto NO. Opt-in vía GPO.
Module Logging / Transcription / Protected Event Logging — Por defecto NO.
Execution Policy — Por defecto RemoteSigned en servidor (medida débil, no es control real).
JEA — Por defecto NO. Opt-in.
Red y protocolos
SMB signing (servidor) — Reforzado en WS2025; auditable. Verificar enforcement.
SMB over QUIC — Disponible ahora también en Standard (antes solo Azure Edition). Opt-in.
Firewall de Windows — Por defecto SÍ, los tres perfiles activos.
TLS server auth con RSA ≥ 2048 bits — Por defecto SÍ (rechaza claves débiles).
OpenSSH server — Instalado por defecto, pero el servicio sshd está desactivado hasta que lo habilites. Reduce esto si no lo usas.
SMB 1.0 — Por defecto NO instalado/deshabilitado en versiones modernas.
Arranque y plataforma
Secure Boot — Depende del firmware UEFI; recomendado, no garantizado de fábrica. Verificar.
TPM (Measured Boot) — Depende de hardware. Base de las defensas VBS.
HVPT (Hypervisor-Enforced Paging Translation) — Disponible en hardware moderno; protege contra write-what-where.
Enclaves VBS — Disponibles; los usan apps que los implementen.
Antimalware
Microsoft Defender Antivirus — Por defecto SÍ, con protección en tiempo real.
Defender protección en la nube / sample submission — Por defecto SÍ habitualmente.
Gestión y baseline
OSConfig + Security Baseline (350+ ajustes) — Por defecto NO aplicado. Es opt-in: hay que desplegarlo (Set-OSConfigDesiredConfiguration). El SO viene "secure by default" en lo de arriba, pero los 350+ ajustes del baseline son explícitos.
Hotpatch (sin reinicio) — Por defecto NO; requiere Azure Arc y habilitarlo.

Resumen mental: lo que viene activo de fábrica es sobre todo la capa de plataforma/identidad en entornos de dominio (Credential Guard, VBS, HVCI, AD cifrado, Defender, Firewall, TLS estricto, PS 2.0 fuera). Lo que es siempre opt-in y donde está el grueso del hardening real: AppLocker/WDAC, ASR, logging de PowerShell, JEA, LAPS, y el baseline OSConfig.
Para un Standard standalone específicamente, lo que probablemente NO tendrás activo aunque creas que sí: Credential Guard/VBS (falta domain-join), LAPS, AppLocker/WDAC, ASR, y todo el logging de PowerShell.
