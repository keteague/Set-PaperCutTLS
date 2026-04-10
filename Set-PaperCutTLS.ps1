#Requires -Version 5.1
<#
.SYNOPSIS
    Installs a TLS/SSL certificate on PaperCut Print Deploy and/or the
    PaperCut Application Server (MF/NG) from any common certificate format.

.DESCRIPTION
    Supports all three PaperCut components in a single pass:

    Print Deploy  (Target = PrintDeploy | All)
    ─────────────────────────────────────────────
    Drops tls.cer and tls.pem into:
      [app-path]\providers\print-deploy\win\data\cert-custom\
    Service: pc-print-deploy

    Mobility Print  (Target = MobilityPrint | All)
    ───────────────────────────────────────────────
    Drops tls.cer and tls.pem directly into:
      [mobility-path]\data\
    (no cert-custom subfolder — files go straight into data\)
    Service: PCMobilityPrint
    Installing a trusted cert on Mobility Print also upgrades job delivery
    from IPP/HTTP to IPPS/HTTPS on port 9164 automatically.

    Application Server  (Target = AppServer | All)
    ────────────────────────────────────────────────
    Builds a JKS keystore from the certificate using PaperCut's bundled
    keytool, places it in [app-path]\server\custom\, and updates
    server.properties with the keystore path and passwords.
    PaperCut MF 23.0+ auto-encrypts plain-text passwords on next restart.
    Service: PaperCut Application Server

    All three targets share the same cert-resolution pipeline (input modes,
    Let's Encrypt scanning, format detection/conversion). OpenSSL is required
    for PFX/DER/P7B/CERTSTORE inputs. For App Server, OpenSSL is also needed
    to repack PEM files into PKCS12 before keytool can import them.

    Input Modes
    ───────────
    LETSENCRYPT  Certbot/Win-ACME folder. Picks the cert with the latest
                 NotAfter, matches its key, archives expired pairs if asked.
                 Print Deploy: no OpenSSL needed.
                 App Server:   OpenSSL needed (PEM -> PKCS12 -> JKS).

    PFX_FILE     Existing .pfx/.p12. OpenSSL splits cert + key for PD;
                 keytool imports directly for App Server.

    CERTSTORE    Export from Windows cert store by thumbprint, then PFX path.

    PEMS_READY   tls.cer + tls.pem already prepared. App Server still needs
                 OpenSSL to repack them for keytool.

    AUTO         Detect format from file path and route accordingly.

    Format detection covers: PEM fullchain, PEM cert, PEM key, DER, PFX, P7B.
    OpenSSL is located automatically; if missing, an interactive prompt shows
    install options. Nothing is ever installed automatically.

.PARAMETER Target
    Which component(s) to configure.
    PrintDeploy | MobilityPrint | AppServer | All
    "Both" is retained as a deprecated alias for All.    Default: All

.PARAMETER MobilityPrintInstallPath
    Install root of the standalone Mobility Print server.
    Default: C:\Program Files (x86)\PaperCut Mobility Print

.PARAMETER MobilityPrintServiceName
    Windows service name for Mobility Print.  Default: PCMobilityPrint

.PARAMETER InputMode
    LETSENCRYPT | PFX_FILE | CERTSTORE | PEMS_READY | AUTO

.PARAMETER LetsEncryptPath
    Certbot/Win-ACME cert folder. Required when InputMode = LETSENCRYPT.

.PARAMETER LetsEncryptKeyPath
    Explicit private key path. Inferred from naming patterns if omitted.

.PARAMETER SAN
    Subject Alternative Name / domain to search for (e.g. papercut.contoso.com).
    When InputMode = LETSENCRYPT and -LetsEncryptPath is not supplied, the script
    searches these common ACME client locations automatically:
      Posh-ACME  : %LOCALAPPDATA%\Posh-ACME\*\*\<domain>\
      Certbot    : C:\Certbot\archive\<domain>\  and  C:\Certbot\live\<domain>\
      Win-ACME   : C:\ProgramData\win-acme\*\Certificates\  (flat, SAN-scanned)
    When -LetsEncryptPath IS supplied, -SAN still filters and validates the
    selected certificate to ensure it covers the specified domain.

.PARAMETER PfxPath
    Path to .pfx/.p12. Required when InputMode = PFX_FILE.

.PARAMETER CertThumbprint
    LocalMachine\My thumbprint. Required when InputMode = CERTSTORE.

.PARAMETER PfxPassword
    PFX password (SecureString). Prompted if omitted.

.PARAMETER AutoCertPath
    Cert file for InputMode = AUTO.

.PARAMETER AutoKeyPath
    Companion private key for AUTO when cert does not embed the key.

.PARAMETER ReadyTlsCer
    Prepared tls.cer. Required when InputMode = PEMS_READY.

.PARAMETER ReadyTlsPem
    Prepared tls.pem. Required when InputMode = PEMS_READY.

.PARAMETER PaperCutInstallPath
    PaperCut MF/NG install root.  Default: C:\Program Files\PaperCut MF

.PARAMETER PaperCutOS
    OS subfolder under providers\print-deploy\.  Default: win

.PARAMETER PrintDeployServiceName
    Print Deploy Windows service name.  Default: pc-print-deploy

.PARAMETER AppServerServiceName
    Application Server Windows service name.
    Default: PaperCut Application Server

.PARAMETER KeystoreName
    JKS keystore filename placed in server\custom\.
    Default: my-ssl-keystore

.PARAMETER KeystorePassword
    Password for the new JKS keystore (SecureString). Prompted if omitted.
    PaperCut 23+ encrypts this automatically on next service start.

.PARAMETER KeyPassword
    Password for the key entry inside the keystore. Defaults to the same
    value as KeystorePassword if omitted.

.PARAMETER OpenSslPath
    Explicit path to openssl.exe. Common install locations are searched
    automatically if omitted.

.PARAMETER ArchiveExpired
    Move expired cert/key pairs in the LE folder to -ArchiveSubfolder.

.PARAMETER ArchiveSubfolder
    Archive subfolder name inside the LE cert folder.  Default: _archive

.PARAMETER ArchiveMinAgeDays
    Only archive certs expired more than this many days ago.  Default: 0

.PARAMETER LogPath
    CSV audit log.  Default: C:\Logs\PaperCutTLS.csv

.PARAMETER WorkDir
    Temp directory for intermediate files.  Default: $env:TEMP\PaperCutTLS

.PARAMETER SkipMissingTargets
    When set, a missing install path for any target is treated as a warning
    and that target is skipped rather than aborting. Useful on servers where
    only some PaperCut components are installed, or for testing without a
    full PaperCut install present.

.PARAMETER Clean
    Undo all changes made by previous runs and restore each target to its
    pre-installation state. Restores the most recent timestamped backup if
    one exists; otherwise removes the deployed files and reverts
    server.properties so PaperCut falls back to its built-in self-signed cert.
    Can be combined with -DryRun to preview what would be removed/restored.
    Cannot be combined with InputMode-related parameters.

.PARAMETER DryRun
    Preview all actions without making any changes.

.EXAMPLE
    # ── DRY RUN — both targets, Let's Encrypt source ────────────────────────
    #
    #   .\Set-PaperCutTLS.ps1 `
    #       -Target          All `
    #       -InputMode       LETSENCRYPT `
    #       -SAN             'papercut.contoso.com' `
    #       -ArchiveExpired `
    #       -DryRun
    #
    #   Representative output:
    #
    #   2026-04-09 09:20:00 [INFO ] ==============================================
    #   2026-04-09 09:20:00 [INFO ]  PaperCut TLS Certificate Installer
    #   2026-04-09 09:20:00 [DRY  ] DRY RUN MODE — no changes will be made
    #   2026-04-09 09:20:00 [INFO ] Target       : All
    #   2026-04-09 09:20:00 [INFO ] Input mode   : LETSENCRYPT
    #   ── Cert Resolution ──────────────────────────────────────────────────────
    #   2026-04-09 09:20:00 [INFO ] Scanning LE folder: C:\Certbot\archive\...
    #   2026-04-09 09:20:00 [INFO ] Found 3 cert file(s):
    #   2026-04-09 09:20:00 [INFO ]   [1] fullchain1.pem  NotAfter: 2025-08-15  EXPIRED
    #   2026-04-09 09:20:00 [INFO ]   [2] fullchain2.pem  NotAfter: 2025-11-13  EXPIRED
    #   2026-04-09 09:20:00 [INFO ]   [3] fullchain3.pem  NotAfter: 2026-05-09  VALID   <- SELECTED
    #   2026-04-09 09:20:00 [INFO ] Matched private key: privkey3.pem
    #   2026-04-09 09:20:00 [INFO ] Format: PEM fullchain + PEM key
    #   2026-04-09 09:20:00 [INFO ] Archiving expired certs (MinAgeDays=0)...
    #   2026-04-09 09:20:00 [DRY  ] Would archive: fullchain1.pem -> _archive\fullchain1.pem
    #   2026-04-09 09:20:00 [DRY  ] Would archive: privkey1.pem   -> _archive\privkey1.pem
    #   2026-04-09 09:20:00 [DRY  ] Would archive: fullchain2.pem -> _archive\fullchain2.pem
    #   2026-04-09 09:20:00 [DRY  ] Would archive: privkey2.pem   -> _archive\privkey2.pem
    #   ── Print Deploy ─────────────────────────────────────────────────────────
    #   2026-04-09 09:20:00 [DRY  ] Would stop service: pc-print-deploy
    #   2026-04-09 09:20:00 [DRY  ] Would backup: tls.cer -> tls.cer.bak_20260409.old
    #   2026-04-09 09:20:00 [DRY  ] Would backup: tls.pem -> tls.pem.bak_20260409.old
    #   2026-04-09 09:20:00 [DRY  ] Would deploy tls.cer: fullchain3.pem -> cert-custom\tls.cer
    #   2026-04-09 09:20:00 [DRY  ] Would deploy tls.pem: privkey3.pem   -> cert-custom\tls.pem
    #   2026-04-09 09:20:00 [DRY  ] Would start service: pc-print-deploy
    #   ── Mobility Print ───────────────────────────────────────────────────────
    #   2026-04-09 09:20:00 [DRY  ] Would stop service: PCMobilityPrint
    #   2026-04-09 09:20:00 [DRY  ] Would backup: tls.cer -> tls.cer.bak_20260409.old
    #   2026-04-09 09:20:00 [DRY  ] Would backup: tls.pem -> tls.pem.bak_20260409.old
    #   2026-04-09 09:20:00 [DRY  ] Would deploy tls.cer: fullchain3.pem -> data\tls.cer
    #   2026-04-09 09:20:00 [DRY  ] Would deploy tls.pem: privkey3.pem   -> data\tls.pem
    #   2026-04-09 09:20:00 [DRY  ] Would start service: PCMobilityPrint
    #   ── Application Server ───────────────────────────────────────────────────
    #   2026-04-09 09:20:00 [INFO ] [APP SERVER] OpenSSL: C:\Program Files\Git\usr\bin\openssl.exe
    #   2026-04-09 09:20:00 [DRY  ] Would run: openssl pkcs12 -export ... (PEM -> PKCS12)
    #   2026-04-09 09:20:00 [INFO ] Keytool: C:\...\runtime\jre\bin\keytool.exe
    #   2026-04-09 09:20:00 [DRY  ] Would run: keytool -importkeystore ... (PKCS12 -> JKS)
    #   2026-04-09 09:20:00 [DRY  ] Would stop service: PaperCut Application Server
    #   2026-04-09 09:20:00 [DRY  ] Would backup: my-ssl-keystore -> my-ssl-keystore.bak_20260409
    #   2026-04-09 09:20:00 [DRY  ] Would copy keystore to: server\custom\my-ssl-keystore
    #   2026-04-09 09:20:00 [DRY  ] Would update server.properties (ssl keys)
    #   2026-04-09 09:20:00 [DRY  ] Would start service: PaperCut Application Server
    #   ─────────────────────────────────────────────────────────────────────────
    #   2026-04-09 09:20:00 [INFO ]  <- Dry run complete. Re-run without -DryRun to apply.

.EXAMPLE
    # All targets — auto-discover cert by SAN, archive certs older than 7 days
    .\Set-PaperCutTLS.ps1 -Target All -InputMode LETSENCRYPT `
        -SAN            'papercut.contoso.com' `
        -ArchiveExpired -ArchiveMinAgeDays 7

.EXAMPLE
    # Explicit path with SAN validation (ensures selected cert covers the domain)
    .\Set-PaperCutTLS.ps1 -Target All -InputMode LETSENCRYPT `
        -SAN             'papercut.contoso.com' `
        -LetsEncryptPath 'C:\Certbot\archive\papercut.contoso.com'

.EXAMPLE
    # Print Deploy only, from PFX
    .\Set-PaperCutTLS.ps1 -Target PrintDeploy -InputMode PFX_FILE `
        -PfxPath "C:\Certs\print.contoso.com.pfx"

.EXAMPLE
    # Mobility Print only (separate install on a different server)
    .\Set-PaperCutTLS.ps1 -Target MobilityPrint -InputMode LETSENCRYPT `
        -LetsEncryptPath       "C:\Certbot\archive\print.contoso.com" `
        -MobilityPrintInstallPath "C:\Program Files (x86)\PaperCut Mobility Print"

.EXAMPLE
    # App Server only, from Windows cert store
    .\Set-PaperCutTLS.ps1 -Target AppServer -InputMode CERTSTORE `
        -CertThumbprint "A1B2C3D4E5F6..."

.EXAMPLE
    # All targets, auto-detect a DER cert with separate PEM key
    .\Set-PaperCutTLS.ps1 -Target All -InputMode AUTO `
        -AutoCertPath "C:\Certs\print.contoso.com.der" `
        -AutoKeyPath  "C:\Certs\print.contoso.com.key"

.EXAMPLE
    # Preview what Clean would remove/restore without making any changes
    .\Set-PaperCutTLS.ps1 -Clean -Target All -DryRun

.EXAMPLE
    # Full clean — restore all targets to factory cert state
    .\Set-PaperCutTLS.ps1 -Clean -Target All

.EXAMPLE
    # Clean Print Deploy only, leave App Server alone
    .\Set-PaperCutTLS.ps1 -Clean -Target PrintDeploy
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    # ── Target component(s) ──────────────────────────────────────────────────
    # All  = Print Deploy + Mobility Print + Application Server
    # Both = alias for All (deprecated; use All)
    [ValidateSet('PrintDeploy','MobilityPrint','AppServer','All','Both')]
    [string]$Target = 'All',

    # ── Input Mode ───────────────────────────────────────────────────────────
    [ValidateSet('LETSENCRYPT','PFX_FILE','CERTSTORE','PEMS_READY','AUTO')]
    [string]$InputMode = 'LETSENCRYPT',

    # LETSENCRYPT
    [string]$LetsEncryptPath    = '',
    [string]$LetsEncryptKeyPath = '',

    # SAN-based auto-discovery: when InputMode = LETSENCRYPT and LetsEncryptPath
    # is not given, the script searches common ACME client storage locations for
    # a certificate whose Subject/SAN covers this domain.
    # Also used to validate/filter cert selection when LetsEncryptPath IS given.
    [string]$SAN = '',

    # PFX_FILE
    [string]$PfxPath = '',

    # CERTSTORE
    [string]$CertThumbprint = '',

    # Shared PFX password (PFX_FILE, CERTSTORE, and intermediate conversions)
    [System.Security.SecureString]$PfxPassword,

    # AUTO
    [string]$AutoCertPath = '',
    [string]$AutoKeyPath  = '',

    # PEMS_READY
    [string]$ReadyTlsCer = '',
    [string]$ReadyTlsPem = '',

    # ── PaperCut paths ────────────────────────────────────────────────────────
    [string]$PaperCutInstallPath = 'C:\Program Files\PaperCut MF',
    [string]$PaperCutOS          = 'win',

    # ── Service names ─────────────────────────────────────────────────────────
    [string]$PrintDeployServiceName   = 'pc-print-deploy',
    [string]$MobilityPrintServiceName = 'PCMobilityPrint',
    [string]$AppServerServiceName     = 'PaperCut Application Server',

    # ── Mobility Print install path ───────────────────────────────────────────
    # Standalone install — separate from the PaperCut MF/NG install root.
    # tls.cer and tls.pem are placed directly in <path>\data\ (no cert-custom subfolder).
    [string]$MobilityPrintInstallPath = 'C:\Program Files (x86)\PaperCut Mobility Print',

    # ── App Server keystore ───────────────────────────────────────────────────
    [string]$KeystoreName = 'my-ssl-keystore',
    [System.Security.SecureString]$KeystorePassword,
    [System.Security.SecureString]$KeyPassword,          # defaults to KeystorePassword if null

    # ── OpenSSL ───────────────────────────────────────────────────────────────
    [string]$OpenSslPath = '',

    # ── LE Archive ────────────────────────────────────────────────────────────
    [switch]$ArchiveExpired,
    [string]$ArchiveSubfolder = '_archive',
    [int]$ArchiveMinAgeDays   = 0,

    # ── Logging & Work ────────────────────────────────────────────────────────
    [string]$LogPath = 'C:\Logs\PaperCutTLS.csv',
    [string]$WorkDir = "$env:TEMP\PaperCutTLS",

    # ── Resilience ────────────────────────────────────────────────────────────
    # When set, a missing install path for any target is logged as a warning
    # and that target is skipped rather than aborting the entire run.
    # Useful on servers where only some PaperCut components are installed,
    # or during initial testing without a full PaperCut install present.
    [switch]$SkipMissingTargets,

    # ── Clean ─────────────────────────────────────────────────────────────────
    # Undo all changes made by previous runs of this script and restore each
    # target to its pre-installation state:
    #   Print Deploy    : restores backed-up tls.cer/tls.pem in cert-custom\, or
    #                     deletes them so PaperCut falls back to its built-in cert.
    #   Mobility Print  : same treatment for data\tls.cer and data\tls.pem.
    #   App Server      : restores backed-up server.properties and keystore, or
    #                     comments out the ssl.* keys and removes the custom keystore.
    # The work directory ($WorkDir) is also purged.
    # Can be combined with -DryRun to preview what would be removed.
    [switch]$Clean,

    # ── Dry Run ───────────────────────────────────────────────────────────────
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ─────────────────────────────────────────────────────────────────────────────
# REGION: Logging
# ─────────────────────────────────────────────────────────────────────────────

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $ts     = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $prefix = switch ($Level) {
        'INFO'  { '[INFO ]' }
        'WARN'  { '[WARN ]' }
        'ERROR' { '[ERROR]' }
        'DRY'   { '[DRY  ]' }
        default { '[-----]' }
    }
    $color = switch ($Level) {
        'WARN'  { 'Yellow' }
        'ERROR' { 'Red'    }
        'DRY'   { 'Cyan'   }
        default { 'White'  }
    }
    Write-Host "$ts $prefix $Message" -ForegroundColor $color
}

function Write-AuditLog {
    param([string]$Action, [string]$Status, [string]$Detail = '')
    $dir = Split-Path $LogPath -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [PSCustomObject]@{
        Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Action    = $Action
        Status    = $Status
        Detail    = $Detail
        DryRun    = $DryRun.IsPresent
        User      = $env:USERNAME
        Computer  = $env:COMPUTERNAME
    } | Export-Csv -Path $LogPath -Append -NoTypeInformation -Force
}

# ─────────────────────────────────────────────────────────────────────────────
# REGION: OpenSSL — Locate and Interactive Prompt
# ─────────────────────────────────────────────────────────────────────────────

function Find-OpenSsl {
    $candidates = @(
        $OpenSslPath,
        'C:\Program Files\OpenSSL-Win64\bin\openssl.exe',
        'C:\Program Files\OpenSSL\bin\openssl.exe',
        'C:\OpenSSL-Win64\bin\openssl.exe',
        'C:\OpenSSL\bin\openssl.exe',
        "$env:ProgramFiles\Git\usr\bin\openssl.exe",
        "$env:ProgramFiles\Git\mingw64\bin\openssl.exe",
        'C:\ProgramData\chocolatey\lib\openssl.light\tools\openssl.exe',
        'C:\ProgramData\chocolatey\bin\openssl.exe'
    )
    foreach ($p in $candidates) {
        if (-not [string]::IsNullOrWhiteSpace($p) -and (Test-Path $p)) { return $p }
    }
    try { return (Get-Command openssl -ErrorAction Stop).Source } catch {}
    return $null
}

function Require-OpenSsl {
    $path = Find-OpenSsl
    if ($path) {
        Write-Log "OpenSSL: $path"
        return $path
    }
    Write-Host ''
    Write-Host '+--------------------------------------------------------------+' -ForegroundColor Yellow
    Write-Host '|  OpenSSL is required but was not found on this system.       |' -ForegroundColor Yellow
    Write-Host '|                                                              |' -ForegroundColor Yellow
    Write-Host '|  Install options (run elevated, then re-run this script):    |' -ForegroundColor Yellow
    Write-Host '|   Chocolatey : choco install openssl.light                  |' -ForegroundColor Yellow
    Write-Host '|   Winget     : winget install ShiningLight.OpenSSL.Light     |' -ForegroundColor Yellow
    Write-Host '|   Git/Win    : bundled at <Git>\usr\bin\openssl.exe          |' -ForegroundColor Yellow
    Write-Host '|   Manual     : https://slproweb.com/products/Win32OpenSSL    |' -ForegroundColor Yellow
    Write-Host '|                                                              |' -ForegroundColor Yellow
    Write-Host '|  Re-run with: -OpenSslPath "C:\path\to\openssl.exe"          |' -ForegroundColor Yellow
    Write-Host '+--------------------------------------------------------------+' -ForegroundColor Yellow
    Write-Host ''
    $answer = Read-Host 'Open the OpenSSL download page now? (Y = open / N = abort)'
    if ($answer -match '^[Yy]') {
        Start-Process 'https://slproweb.com/products/Win32OpenSSL.html'
        Write-Log 'Download page opened. Install OpenSSL then re-run.' 'WARN'
    }
    throw 'OpenSSL required but not installed. Aborted.'
}

function Invoke-OpenSsl {
    param([string]$OpenSsl, [string[]]$Arguments, [string]$Description)
    Write-Log "OpenSSL: $Description"
    if ($DryRun) { Write-Log "Would run: openssl $($Arguments -join ' ')" 'DRY'; return }
    $result = & $OpenSsl @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw "OpenSSL failed [$Description]: $result" }
}

# ─────────────────────────────────────────────────────────────────────────────
# REGION: Keytool — PaperCut Bundled JRE
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# REGION: Keytool — PaperCut Bundled JRE
# ─────────────────────────────────────────────────────────────────────────────

function Find-Keytool {
    # PaperCut bundles its own JRE — use that first to ensure version compatibility
    $bundled = Join-Path $PaperCutInstallPath 'runtime\jre\bin\keytool.exe'
    if (Test-Path $bundled) { return $bundled }
    try { return (Get-Command keytool -ErrorAction Stop).Source } catch {}
    return $null
}

function Require-Keytool {
    $path = Find-Keytool
    if ($path) { Write-Log "Keytool: $path"; return $path }
    throw "keytool.exe not found.`nExpected at: $PaperCutInstallPath\runtime\jre\bin\keytool.exe`nVerify -PaperCutInstallPath."
}

function Invoke-Keytool {
    param([string]$Keytool, [string[]]$Arguments, [string]$Description)
    Write-Log "Keytool: $Description"
    if ($DryRun) {
        $passwordFlags = @('-srcstorepass','-deststorepass','-destkeypass','-storepass','-keypass')
        $masked = for ($i = 0; $i -lt $Arguments.Count; $i++) {
            if ($Arguments[$i] -in $passwordFlags -and $i + 1 -lt $Arguments.Count) {
                $Arguments[$i]; '<hidden>'; $i++
            } else { $Arguments[$i] }
        }
        Write-Log "Would run: keytool $($masked -join ' ')" 'DRY'
        return
    }

    # Use Start-Process with file-based redirection so Java's output is fully captured.
    # PowerShell's 2>&1 operator does not reliably capture Java stderr in PS 5.1.
    $stdoutFile = [System.IO.Path]::GetTempFileName()
    $stderrFile = [System.IO.Path]::GetTempFileName()
    try {
        $proc = Start-Process -FilePath $Keytool -ArgumentList $Arguments `
            -RedirectStandardOutput $stdoutFile `
            -RedirectStandardError  $stderrFile `
            -Wait -PassThru -NoNewWindow
        $stdout = (Get-Content $stdoutFile -Raw -EA SilentlyContinue) -replace '\r\n',"`n"
        $stderr = (Get-Content $stderrFile -Raw -EA SilentlyContinue) -replace '\r\n',"`n"
        if ($stdout) { $stdout.Split("`n") | Where-Object { $_ } | ForEach-Object { Write-Log "  [out] $_" } }
        if ($stderr) { $stderr.Split("`n") | Where-Object { $_ } | ForEach-Object { Write-Log "  [err] $_" 'WARN' } }
        if ($proc.ExitCode -ne 0) {
            throw "keytool failed [$Description] (exit $($proc.ExitCode)):`nSTDOUT: $stdout`nSTDERR: $stderr"
        }
    } finally {
        Remove-Item $stdoutFile,$stderrFile -Force -EA SilentlyContinue
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# REGION: PaperCut create-ssl-keystore (preferred) + keytool fallback
# ─────────────────────────────────────────────────────────────────────────────

# PaperCut ships create-ssl-keystore in server\bin\ — it accepts PEM files
# directly and produces a JKS keystore without any OpenSSL involvement.
# This completely avoids the OpenSSL 3.x PKCS12 / legacy provider issues.
function Find-CreateSslKeystore {
    foreach ($subdir in @('server\bin\win', 'server\bin')) {
        foreach ($name in @('create-ssl-keystore.exe', 'create-ssl-keystore.bat', 'create-ssl-keystore')) {
            $p = Join-Path $PaperCutInstallPath "$subdir\$name"
            if (Test-Path $p) { return $p }
        }
    }
    return $null
}

function Invoke-CreateSslKeystore {
    # create-ssl-keystore.exe may write the keystore relative to ITS OWN directory
    # (server\bin\win\) rather than to the working directory or server\custom\.
    # We clean up all candidate locations before running and search all of them after.
    param([string]$Tool, [string]$TlsCer, [string]$TlsPem,
          [string]$KsPass, [string]$KeyPass, [string]$DestKeystore)

    $toolDir = Split-Path $Tool -Parent

    $cskArgs = @(
        '-f',
        '-k',                $DestKeystore,
        '-cert',             $TlsCer,
        '-key',              $TlsPem,
        '-keypass',          $KeyPass,
        '-keystorepass',     $KsPass,
        '-keystorekeypass',  $KsPass,
        '-keystoreentry',   'standard'
    )

    if ($DryRun) {
        Write-Log "Would run: create-ssl-keystore $($cskArgs -join ' ')" 'DRY'
        return
    }

    # All locations the tool might write to or try to open as an existing keystore.
    # We delete them all so the tool always starts with no pre-existing file.
    $candidatePaths = @(
        $DestKeystore,                             # server\custom\my-ssl-keystore
        (Join-Path $toolDir  'my-ssl-keystore'),   # server\bin\win\my-ssl-keystore  ← most likely
        (Join-Path $WorkDir  'my-ssl-keystore'),
        (Join-Path $WorkDir  'my-ssl-keystore.new')
    )
    foreach ($p in $candidatePaths) {
        if (Test-Path $p) {
            Remove-Item $p -Force -EA SilentlyContinue
            Write-Log "Removed stale keystore: $p"
        }
    }

    Write-Log "[APP SERVER] Running create-ssl-keystore..."
    $result = & $Tool @cskArgs 2>&1
    $result | ForEach-Object { Write-Log "  csk: $($_.ToString())" }
    if ($LASTEXITCODE -ne 0) {
        $errorText = ($result | ForEach-Object { $_.ToString() }) -join "`n"
        throw "create-ssl-keystore failed:`n$errorText"
    }

    # Search all candidate output locations for the newly created keystore.
    $found = $candidatePaths | Where-Object { Test-Path $_ } | Select-Object -First 1
    if ($found) {
        if ($found -ne $DestKeystore) {
            $destDir = Split-Path $DestKeystore -Parent
            if (-not (Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
            Move-Item $found $DestKeystore -Force
            Write-Log "[APP SERVER] Moved keystore from $found to: $DestKeystore"
        }
    } else {
        throw "create-ssl-keystore completed but keystore not found in any expected location:`n  $($candidatePaths -join "`n  ")"
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# REGION: Certificate Format Detection
# ─────────────────────────────────────────────────────────────────────────────

function Get-CertFormat {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return 'UNKNOWN' }
    try {
        $text = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::ASCII)
        if ($text -match '-----BEGIN') {
            if ($text -match '-----BEGIN PKCS7-----')              { return 'PEM_P7B'      }
            if ($text -match '-----BEGIN.{0,30}PRIVATE KEY-----')  { return 'PEM_KEY'      }
            $n = ([regex]'-----BEGIN CERTIFICATE-----').Matches($text).Count
            if ($n -ge 2)  { return 'PEM_FULLCHAIN' }
            if ($n -eq 1)  { return 'PEM_CERT'      }
            return 'PEM_UNKNOWN'
        }
    } catch {}
    try {
        $c = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($Path)
        return 'DER'
    } catch {}
    try {
        $f = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet
        $c = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($Path, [string]::Empty, $f)
        return 'PFX'
    } catch {}
    switch ([System.IO.Path]::GetExtension($Path).ToLower()) {
        { $_ -in @('.pfx','.p12') } { return 'PFX'     }
        { $_ -in @('.p7b','.p7c') } { return 'PEM_P7B' }
    }
    return 'UNKNOWN'
}

function Get-CertNotAfter {
    param([string]$Path)
    try {
        switch (Get-CertFormat $Path) {
            { $_ -in @('PEM_CERT','PEM_FULLCHAIN') } {
                $text = Get-Content $Path -Raw
                if ($text -match '-----BEGIN CERTIFICATE-----\r?\n?([\s\S]+?)\r?\n?-----END CERTIFICATE-----') {
                    $b = [Convert]::FromBase64String(($Matches[1] -replace '\r?\n',''))
                    $c = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($b)
                    return $c.NotAfter
                }
            }
            'DER' {
                $c = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($Path)
                return $c.NotAfter
            }
        }
    } catch {}
    return [DateTime]::MinValue
}

# ─────────────────────────────────────────────────────────────────────────────
# REGION: Let's Encrypt — Scan, Select, Archive
# ─────────────────────────────────────────────────────────────────────────────

$script:CertExt      = @('.pem','.cer','.crt','.der')
$script:KeyExt       = @('.pem','.key')             # extensions that may be private keys
$script:KeyTokens    = @('privkey','private','key')

# Returns $true if the first cert in the file has BasicConstraints CA:TRUE
# Used to exclude intermediate/root CA certs from leaf-cert selection.
function Test-IsCACert {
    param([string]$Path)
    try {
        $text = Get-Content $Path -Raw -ErrorAction Stop
        if ($text -match '-----BEGIN CERTIFICATE-----\r?\n?([\s\S]+?)\r?\n?-----END CERTIFICATE-----') {
            $b  = [Convert]::FromBase64String(($Matches[1] -replace '\r?\n',''))
            $c  = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($b)
            $bc = $c.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' }
            if ($bc) {
                $bcExt = [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]$bc
                return $bcExt.CertificateAuthority
            }
        }
    } catch {}
    return $false
}

# ── Domain / SAN matching ────────────────────────────────────────────────────

# Returns $true if $Pattern (which may be a wildcard like *.contoso.com)
# matches $Domain.  Wildcard matching is single-label only per RFC 6125.
function Test-DomainMatch {
    param([string]$Pattern, [string]$Domain)
    if ([string]::IsNullOrWhiteSpace($Pattern) -or [string]::IsNullOrWhiteSpace($Domain)) { return $false }
    $Pattern = $Pattern.Trim().ToLower()
    $Domain  = $Domain.Trim().ToLower()
    if ($Pattern -eq $Domain) { return $true }
    # Wildcard: *.contoso.com covers sub.contoso.com but NOT sub.sub.contoso.com
    if ($Pattern -match '^\*\.(.+)$') {
        $base = $Matches[1]
        if ($Domain -match "^[^.]+\.$([regex]::Escape($base))$") { return $true }
    }
    return $false
}

# Returns $true if the leaf certificate in $Path covers $Domain (CN or SAN).
function Test-CertCoversDomain {
    param([string]$Path, [string]$Domain)
    if ([string]::IsNullOrWhiteSpace($Domain)) { return $true }   # no filter — always pass
    try {
        $text = Get-Content $Path -Raw -ErrorAction Stop
        if ($text -match '-----BEGIN CERTIFICATE-----\r?\n?([\s\S]+?)\r?\n?-----END CERTIFICATE-----') {
            $b    = [Convert]::FromBase64String(($Matches[1] -replace '\r?\n',''))
            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($b)

            # Check Subject CN
            $cn = $cert.GetNameInfo(
                [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
            if (Test-DomainMatch -Pattern $cn -Domain $Domain) { return $true }

            # Check SAN extension (OID 2.5.29.17)
            $sanExt = $cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' }
            if ($sanExt) {
                # Format() returns e.g. "DNS Name=sub.contoso.com, DNS Name=*.contoso.com"
                foreach ($entry in ($sanExt.Format($false) -split ',\s*|\n')) {
                    if ($entry -match 'DNS Name=(.+)') {
                        if (Test-DomainMatch -Pattern $Matches[1].Trim() -Domain $Domain) { return $true }
                    }
                }
            }
        }
    } catch {}
    return $false
}

# ── Common ACME client location discovery ────────────────────────────────────

# Searches well-known ACME client storage paths for a folder/set of cert files
# covering $Domain.  Returns an array of [PSCustomObject]@{Path; Source} sorted
# by the NotAfter of the best cert found in each location (newest first).
function Find-CertByDomain {
    param([string]$Domain)

    Write-Log "Searching common ACME locations for: $Domain"
    $candidates = @()

    # ── Posh-ACME ────────────────────────────────────────────────────────────
    # Structure: %LOCALAPPDATA%\Posh-ACME\<server-hash>\<account-id>\<domain>\
    $poshBase = Join-Path $env:LOCALAPPDATA 'Posh-ACME'
    if (Test-Path $poshBase) {
        $domainDirs = Get-ChildItem -Path $poshBase -Recurse -Directory -Depth 3 `
                          -ErrorAction SilentlyContinue |
                      Where-Object { Test-DomainMatch -Pattern $_.Name -Domain $Domain }
        foreach ($d in $domainDirs) {
            $hasCerts = @(Get-ChildItem -Path $d.FullName -File -ErrorAction SilentlyContinue |
                          Where-Object { $_.Extension -in @('.cer','.pem','.key') })
            if ($hasCerts.Count -gt 0) {
                Write-Log "  [Posh-ACME] $($d.FullName)"
                $candidates += [PSCustomObject]@{ Path = $d.FullName; Source = 'Posh-ACME' }
            }
        }
    }

    # ── Certbot ──────────────────────────────────────────────────────────────
    # Structure: C:\Certbot\archive\<domain>\ (numbered renewals)
    #            C:\Certbot\live\<domain>\    (symlinks — prefer archive on Windows)
    foreach ($root in @('C:\Certbot', 'C:\ProgramData\certbot')) {
        foreach ($sub in @('archive', 'live')) {
            $p = Join-Path $root "$sub\$Domain"
            if (Test-Path $p) {
                Write-Log "  [Certbot/$sub] $p"
                $candidates += [PSCustomObject]@{ Path = $p; Source = "Certbot ($sub)" }
            }
        }
    }

    # ── Win-ACME (wacs) ──────────────────────────────────────────────────────
    # Flat Certificates folder; cert filenames embed domain/hash rather than
    # being in per-domain subdirectories.  Scan by SAN content.
    foreach ($root in @('C:\ProgramData\win-acme', 'C:\ProgramData\letsencrypt-win-simple')) {
        if (-not (Test-Path $root)) { continue }
        $certDirs = Get-ChildItem -Path $root -Recurse -Directory -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -eq 'Certificates' }
        foreach ($cd in $certDirs) {
            $matchingFiles = @(Get-ChildItem -Path $cd.FullName -File -ErrorAction SilentlyContinue |
                               Where-Object { $_.Extension -in @('.pem','.cer','.crt') } |
                               Where-Object { Test-CertCoversDomain -Path $_.FullName -Domain $Domain })
            if ($matchingFiles.Count -gt 0) {
                Write-Log "  [Win-ACME] $($cd.FullName)"
                $candidates += [PSCustomObject]@{ Path = $cd.FullName; Source = 'Win-ACME' }
            }
        }
    }

    if ($candidates.Count -eq 0) {
        Write-Log "  No matching locations found." 'WARN'
        return @()
    }

    # ── Rank by freshness of the best cert in each candidate folder ──────────
    # Parse the newest valid leaf NotAfter from each location and sort descending.
    $ranked = foreach ($c in $candidates) {
        $best = [DateTime]::MinValue
        $certFiles = @(Get-ChildItem -Path $c.Path -File -ErrorAction SilentlyContinue |
                       Where-Object { $_.Extension -in @('.cer','.pem','.crt') })
        foreach ($f in $certFiles) {
            $fmt = Get-CertFormat $f.FullName
            if ($fmt -notin @('PEM_CERT','PEM_FULLCHAIN','DER')) { continue }
            if (Test-IsCACert $f.FullName)                       { continue }
            $exp = Get-CertNotAfter $f.FullName
            if ($exp -gt $best) { $best = $exp }
        }
        [PSCustomObject]@{ Path = $c.Path; Source = $c.Source; BestNotAfter = $best }
    }
    $ranked = @($ranked | Sort-Object BestNotAfter -Descending)

    if ($ranked.Count -gt 1) {
        Write-Log "Multiple locations found — ranked by cert freshness:" 'WARN'
        $ranked | ForEach-Object {
            Write-Log ("  {0,-14} NotAfter: {1:yyyy-MM-dd}  {2}" -f `
                $_.Source, $_.BestNotAfter, $_.Path) 'WARN'
        }
        Write-Log "Using: $($ranked[0].Path)" 'WARN'
    }

    return $ranked
}

function Find-CompanionKey {
    param([string]$CertFile, [string[]]$AllFiles, [string]$ExplicitKey)
    if (-not [string]::IsNullOrWhiteSpace($ExplicitKey)) {
        # If caller passed a directory rather than a file, ignore it gracefully
        if (Test-Path $ExplicitKey -PathType Leaf)      { return $ExplicitKey }
        if (Test-Path $ExplicitKey -PathType Container) {
            Write-Log "ExplicitKey '$ExplicitKey' is a folder — ignoring, will auto-detect key." 'WARN'
            # Fall through to auto-detection
        } else {
            throw "Explicit key path not found: $ExplicitKey"
        }
    }
    $stem   = [System.IO.Path]::GetFileNameWithoutExtension($CertFile)
    $numM   = [regex]::Match($stem, '(\d+)$')
    $suffix = if ($numM.Success) { $numM.Groups[1].Value } else { '' }

    # Strategy 1: same numeric suffix, key-token in stem (certbot archive pattern)
    if ($suffix) {
        foreach ($f in $AllFiles) {
            $n = [System.IO.Path]::GetFileNameWithoutExtension($f).ToLower()
            if ($n -match "^.+?$suffix$") {
                foreach ($t in $script:KeyTokens) { if ($n -match $t) { return $f } }
            }
        }
    }
    # Strategy 2: common standalone key filenames (covers Posh-ACME's cert.key,
    # certbot's privkey.pem, and generic key.pem / private.pem)
    foreach ($f in $AllFiles) {
        $n = [System.IO.Path]::GetFileNameWithoutExtension($f).ToLower()
        $ext = [System.IO.Path]::GetExtension($f).ToLower()
        $isKeyName = $n -in @('cert','privkey','private','key','tls') -and $ext -in @('.key','.pem')
        if ($isKeyName -and (Get-CertFormat $f) -eq 'PEM_KEY') { return $f }
    }
    # Strategy 3: only one PEM key in the folder
    $keys = @($AllFiles | Where-Object { (Get-CertFormat $_) -eq 'PEM_KEY' })
    if ($keys.Count -eq 1) { return $keys[0] }
    # Strategy 4: ask
    Write-Log 'Cannot auto-identify the companion private key.' 'WARN'
    if ($keys.Count -gt 0) { $keys | ForEach-Object { Write-Log "  Key candidate: $_" 'WARN' } }
    $ans = Read-Host 'Enter full path to the private key (blank = abort)'
    if ([string]::IsNullOrWhiteSpace($ans)) { throw 'No private key specified. Aborted.' }
    if (-not (Test-Path $ans))              { throw "Key file not found: $ans" }
    return $ans
}

function Invoke-LetsEncryptScan {
    param([string]$FolderPath, [string]$ExplicitKey, [string]$Domain = '')
    Write-Log "Scanning LE folder: $FolderPath"
    if (-not [string]::IsNullOrWhiteSpace($Domain)) {
        Write-Log "SAN filter     : $Domain"
    }

    # Broad scan for ALL files — used by Find-CompanionKey so it can see .key files
    $allFiles = @(Get-ChildItem -Path $FolderPath -File |
                  Select-Object -ExpandProperty FullName)
    if ($allFiles.Count -eq 0) { throw "No files found in: $FolderPath" }

    # Narrow scan for cert-extension files only — used for parsing NotAfter
    $certFiles = @($allFiles | Where-Object {
        [System.IO.Path]::GetExtension($_).ToLower() -in $script:CertExt
    })
    if ($certFiles.Count -eq 0) { throw "No certificate files found in: $FolderPath" }

    $certEntries = @()
    foreach ($f in $certFiles) {
        $fmt = Get-CertFormat $f
        if ($fmt -notin @('PEM_CERT','PEM_FULLCHAIN','DER')) { continue }
        $exp = Get-CertNotAfter $f
        if ($exp -eq [DateTime]::MinValue) { continue }
        $isCA = Test-IsCACert $f
        $certEntries += [PSCustomObject]@{
            Path=      $f
            Name=      (Split-Path $f -Leaf)
            Format=    $fmt
            NotAfter=  $exp
            IsExpired= ($exp -lt (Get-Date))
            IsCA=      $isCA
        }
    }
    if ($certEntries.Count -eq 0) { throw "No parseable X.509 files found in: $FolderPath" }

    # If a domain filter was supplied, narrow to certs that actually cover it.
    # Log a warning but fall back to all certs if nothing matches (avoids hard failure
    # on misconfigured wildcard certs where the SAN parse may differ).
    if (-not [string]::IsNullOrWhiteSpace($Domain)) {
        $filtered = @($certEntries | Where-Object { Test-CertCoversDomain -Path $_.Path -Domain $Domain })
        if ($filtered.Count -gt 0) {
            $certEntries = $filtered
        } else {
            Write-Log "No cert in this folder has '$Domain' in its SAN — proceeding without SAN filter." 'WARN'
        }
    }

    # Sort: leaf certs (IsCA=$false) first; among those, "fullchain" files before
    # plain "cert" files (same NotAfter but fullchain carries the intermediate chain
    # that PaperCut needs); finally by NotAfter descending.
    $certEntries = @($certEntries | Sort-Object `
        @{ e={ [int]$_.IsCA } },
        @{ e={ if ($_.Name -match 'fullchain') { 0 } else { 1 } } },
        @{ e='NotAfter'; desc=$true })

    Write-Log "Found $($certEntries.Count) cert file(s):"
    for ($i = $certEntries.Count - 1; $i -ge 0; $i--) {
        $e       = $certEntries[$i]
        $status  = if ($e.IsExpired) { 'EXPIRED' } elseif ($e.IsCA) { 'CA CERT' } else { 'VALID  ' }
        $marker  = if ($i -eq 0)    { ' <- SELECTED' } else { '' }
        Write-Log ("  [{0}] {1,-26} NotAfter: {2:yyyy-MM-dd}  {3}{4}" -f
            ($certEntries.Count - $i), $e.Name, $e.NotAfter, $status, $marker)
    }

    $sel     = $certEntries[0]
    $keyPath = Find-CompanionKey -CertFile $sel.Path -AllFiles $allFiles -ExplicitKey $ExplicitKey
    Write-Log "Matched private key: $(Split-Path $keyPath -Leaf)"

    $fmtLabel = switch ($sel.Format) {
        'PEM_FULLCHAIN' { 'PEM fullchain + PEM key' }
        'PEM_CERT'      { 'PEM cert + PEM key'      }
        'DER'           { 'DER cert + PEM key'       }
        default         { $sel.Format }
    }
    Write-Log "Format: $fmtLabel"

    return [PSCustomObject]@{
        SelectedCert=   $sel
        AllCertEntries= $certEntries
        AllFiles=       $allFiles
        KeyPath=        $keyPath
        NeedsOpenSsl=   ($sel.Format -eq 'DER')
    }
}

function Invoke-ArchiveExpired {
    param(
        [PSCustomObject[]]$AllCertEntries, [string[]]$AllFiles,
        [string]$FolderPath, [string]$SelectedCertPath, [string]$SelectedKeyPath,
        [string]$SubfolderName, [int]$MinAgeDays
    )
    $archiveDir = Join-Path $FolderPath $SubfolderName
    $cutoff     = (Get-Date).AddDays(-$MinAgeDays)
    $moved      = 0

    foreach ($entry in $AllCertEntries) {
        if ($entry.Path -eq $SelectedCertPath) { continue }
        if (-not $entry.IsExpired)              { continue }
        if ($entry.NotAfter -gt $cutoff)        { continue }

        $certLeaf = Split-Path $entry.Path -Leaf
        $expKey   = $null
        try {
            $k = Find-CompanionKey -CertFile $entry.Path -AllFiles $AllFiles -ExplicitKey ''
            if ($k -ne $SelectedKeyPath) { $expKey = $k }
        } catch {}

        if (-not $DryRun) {
            if (-not (Test-Path $archiveDir)) { New-Item -ItemType Directory -Path $archiveDir -Force | Out-Null }
            Move-Item -Path $entry.Path -Destination (Join-Path $archiveDir $certLeaf) -Force
        }
        Write-Log "Would archive: $certLeaf -> $SubfolderName\$certLeaf" 'DRY'
        $moved++

        if ($expKey -and (Test-Path $expKey)) {
            $keyLeaf = Split-Path $expKey -Leaf
            if (-not $DryRun) { Move-Item -Path $expKey -Destination (Join-Path $archiveDir $keyLeaf) -Force }
            Write-Log "Would archive: $keyLeaf -> $SubfolderName\$keyLeaf" 'DRY'
            $moved++
        }
    }
    if ($moved -eq 0) { Write-Log "No expired certs met archive criteria (MinAgeDays=$MinAgeDays)." }
}

# ─────────────────────────────────────────────────────────────────────────────
# REGION: Format Converters (OpenSSL)
# ─────────────────────────────────────────────────────────────────────────────

function Invoke-PfxSplit {
    # Split PFX -> tls.cer (PEM chain) + tls.pem (unencrypted private key)
    param([string]$PfxFile, [string]$OpenSsl, [System.Security.SecureString]$Password)
    $tmpKey    = Join-Path $WorkDir 'tlspw_intermediate.pem'
    $outTlsPem = Join-Path $WorkDir 'tls.pem'
    $outTlsCer = Join-Path $WorkDir 'tls.cer'
    if (-not $Password) {
        Write-Log 'Enter PFX password (blank if none):' 'WARN'
        $Password = Read-Host -AsSecureString 'PFX Password'
    }
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))
    try {
        Invoke-OpenSsl -OpenSsl $OpenSsl -Description 'Extract private key from PFX' -Arguments @(
            'pkcs12','-in',$PfxFile,'-nocerts','-out',$tmpKey,
            '-passin',"pass:$plain",'-passout','pass:pc_temp')
        Invoke-OpenSsl -OpenSsl $OpenSsl -Description 'Strip key passphrase -> tls.pem' -Arguments @(
            'rsa','-in',$tmpKey,'-out',$outTlsPem,'-passin','pass:pc_temp')
        Invoke-OpenSsl -OpenSsl $OpenSsl -Description 'Extract cert chain -> tls.cer' -Arguments @(
            'pkcs12','-in',$PfxFile,'-nokeys','-out',$outTlsCer,'-passin',"pass:$plain")
    } finally {
        $plain = $null
        if (Test-Path $tmpKey) { Remove-Item $tmpKey -Force -EA SilentlyContinue }
    }
    return [PSCustomObject]@{ TlsCer = $outTlsCer; TlsPem = $outTlsPem }
}

function Invoke-DerConvert {
    param([string]$DerFile, [string]$OpenSsl)
    $out = Join-Path $WorkDir 'tls.cer'
    Invoke-OpenSsl -OpenSsl $OpenSsl -Description 'Convert DER -> PEM cert' -Arguments @(
        'x509','-in',$DerFile,'-inform','DER','-out',$out,'-outform','PEM')
    return $out
}

function Invoke-P7bConvert {
    param([string]$P7bFile, [string]$OpenSsl)
    $out = Join-Path $WorkDir 'tls.cer'
    Invoke-OpenSsl -OpenSsl $OpenSsl -Description 'Extract cert chain from P7B -> PEM' -Arguments @(
        'pkcs7','-in',$P7bFile,'-print_certs','-out',$out)
    return $out
}

function New-AppServerPfx {
    # Repack tls.cer + tls.pem -> PKCS12 with alias 'jetty' for keytool import.
    #
    # OpenSSL 3.x changed the default PKCS12 encryption to AES-256, which older
    # JRE versions (including PaperCut's bundled JRE) cannot read.  The usual fix
    # is -legacy, but minimal OpenSSL builds (e.g. Git for Windows) do not ship
    # the legacy provider DLL.  Instead, we specify the older ciphers explicitly:
    #   -keypbe  PBE-SHA1-3DES   : encrypt the private key with 3DES
    #   -certpbe PBE-SHA1-3DES   : encrypt the cert bag with 3DES
    #   -macalg  SHA1            : use SHA1 for the MAC (Java compatibility)
    # These produce the same result as -legacy without requiring the provider.
    # On OpenSSL 1.x these flags are also valid and produce the same output,
    # so they are safe to use unconditionally.
    param([string]$TlsCer, [string]$TlsPem, [string]$OpenSsl, [string]$PfxPass)
    $out = Join-Path $WorkDir 'app_server.pfx'

    # Log the OpenSSL version for diagnostics
    $versionOutput = (& $OpenSsl version 2>&1 | Select-Object -First 1).ToString()
    Write-Log "OpenSSL version: $versionOutput"

    Invoke-OpenSsl -OpenSsl $OpenSsl -Description 'Pack PEM -> PKCS12 (Java-compatible, alias: jetty)' `
                   -Arguments @(
        'pkcs12', '-export',
        '-in',      $TlsCer,
        '-inkey',   $TlsPem,
        '-out',     $out,
        '-passout', "pass:$PfxPass",
        '-name',    'jetty',
        '-keypbe',  'PBE-SHA1-3DES',
        '-certpbe', 'PBE-SHA1-3DES',
        '-macalg',  'SHA1'
    )
    return $out
}

# ─────────────────────────────────────────────────────────────────────────────
# REGION: App Server — Keystore and server.properties
# ─────────────────────────────────────────────────────────────────────────────

function Install-AppServerCert {
    param(
        [string]$SrcTlsCer,
        [string]$SrcTlsPem,
        [string]$KsPass,     # plain-text keystore password
        [string]$KeyPass     # plain-text key password
    )

    $customDir    = Join-Path $PaperCutInstallPath 'server\custom'
    $destKeystore = Join-Path $customDir $KeystoreName
    $serverProps  = Join-Path $PaperCutInstallPath 'server\server.properties'
    $tmpKs        = Join-Path $WorkDir "$KeystoreName.new"
    # Note: server.properties existence is validated by the caller.

    # ── Strategy 1: PaperCut's create-ssl-keystore (preferred) ───────────────
    # Accepts PEM files directly — no OpenSSL or JRE compatibility issues.
    # Writes directly to $destKeystore; backup must happen before the call.
    $csk = Find-CreateSslKeystore
    if ($csk) {
        Write-Log "[APP SERVER] Using PaperCut create-ssl-keystore: $csk"

        # Backup existing keystore BEFORE deleting it (deletion happens inside
        # Invoke-CreateSslKeystore so the tool finds no existing file).
        if (-not $DryRun -and (Test-Path $destKeystore)) {
            $stamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
            $backup = "$destKeystore.bak_$stamp"
            Copy-Item $destKeystore $backup -Force
            Write-Log "Backed up keystore: $backup"
        } elseif ($DryRun) {
            Write-Log "Would backup: $KeystoreName -> $KeystoreName.bak_<stamp>" 'DRY'
        }

        # Clear any existing SSL settings from server.properties before calling
        # create-ssl-keystore.  The tool reads server.properties, and if it finds
        # an encrypted keystore password from a previous run pointing to a now-
        # deleted keystore, it tries to fall back to server.keystore and fails
        # with "Keystore was tampered with" because our new password doesn't match.
        # Clearing the settings lets the tool create a genuinely fresh keystore.
        if (-not $DryRun -and (Test-Path $serverProps)) {
            Write-Log "[APP SERVER] Clearing SSL settings from server.properties so create-ssl-keystore starts fresh..."
            Revoke-ServerPropertiesSSL -ServerPropsPath $serverProps
        } elseif ($DryRun) {
            Write-Log 'Would comment out server.ssl.* in server.properties before keystore creation.' 'DRY'
        }

        Invoke-CreateSslKeystore -Tool $csk `
            -TlsCer $SrcTlsCer -TlsPem $SrcTlsPem `
            -KsPass $KsPass    -KeyPass $KeyPass `
            -DestKeystore $destKeystore

        if (-not $DryRun) { Write-Log "[APP SERVER] Keystore deployed: $destKeystore" }
    } else {
        # ── Strategy 2: OpenSSL → PKCS12 → keytool → JKS (fallback) ─────────
        Write-Log '[APP SERVER] create-ssl-keystore not found — falling back to OpenSSL + keytool.' 'WARN'

        $ossl    = Require-OpenSsl
        $keytool = Require-Keytool

        Write-Log '[APP SERVER] Building PKCS12 from PEM files...'
        if (-not $DryRun) {
            $appPfx = New-AppServerPfx -TlsCer $SrcTlsCer -TlsPem $SrcTlsPem `
                                       -OpenSsl $ossl -PfxPass $KsPass
            $pfxSz = (Get-Item $appPfx -EA SilentlyContinue).Length
            Write-Log "[APP SERVER] PKCS12 created: $appPfx ($pfxSz bytes)"
            if ($pfxSz -lt 100) { throw "PKCS12 file appears empty or corrupt: $appPfx" }
        } else {
            Write-Log 'Would run: openssl pkcs12 -export ... (PEM -> PKCS12)' 'DRY'
            $appPfx = Join-Path $WorkDir 'app_server.pfx'
        }

        # Validate the PKCS12 before attempting import — reveals the actual Java error
        # if keytool can't open the file (bad password, unsupported cipher, etc.)
        Write-Log '[APP SERVER] Validating PKCS12 (keytool -list)...'
        Invoke-Keytool -Keytool $keytool -Description 'Validate PKCS12' -Arguments @(
            '-list', '-v',
            '-keystore',  $appPfx,
            '-storetype', 'PKCS12',
            '-storepass', $KsPass
        )

        Write-Log '[APP SERVER] Importing PKCS12 -> JKS keystore...'
        Invoke-Keytool -Keytool $keytool -Description 'PKCS12 -> JKS keystore' -Arguments @(
            '-importkeystore',
            '-srckeystore',   $appPfx,
            '-srcstoretype',  'PKCS12',
            '-srcstorepass',  $KsPass,
            '-destkeystore',  $tmpKs,
            '-deststoretype', 'JKS',
            '-deststorepass', $KsPass,
            '-destkeypass',   $KeyPass,
            '-destalias',     'jetty',
            '-noprompt'
        )

        # ── Backup existing keystore ─────────────────────────────────────────
        if (Test-Path $destKeystore) {
            $stamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
            $backup = "$destKeystore.bak_$stamp"
            if ($DryRun) {
                Write-Log "Would backup: $KeystoreName -> $KeystoreName.bak_$stamp" 'DRY'
            } else {
                Copy-Item $destKeystore $backup -Force
                Write-Log "Backed up keystore: $backup"
            }
        }

        # ── Place new keystore ───────────────────────────────────────────────
        if ($DryRun) {
            Write-Log "Would copy keystore to: server\custom\$KeystoreName" 'DRY'
        } else {
            if (-not (Test-Path $customDir)) { New-Item -ItemType Directory -Path $customDir -Force | Out-Null }
            Copy-Item $tmpKs $destKeystore -Force
            Write-Log "[APP SERVER] Keystore deployed: $destKeystore"
        }
    } # end keytool fallback else

    # ── Update server.properties ─────────────────────────────────────────────
    Update-ServerProperties -ServerPropsPath $serverProps `
                            -KeystoreName $KeystoreName `
                            -KsPass $KsPass -KeyPass $KeyPass
}

function Update-ServerProperties {
    param(
        [string]$ServerPropsPath,
        [string]$KeystoreName,
        [string]$KsPass,
        [string]$KeyPass
    )

    # The three properties we manage.
    # PaperCut 23+ auto-encrypts plain-text passwords on next service start.
    # We intentionally write plain text — PaperCut will encrypt it on restart.
    $props = [ordered]@{
        'server.ssl.keystore'          = "custom/$KeystoreName"
        'server.ssl.keystore-password' = $KsPass
        'server.ssl.key-password'      = $KeyPass
    }

    if ($DryRun) {
        Write-Log 'Would update server.properties:' 'DRY'
        Write-Log "  server.ssl.keystore=custom/$KeystoreName" 'DRY'
        Write-Log '  server.ssl.keystore-password=<set>' 'DRY'
        Write-Log '  server.ssl.key-password=<set>' 'DRY'
        return
    }

    # Backup before editing
    $stamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
    $backup = "$ServerPropsPath.bak_$stamp"
    Copy-Item $ServerPropsPath $backup -Force
    Write-Log "[APP SERVER] Backed up server.properties: $backup"

    $content = Get-Content $ServerPropsPath -Raw -Encoding UTF8

    foreach ($key in $props.Keys) {
        $val = $props[$key]

        # Escape the key for use as a regex literal (handles dots, hyphens, etc.)
        $escapedKey = [regex]::Escape($key)

        # Match any line that is:
        #   - optionally indented
        #   - optionally commented out with one or more # characters (with or without space after)
        #   - followed by the key, optional whitespace, =, and any value
        # This covers all factory default variants:
        #   #server.ssl.keystore=custom/my-ssl-keystore        (no space)
        #   # server.ssl.keystore=custom/my-ssl-keystore       (one space)
        #   server.ssl.keystore=old-value                      (already active)
        #   server.ssl.keystore-password=ENCRYPTED\:abc123     (encrypted from prev run)
        $pattern = "(?m)^[ \t]*#+[ \t]*${escapedKey}[ \t]*=.*$|(?m)^[ \t]*${escapedKey}[ \t]*=.*$"
        $replace = "${key}=${val}"

        if ($content -match $pattern) {
            $content = [regex]::Replace($content, $pattern, $replace)
            $displayVal = if ($key -match 'password') { '<set>' } else { $val }
            Write-Log "[APP SERVER] server.properties: set ${key}=${displayVal}"
        } else {
            # Property not present at all — append after the ### SSL ### comment block if found,
            # otherwise at the end of the file.
            $sslHeader = '### SSL'
            $insertAfter = $content.LastIndexOf($sslHeader)
            if ($insertAfter -ge 0) {
                # Find the end of that line and insert after it
                $lineEnd = $content.IndexOf("`n", $insertAfter)
                if ($lineEnd -lt 0) { $lineEnd = $content.Length - 1 }
                $content = $content.Substring(0, $lineEnd + 1) + "${replace}`r`n" + $content.Substring($lineEnd + 1)
            } else {
                $content = $content.TrimEnd() + "`r`n${replace}`r`n"
            }
            $displayVal = if ($key -match 'password') { '<set>' } else { $val }
            Write-Log "[APP SERVER] server.properties: added ${key}=${displayVal}"
        }
    }

    Set-Content -Path $ServerPropsPath -Value $content -Encoding UTF8 -NoNewline
    Write-Log "[APP SERVER] server.properties saved."
    Write-Log "[APP SERVER] NOTE: PaperCut 23+ will encrypt the passwords above on next service start." 'WARN'
}

# ─────────────────────────────────────────────────────────────────────────────
# REGION: Shared File and Service Operations
# ─────────────────────────────────────────────────────────────────────────────

function Backup-CertFile {
    param([string]$FilePath)
    if (Test-Path $FilePath) {
        $stamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
        $backup = "$FilePath.bak_$stamp.old"
        if ($DryRun) {
            Write-Log "Would backup: $(Split-Path $FilePath -Leaf) -> $(Split-Path $backup -Leaf)" 'DRY'
        } else {
            Copy-Item $FilePath $backup -Force
            Write-Log "Backed up: $backup"
        }
    }
}

function Deploy-CertFile {
    param([string]$Src, [string]$Dst, [string]$Label)
    if ($DryRun) {
        Write-Log "Would deploy ${Label}: $(Split-Path $Src -Leaf) -> $(Split-Path $Dst -Leaf)" 'DRY'
    } else {
        Copy-Item $Src $Dst -Force
        Write-Log "Deployed ${Label}: $Dst"
    }
}

function Control-Service {
    param([string]$Name, [string]$Action, [string]$Component)
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Log "[$Component] Service '$Name' not found — skipping $Action." 'WARN'
        return
    }
    if ($DryRun) { Write-Log "Would $Action service: $Name" 'DRY'; return }
    $gerund = if ($Action -eq 'Stop') { 'Stopping' } else { 'Starting' }
    Write-Log "[$Component] $gerund service: $Name..."
    if ($Action -eq 'Stop') {
        Stop-Service  -Name $Name -Force -EA Stop
        $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(60))
    } else {
        Start-Service -Name $Name -EA Stop
        $svc.WaitForStatus('Running', [TimeSpan]::FromSeconds(60))
    }
    Write-Log "[$Component] Service '$Name' -> $($(Get-Service -Name $Name).Status)"
}

# ─────────────────────────────────────────────────────────────────────────────
# REGION: Clean
# ─────────────────────────────────────────────────────────────────────────────

# Returns the full path of the most recent timestamped backup of $OriginalPath,
# or $null if none exist.  Backup names follow the pattern: <name>.bak_yyyyMMdd_HHmmss[.old]
function Get-MostRecentBackup {
    param([string]$OriginalPath)
    $dir  = Split-Path $OriginalPath -Parent
    $leaf = Split-Path $OriginalPath -Leaf
    if (-not (Test-Path $dir)) { return $null }
    $backups = @(Get-ChildItem -Path $dir -ErrorAction SilentlyContinue |
                 Where-Object { $_.Name -match "^$([regex]::Escape($leaf))\.bak_\d{8}_\d{6}" } |
                 Sort-Object Name -Descending)
    if ($backups.Count -gt 0) { return $backups[0].FullName }
    return $null
}

# Restore $OriginalPath from its most recent backup, or delete it if no backup exists.
function Restore-OrRemove {
    param([string]$OriginalPath, [string]$Label)
    $backup = Get-MostRecentBackup -OriginalPath $OriginalPath
    if ($backup) {
        if ($DryRun) {
            Write-Log "Would restore $Label : $(Split-Path $backup -Leaf) -> $(Split-Path $OriginalPath -Leaf)" 'DRY'
        } else {
            Copy-Item $backup $OriginalPath -Force
            Write-Log "Restored $Label : $backup -> $OriginalPath"
        }
    } elseif (Test-Path $OriginalPath) {
        if ($DryRun) {
            Write-Log "Would remove $Label (no backup found): $(Split-Path $OriginalPath -Leaf)" 'DRY'
        } else {
            Remove-Item $OriginalPath -Force
            Write-Log "Removed $Label (no backup): $OriginalPath"
        }
    } else {
        Write-Log "  $Label not present — nothing to restore." 'WARN'
    }
}

# Comment out any uncommented server.ssl.* lines in server.properties so
# PaperCut falls back to its built-in keystore.
function Revoke-ServerPropertiesSSL {
    param([string]$ServerPropsPath)
    $content = Get-Content $ServerPropsPath -Raw
    $changed = $false
    foreach ($key in @('server.ssl.keystore','server.ssl.keystore-password','server.ssl.key-password')) {
        $pattern = "(?m)^([ \t]*)(?![ \t]*#)([ \t]*${key}[ \t]*=.*)$"
        if ($content -match $pattern) {
            $content = [regex]::Replace($content, $pattern, '$1# $2')
            $changed = $true
        }
    }
    if ($changed) {
        Set-Content -Path $ServerPropsPath -Value $content -Encoding UTF8 -NoNewline
        Write-Log '[APP SERVER] SSL keys commented out in server.properties.'
    } else {
        Write-Log '[APP SERVER] No active SSL keys found in server.properties — nothing to revert.' 'WARN'
    }
}

function Invoke-CleanRun {
    Write-Log '── Clean: undoing previous certificate installation ─────────────────'

    # ── Print Deploy ─────────────────────────────────────────────────────────
    if ($Target -in @('PrintDeploy','All')) {
        Write-Log ''
        Write-Log '── Print Deploy ─────────────────────────────────────────────────'
        $pdCertDir = Join-Path $PaperCutInstallPath "providers\print-deploy\$PaperCutOS\data\cert-custom"
        if (-not (Test-Path $pdCertDir) -and -not $DryRun) {
            Write-Log "[PRINT DEPLOY] cert-custom dir not found — nothing to clean." 'WARN'
        } else {
            Control-Service -Name $PrintDeployServiceName -Action 'Stop' -Component 'PRINT DEPLOY'
            Restore-OrRemove -OriginalPath (Join-Path $pdCertDir 'tls.cer') -Label 'tls.cer'
            Restore-OrRemove -OriginalPath (Join-Path $pdCertDir 'tls.pem') -Label 'tls.pem'
            Control-Service -Name $PrintDeployServiceName -Action 'Start' -Component 'PRINT DEPLOY'
            Write-AuditLog -Action 'PD_TLS_CLEAN' -Status 'SUCCESS' `
                -Detail "Dest=$pdCertDir | DryRun=$($DryRun.IsPresent)"
        }
    }

    # ── Mobility Print ────────────────────────────────────────────────────────
    if ($Target -in @('MobilityPrint','All')) {
        Write-Log ''
        Write-Log '── Mobility Print ───────────────────────────────────────────────'
        $mpDataDir = Join-Path $MobilityPrintInstallPath 'data'
        if (-not (Test-Path $mpDataDir) -and -not $DryRun) {
            Write-Log "[MOBILITY PRINT] data folder not found — nothing to clean." 'WARN'
        } else {
            Control-Service -Name $MobilityPrintServiceName -Action 'Stop' -Component 'MOBILITY PRINT'
            Restore-OrRemove -OriginalPath (Join-Path $mpDataDir 'tls.cer') -Label 'tls.cer'
            Restore-OrRemove -OriginalPath (Join-Path $mpDataDir 'tls.pem') -Label 'tls.pem'
            Control-Service -Name $MobilityPrintServiceName -Action 'Start' -Component 'MOBILITY PRINT'
            Write-AuditLog -Action 'MP_TLS_CLEAN' -Status 'SUCCESS' `
                -Detail "Dest=$mpDataDir | DryRun=$($DryRun.IsPresent)"
        }
    }

    # ── Application Server ────────────────────────────────────────────────────
    if ($Target -in @('AppServer','All')) {
        Write-Log ''
        Write-Log '── Application Server ───────────────────────────────────────────'
        $serverProps  = Join-Path $PaperCutInstallPath 'server\server.properties'
        $customDir    = Join-Path $PaperCutInstallPath 'server\custom'
        $keystorePath = Join-Path $customDir $KeystoreName

        if (-not (Test-Path $serverProps) -and -not $DryRun) {
            Write-Log "[APP SERVER] server.properties not found — nothing to clean." 'WARN'
        } else {
            Control-Service -Name $AppServerServiceName -Action 'Stop' -Component 'APP SERVER'

            # Restore server.properties or comment out SSL keys
            $propsBackup = Get-MostRecentBackup -OriginalPath $serverProps
            if ($propsBackup) {
                if ($DryRun) {
                    Write-Log "Would restore server.properties from: $(Split-Path $propsBackup -Leaf)" 'DRY'
                } else {
                    Copy-Item $propsBackup $serverProps -Force
                    Write-Log "[APP SERVER] Restored server.properties from: $propsBackup"
                }
            } else {
                if ($DryRun) {
                    Write-Log 'Would comment out server.ssl.* keys in server.properties.' 'DRY'
                } else {
                    Revoke-ServerPropertiesSSL -ServerPropsPath $serverProps
                }
            }

            # Restore keystore or delete it
            Restore-OrRemove -OriginalPath $keystorePath -Label 'keystore'

            Control-Service -Name $AppServerServiceName -Action 'Start' -Component 'APP SERVER'
            Write-AuditLog -Action 'AS_TLS_CLEAN' -Status 'SUCCESS' `
                -Detail "InstallPath=$PaperCutInstallPath | DryRun=$($DryRun.IsPresent)"
        }
    }

    # ── Work directory ────────────────────────────────────────────────────────
    if (Test-Path $WorkDir) {
        if ($DryRun) {
            Write-Log "Would purge work directory: $WorkDir" 'DRY'
        } else {
            Remove-Item $WorkDir -Recurse -Force -ErrorAction SilentlyContinue
            Write-Log "Purged work directory: $WorkDir"
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# REGION: Main
# ─────────────────────────────────────────────────────────────────────────────

Write-Log '============================================================'
Write-Log ' PaperCut TLS Certificate Installer'
Write-Log '============================================================'
if ($DryRun) { Write-Log 'DRY RUN MODE — no changes will be made' 'DRY' }

# Normalize deprecated alias
if ($Target -eq 'Both') {
    Write-Log '"Both" is deprecated — treating as "All".' 'WARN'
    $Target = 'All'
}

Write-Log "Target       : $Target"
Write-Log "Input mode   : $InputMode"
Write-Log "Install path : $PaperCutInstallPath"

if (-not (Test-Path $WorkDir)) { New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null }

# ── Clean mode: undo previous runs and exit ───────────────────────────────────
if ($Clean) {
    Write-Log 'Mode: CLEAN — restoring pre-installation state'
    if ($DryRun) { Write-Log 'DRY RUN — no changes will be made' 'DRY' }
    try {
        Invoke-CleanRun
        Write-Log ''
        Write-Log '============================================================'
        if ($DryRun) {
            Write-Log ' <- Clean dry run complete. Re-run without -DryRun to apply.'
            Write-Log '    (No changes were made)' 'DRY'
        } else {
            Write-Log ' <- Clean complete. PaperCut is back to factory cert state.'
        }
        Write-Log '============================================================'
        Write-AuditLog -Action 'CLEAN' -Status 'SUCCESS' `
            -Detail "Target=$Target | DryRun=$($DryRun.IsPresent)"
    } catch {
        Write-Log "Clean FAILED: $_" 'ERROR'
        Write-AuditLog -Action 'CLEAN' -Status 'FAILED' -Detail $_.Exception.Message
        exit 1
    }
    exit 0
}

# Resolved source cert and key — populated by the input-mode block below
$SrcTlsCer = $null
$SrcTlsPem = $null
$TmpPfx    = Join-Path $WorkDir 'certstore_export.pfx'

# Resolved App Server passwords (plain text in memory only)
$KsPassPlain  = $null
$KeyPassPlain = $null

try {

    # ══════════════════════════════════════════════════════════════════════════
    # STEP 1 — Resolve shared cert source
    # ══════════════════════════════════════════════════════════════════════════

    Write-Log '── Cert Resolution ──────────────────────────────────────────────'

    switch ($InputMode) {

        'PEMS_READY' {
            Write-Log 'Mode PEMS_READY: using provided PEM files.'
            if (-not (Test-Path $ReadyTlsCer)) { throw "ReadyTlsCer not found: $ReadyTlsCer" }
            if (-not (Test-Path $ReadyTlsPem)) { throw "ReadyTlsPem not found: $ReadyTlsPem" }
            $SrcTlsCer = $ReadyTlsCer
            $SrcTlsPem = $ReadyTlsPem
        }

        'LETSENCRYPT' {
            # ── Auto-discover path from -SAN when -LetsEncryptPath not given ─
            if ([string]::IsNullOrWhiteSpace($LetsEncryptPath)) {
                if ([string]::IsNullOrWhiteSpace($SAN)) {
                    throw ('InputMode = LETSENCRYPT requires either -LetsEncryptPath (explicit) ' +
                           'or -SAN (for automatic discovery of common ACME locations).')
                }
                $discovered = @(Find-CertByDomain -Domain $SAN)
                if ($discovered.Count -eq 0) {
                    throw ("No certificates found for '$SAN' in any common ACME client location.`n" +
                           'Searched: Posh-ACME, Certbot, Win-ACME.`n' +
                           'Specify -LetsEncryptPath manually if your client stores certs elsewhere.')
                }
                $LetsEncryptPath = $discovered[0].Path
                Write-Log "Auto-discovered path [$($discovered[0].Source)]: $LetsEncryptPath"
            }

            if (-not $DryRun -and -not (Test-Path $LetsEncryptPath)) {
                throw "LetsEncryptPath not found: $LetsEncryptPath"
            }
            $le = Invoke-LetsEncryptScan -FolderPath $LetsEncryptPath `
                                         -ExplicitKey $LetsEncryptKeyPath `
                                         -Domain      $SAN
            if ($ArchiveExpired) {
                Write-Log "Archiving expired certs (MinAgeDays=$ArchiveMinAgeDays)..."
                Invoke-ArchiveExpired `
                    -AllCertEntries   $le.AllCertEntries -AllFiles $le.AllFiles `
                    -FolderPath       $LetsEncryptPath `
                    -SelectedCertPath $le.SelectedCert.Path -SelectedKeyPath $le.KeyPath `
                    -SubfolderName    $ArchiveSubfolder -MinAgeDays $ArchiveMinAgeDays
            }
            if ($le.NeedsOpenSsl) {
                $ossl      = Require-OpenSsl
                $SrcTlsCer = Invoke-DerConvert -DerFile $le.SelectedCert.Path -OpenSsl $ossl
            } else {
                $SrcTlsCer = $le.SelectedCert.Path
            }
            $SrcTlsPem = $le.KeyPath
        }

        'PFX_FILE' {
            if ([string]::IsNullOrWhiteSpace($PfxPath) -or
                (-not $DryRun -and -not (Test-Path $PfxPath))) {
                throw "PfxPath not found: $PfxPath"
            }
            Write-Log "PFX source: $PfxPath"
            $ossl      = Require-OpenSsl
            $result    = Invoke-PfxSplit -PfxFile $PfxPath -OpenSsl $ossl -Password $PfxPassword
            $SrcTlsCer = $result.TlsCer
            $SrcTlsPem = $result.TlsPem
        }

        'CERTSTORE' {
            if ([string]::IsNullOrWhiteSpace($CertThumbprint)) {
                throw 'CertThumbprint is required when InputMode = CERTSTORE.'
            }
            $thumb = $CertThumbprint.Replace(' ','')
            Write-Log "Searching LocalMachine\My for: $thumb"
            $cert = Get-ChildItem Cert:\LocalMachine\My |
                    Where-Object { $_.Thumbprint -eq $thumb } |
                    Select-Object -First 1
            if (-not $cert) { throw "Certificate not found with thumbprint: $thumb" }
            Write-Log "Found: $($cert.Subject)  Expires: $($cert.NotAfter)"

            if (-not $PfxPassword) {
                Write-Log 'Enter a temporary PFX export password:' 'WARN'
                $PfxPassword = Read-Host -AsSecureString 'PFX Export Password'
            }
            if (-not $DryRun) {
                Export-PfxCertificate -Cert $cert -FilePath $TmpPfx -Password $PfxPassword | Out-Null
                Write-Log 'Exported cert to temp PFX.'
            } else {
                Write-Log "Would export cert to: $TmpPfx" 'DRY'
            }
            $ossl      = Require-OpenSsl
            $result    = Invoke-PfxSplit -PfxFile $TmpPfx -OpenSsl $ossl -Password $PfxPassword
            $SrcTlsCer = $result.TlsCer
            $SrcTlsPem = $result.TlsPem
        }

        'AUTO' {
            if ([string]::IsNullOrWhiteSpace($AutoCertPath)) {
                throw 'AutoCertPath is required when InputMode = AUTO.'
            }
            $fmt = Get-CertFormat $AutoCertPath
            Write-Log "Detected format: $fmt  ($AutoCertPath)"
            switch ($fmt) {
                { $_ -in @('PEM_FULLCHAIN','PEM_CERT') } {
                    if ([string]::IsNullOrWhiteSpace($AutoKeyPath) -or -not (Test-Path $AutoKeyPath)) {
                        throw "Format $fmt requires -AutoKeyPath."
                    }
                    $SrcTlsCer = $AutoCertPath; $SrcTlsPem = $AutoKeyPath
                }
                'DER' {
                    if ([string]::IsNullOrWhiteSpace($AutoKeyPath) -or -not (Test-Path $AutoKeyPath)) {
                        throw 'DER cert requires -AutoKeyPath for the PEM private key.'
                    }
                    $ossl      = Require-OpenSsl
                    $SrcTlsCer = Invoke-DerConvert -DerFile $AutoCertPath -OpenSsl $ossl
                    $SrcTlsPem = $AutoKeyPath
                }
                'PFX' {
                    $ossl      = Require-OpenSsl
                    $result    = Invoke-PfxSplit -PfxFile $AutoCertPath -OpenSsl $ossl `
                                                 -Password $PfxPassword
                    $SrcTlsCer = $result.TlsCer; $SrcTlsPem = $result.TlsPem
                }
                'PEM_P7B' {
                    if ([string]::IsNullOrWhiteSpace($AutoKeyPath) -or -not (Test-Path $AutoKeyPath)) {
                        throw 'P7B requires -AutoKeyPath for the PEM private key.'
                    }
                    $ossl      = Require-OpenSsl
                    $SrcTlsCer = Invoke-P7bConvert -P7bFile $AutoCertPath -OpenSsl $ossl
                    $SrcTlsPem = $AutoKeyPath
                }
                default { throw "Cannot determine format for: $AutoCertPath" }
            }
        }
    }

    # ── Quick sanity check ───────────────────────────────────────────────────
    if (-not $DryRun) {
        if (-not (Test-Path $SrcTlsCer)) { throw "Resolved tls.cer not found: $SrcTlsCer" }
        if (-not (Test-Path $SrcTlsPem)) { throw "Resolved tls.pem not found: $SrcTlsPem"  }
        $cerSz = (Get-Item $SrcTlsCer).Length
        $pemSz = (Get-Item $SrcTlsPem).Length
        Write-Log "tls.cer : $SrcTlsCer ($cerSz bytes)"
        Write-Log "tls.pem : $SrcTlsPem ($pemSz bytes)"
        if ($cerSz -lt 100) { Write-Log 'tls.cer appears unusually small.' 'WARN' }
        if ($pemSz -lt 100) { Write-Log 'tls.pem appears unusually small.' 'WARN' }
    }

    # ── Passwords for App Server are prompted later, inside the AS step, ────────
    # after path validation — avoids prompting on machines without PaperCut.

    # ══════════════════════════════════════════════════════════════════════════
    # STEP 2 — Print Deploy
    # ══════════════════════════════════════════════════════════════════════════

    if ($Target -in @('PrintDeploy','All')) {
        Write-Log ''
        Write-Log '── Print Deploy ─────────────────────────────────────────────────'

        $pdCertDir = Join-Path $PaperCutInstallPath "providers\print-deploy\$PaperCutOS\data\cert-custom"
        $pdTlsCer  = Join-Path $pdCertDir 'tls.cer'
        $pdTlsPem  = Join-Path $pdCertDir 'tls.pem'

        $pdPathOk = $DryRun -or (Test-Path $pdCertDir)
        if (-not $pdPathOk -and $SkipMissingTargets) {
            Write-Log "[PRINT DEPLOY] cert-custom dir not found: $pdCertDir — skipping target." 'WARN'
            Write-AuditLog -Action 'PD_TLS_INSTALL' -Status 'SKIPPED' `
                -Detail "cert-custom not found: $pdCertDir"
        } elseif (-not $pdPathOk) {
            throw "Print Deploy cert-custom dir not found: $pdCertDir`nVerify -PaperCutInstallPath and -PaperCutOS."
        } else {
            Control-Service -Name $PrintDeployServiceName -Action 'Stop' -Component 'PRINT DEPLOY'

            Write-Log '[PRINT DEPLOY] Backing up existing certs...'
            Backup-CertFile -FilePath $pdTlsCer
            Backup-CertFile -FilePath $pdTlsPem

            Write-Log '[PRINT DEPLOY] Deploying new certs...'
            if (-not $DryRun -and -not (Test-Path $pdCertDir)) {
                New-Item -ItemType Directory -Path $pdCertDir -Force | Out-Null
            }
            Deploy-CertFile -Src $SrcTlsCer -Dst $pdTlsCer -Label 'tls.cer'
            Deploy-CertFile -Src $SrcTlsPem -Dst $pdTlsPem -Label 'tls.pem'

            Control-Service -Name $PrintDeployServiceName -Action 'Start' -Component 'PRINT DEPLOY'

            Write-AuditLog -Action 'PD_TLS_INSTALL' -Status 'SUCCESS' `
                -Detail "Mode=$InputMode | Dest=$pdCertDir | DryRun=$($DryRun.IsPresent)"
        } # end else (pdPathOk)
    } # end if (Target PrintDeploy)

    # ══════════════════════════════════════════════════════════════════════════
    # STEP 3 — Mobility Print
    # ══════════════════════════════════════════════════════════════════════════

    if ($Target -in @('MobilityPrint','All')) {
        Write-Log ''
        Write-Log '── Mobility Print ───────────────────────────────────────────────'

        # Files go directly into <install>\data\ — no cert-custom subfolder
        $mpDataDir = Join-Path $MobilityPrintInstallPath 'data'
        $mpTlsCer  = Join-Path $mpDataDir 'tls.cer'
        $mpTlsPem  = Join-Path $mpDataDir 'tls.pem'

        $mpPathOk = $DryRun -or (Test-Path $mpDataDir)
        if (-not $mpPathOk -and $SkipMissingTargets) {
            Write-Log "[MOBILITY PRINT] data folder not found: $mpDataDir — skipping target." 'WARN'
            Write-AuditLog -Action 'MP_TLS_INSTALL' -Status 'SKIPPED' `
                -Detail "data folder not found: $mpDataDir"
        } elseif (-not $mpPathOk) {
            throw "[MOBILITY PRINT] data folder not found: $mpDataDir`nVerify -MobilityPrintInstallPath."
        } else {
            Control-Service -Name $MobilityPrintServiceName -Action 'Stop' -Component 'MOBILITY PRINT'

            Write-Log '[MOBILITY PRINT] Backing up existing certs...'
            Backup-CertFile -FilePath $mpTlsCer
            Backup-CertFile -FilePath $mpTlsPem

            Write-Log '[MOBILITY PRINT] Deploying new certs...'
            Deploy-CertFile -Src $SrcTlsCer -Dst $mpTlsCer -Label 'tls.cer'
            Deploy-CertFile -Src $SrcTlsPem -Dst $mpTlsPem -Label 'tls.pem'

            Control-Service -Name $MobilityPrintServiceName -Action 'Start' -Component 'MOBILITY PRINT'

            Write-Log '[MOBILITY PRINT] NOTE: If using Known Host or DNS discovery, job delivery' 'WARN'
            Write-Log '   will automatically upgrade to IPPS/HTTPS on port 9164 after restart.' 'WARN'

            Write-AuditLog -Action 'MP_TLS_INSTALL' -Status 'SUCCESS' `
                -Detail "Mode=$InputMode | Dest=$mpDataDir | DryRun=$($DryRun.IsPresent)"
        } # end else (mpPathOk)
    } # end if (Target MobilityPrint)

    # ══════════════════════════════════════════════════════════════════════════
    # STEP 4 — Application Server
    # ══════════════════════════════════════════════════════════════════════════

    if ($Target -in @('AppServer','All')) {
        Write-Log ''
        Write-Log '── Application Server ───────────────────────────────────────────'

        # ── Pre-flight: verify server.properties exists before prompting ──────
        $serverProps = Join-Path $PaperCutInstallPath 'server\server.properties'
        $asPathOk    = $DryRun -or (Test-Path $serverProps)
        if (-not $asPathOk -and $SkipMissingTargets) {
            Write-Log "[APP SERVER] server.properties not found: $serverProps — skipping target." 'WARN'
            Write-AuditLog -Action 'AS_TLS_INSTALL' -Status 'SKIPPED' `
                -Detail "server.properties not found: $serverProps"
        } elseif (-not $asPathOk) {
            throw "[APP SERVER] server.properties not found: $serverProps`nVerify -PaperCutInstallPath."
        } else {

        # ── Prompt for keystore passwords now that paths are confirmed ────────
        # In DryRun, skip the prompt entirely and use a placeholder so the
        # full command sequence can still be logged without requiring input.
        if ($DryRun) {
            $KsPassPlain  = '<dry-run-password>'
            $KeyPassPlain = '<dry-run-password>'
            Write-Log '[APP SERVER] DryRun: skipping keystore password prompt.' 'DRY'
        } else {
            if (-not $KeystorePassword) {
                Write-Log '[APP SERVER] Enter the JKS keystore password (stored in server.properties):' 'WARN'
                $KeystorePassword = Read-Host -AsSecureString 'Keystore Password'
            }
            $KsPassPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [Runtime.InteropServices.Marshal]::SecureStringToBSTR($KeystorePassword))
            $KeyPassPlain = if ($KeyPassword) {
                [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($KeyPassword))
            } else { $KsPassPlain }   # default: key password == keystore password
        }

        # App Server keystore strategy is chosen inside Install-AppServerCert:
        # 1. PaperCut's create-ssl-keystore (preferred — no OpenSSL needed)
        # 2. OpenSSL + keytool fallback (if create-ssl-keystore is absent)
        Control-Service -Name $AppServerServiceName -Action 'Stop' -Component 'APP SERVER'

        Install-AppServerCert `
            -SrcTlsCer $SrcTlsCer -SrcTlsPem $SrcTlsPem `
            -KsPass $KsPassPlain  -KeyPass $KeyPassPlain

        Control-Service -Name $AppServerServiceName -Action 'Start' -Component 'APP SERVER'

        Write-AuditLog -Action 'AS_TLS_INSTALL' -Status 'SUCCESS' `
            -Detail "Mode=$InputMode | Keystore=$KeystoreName | DryRun=$($DryRun.IsPresent)"
        } # end else (asPathOk)
    } # end if (Target AppServer)

    # ══════════════════════════════════════════════════════════════════════════
    # STEP 5 — Summary
    # ══════════════════════════════════════════════════════════════════════════

    Write-Log ''
    Write-Log '============================================================'
    if ($DryRun) {
        Write-Log ' <- Dry run complete. Re-run without -DryRun to apply.'
        Write-Log '    (No changes were made)' 'DRY'
    } else {
        Write-Log ' <- TLS certificate installation complete!'
        if ($Target -in @('AppServer','All')) {
            Write-Log '    Verify App Server: https://<fqdn>:9192/admin' 'WARN'
        }
    }
    Write-Log '============================================================'

} catch {
    Write-Log "FAILED: $_" 'ERROR'
    Write-AuditLog -Action 'TLS_INSTALL' -Status 'FAILED' -Detail $_.Exception.Message
    # Best-effort restart of whichever services may have been stopped
    if ($Target -in @('PrintDeploy','All')) {
        try { Control-Service -Name $PrintDeployServiceName   -Action 'Start' -Component 'PRINT DEPLOY'   } catch {}
    }
    if ($Target -in @('MobilityPrint','All')) {
        try { Control-Service -Name $MobilityPrintServiceName -Action 'Start' -Component 'MOBILITY PRINT' } catch {}
    }
    if ($Target -in @('AppServer','All')) {
        try { Control-Service -Name $AppServerServiceName     -Action 'Start' -Component 'APP SERVER'     } catch {}
    }
    exit 1

} finally {
    # Clear plain-text passwords from memory
    $KsPassPlain  = $null
    $KeyPassPlain = $null

    # Remove temp PFX exported from the Windows cert store
    if ($InputMode -eq 'CERTSTORE' -and (Test-Path $TmpPfx) -and -not $DryRun) {
        Remove-Item $TmpPfx -Force -EA SilentlyContinue
        Write-Log 'Removed temporary cert store export.'
    }
    # Remove the intermediate app_server.pfx (contains private key)
    $appPfxClean = Join-Path $WorkDir 'app_server.pfx'
    if ((Test-Path $appPfxClean) -and -not $DryRun) {
        Remove-Item $appPfxClean -Force -EA SilentlyContinue
    }
}