# Set-PaperCutTLS

A PowerShell script that installs a TLS/SSL certificate on PaperCut MF/NG components — Print Deploy, Mobility Print, and the Application Server — from any common certificate format.

## Requirements

- PowerShell 5.1 or later
- Run as Administrator
- OpenSSL is required for PFX/DER/P7B/CERTSTORE input modes and for the Application Server target (PEM → PKCS12 conversion). The script searches common install locations automatically and prompts with install options if not found — nothing is installed automatically.

## Supported Targets

| Target | Service | What it does |
|---|---|---|
| `PrintDeploy` | `pc-print-deploy` | Copies `tls.cer` + `tls.pem` to `providers\print-deploy\win\data\cert-custom\` |
| `MobilityPrint` | `PCMobilityPrint` | Copies `tls.cer` + `tls.pem` directly to the Mobility Print `data\` folder |
| `AppServer` | `PaperCut Application Server` | Creates a JKS keystore via PaperCut's bundled `create-ssl-keystore.exe` and updates `server.properties` |
| `All` | All three above | Default |

## Input Modes

| Mode | Description |
|---|---|
| `LETSENCRYPT` | Reads from a Certbot/Win-ACME/Posh-ACME/Certify the Web folder. Auto-selects the cert with the latest `NotAfter`, matches its key, optionally archives expired pairs. |
| `PFX_FILE` | Existing `.pfx` / `.p12` file. |
| `CERTSTORE` | Export from the Windows `LocalMachine\My` cert store by thumbprint. |
| `PEMS_READY` | Pre-prepared `tls.cer` + `tls.pem` files. |
| `AUTO` | Detect format from the supplied file path and route accordingly. |

## Auto-Discovery (LETSENCRYPT mode)

When `-SAN` is supplied and `-LetsEncryptPath` is omitted, the script scans common ACME client storage locations automatically:

| Client | Path |
|---|---|
| Posh-ACME | `%LOCALAPPDATA%\Posh-ACME\*\*\<domain>\` |
| Certbot | `C:\Certbot\archive\<domain>\` and `C:\Certbot\live\<domain>\` |
| Win-ACME | `C:\ProgramData\win-acme\*\Certificates\` (flat, SAN-scanned) |
| Certify the Web | `C:\ProgramData\certify\assets\<id>\` (per-item subdirs, SAN-scanned) |

## Usage Examples

```powershell
# Dry run — preview all actions without making changes
.\Set-PaperCutTLS.ps1 -InputMode LETSENCRYPT -SAN 'papercut.contoso.com' -DryRun

# All targets — auto-discover cert by SAN
.\Set-PaperCutTLS.ps1 -InputMode LETSENCRYPT -SAN 'papercut.contoso.com'

# All targets — auto-discover, archive certs expired more than 7 days ago
.\Set-PaperCutTLS.ps1 -InputMode LETSENCRYPT -SAN 'papercut.contoso.com' `
    -ArchiveExpired -ArchiveMinAgeDays 7

# Explicit path with SAN validation
.\Set-PaperCutTLS.ps1 -InputMode LETSENCRYPT -SAN 'papercut.contoso.com' `
    -LetsEncryptPath 'C:\Certbot\archive\papercut.contoso.com'

# Skip targets whose install path is not present on this machine
.\Set-PaperCutTLS.ps1 -InputMode LETSENCRYPT -SAN 'papercut.contoso.com' `
    -SkipMissingTargets

# Print Deploy only, from PFX
.\Set-PaperCutTLS.ps1 -Target PrintDeploy -InputMode PFX_FILE `
    -PfxPath 'C:\Certs\print.contoso.com.pfx'

# App Server only, from Windows cert store
.\Set-PaperCutTLS.ps1 -Target AppServer -InputMode CERTSTORE `
    -CertThumbprint 'A1B2C3D4E5F6...'

# App Server only, with non-default install path (PaperCut NG)
.\Set-PaperCutTLS.ps1 -Target AppServer -InputMode LETSENCRYPT `
    -SAN 'papercut.contoso.com' `
    -PaperCutInstallPath 'C:\Program Files\PaperCut NG'

# Clean — restore all targets to factory self-signed cert state
.\Set-PaperCutTLS.ps1 -Clean -Target All

# Preview what Clean would do without making changes
.\Set-PaperCutTLS.ps1 -Clean -Target All -DryRun
```

## Key Parameters

| Parameter | Default | Description |
|---|---|---|
| `-Target` | `All` | `PrintDeploy`, `MobilityPrint`, `AppServer`, or `All` |
| `-InputMode` | `LETSENCRYPT` | Certificate source mode (see table above) |
| `-SAN` | | Domain name for auto-discovery and cert validation |
| `-LetsEncryptPath` | | Explicit ACME cert folder (bypasses auto-discovery) |
| `-PfxPath` | | Path to `.pfx`/`.p12` (required for `PFX_FILE` mode) |
| `-CertThumbprint` | | `LocalMachine\My` thumbprint (required for `CERTSTORE` mode) |
| `-PaperCutInstallPath` | `C:\Program Files\PaperCut MF` | PaperCut MF/NG install root |
| `-MobilityPrintInstallPath` | `C:\Program Files (x86)\PaperCut Mobility Print` | Standalone Mobility Print root |
| `-KeystoreName` | `my-ssl-keystore` | JKS keystore filename placed in `server\custom\` |
| `-ArchiveExpired` | | Move expired cert/key pairs to `-ArchiveSubfolder` |
| `-ArchiveMinAgeDays` | `0` | Only archive certs expired at least this many days ago |
| `-SkipMissingTargets` | | Warn and skip targets whose install path doesn't exist |
| `-Clean` | | Restore targets to pre-installation state using backups |
| `-DryRun` | | Preview all actions without making any changes |
| `-LogPath` | `C:\Logs\PaperCutTLS.csv` | CSV audit log path |

## Notes

- Each run creates timestamped backups before replacing any files. `-Clean` restores the most recent backup, or removes deployed files if no backup exists.
- PaperCut MF 23.0+ auto-encrypts plain-text keystore passwords in `server.properties` on the next service restart.
- Installing a trusted certificate on Mobility Print automatically upgrades job delivery from IPP/HTTP to IPPS/HTTPS on port 9164.
- Certify the Web's default output is a password-protected PFX. Auto-discovery matches `.cer` (DER) and PEM exports. If only a password-protected PFX is present, use `-InputMode PFX_FILE -PfxPath <path>` instead.
