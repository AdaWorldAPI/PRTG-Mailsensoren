<#
.SYNOPSIS
    Grants read access to the sensor's config JSON and certificate private key
    to one or more identities (typically the PRTG probe service account, plus
    optionally a colleague's account).

.DESCRIPTION
    The provisioning helper (New-PRTGSensorCredential.ps1) hardens the config
    JSON so only SYSTEM, Administrators and the user who ran provisioning have
    access. The certificate private key, similarly, is by default readable
    only by SYSTEM and the creating user.

    For a productive PRTG deployment the *probe service account* needs read
    access to BOTH the config and the cert private key. This script grants
    that access without opening up the file/key to "Authenticated Users".

.PARAMETER Identity
    One or more accounts to grant access to. Domain users in the form
    DOMAIN\username, local users in the form COMPUTERNAME\username, or
    well-known SIDs.

.PARAMETER ConfigPath
    Path to the sensor config JSON.
    Default: C:\ProgramData\PRTGSensors\folderhealth.json

.PARAMETER Thumbprint
    Cert thumbprint to grant access to. If omitted, read from ConfigPath.

.PARAMETER CertStore
    LocalMachine | CurrentUser. Default LocalMachine.

.EXAMPLE
    # Probe service account
    .\Grant-PRTGSensorAccess.ps1 -Identity 'DOMAIN\svc_prtgprobe'

.EXAMPLE
    # Probe + colleague
    .\Grant-PRTGSensorAccess.ps1 -Identity 'DOMAIN\svc_prtgprobe','DOMAIN\T1.User'

.NOTES
    Requires elevated PowerShell. Idempotent - existing rules for the same
    identity are not duplicated.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string[]]$Identity,

    [string]$ConfigPath = 'C:\ProgramData\PRTGSensors\folderhealth.json',

    [string]$Thumbprint,

    [ValidateSet('LocalMachine','CurrentUser')]
    [string]$CertStore = 'LocalMachine'
)

function Test-Elevation {
    $p = New-Object Security.Principal.WindowsPrincipal(
            [Security.Principal.WindowsIdentity]::GetCurrent())
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Elevation)) {
    throw "This script must run elevated (Administrator)."
}

# ---------------------------------------------------------------------
#  Resolve thumbprint from config if not given
# ---------------------------------------------------------------------
if (-not $Thumbprint) {
    if (-not (Test-Path -LiteralPath $ConfigPath)) {
        throw "Config not found: $ConfigPath. Supply -Thumbprint explicitly."
    }
    $cfg = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
    $Thumbprint = $cfg.Cert.Thumbprint
    if (-not $Thumbprint) {
        throw "Config $ConfigPath has no Cert.Thumbprint - is this a Cert-method config?"
    }
}

# ---------------------------------------------------------------------
#  1. Grant Read on config JSON
# ---------------------------------------------------------------------
if (Test-Path -LiteralPath $ConfigPath) {
    $acl = Get-Acl -LiteralPath $ConfigPath
    foreach ($id in $Identity) {
        $existing = $acl.Access | Where-Object {
            $_.IdentityReference.Value -eq $id -and
            $_.AccessControlType -eq 'Allow' -and
            ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Read)
        }
        if ($existing) {
            Write-Host "[~] Config: $id already has Read" -ForegroundColor Yellow
            continue
        }
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            $id, 'Read', 'Allow')
        $acl.AddAccessRule($rule)
        Write-Host "[+] Config: granted Read to $id" -ForegroundColor Green
    }
    Set-Acl -LiteralPath $ConfigPath -AclObject $acl
} else {
    Write-Warning "Config path $ConfigPath does not exist; skipping config ACL."
}

# ---------------------------------------------------------------------
#  2. Grant Read on certificate private key
# ---------------------------------------------------------------------
$cert = Get-Item "Cert:\${CertStore}\My\${Thumbprint}" -ErrorAction Stop

# Locate the actual private-key file. CNG keys live under \Crypto\Keys\,
# CSP keys under \Crypto\RSA\MachineKeys\ (or \Crypto\RSA\<SID>\ for
# CurrentUser scope).
$keyFile = $null

# Try CNG first
try {
    $cng = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    if ($cng -and $cng.Key -and $cng.Key.UniqueName) {
        $keyName = $cng.Key.UniqueName
        if ($CertStore -eq 'LocalMachine') {
            $candidate = Join-Path $env:ProgramData "Microsoft\Crypto\Keys\$keyName"
            if (Test-Path -LiteralPath $candidate) { $keyFile = $candidate }
        } else {
            $candidate = Join-Path $env:APPDATA "Microsoft\Crypto\Keys\$keyName"
            if (Test-Path -LiteralPath $candidate) { $keyFile = $candidate }
        }
    }
} catch {}

# Fall back to legacy CSP
if (-not $keyFile -and $cert.PrivateKey) {
    try {
        $keyName = $cert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
        $candidates = @(
            (Join-Path $env:ProgramData "Microsoft\Crypto\RSA\MachineKeys\$keyName"),
            (Join-Path $env:APPDATA      "Microsoft\Crypto\RSA\$keyName")
        )
        foreach ($c in $candidates) {
            if (Test-Path -LiteralPath $c) { $keyFile = $c; break }
        }
    } catch {}
}

if (-not $keyFile) {
    throw "Could not locate the private key file for thumbprint $Thumbprint."
}

Write-Host "    Private key file: $keyFile"
$acl = Get-Acl -LiteralPath $keyFile
foreach ($id in $Identity) {
    $existing = $acl.Access | Where-Object {
        $_.IdentityReference.Value -eq $id -and
        $_.AccessControlType -eq 'Allow' -and
        ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Read)
    }
    if ($existing) {
        Write-Host "[~] PrivateKey: $id already has Read" -ForegroundColor Yellow
        continue
    }
    $rule = New-Object Security.AccessControl.FileSystemAccessRule(
        $id, 'Read', 'Allow')
    $acl.AddAccessRule($rule)
    Write-Host "[+] PrivateKey: granted Read to $id" -ForegroundColor Green
}
Set-Acl -LiteralPath $keyFile -AclObject $acl

Write-Host ""
Write-Host "Done. Verify with: " -NoNewline
Write-Host "Get-Acl '$keyFile' | Format-List" -ForegroundColor Cyan
