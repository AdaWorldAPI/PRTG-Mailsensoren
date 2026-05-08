<#
.SYNOPSIS
    Provisions and stores credentials for Get-PRTGMailboxFolderHealth.ps1
    (and the mail-flow sensor).

.DESCRIPTION
    One helper, six credential storage methods, plus self-signed cert
    generation. Writes a config JSON that the sensor consumes via -Config.

    Storage methods (resilience against AD profile rebuild / password drift):

      CertLM       : self-signed cert in Cert:\LocalMachine\My         [SAFE]
      CertCU       : self-signed cert in Cert:\CurrentUser\My          [profile-bound]
      Plain        : ClientSecret as plaintext in ACL'd JSON           [SAFE - relies on NTFS]
      DPAPI-LM     : DPAPI machine-scope encrypted secret              [SAFE]
      DPAPI-CU     : DPAPI user-scope encrypted secret                 [profile-bound]
      XOR          : obfuscated secret + keyfile (NOT real crypto)     [SAFE - relies on NTFS]
      Registry-LM  : HKLM\Software\... value (Plain or DPAPI-LM body)  [SAFE]
      Registry-CU  : HKCU\Software\... value                           [profile-bound]
      CredMgr      : Windows Credential Manager                        [profile-bound]

    For PRTG running under a service account, ALWAYS use a *-LM method.
    The CU and CredMgr methods are exposed for interactive testing only.

.PARAMETER Method
    One of: CertLM, CertCU, Plain, DPAPI-LM, DPAPI-CU, XOR,
            Registry-LM, Registry-CU, CredMgr.

.PARAMETER TenantId
.PARAMETER ClientId
    Azure AD tenant + app-registration IDs to bake into the resulting config.

.PARAMETER ConfigPath
    Where to write the resulting config JSON. Default:
    C:\ProgramData\PRTGSensors\folderhealth.json

.PARAMETER ClientSecret
    SecureString. Required for Plain / DPAPI-* / XOR / Registry-* / CredMgr.
    If not provided, the script prompts. PRTG service-account use case:
    pass via -ClientSecret (Read-Host -AsSecureString) once during setup.

.PARAMETER CertSubject
    Cert mode. Default: "CN=PRTG-MailHealth-$ComputerName".

.PARAMETER CertValidYears
    Cert mode. Default 2.

.PARAMETER CertExportPath
    Cert mode. Folder to drop the .cer (public key, for Azure upload).
    Default: $env:USERPROFILE\Desktop, fallback $env:TEMP.

.PARAMETER PfxPassword
    Cert mode. If provided, ALSO exports the .pfx (private + public)
    next to the .cer. Useful for backup / cross-host deployment.

.PARAMETER XORKeyFile
    XOR mode. Path to keyfile. Created if not present (256 random bytes).
    Default: C:\ProgramData\PRTGSensors\sensor.key

.PARAMETER RegistryPath
    Registry-* modes. Default HKLM:\Software\PRTGSensors\Default
    (or HKCU equivalent for Registry-CU).

.PARAMETER CredentialName
    CredMgr mode. Default: PRTG-MailHealth.

.PARAMETER TestToken
    After provisioning, attempt a Graph token acquisition end-to-end and
    report success/failure. Default $true.

.EXAMPLE
    # SAFE recommended path: cert in LocalMachine, public key on Desktop
    .\New-PRTGSensorCredential.ps1 -Method CertLM `
        -TenantId 00000000-0000-0000-0000-000000000000 `
        -ClientId 11111111-1111-1111-1111-111111111111

.EXAMPLE
    # Secret-based, machine-scoped DPAPI
    $sec = Read-Host "ClientSecret" -AsSecureString
    .\New-PRTGSensorCredential.ps1 -Method DPAPI-LM -ClientSecret $sec `
        -TenantId ... -ClientId ...

.EXAMPLE
    # Obfuscated secret + keyfile (for environments where DPAPI is unwanted)
    .\New-PRTGSensorCredential.ps1 -Method XOR -ClientSecret $sec `
        -TenantId ... -ClientId ... `
        -XORKeyFile 'D:\PRTG\Keys\bsm.key'

.NOTES
    Author : Jan Hubener
    Repo   : PSScript / Get-PRTGMailboxFolderHealth (helpers)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('CertLM','CertCU','Plain','DPAPI-LM','DPAPI-CU','XOR',
                 'Registry-LM','Registry-CU','CredMgr')]
    [string]$Method,

    [Parameter(Mandatory)]
    [string]$TenantId,

    [Parameter(Mandatory)]
    [string]$ClientId,

    [string]$ConfigPath = (Join-Path $env:ProgramData 'PRTGSensors\folderhealth.json'),

    # Secret modes
    [securestring]$ClientSecret,

    # Cert modes
    [string]$CertSubject     = "CN=PRTG-MailHealth-$env:COMPUTERNAME",
    [int]   $CertValidYears  = 2,
    [string]$CertExportPath,
    [securestring]$PfxPassword,

    # XOR mode
    [string]$XORKeyFile      = (Join-Path $env:ProgramData 'PRTGSensors\sensor.key'),

    # Registry modes
    [string]$RegistryPath,

    # CredMgr mode
    [string]$CredentialName  = 'PRTG-MailHealth',

    [bool]  $TestToken       = $true,

    [switch]$Force
)

# ---------------------------------------------------------------------
#  Helpers
# ---------------------------------------------------------------------

function Write-Step {
    param([string]$Text, [ValidateSet('Info','OK','Warn','Err','Step')] [string]$Level = 'Info')
    $color = switch ($Level) {
        'Step' { 'Cyan' }
        'OK'   { 'Green' }
        'Warn' { 'Yellow' }
        'Err'  { 'Red' }
        default { 'White' }
    }
    $tag = switch ($Level) {
        'Step' { '[*]' }
        'OK'   { '[+]' }
        'Warn' { '[!]' }
        'Err'  { '[X]' }
        default { '[ ]' }
    }
    Write-Host "$tag $Text" -ForegroundColor $color
}

function ConvertFrom-SecureToPlain {
    param([securestring]$Secure)
    $bstr  = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try   { return [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function Test-Elevation {
    $p = New-Object Security.Principal.WindowsPrincipal(
            [Security.Principal.WindowsIdentity]::GetCurrent())
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Set-PathACL {
    <# Strip Users group, leave SYSTEM + Administrators + the current/service user #>
    param([Parameter(Mandatory)] [string]$Path)
    if (-not (Test-Path $Path)) { return }
    try {
        $acl = Get-Acl -Path $Path
        $acl.SetAccessRuleProtection($true, $false)   # disable inheritance, copy nothing
        $rules = @(
            New-Object Security.AccessControl.FileSystemAccessRule(
                'NT AUTHORITY\SYSTEM','FullControl','Allow')
            New-Object Security.AccessControl.FileSystemAccessRule(
                'BUILTIN\Administrators','FullControl','Allow')
            New-Object Security.AccessControl.FileSystemAccessRule(
                ([Security.Principal.WindowsIdentity]::GetCurrent().Name),
                'FullControl','Allow')
        )
        foreach ($r in $rules) { $acl.AddAccessRule($r) }
        Set-Acl -Path $Path -AclObject $acl
        Write-Step "ACL hardened: $Path" -Level OK
    }
    catch {
        Write-Step "ACL hardening failed for ${Path}: $($_.Exception.Message)" -Level Warn
    }
}

# ---------------------------------------------------------------------
#  Method dispatchers
# ---------------------------------------------------------------------

function New-CertCredential {
    param(
        [string]$Subject,
        [int]   $Years,
        [ValidateSet('LocalMachine','CurrentUser')] [string]$Scope,
        [string]$ExportPath,
        [securestring]$PfxPwd
    )

    if ($Scope -eq 'LocalMachine' -and -not (Test-Elevation)) {
        throw "CertLM requires elevated PowerShell. Restart as Administrator."
    }

    $storePath = "Cert:\${Scope}\My"
    Write-Step "Creating self-signed cert in ${storePath} (subject=${Subject}, ${Years}y)" -Level Step

    $cert = New-SelfSignedCertificate `
        -Subject           $Subject `
        -CertStoreLocation $storePath `
        -KeyExportPolicy   Exportable `
        -KeyAlgorithm      RSA `
        -KeyLength         2048 `
        -NotAfter          (Get-Date).AddYears($Years) `
        -KeyUsage          DigitalSignature, KeyEncipherment `
        -HashAlgorithm     SHA256 `
        -ErrorAction       Stop

    Write-Step "Thumbprint: $($cert.Thumbprint)" -Level OK

    # Export .cer (public key) for Azure upload
    if (-not $ExportPath) {
        $desktop = [Environment]::GetFolderPath('Desktop')
        $ExportPath = if ($desktop -and (Test-Path $desktop)) { $desktop } else { $env:TEMP }
    }
    if (-not (Test-Path $ExportPath)) { New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null }

    $cerFile = Join-Path $ExportPath "PRTG-MailHealth-$($cert.Thumbprint.Substring(0,8)).cer"
    Export-Certificate -Cert $cert -FilePath $cerFile -Type CERT | Out-Null
    Write-Step ".CER exported: ${cerFile}" -Level OK

    if ($PfxPwd) {
        $pfxFile = [IO.Path]::ChangeExtension($cerFile, '.pfx')
        Export-PfxCertificate -Cert $cert -FilePath $pfxFile -Password $PfxPwd | Out-Null
        Write-Step ".PFX exported: ${pfxFile}" -Level OK
    }

    return @{
        CredentialSource = 'Cert'
        Cert = @{
            Thumbprint = $cert.Thumbprint
            Store      = $Scope
            Subject    = $Subject
            NotAfter   = $cert.NotAfter.ToString('o')
        }
        _AzureUpload = @{
            File = $cerFile
            Steps = @(
                "1. Open https://entra.microsoft.com -> App registrations -> ${ClientId}",
                "2. Certificates & secrets -> Certificates -> Upload certificate",
                "3. Browse to: ${cerFile}",
                "4. Verify thumbprint matches: $($cert.Thumbprint)"
            )
        }
    }
}

function New-PlainCredential {
    param([securestring]$Secret)
    return @{
        CredentialSource = 'Plain'
        Plain = @{ Secret = (ConvertFrom-SecureToPlain $Secret) }
    }
}

function New-DPAPICredential {
    param(
        [securestring]$Secret,
        [ValidateSet('LocalMachine','CurrentUser')] [string]$Scope
    )

    Add-Type -AssemblyName System.Security
    $plainBytes = [Text.Encoding]::UTF8.GetBytes((ConvertFrom-SecureToPlain $Secret))
    $entropy    = [Text.Encoding]::UTF8.GetBytes('PRTG-MailHealth-v1')

    $scopeEnum = if ($Scope -eq 'LocalMachine') {
        [Security.Cryptography.DataProtectionScope]::LocalMachine
    } else {
        [Security.Cryptography.DataProtectionScope]::CurrentUser
    }

    $protected = [Security.Cryptography.ProtectedData]::Protect(
        $plainBytes, $entropy, $scopeEnum)

    [Array]::Clear($plainBytes, 0, $plainBytes.Length)

    return @{
        CredentialSource = 'DPAPI'
        DPAPI = @{
            Scope           = $Scope
            ProtectedSecret = [Convert]::ToBase64String($protected)
            EntropyTag      = 'PRTG-MailHealth-v1'
        }
    }
}

function New-XORCredential {
    param([securestring]$Secret, [string]$KeyFile)

    $keyDir = Split-Path $KeyFile -Parent
    if (-not (Test-Path $keyDir)) { New-Item -ItemType Directory -Path $keyDir -Force | Out-Null }

    if (-not (Test-Path $KeyFile)) {
        Write-Step "Generating new XOR keyfile: ${KeyFile}" -Level Step
        $keyBytes = New-Object byte[] 256
        [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($keyBytes)
        [IO.File]::WriteAllBytes($KeyFile, $keyBytes)
        Set-PathACL -Path $KeyFile
    }
    $key = [IO.File]::ReadAllBytes($KeyFile)

    $plainBytes = [Text.Encoding]::UTF8.GetBytes((ConvertFrom-SecureToPlain $Secret))
    $obf        = New-Object byte[] $plainBytes.Length
    for ($i = 0; $i -lt $plainBytes.Length; $i++) {
        $obf[$i] = $plainBytes[$i] -bxor $key[$i % $key.Length]
    }
    [Array]::Clear($plainBytes, 0, $plainBytes.Length)

    return @{
        CredentialSource = 'XOR'
        XOR = @{
            ObfuscatedSecret = [Convert]::ToBase64String($obf)
            KeyFile          = $KeyFile
        }
    }
}

function New-RegistryCredential {
    param(
        [securestring]$Secret,
        [ValidateSet('LocalMachine','CurrentUser')] [string]$Scope,
        [string]$Path,
        [string]$ValueName = 'ClientSecret'
    )

    if (-not $Path) {
        $hive = if ($Scope -eq 'LocalMachine') { 'HKLM:' } else { 'HKCU:' }
        $Path = "${hive}\Software\PRTGSensors\Default"
    }
    if ($Scope -eq 'LocalMachine' -and -not (Test-Elevation)) {
        throw "Registry-LM requires elevated PowerShell."
    }

    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }

    # Body: DPAPI-encrypt with same scope as the hive
    Add-Type -AssemblyName System.Security
    $plainBytes = [Text.Encoding]::UTF8.GetBytes((ConvertFrom-SecureToPlain $Secret))
    $entropy    = [Text.Encoding]::UTF8.GetBytes('PRTG-MailHealth-v1')
    $scopeEnum  = if ($Scope -eq 'LocalMachine') {
        [Security.Cryptography.DataProtectionScope]::LocalMachine
    } else {
        [Security.Cryptography.DataProtectionScope]::CurrentUser
    }
    $protected = [Security.Cryptography.ProtectedData]::Protect(
        $plainBytes, $entropy, $scopeEnum)
    [Array]::Clear($plainBytes, 0, $plainBytes.Length)

    Set-ItemProperty -Path $Path -Name $ValueName `
                     -Value ([Convert]::ToBase64String($protected)) -Force

    return @{
        CredentialSource = 'Registry'
        Registry = @{
            Path       = $Path
            ValueName  = $ValueName
            Encoding   = 'DPAPI'
            DpapiScope = $Scope
            EntropyTag = 'PRTG-MailHealth-v1'
        }
    }
}

function New-CredMgrCredential {
    param([securestring]$Secret, [string]$Target, [string]$ClientId)

    # Use cmdkey under the hood (no extra module dependency)
    $plain = ConvertFrom-SecureToPlain $Secret
    $rc = (Start-Process -FilePath cmdkey.exe `
            -ArgumentList "/generic:${Target}", "/user:${ClientId}", "/pass:${plain}" `
            -NoNewWindow -Wait -PassThru).ExitCode
    if ($rc -ne 0) { throw "cmdkey failed (exit ${rc})" }

    return @{
        CredentialSource = 'CredentialManager'
        CredentialManager = @{
            Target = $Target
            User   = $ClientId
        }
    }
}

# ---------------------------------------------------------------------
#  Main
# ---------------------------------------------------------------------

Write-Step "PRTG Sensor Credential Provisioning ($Method)" -Level Step
Write-Step "Tenant: $TenantId  /  Client: $ClientId" -Level Info

# Validate / prompt for secret if needed
$secretRequired = $Method -in 'Plain','DPAPI-LM','DPAPI-CU','XOR','Registry-LM','Registry-CU','CredMgr'
if ($secretRequired -and -not $ClientSecret) {
    $ClientSecret = Read-Host -Prompt "Paste ClientSecret value from App Registration" -AsSecureString
}

# Prepare config dir
$cfgDir = Split-Path $ConfigPath -Parent
if (-not (Test-Path $cfgDir)) { New-Item -ItemType Directory -Path $cfgDir -Force | Out-Null }

# Dispatch
$credBlock = switch ($Method) {
    'CertLM'      { New-CertCredential -Subject $CertSubject -Years $CertValidYears `
                         -Scope LocalMachine -ExportPath $CertExportPath -PfxPwd $PfxPassword }
    'CertCU'      { New-CertCredential -Subject $CertSubject -Years $CertValidYears `
                         -Scope CurrentUser  -ExportPath $CertExportPath -PfxPwd $PfxPassword }
    'Plain'       { New-PlainCredential -Secret $ClientSecret }
    'DPAPI-LM'    { New-DPAPICredential -Secret $ClientSecret -Scope LocalMachine }
    'DPAPI-CU'    { New-DPAPICredential -Secret $ClientSecret -Scope CurrentUser }
    'XOR'         { New-XORCredential   -Secret $ClientSecret -KeyFile $XORKeyFile }
    'Registry-LM' { New-RegistryCredential -Secret $ClientSecret -Scope LocalMachine -Path $RegistryPath }
    'Registry-CU' { New-RegistryCredential -Secret $ClientSecret -Scope CurrentUser  -Path $RegistryPath }
    'CredMgr'     { New-CredMgrCredential  -Secret $ClientSecret -Target $CredentialName -ClientId $ClientId }
}

# Pull aside the Azure-upload metadata (not part of the persistent config)
$azureUpload = $null
if ($credBlock._AzureUpload) {
    $azureUpload = $credBlock._AzureUpload
    $credBlock.Remove('_AzureUpload')
}

# Build / merge the config file
$cfg = @{}
if ((Test-Path $ConfigPath) -and -not $Force) {
    try {
        $raw = Get-Content $ConfigPath -Raw -ErrorAction Stop
        if ((Get-Command ConvertFrom-Json).Parameters.ContainsKey('AsHashtable')) {
            $cfg = $raw | ConvertFrom-Json -AsHashtable
        }
        else {
            # Windows PowerShell 5.1 fallback
            $obj = $raw | ConvertFrom-Json
            $cfg = @{}
            $obj.PSObject.Properties | ForEach-Object { $cfg[$_.Name] = $_.Value }
        }
    } catch {
        Write-Step "Existing config could not be parsed; rewriting clean: $($_.Exception.Message)" -Level Warn
        $cfg = @{}
    }
}
$cfg.TenantId = $TenantId
$cfg.ClientId = $ClientId
foreach ($k in $credBlock.Keys) { $cfg[$k] = $credBlock[$k] }

$cfg | ConvertTo-Json -Depth 10 | Set-Content -Path $ConfigPath -Encoding UTF8
Set-PathACL -Path $ConfigPath
Write-Step "Config written: ${ConfigPath}" -Level OK

# Profile-resilience reminder
$profileBound = $Method -in 'CertCU','DPAPI-CU','Registry-CU','CredMgr'
if ($profileBound) {
    Write-Step ("Method '${Method}' is profile-bound. The credential will become " +
                "unreadable if the user profile is rebuilt or the password rotates. " +
                "Use *-LM, Plain, or XOR for service-account / unattended scenarios.") -Level Warn
}

# Azure upload guidance for cert
if ($azureUpload) {
    Write-Host ""
    Write-Step "AZURE PORTAL UPLOAD STEPS" -Level Step
    foreach ($s in $azureUpload.Steps) { Write-Host "    $s" }
}

# Optional self-test
if ($TestToken) {
    Write-Host ""
    Write-Step "Self-test (Graph token acquisition)" -Level Step

    # Lazy-load the resolver from the main sensor if available alongside
    $resolverPath = Join-Path $PSScriptRoot 'Get-PRTGMailboxFolderHealth.ps1'
    if (Test-Path $resolverPath) {
        . $resolverPath -NoAutoRun
        try {
            $cred = Resolve-SensorCredential -Config $cfg
            $token = Get-GraphAccessToken -TenantId $TenantId -ClientId $ClientId `
                        -ClientSecret $cred.ClientSecret `
                        -CertificateThumbprint $cred.CertificateThumbprint
            if ($token) {
                Write-Step "Graph token acquired (length=$($token.Length))" -Level OK
            }
        }
        catch {
            Write-Step "Self-test FAILED: $($_.Exception.Message)" -Level Err
            if ($Method -like 'Cert*') {
                Write-Step "Did you upload the .CER to the App Registration?" -Level Warn
            }
        }
    }
    else {
        Write-Step "Sensor script not found next to this helper; skipping self-test." -Level Warn
    }
}

Write-Host ""
Write-Step "Done. Use '-Config ${ConfigPath}' on the sensor command line." -Level OK
