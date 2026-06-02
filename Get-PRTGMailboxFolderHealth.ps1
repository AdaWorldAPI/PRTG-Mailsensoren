<#
.SYNOPSIS
    PRTG sensor that reports per-folder mailbox health (total + aged items)
    via Microsoft Graph (primary) or Get-MailboxFolderStatistics (backup).

.DESCRIPTION
    Replaces the on-prem EWS folder sensor for cloud / hybrid mailboxes.

    Two flavours, one script:

      Graph  (default)   App-Registration / client_credentials.
                         Secret OR certificate auth. Folder is resolved by
                         displayName (root or nested). Returns:
                           - <Folder>          totalItemCount of folder
                           - <Folder> 1H       count of items where
                                               receivedDateTime is older
                                               than $ThresholdMinutes
                                               (i.e. "stuck" items / SLA breach)
                         Permissions: Mail.Read (Application).

      Legacy             ExchangeOnlineManagement, certificate based.
                         Wraps Get-MailboxFolderStatistics. Returns
                         ItemsInFolder and ItemsInFolderAndSubfolders.
                         No 1H aging available from this cmdlet -> the 1H
                         channels are emitted as -1 (PRTG: error/skip).

    Three call patterns are supported:

      1. Direct execution (PRTG default):
         .\Get-PRTGMailboxFolderHealth.ps1 `
              -Mailbox 'bsm@contoso.de' `
              -Folders 'Inbox','VM Fehler','VM in Arbeit' `
              -OneHourFolders 'Inbox','VM in Arbeit' `
              -Config 'C:\PRTG\Custom Sensors\EXEXML\folderhealth.json'

      2. Dot-source then call:
         . .\Get-PRTGMailboxFolderHealth.ps1
         Get-MailboxFolderHealth -Mailbox 'bsm@contoso.de' -Folders 'Inbox'

      3. Import-Module:
         Import-Module .\Get-PRTGMailboxFolderHealth.ps1 -Force
         Get-MailboxFolderHealth ...

    Auto-run is suppressed when the script is dot-sourced or imported, so
    selecting the whole file in ISE / VS Code and pressing F8 only loads
    the functions; it does not fire a sensor read.

.PARAMETER Mailbox
    Primary SMTP / UPN of the mailbox to probe (e.g. bsm@contoso.de).

.PARAMETER Folders
    One or more folder names to monitor. May be:
      - well-known shortcuts: Inbox, Posteingang, SentItems, Drafts ...
      - display name at root: "VM Fehler"
      - relative path:        "Inbox/VM Fehler"   (slash separator)

.PARAMETER OneHourFolders
    Subset of -Folders for which a "<Folder> 1H" channel is also produced.
    Counts items in that folder whose receivedDateTime is older than
    -ThresholdMinutes (default 60). Used as SLA / stuck-item indicator.

.PARAMETER ThresholdMinutes
    Age in minutes for the 1H channel. Default 60.

.PARAMETER Mode
    Graph (default) or Legacy. Legacy = Get-MailboxFolderStatistics fallback.

.PARAMETER TenantId, ClientId, ClientSecret, CertificateThumbprint, Organization
    Auth parameters. Either ClientSecret or CertificateThumbprint must be
    supplied for Graph. Legacy needs ClientId + CertificateThumbprint +
    Organization.

.PARAMETER Config
    Optional JSON file with the same parameter names. CLI args win over
    config; config wins over built-in defaults. Sensitive fields can be
    DPAPI-encrypted (suffix *Encrypted, e.g. ClientSecretEncrypted).

.PARAMETER OutputFormat
    Json   (default) -> PRTG EXE/Script Advanced (EXEXML) format
    KeyValue         -> legacy EXE/Script "value:message" format
                        (returns first folder's total count only,
                         since legacy sensors expose a single channel)

.PARAMETER WarningCount, ErrorCount, WarningCount1H, ErrorCount1H
    Per-channel limits embedded into the JSON output. Override per call
    or per channel via -ChannelLimits hashtable.

.EXAMPLE
    PRTG parameter line (EXE/Script Advanced):
      -Mailbox '%host' -Folders 'Inbox','VM Fehler','VM in Arbeit'
      -OneHourFolders 'Inbox','VM in Arbeit'
      -Config 'C:\PRTGSensorConfig\graph.json'

.NOTES
    Author : Jan Hubener
    Repo   : PSScript / Get-PRTGMailboxFolderHealth
    PRTG   : EXE/Script Advanced (Json) or EXE/Script (KeyValue)
#>

[CmdletBinding(DefaultParameterSetName = 'Graph')]
param(
    [Parameter(Position = 0)]
    [string]$Mailbox,

    [string[]]$Folders = @('Inbox'),

    [string[]]$OneHourFolders = @(),

    [int]$ThresholdMinutes = 60,

    [ValidateSet('Graph', 'Legacy')]
    [string]$Mode = 'Graph',

    # --- Graph auth -------------------------------------------------------
    [Parameter(ParameterSetName = 'Graph')]
    [string]$TenantId,

    [Parameter(ParameterSetName = 'Graph')]
    [string]$ClientId,

    [Parameter(ParameterSetName = 'Graph')]
    [string]$ClientSecret,

    [Parameter(ParameterSetName = 'Graph')]
    [string]$CertificateThumbprint,

    # --- Legacy auth (EXO + cert) ----------------------------------------
    [Parameter(ParameterSetName = 'Legacy')]
    [string]$Organization,

    # --- Generic ----------------------------------------------------------
    [string]$Config,

    [ValidateSet('Json', 'KeyValue')]
    [string]$OutputFormat = 'Json',

    # In KeyValue mode, which single channel becomes the value:
    #   Auto    - first existing in precedence: Aged(1H) -> QRecent -> Total -> QTotal
    #   Total   - first folder Total
    #   Aged    - first folder 1H (aged) channel
    #   QTotal / QRecent / QPhish / QMalware / QSpam - that quarantine channel
    [ValidateSet('Auto','Total','Aged','QTotal','QRecent','QPhish','QMalware','QSpam')]
    [string]$KeyValueChannel = 'Auto',

    [int]$WarningCount    = 25,
    [int]$ErrorCount      = 100,
    [int]$WarningCount1H  = 1,
    [int]$ErrorCount1H    = 5,

    [hashtable]$ChannelLimits = @{},

    # --- Quarantine (Defender for Office 365) ---------------------------
    # Requires EXO RBAC role 'Transport Hygiene' assigned to the Service
    # Principal (one-time):
    #   New-ManagementRoleAssignment -Role 'Transport Hygiene' -App <sp-objectid>
    [switch]$IncludeQuarantine,

    [ValidateSet('Graph','EXO')]
    [string]$QuarantineSource = 'Graph',

    [int]$QuarantineLookbackDays = 30,
    [int]$QuarantineRecentMinutes = 60,

    # Default thresholds tuned for security alerts:
    #  - Recent surge -> moderate alert (phishing campaign signal)
    #  - Any Phish / Malware -> sharp alert
    #  - Total / Spam      -> reference only, no thresholds
    [int]$WarningQuarantineRecent  = 5,
    [int]$ErrorQuarantineRecent    = 20,
    [int]$WarningQuarantinePhish   = 1,
    [int]$ErrorQuarantinePhish     = 5,
    [int]$WarningQuarantineMalware = 1,
    [int]$ErrorQuarantineMalware   = 3,

    [switch]$AsObject,             # return PSObject instead of writing to stdout
    [switch]$NoAutoRun             # for explicit "load only" via direct invoke
)

# TLS 1.2 hardening - Win PS 5.1 defaults to SSL3/TLS 1.0 which Microsoft
# endpoints rejected since 2022. Idempotent OR-in.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12


# =====================================================================
#  Module-scope state (token cache, log buffer)
# =====================================================================

$script:GraphState = @{
    Token   = $null
    Expires = [datetime]::MinValue
}

$script:LogBuffer = New-Object System.Collections.Generic.List[string]


# =====================================================================
#  Logging - everything goes to stderr so PRTG only sees the result
# =====================================================================

function Write-SensorLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Message,
        [ValidateSet('Info', 'Warn', 'Error', 'Debug')]
        [string]$Level = 'Info'
    )
    $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line  = "[$stamp][$Level] $Message"
    $script:LogBuffer.Add($line) | Out-Null
    if ($Level -eq 'Debug' -and -not $VerbosePreference) { return }
    [Console]::Error.WriteLine($line)
}


# =====================================================================
#  Configuration loader (JSON + DPAPI-encrypted fields)
# =====================================================================

function Import-SensorConfig {
    [CmdletBinding()]
    param([string]$Path)

    if (-not $Path) { return $null }

    if (-not (Test-Path -LiteralPath $Path)) {
        # Loud failure - empty config -> empty TenantId -> cryptic bind error
        # downstream. Throw with a clear message so the caller produces a
        # PRTG error envelope pointing at the actual problem.
        throw "Config file not found: '$Path'. Check the -Config path."
    }

    try {
        $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop |
               ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Config '$Path' could not be parsed: $($_.Exception.Message)"
    }

    # Decrypt *Encrypted fields (DPAPI, current user / machine)
    $cfg = @{}
    foreach ($prop in $raw.PSObject.Properties) {
        if ($prop.Name -like '*Encrypted') {
            $plainName = $prop.Name -replace 'Encrypted$', ''
            try {
                $sec   = ConvertTo-SecureString -String $prop.Value -ErrorAction Stop
                $bstr  = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
                $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
                $cfg[$plainName] = $plain
            }
            catch {
                Write-SensorLog "Decrypt failed for '$($prop.Name)': $_" -Level Warn
            }
        }
        else {
            $cfg[$prop.Name] = $prop.Value
        }
    }
    return $cfg
}


# =====================================================================
#  Microsoft Graph - token + paged request helper
# =====================================================================

# =====================================================================
#  Credential resolver - resolves config-stored credentials to plaintext
#
#  Supported storage formats (created by New-PRTGSensorCredential.ps1):
#
#    Cert      -> $cfg.Cert.Thumbprint + $cfg.Cert.Store
#    Plain     -> $cfg.Plain.Secret
#    DPAPI     -> $cfg.DPAPI.ProtectedSecret + $cfg.DPAPI.Scope
#    XOR       -> $cfg.XOR.ObfuscatedSecret + $cfg.XOR.KeyFile
#    Registry  -> $cfg.Registry.Path / .ValueName / .Encoding / .DpapiScope
#    CredMgr   -> $cfg.CredentialManager.Target
#
#  Fallback chain when $cfg.CredentialSource = 'Auto':
#    Cert > DPAPI-LM > Plain > XOR > Registry > DPAPI-CU > CredMgr
# =====================================================================

function Resolve-SensorCredential {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Config
    )

    # Normalise hashtable / PSCustomObject access
    function Get-Field { param($Obj, [string]$Name)
        if ($null -eq $Obj) { return $null }
        if ($Obj -is [hashtable]) { return $Obj[$Name] }
        if ($Obj.PSObject.Properties[$Name]) { return $Obj.$Name }
        return $null
    }

    $source = Get-Field $Config 'CredentialSource'
    if (-not $source) { $source = 'Auto' }

    $tryOrder = if ($source -eq 'Auto') {
        @('Cert','DPAPI','Plain','XOR','Registry','CredentialManager')
    } else {
        @($source)
    }

    foreach ($s in $tryOrder) {
        try {
            switch ($s) {

                'Cert' {
                    $cert = Get-Field $Config 'Cert'
                    if (-not $cert) { continue }
                    $tp    = Get-Field $cert 'Thumbprint'
                    $store = Get-Field $cert 'Store'
                    if (-not $tp) { continue }
                    return [pscustomobject]@{
                        Method                = 'Cert'
                        ClientSecret          = $null
                        CertificateThumbprint = $tp
                        CertificateStore      = if ($store) { $store } else { 'LocalMachine' }
                    }
                }

                'Plain' {
                    $p = Get-Field $Config 'Plain'
                    if (-not $p) { continue }
                    $sec = Get-Field $p 'Secret'
                    if (-not $sec) { continue }
                    return [pscustomobject]@{
                        Method                = 'Plain'
                        ClientSecret          = $sec
                        CertificateThumbprint = $null
                    }
                }

                'DPAPI' {
                    $d = Get-Field $Config 'DPAPI'
                    if (-not $d) { continue }
                    $body  = Get-Field $d 'ProtectedSecret'
                    $scope = Get-Field $d 'Scope'
                    $tag   = Get-Field $d 'EntropyTag'
                    if (-not $body) { continue }
                    if (-not $tag)  { $tag = 'PRTG-MailHealth-v1' }
                    Add-Type -AssemblyName System.Security
                    $bytes = [Convert]::FromBase64String($body)
                    $entr  = [Text.Encoding]::UTF8.GetBytes($tag)
                    $scopeEnum = if ($scope -eq 'LocalMachine') {
                        [Security.Cryptography.DataProtectionScope]::LocalMachine
                    } else {
                        [Security.Cryptography.DataProtectionScope]::CurrentUser
                    }
                    $plain = [Text.Encoding]::UTF8.GetString(
                        [Security.Cryptography.ProtectedData]::Unprotect($bytes, $entr, $scopeEnum))
                    return [pscustomobject]@{
                        Method                = "DPAPI-$scope"
                        ClientSecret          = $plain
                        CertificateThumbprint = $null
                    }
                }

                'XOR' {
                    $x = Get-Field $Config 'XOR'
                    if (-not $x) { continue }
                    $obf = Get-Field $x 'ObfuscatedSecret'
                    $kf  = Get-Field $x 'KeyFile'
                    if (-not $obf -or -not $kf -or -not (Test-Path $kf)) { continue }
                    $key   = [IO.File]::ReadAllBytes($kf)
                    $bytes = [Convert]::FromBase64String($obf)
                    $out   = New-Object byte[] $bytes.Length
                    for ($i=0; $i -lt $bytes.Length; $i++) {
                        $out[$i] = $bytes[$i] -bxor $key[$i % $key.Length]
                    }
                    return [pscustomobject]@{
                        Method                = 'XOR'
                        ClientSecret          = [Text.Encoding]::UTF8.GetString($out)
                        CertificateThumbprint = $null
                    }
                }

                'Registry' {
                    $r = Get-Field $Config 'Registry'
                    if (-not $r) { continue }
                    $path = Get-Field $r 'Path'
                    $vn   = Get-Field $r 'ValueName'
                    $enc  = Get-Field $r 'Encoding'
                    $sc   = Get-Field $r 'DpapiScope'
                    $tag  = Get-Field $r 'EntropyTag'
                    if (-not $vn)  { $vn  = 'ClientSecret' }
                    if (-not $enc) { $enc = 'Plain' }
                    if (-not $tag) { $tag = 'PRTG-MailHealth-v1' }
                    if (-not $path -or -not (Test-Path $path)) { continue }
                    $val = (Get-ItemProperty -Path $path -Name $vn -ErrorAction Stop).$vn
                    if (-not $val) { continue }
                    if ($enc -eq 'Plain') {
                        $plain = $val
                    }
                    else {
                        Add-Type -AssemblyName System.Security
                        $bytes = [Convert]::FromBase64String($val)
                        $entr  = [Text.Encoding]::UTF8.GetBytes($tag)
                        $scopeEnum = if ($sc -eq 'LocalMachine') {
                            [Security.Cryptography.DataProtectionScope]::LocalMachine
                        } else {
                            [Security.Cryptography.DataProtectionScope]::CurrentUser
                        }
                        $plain = [Text.Encoding]::UTF8.GetString(
                            [Security.Cryptography.ProtectedData]::Unprotect($bytes, $entr, $scopeEnum))
                    }
                    return [pscustomobject]@{
                        Method                = 'Registry'
                        ClientSecret          = $plain
                        CertificateThumbprint = $null
                    }
                }

                'CredentialManager' {
                    $cm = Get-Field $Config 'CredentialManager'
                    if (-not $cm) { continue }
                    $target = Get-Field $cm 'Target'
                    if (-not $target) { continue }
                    # P/Invoke CredRead - no module dependency
                    $sig = @'
[DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
public static extern bool CredReadW(string target, uint type, uint flags, out IntPtr cred);
[DllImport("advapi32.dll", SetLastError=true)]
public static extern void CredFree(IntPtr buf);
[StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
public struct CRED {
  public uint Flags; public uint Type; public string TargetName;
  public string Comment; public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
  public uint CredentialBlobSize; public IntPtr CredentialBlob;
  public uint Persist; public uint AttributeCount; public IntPtr Attributes;
  public string TargetAlias; public string UserName;
}
'@
                    if (-not ('CredApi' -as [type])) {
                        Add-Type -Namespace 'PRTGCred' -Name 'CredApi' -MemberDefinition $sig `
                                 -UsingNamespace 'System.Runtime.InteropServices' | Out-Null
                    }
                    $ptr = [IntPtr]::Zero
                    if (-not [PRTGCred.CredApi]::CredReadW($target, 1, 0, [ref]$ptr)) { continue }
                    try {
                        $cred  = [Runtime.InteropServices.Marshal]::PtrToStructure($ptr, [type][PRTGCred.CredApi+CRED])
                        $size  = [int]$cred.CredentialBlobSize
                        $bytes = New-Object byte[] $size
                        [Runtime.InteropServices.Marshal]::Copy($cred.CredentialBlob, $bytes, 0, $size)
                        $plain = [Text.Encoding]::Unicode.GetString($bytes)
                    }
                    finally { [PRTGCred.CredApi]::CredFree($ptr) }
                    return [pscustomobject]@{
                        Method                = 'CredentialManager'
                        ClientSecret          = $plain
                        CertificateThumbprint = $null
                    }
                }
            }
        }
        catch {
            Write-SensorLog "Credential source '${s}' failed: $($_.Exception.Message)" -Level Debug
            continue
        }
    }

    # Last-resort: legacy ClientSecretEncrypted (CurrentUser DPAPI string)
    $legacy = Get-Field $Config 'ClientSecretEncrypted'
    if ($legacy) {
        try {
            $sec  = ConvertTo-SecureString -String $legacy -ErrorAction Stop
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
            $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            return [pscustomobject]@{
                Method                = 'LegacyDPAPI-CU'
                ClientSecret          = $plain
                CertificateThumbprint = $null
            }
        } catch {}
    }

    # Plaintext at root level (lowest priority back-compat)
    $rootSecret = Get-Field $Config 'ClientSecret'
    $rootCert   = Get-Field $Config 'CertificateThumbprint'
    if ($rootSecret -or $rootCert) {
        return [pscustomobject]@{
            Method                = 'RootField'
            ClientSecret          = $rootSecret
            CertificateThumbprint = $rootCert
        }
    }

    throw "No usable credential found in config (CredentialSource='${source}')."
}



function Get-GraphAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$TenantId,
        [Parameter(Mandatory)] [string]$ClientId,
        [string]$ClientSecret,
        [string]$CertificateThumbprint
    )


    if ($script:GraphState.Token -and
        $script:GraphState.Expires -gt (Get-Date).AddMinutes(2)) {
        return $script:GraphState.Token
    }

    $tokenUrl = "https://login.microsoftonline.com/${TenantId}/oauth2/v2.0/token"

    if ($CertificateThumbprint) {

        $cert = Get-ChildItem -Path "Cert:\CurrentUser\My\${CertificateThumbprint}" -ErrorAction SilentlyContinue
        if (-not $cert) {
            $cert = Get-ChildItem -Path "Cert:\LocalMachine\My\${CertificateThumbprint}" -ErrorAction Stop
        }

        # Build client_assertion JWT
        $now    = [int][double]::Parse((Get-Date -UFormat %s))
        $jwtHdr = @{
            alg = 'RS256'
            typ = 'JWT'
            x5t = [Convert]::ToBase64String($cert.GetCertHash()) `
                       -replace '\+','-' -replace '/','_' -replace '='
        } | ConvertTo-Json -Compress

        $jwtBody = @{
            aud = $tokenUrl
            iss = $ClientId
            sub = $ClientId
            jti = [guid]::NewGuid().ToString()
            nbf = $now
            exp = $now + 600
        } | ConvertTo-Json -Compress

        $b64Hdr  = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($jwtHdr)) `
                        -replace '\+','-' -replace '/','_' -replace '='
        $b64Body = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($jwtBody)) `
                        -replace '\+','-' -replace '/','_' -replace '='

        $toSign  = "${b64Hdr}.${b64Body}"
        $rsa     = $cert.PrivateKey
        if (-not $rsa) {
            $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
        }
        $sigBytes = $rsa.SignData(
            [Text.Encoding]::UTF8.GetBytes($toSign),
            [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $b64Sig  = [Convert]::ToBase64String($sigBytes) `
                        -replace '\+','-' -replace '/','_' -replace '='

        $assertion = "${toSign}.${b64Sig}"

        $body = @{
            client_id             = $ClientId
            scope                 = 'https://graph.microsoft.com/.default'
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion      = $assertion
            grant_type            = 'client_credentials'
        }
    }
    elseif ($ClientSecret) {
        $body = @{
            client_id     = $ClientId
            client_secret = $ClientSecret
            scope         = 'https://graph.microsoft.com/.default'
            grant_type    = 'client_credentials'
        }
    }
    else {
        throw "No Graph credential supplied (need ClientSecret or CertificateThumbprint)."
    }

    Write-SensorLog "Acquiring Graph token (tenant=${TenantId})" -Level Debug
    $resp = Invoke-RestMethod -Method Post -Uri $tokenUrl `
                              -ContentType 'application/x-www-form-urlencoded' `
                              -Body $body -ErrorAction Stop

    $script:GraphState.Token   = $resp.access_token
    $script:GraphState.Expires = (Get-Date).AddSeconds([int]$resp.expires_in - 120)
    return $script:GraphState.Token
}

function Invoke-GraphCall {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Uri,
        [string]$Method = 'GET',
        [hashtable]$ExtraHeaders = @{},
        [Parameter(Mandatory)] [string]$Token,
        [int]$RetryMax = 4
    )


    $headers = @{
        Authorization    = "Bearer ${Token}"
        ConsistencyLevel = 'eventual'   # required for $count + advanced filters
    }
    foreach ($k in $ExtraHeaders.Keys) { $headers[$k] = $ExtraHeaders[$k] }

    for ($attempt = 1; $attempt -le $RetryMax; $attempt++) {
        try {
            return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers `
                                     -ErrorAction Stop
        }
        catch {
            $code = $_.Exception.Response.StatusCode.value__
            if ($code -in 429, 503) {
                $retry = $_.Exception.Response.Headers['Retry-After']
                $wait  = if ($retry) { [int]$retry } else { [int][math]::Pow(2, $attempt) }
                Write-SensorLog "Graph throttled (${code}); waiting ${wait}s (try $attempt/$RetryMax)" -Level Warn
                Start-Sleep -Seconds $wait
                continue
            }
            throw
        }
    }
    throw "Graph call exhausted ${RetryMax} retries: ${Uri}"
}


# =====================================================================
#  Folder resolution - well-known names, root displayName, nested path
# =====================================================================

function Resolve-MailFolder {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Mailbox,
        [Parameter(Mandatory)] [string]$FolderSpec,
        [Parameter(Mandatory)] [string]$Token
    )

    # Well-known folder shortcuts (DE + EN)
    $wellKnown = @{
        'inbox'         = 'inbox'
        'posteingang'   = 'inbox'
        'sentitems'     = 'sentitems'
        'gesendete'     = 'sentitems'
        'drafts'        = 'drafts'
        'entwuerfe'     = 'drafts'
        'entwürfe'      = 'drafts'
        'deleteditems'  = 'deleteditems'
        'geloescht'     = 'deleteditems'
        'gelöscht'      = 'deleteditems'
        'junkemail'     = 'junkemail'
        'junk'          = 'junkemail'
        'archive'       = 'archive'
        'archiv'        = 'archive'
    }

    $key = ($FolderSpec -replace '[\s_-]','').ToLowerInvariant()
    if ($wellKnown.ContainsKey($key)) {
        $wk  = $wellKnown[$key]
        $uri = "https://graph.microsoft.com/v1.0/users/${Mailbox}/mailFolders/${wk}"
        $r   = Invoke-GraphCall -Uri $uri -Token $Token
        return [pscustomobject]@{
            Id              = $r.id
            DisplayName     = $r.displayName
            TotalItemCount  = [int]$r.totalItemCount
            UnreadItemCount = [int]$r.unreadItemCount
            ResolvedFrom    = $FolderSpec
        }
    }

    # Path-based or root displayName
    $segments = $FolderSpec -split '[\\/]' | Where-Object { $_ }
    $parentId = $null
    $current  = $null

    foreach ($seg in $segments) {

        $segEsc = $seg -replace "'","''"

        if ($null -eq $parentId) {
            $listUri = "https://graph.microsoft.com/v1.0/users/${Mailbox}/mailFolders?`$filter=displayName eq '${segEsc}'&`$top=10"
        }
        else {
            $listUri = "https://graph.microsoft.com/v1.0/users/${Mailbox}/mailFolders/${parentId}/childFolders?`$filter=displayName eq '${segEsc}'&`$top=10"
        }

        $resp = Invoke-GraphCall -Uri $listUri -Token $Token
        if (-not $resp.value -or $resp.value.Count -eq 0) {
            throw "Folder segment '${seg}' not found under '${Mailbox}' (path: ${FolderSpec})."
        }

        $current  = $resp.value[0]
        $parentId = $current.id
    }

    return [pscustomobject]@{
        Id              = $current.id
        DisplayName     = $current.displayName
        TotalItemCount  = [int]$current.totalItemCount
        UnreadItemCount = [int]$current.unreadItemCount
        ResolvedFrom    = $FolderSpec
    }
}


# =====================================================================
#  Aged-item count (items older than threshold) via Graph
# =====================================================================

function Get-FolderAgedCount {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Mailbox,
        [Parameter(Mandatory)] [string]$FolderId,
        [Parameter(Mandatory)] [int]$ThresholdMinutes,
        [Parameter(Mandatory)] [string]$Token
    )

    $cutoff = (Get-Date).ToUniversalTime().AddMinutes(-$ThresholdMinutes).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $filter = "receivedDateTime lt ${cutoff}"
    $enc    = [Uri]::EscapeDataString($filter)
    $uri    = "https://graph.microsoft.com/v1.0/users/${Mailbox}/mailFolders/${FolderId}/messages?`$count=true&`$top=1&`$filter=${enc}"

    $resp = Invoke-GraphCall -Uri $uri -Token $Token
    return [int]$resp.'@odata.count'
}


# =====================================================================
#  Legacy flavour - Get-MailboxFolderStatistics (cert-based EXO connect)
# =====================================================================

function Connect-LegacyEXO {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$ClientId,
        [Parameter(Mandatory)] [string]$CertificateThumbprint,
        [Parameter(Mandatory)] [string]$Organization
    )


    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        throw "Module ExchangeOnlineManagement not installed on this probe."
    }
    Import-Module ExchangeOnlineManagement -ErrorAction Stop

    $existing = Get-ConnectionInformation -ErrorAction SilentlyContinue |
                Where-Object { $_.Organization -eq $Organization -and $_.State -eq 'Connected' }
    if ($existing) {
        Write-SensorLog "Reusing EXO connection: $($existing.ConnectionId)" -Level Debug
        return
    }

    Connect-ExchangeOnline `
        -AppId               $ClientId `
        -CertificateThumbprint $CertificateThumbprint `
        -Organization        $Organization `
        -ShowBanner:$false   `
        -ShowProgress:$false `
        -ErrorAction Stop | Out-Null
}

function Get-MailboxQuarantineCountsGraph {
    <#
    .SYNOPSIS
        Returns quarantine counts via Graph Advanced Hunting (EmailEvents).

    .DESCRIPTION
        Single KQL query aggregates all buckets server-side. Pure REST, no
        EXO module needed. Requires app permission ThreatHunting.Read.All.

        Quarantine in EmailEvents = DeliveryLocation == 'Quarantine'
        (NOT DeliveryAction - that is Delivered/Junked/Blocked/Replaced).

        NOTE: Advanced Hunting has ~15-30 min ingestion latency, so the
        Recent bucket can lag slightly behind real-time. The Total (lookback
        window) is reliable. For real-time use -QuarantineSource EXO.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Mailbox,
        [Parameter(Mandatory)] [string]$Token,
        [int]$LookbackDays   = 30,
        [int]$RecentMinutes  = 60
    )

    # Escape single quotes in the mailbox address for KQL string literal
    $mb = $Mailbox -replace "'", "''"

    $kql = @"
EmailEvents
| where Timestamp > ago($([int]$LookbackDays)d)
| where RecipientEmailAddress == '$mb'
| where DeliveryLocation == 'Quarantine'
| extend Bucket = case(
    ThreatTypes has 'Phish', 'Phish',
    ThreatTypes has 'Malware', 'Malware',
    ThreatTypes has 'Spam', 'Spam',
    'Other')
| summarize Total=count(),
            Recent=countif(Timestamp > ago($([int]$RecentMinutes)m)),
            Phish=countif(Bucket == 'Phish'),
            Malware=countif(Bucket == 'Malware'),
            Spam=countif(Bucket == 'Spam')
"@

    $body = @{ Query = $kql } | ConvertTo-Json
    $resp = Invoke-RestMethod -Method POST `
                -Uri "https://graph.microsoft.com/v1.0/security/runHuntingQuery" `
                -Headers @{ Authorization = "Bearer ${Token}"; 'Content-Type' = 'application/json' } `
                -Body $body -ErrorAction Stop

    $r = @($resp.results) | Select-Object -First 1
    if (-not $r) {
        # summarize with no matching rows still returns one row of zeros,
        # but guard anyway
        return [pscustomobject]@{ Total=0; Recent=0; Phish=0; Malware=0; Spam=0 }
    }
    return [pscustomobject]@{
        Total   = [int]$r.Total
        Recent  = [int]$r.Recent
        Phish   = [int]$r.Phish
        Malware = [int]$r.Malware
        Spam    = [int]$r.Spam
    }
}

function Get-MailboxQuarantineCounts {
    <#
    .SYNOPSIS
        Returns quarantine counts for a specific recipient mailbox.

    .DESCRIPTION
        Uses EXO PowerShell Get-QuarantineMessage with app-only cert auth.
        Caller must have Connect-LegacyEXO'd first.

        Returns five buckets:
          Total       - all quarantined messages in lookback window
          Recent      - messages received in last $RecentMinutes
          Phish       - Type in 'Phish','HighConfPhish','SpoofIntra'
          Malware     - Type eq 'Malware'
          Spam        - Type in 'Spam','HighConfSpam','Bulk'

    .NOTES
        Required RBAC role on the SP: 'Transport Hygiene'.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Mailbox,
        [int]$LookbackDays   = 30,
        [int]$RecentMinutes  = 60
    )

    if (-not (Get-Command Get-QuarantineMessage -ErrorAction SilentlyContinue)) {
        throw "Get-QuarantineMessage not available - EXO module not loaded or RBAC role missing."
    }

    $end   = Get-Date
    $start = $end.AddDays(-[Math]::Max(1, $LookbackDays))

    # Get-QuarantineMessage pagination - PageSize 1000 max, iterate Page
    $all  = New-Object System.Collections.Generic.List[object]
    $page = 1
    do {
        $batch = Get-QuarantineMessage `
                    -RecipientAddress $Mailbox `
                    -StartReceivedDate $start `
                    -EndReceivedDate   $end `
                    -PageSize 1000 -Page $page `
                    -ErrorAction Stop
        if (-not $batch) { break }
        $bc = ($batch | Measure-Object).Count
        foreach ($m in $batch) { $all.Add($m) | Out-Null }
        if ($bc -lt 1000) { break }
        $page++
        # safety: cap at 10 pages = 10k messages (would indicate misconfigured threshold)
        if ($page -gt 10) {
            Write-SensorLog "Quarantine query for $Mailbox capped at 10k messages." -Level Warn
            break
        }
    } while ($true)

    $recentCutoff = $end.AddMinutes(-[Math]::Abs($RecentMinutes))

    # Type field values from Get-QuarantineMessage:
    #   Spam, HighConfSpam, Phish, HighConfPhish, Bulk, Malware,
    #   SpoofIntra, TransportRule, UnAuth, Mass, FileTypeBlock
    $phishTypes   = @('Phish','HighConfPhish','SpoofIntra')
    $malwareTypes = @('Malware','FileTypeBlock')
    $spamTypes    = @('Spam','HighConfSpam','Bulk','Mass')

    return [pscustomobject]@{
        Total       = $all.Count
        Recent      = @($all | Where-Object { $_.ReceivedTime -ge $recentCutoff }).Count
        Phish       = @($all | Where-Object { $_.Type -in $phishTypes }).Count
        Malware     = @($all | Where-Object { $_.Type -in $malwareTypes }).Count
        Spam        = @($all | Where-Object { $_.Type -in $spamTypes }).Count
        WindowStart = $start.ToString('o')
        WindowEnd   = $end.ToString('o')
    }
}


function Get-FolderStatsLegacy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Mailbox,
        [Parameter(Mandatory)] [string]$FolderSpec
    )

    # Map well-known scopes for fast scoped query, fallback to full enumerate
    $scopeMap = @{
        'inbox'        = 'Inbox';       'posteingang'  = 'Inbox'
        'sentitems'    = 'SentItems';   'gesendete'    = 'SentItems'
        'drafts'       = 'Drafts';      'entwuerfe'    = 'Drafts'
        'deleteditems' = 'DeletedItems';'geloescht'    = 'DeletedItems'
    }
    $key   = ($FolderSpec -replace '[\s_-]','').ToLowerInvariant()
    $scope = if ($scopeMap.ContainsKey($key)) { $scopeMap[$key] } else { 'All' }

    $stats = Get-MailboxFolderStatistics -Identity $Mailbox -FolderScope $scope -ErrorAction Stop

    # Match by FolderPath suffix or Name
    $segments = $FolderSpec -split '[\\/]' | Where-Object { $_ }
    $leaf     = $segments[-1]
    $match    = $stats | Where-Object {
                  $_.Name -eq $leaf -or $_.FolderPath -like "*\${leaf}"
                } | Select-Object -First 1

    if (-not $match) {
        throw "Folder '${FolderSpec}' not found in ${Mailbox} (scope=${scope})."
    }

    return [pscustomobject]@{
        DisplayName               = $match.Name
        FolderPath                = $match.FolderPath
        ItemsInFolder             = [int]$match.ItemsInFolder
        ItemsInFolderAndSubfolders = [int]$match.ItemsInFolderAndSubfolders
        ResolvedFrom              = $FolderSpec
    }
}


# =====================================================================
#  Public function - the actual sensor read
# =====================================================================

function Get-MailboxFolderHealth {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Mailbox,
        [string[]]$Folders         = @('Inbox'),
        [string[]]$OneHourFolders  = @(),
        [int]$ThresholdMinutes     = 60,

        [ValidateSet('Graph','Legacy')]
        [string]$Mode = 'Graph',

        [string]$TenantId,
        [string]$ClientId,
        [string]$ClientSecret,
        [string]$CertificateThumbprint,
        [string]$Organization,

        # Quarantine (optional)
        [switch]$IncludeQuarantine,
        [ValidateSet('Graph','EXO')]
        [string]$QuarantineSource = 'Graph',
        [int]$QuarantineLookbackDays  = 30,
        [int]$QuarantineRecentMinutes = 60
    )

    $result = [ordered]@{
        Mailbox     = $Mailbox
        Mode        = $Mode
        Threshold   = $ThresholdMinutes
        Channels    = New-Object System.Collections.Generic.List[object]
        Errors      = New-Object System.Collections.Generic.List[string]
        Timestamp   = (Get-Date).ToString('o')
    }

    # Union: any entry in OneHourFolders that is not yet in Folders is added,
    # so -OneHourFolders 'X' alone (without -Folders 'X') still produces both
    # the Total and the 1H channel for X. The relative order in -Folders is
    # preserved; OneHourFolders-only entries are appended.
    if ($OneHourFolders.Count -gt 0) {
        $missing = $OneHourFolders | Where-Object { $Folders -notcontains $_ }
        if ($missing) { $Folders = @($Folders) + @($missing) }
    }

    if ($Mode -eq 'Graph') {

        $token = Get-GraphAccessToken `
                    -TenantId $TenantId `
                    -ClientId $ClientId `
                    -ClientSecret $ClientSecret `
                    -CertificateThumbprint $CertificateThumbprint

        foreach ($f in $Folders) {
            try {
                $resolved = Resolve-MailFolder -Mailbox $Mailbox -FolderSpec $f -Token $token
                $result.Channels.Add([pscustomobject]@{
                    Channel = $resolved.DisplayName
                    Kind    = 'Total'
                    Folder  = $f
                    Value   = $resolved.TotalItemCount
                })

                if ($OneHourFolders -contains $f) {
                    $aged = Get-FolderAgedCount -Mailbox $Mailbox -FolderId $resolved.Id `
                                -ThresholdMinutes $ThresholdMinutes -Token $token
                    $result.Channels.Add([pscustomobject]@{
                        Channel = "$($resolved.DisplayName) 1H"
                        Kind    = 'Aged'
                        Folder  = $f
                        Value   = $aged
                    })
                }
            }
            catch {
                $msg = "Folder '${f}' failed: $($_.Exception.Message)"
                Write-SensorLog $msg -Level Error
                $result.Errors.Add($msg) | Out-Null
            }
        }
    }
    else {
        # Legacy
        Connect-LegacyEXO -ClientId $ClientId `
                          -CertificateThumbprint $CertificateThumbprint `
                          -Organization $Organization

        foreach ($f in $Folders) {
            try {
                $stats = Get-FolderStatsLegacy -Mailbox $Mailbox -FolderSpec $f
                $result.Channels.Add([pscustomobject]@{
                    Channel = $stats.DisplayName
                    Kind    = 'Total'
                    Folder  = $f
                    Value   = $stats.ItemsInFolder
                })
                $result.Channels.Add([pscustomobject]@{
                    Channel = "$($stats.DisplayName) (incl. Subfolders)"
                    Kind    = 'TotalSub'
                    Folder  = $f
                    Value   = $stats.ItemsInFolderAndSubfolders
                })

                if ($OneHourFolders -contains $f) {
                    # Legacy cannot age messages -> emit -1 to signal "not supported"
                    $result.Channels.Add([pscustomobject]@{
                        Channel = "$($stats.DisplayName) 1H"
                        Kind    = 'Aged'
                        Folder  = $f
                        Value   = -1
                    })
                }
            }
            catch {
                $msg = "Folder '${f}' failed: $($_.Exception.Message)"
                Write-SensorLog $msg -Level Error
                $result.Errors.Add($msg) | Out-Null
            }
        }
    }

    # ---------------------------------------------------------------
    #  Optional Quarantine block (Defender for Office 365)
    #  Two backends:
    #    Graph (default) - Advanced Hunting EmailEvents, pure REST,
    #                      needs app perm ThreatHunting.Read.All
    #    EXO             - Get-QuarantineMessage, real-time, needs EXO
    #                      module + RBAC role 'Transport Hygiene'
    # ---------------------------------------------------------------
    if ($IncludeQuarantine) {
        try {
            if ($QuarantineSource -eq 'Graph') {
                # Reuse the Graph token already acquired above (Mode=Graph),
                # otherwise acquire one now (Mode=Legacy path).
                if (-not $token) {
                    $token = Get-GraphAccessToken `
                                -TenantId $TenantId -ClientId $ClientId `
                                -ClientSecret $ClientSecret `
                                -CertificateThumbprint $CertificateThumbprint
                }
                $q = Get-MailboxQuarantineCountsGraph -Mailbox $Mailbox -Token $token `
                        -LookbackDays  $QuarantineLookbackDays `
                        -RecentMinutes $QuarantineRecentMinutes
            }
            else {
                # EXO backend
                if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
                    throw "ExchangeOnlineManagement module not installed - cannot query quarantine via EXO."
                }
                if (-not $Organization) {
                    $domain = ($Mailbox -split '@')[-1]
                    Write-SensorLog "Organization not set; deriving '$domain' from mailbox for EXO connect." -Level Debug
                    $Organization = $domain
                }
                Connect-LegacyEXO -ClientId $ClientId `
                                  -CertificateThumbprint $CertificateThumbprint `
                                  -Organization $Organization
                $q = Get-MailboxQuarantineCounts -Mailbox $Mailbox `
                        -LookbackDays  $QuarantineLookbackDays `
                        -RecentMinutes $QuarantineRecentMinutes
            }

            $result.Channels.Add([pscustomobject]@{ Channel='Quarantine Total';   Kind='QTotal';   Folder='_quarantine'; Value=$q.Total   }) | Out-Null
            $result.Channels.Add([pscustomobject]@{ Channel='Quarantine Recent';  Kind='QRecent';  Folder='_quarantine'; Value=$q.Recent  }) | Out-Null
            $result.Channels.Add([pscustomobject]@{ Channel='Quarantine Phish';   Kind='QPhish';   Folder='_quarantine'; Value=$q.Phish   }) | Out-Null
            $result.Channels.Add([pscustomobject]@{ Channel='Quarantine Malware'; Kind='QMalware'; Folder='_quarantine'; Value=$q.Malware }) | Out-Null
            $result.Channels.Add([pscustomobject]@{ Channel='Quarantine Spam';    Kind='QSpam';    Folder='_quarantine'; Value=$q.Spam    }) | Out-Null
        }
        catch {
            $msg = "Quarantine query ($QuarantineSource) failed: $($_.Exception.Message)"
            Write-SensorLog $msg -Level Error
            $result.Errors.Add($msg) | Out-Null
            if ($_.Exception.Message -match 'role|permission|denied|unauthor|forbidden') {
                if ($QuarantineSource -eq 'Graph') {
                    $result.Errors.Add("Hint: App needs permission 'ThreatHunting.Read.All' (admin-consented).") | Out-Null
                } else {
                    $result.Errors.Add("Hint: Service Principal needs RBAC role 'Transport Hygiene'. Run: Connect-ExchangeOnline; New-ManagementRoleAssignment -Role 'Transport Hygiene' -App <sp-objectid>") | Out-Null
                }
            }
        }
    }

    return [pscustomobject]$result
}


# =====================================================================
#  PRTG output formatters
# =====================================================================

function Format-PrtgJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Health,
        [int]$WarningCount    = 25,
        [int]$ErrorCount      = 100,
        [int]$WarningCount1H  = 1,
        [int]$ErrorCount1H    = 5,

        # Quarantine thresholds
        [int]$WarningQuarantineRecent  = 5,
        [int]$ErrorQuarantineRecent    = 20,
        [int]$WarningQuarantinePhish   = 1,
        [int]$ErrorQuarantinePhish     = 5,
        [int]$WarningQuarantineMalware = 1,
        [int]$ErrorQuarantineMalware   = 3,

        [hashtable]$ChannelLimits = @{}
    )

    $channels = New-Object System.Collections.Generic.List[object]

    foreach ($c in $Health.Channels) {

        $isAged   = ($c.Kind -eq 'Aged')
        $is1H     = ($c.Channel -like '* 1H')

        # Channel-specific override?
        if ($ChannelLimits.ContainsKey($c.Channel)) {
            $lim = $ChannelLimits[$c.Channel]
            $w   = [int]$lim.Warning
            $e   = [int]$lim.Error
            $suppress = $false
        }
        # Quarantine Kinds:
        #  QRecent (recent-window spike) is the ONLY alerting channel.
        #  QTotal/QPhish/QMalware/QSpam are CUMULATIVE over the lookback
        #  window, so they are volume/trend references - alerting on a
        #  cumulative count would mean permanent red once the window has
        #  any history. They stay reference-only unless the caller overrides
        #  via -ChannelLimits.
        elseif ($c.Kind -eq 'QRecent') {
            $w = $WarningQuarantineRecent  ; $e = $ErrorQuarantineRecent  ; $suppress = $false
        }
        elseif ($c.Kind -in 'QTotal','QPhish','QMalware','QSpam') {
            $w = 0 ; $e = 0 ; $suppress = $true
        }
        elseif ($isAged -or $is1H) {
            $w = $WarningCount1H ; $e = $ErrorCount1H ; $suppress = $false
        }
        else {
            $w = $WarningCount   ; $e = $ErrorCount   ; $suppress = $false
        }

        $channelObj = [ordered]@{
            channel       = $c.Channel
            value         = $c.Value
            unit          = 'Custom'
            customunit    = '#'
            float         = 0
            limitmode     = if ($suppress) { 0 } else { 1 }
        }
        if (-not $suppress) {
            $channelObj.limitmaxwarning = $w
            $channelObj.limitmaxerror   = $e
        }

        # -1 = "not supported by this flavour" -> downgrade to error/skip
        if ($c.Value -lt 0) {
            $channelObj.limitmode       = 1
            $channelObj.limitmaxerror   = 0
            $channelObj.limitmaxwarning = 0
        }

        $channels.Add([pscustomobject]$channelObj) | Out-Null
    }

    $text = if ($Health.Errors.Count) {
        "Errors: " + ($Health.Errors -join ' | ')
    } else {
        "OK - $($Health.Channels.Count) channels - $($Health.Mode)"
    }

    $obj = @{
        prtg = @{
            result = $channels
            text   = $text
        }
    }

    if ($Health.Errors.Count -and $Health.Channels.Count -eq 0) {
        $obj.prtg['error'] = 1
    }

    return ($obj | ConvertTo-Json -Depth 6 -Compress:$false)
}

function Format-PrtgKeyValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Health,
        [ValidateSet('Auto','Total','Aged','QTotal','QRecent','QPhish','QMalware','QSpam')]
        [string]$Select = 'Auto'
    )

    if ($Health.Errors.Count -and $Health.Channels.Count -eq 0) {
        return "-1:$($Health.Errors -join ' | ')"
    }

    $pick = $null

    if ($Select -ne 'Auto') {
        # Explicit: find the channel whose Kind matches the selector
        $pick = $Health.Channels | Where-Object { $_.Kind -eq $Select } | Select-Object -First 1
        if (-not $pick) {
            return "-1:KeyValueChannel '$Select' not present (channel not produced - check -IncludeQuarantine / -OneHourFolders)"
        }
    }
    else {
        # Auto precedence: the most specific intentional signal wins.
        #   Aged (1H folder stuck-detection) -> QRecent (quarantine spike)
        #   -> Total (folder volume) -> QTotal (quarantine volume)
        foreach ($kind in 'Aged','QRecent','Total','QTotal') {
            $pick = $Health.Channels | Where-Object { $_.Kind -eq $kind } | Select-Object -First 1
            if ($pick) { break }
        }
    }

    if (-not $pick) { return "-1:no channel produced" }

    $msg = "$($pick.Channel)=$($pick.Value)"
    if ($Health.Errors.Count) {
        $msg += " (warn: $($Health.Errors.Count) error(s))"
    }
    return "$($pick.Value):${msg}"
}


# =====================================================================
#  Main entry - merges Config -> CLI, calls Get-MailboxFolderHealth,
#  emits PRTG-shaped output. Wrapped so that dot-source skips it.
# =====================================================================

function Invoke-PRTGFolderSensor {
    [CmdletBinding()]
    param([hashtable]$Bound)

    # 1. Layer config under CLI args
    $effective = @{}
    if ($Bound.Config) {
        try {
            $cfg = Import-SensorConfig -Path $Bound.Config
            if ($cfg) { foreach ($k in $cfg.Keys) { $effective[$k] = $cfg[$k] } }
        }
        catch {
            $err = $_.Exception.Message
            Write-SensorLog $err -Level Error
            $fmt = if ($Bound.OutputFormat -eq 'KeyValue') { 'KeyValue' } else { 'Json' }
            if ($fmt -eq 'KeyValue') { Write-Output "-1:${err}" }
            else { Write-Output (@{ prtg = @{ error = 1; text = $err } } | ConvertTo-Json -Depth 4) }
            return
        }
    }
    foreach ($k in $Bound.Keys) {
        if ($null -ne $Bound[$k] -and $Bound[$k] -isnot [switch]) {
            $effective[$k] = $Bound[$k]
        }
        elseif ($Bound[$k] -is [switch] -and $Bound[$k].IsPresent) {
            $effective[$k] = $true
        }
    }

    # 1b. Resolve credentials via the multi-source resolver IF the config carries
    #     a CredentialSource block and CLI didn't supply explicit secret/cert.
    if (-not $effective.ClientSecret -and -not $effective.CertificateThumbprint) {
        $hasStructuredCred = $effective.ContainsKey('CredentialSource') -or
                             $effective.ContainsKey('Cert') -or
                             $effective.ContainsKey('Plain') -or
                             $effective.ContainsKey('DPAPI') -or
                             $effective.ContainsKey('XOR') -or
                             $effective.ContainsKey('Registry') -or
                             $effective.ContainsKey('CredentialManager')
        if ($hasStructuredCred) {
            try {
                $resolved = Resolve-SensorCredential -Config ([pscustomobject]$effective)
                if ($resolved.ClientSecret)          { $effective.ClientSecret          = $resolved.ClientSecret }
                if ($resolved.CertificateThumbprint) { $effective.CertificateThumbprint = $resolved.CertificateThumbprint }
                Write-SensorLog "Credential resolved via $($resolved.Method)" -Level Debug
            }
            catch {
                $err = "Credential resolution failed: $($_.Exception.Message)"
                Write-SensorLog $err -Level Error
                if ($effective.OutputFormat -eq 'KeyValue') { Write-Output "-1:${err}" }
                else {
                    $j = @{ prtg = @{ error = 1; text = $err } } | ConvertTo-Json -Depth 4
                    Write-Output $j
                }
                return
            }
        }
    }

    if (-not $effective.Mailbox) {
        $err = "Mailbox parameter is required."
        if ($effective.OutputFormat -eq 'KeyValue') { Write-Output "-1:${err}" }
        else {
            $j = @{ prtg = @{ error = 1; text = $err } } | ConvertTo-Json -Depth 4
            Write-Output $j
        }
        return
    }

    # 2. Build splat for Get-MailboxFolderHealth
    $passKeys = @('Mailbox','Folders','OneHourFolders','ThresholdMinutes','Mode',
                  'TenantId','ClientId','ClientSecret','CertificateThumbprint','Organization',
                  'IncludeQuarantine','QuarantineSource','QuarantineLookbackDays','QuarantineRecentMinutes')
    $splat = @{}
    foreach ($k in $passKeys) {
        if ($effective.ContainsKey($k) -and $null -ne $effective[$k] -and "$($effective[$k])" -ne '') {
            $splat[$k] = $effective[$k]
        }
    }

    try {
        $health = Get-MailboxFolderHealth @splat
    }
    catch {
        $err = $_.Exception.Message
        Write-SensorLog $err -Level Error
        if ($effective.OutputFormat -eq 'KeyValue') { Write-Output "-1:${err}" }
        else {
            $j = @{ prtg = @{ error = 1; text = $err } } | ConvertTo-Json -Depth 4
            Write-Output $j
        }
        return
    }

    if ($effective.AsObject) { return $health }

    # 3. Format
    if ($effective.OutputFormat -eq 'KeyValue') {
        $kvSel = if ($effective.KeyValueChannel) { $effective.KeyValueChannel } else { 'Auto' }
        Write-Output (Format-PrtgKeyValue -Health $health -Select $kvSel)
    }
    else {
        $fmtParams = @{
            Health           = $health
            WarningCount     = if ($effective.WarningCount)    { [int]$effective.WarningCount }    else { 25 }
            ErrorCount       = if ($effective.ErrorCount)      { [int]$effective.ErrorCount }      else { 100 }
            WarningCount1H   = if ($effective.WarningCount1H)  { [int]$effective.WarningCount1H }  else { 1 }
            ErrorCount1H     = if ($effective.ErrorCount1H)    { [int]$effective.ErrorCount1H }    else { 5 }
            WarningQuarantineRecent  = if ($effective.WarningQuarantineRecent)  { [int]$effective.WarningQuarantineRecent }  else { 5 }
            ErrorQuarantineRecent    = if ($effective.ErrorQuarantineRecent)    { [int]$effective.ErrorQuarantineRecent }    else { 20 }
            WarningQuarantinePhish   = if ($effective.WarningQuarantinePhish)   { [int]$effective.WarningQuarantinePhish }   else { 1 }
            ErrorQuarantinePhish     = if ($effective.ErrorQuarantinePhish)     { [int]$effective.ErrorQuarantinePhish }     else { 5 }
            WarningQuarantineMalware = if ($effective.WarningQuarantineMalware) { [int]$effective.WarningQuarantineMalware } else { 1 }
            ErrorQuarantineMalware   = if ($effective.ErrorQuarantineMalware)   { [int]$effective.ErrorQuarantineMalware }   else { 3 }
            ChannelLimits    = if ($effective.ChannelLimits)   { $effective.ChannelLimits }        else { @{} }
        }
        Write-Output (Format-PrtgJson @fmtParams)
    }
}


# =====================================================================
#  Auto-run guard
#
#  Fires Invoke-PRTGFolderSensor only when the file is invoked directly
#  (PRTG, .\script.ps1). Skipped on:
#    - dot-source ( . .\script.ps1 )
#    - Import-Module / New-Module
#    - explicit -NoAutoRun
#
#  In module context, PowerShell exports every top-level function by
#  default - we deliberately do NOT call Export-ModuleMember, so all
#  functions become Get-Command-able after Import-Module.
# =====================================================================

$shouldAutoRun = (-not $NoAutoRun) -and
                 (-not $ExecutionContext.SessionState.Module) -and
                 ($MyInvocation.InvocationName -ne '.') -and
                 ($MyInvocation.Line -notmatch '^\s*\.\s+') -and
                 ($MyInvocation.Line -notmatch '\bImport-Module\b') -and
                 ($MyInvocation.MyCommand.ScriptBlock.Module -eq $null) -and
                 ($PSCommandPath)

if ($shouldAutoRun) {
    Invoke-PRTGFolderSensor -Bound $PSBoundParameters
}
