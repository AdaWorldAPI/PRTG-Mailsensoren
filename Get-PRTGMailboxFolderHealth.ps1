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

    [int]$WarningCount    = 25,
    [int]$ErrorCount      = 100,
    [int]$WarningCount1H  = 1,
    [int]$ErrorCount1H    = 5,

    [hashtable]$ChannelLimits = @{},

    [switch]$AsObject,             # return PSObject instead of writing to stdout
    [switch]$NoAutoRun             # for explicit "load only" via direct invoke
)

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

    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $null }

    try {
        $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop |
               ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Write-SensorLog "Config '$Path' could not be parsed: $_" -Level Error
        return $null
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
        [string]$Organization
    )

    $result = [ordered]@{
        Mailbox     = $Mailbox
        Mode        = $Mode
        Threshold   = $ThresholdMinutes
        Channels    = New-Object System.Collections.Generic.List[object]
        Errors      = New-Object System.Collections.Generic.List[string]
        Timestamp   = (Get-Date).ToString('o')
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
        }
        elseif ($isAged -or $is1H) {
            $w = $WarningCount1H ; $e = $ErrorCount1H
        }
        else {
            $w = $WarningCount   ; $e = $ErrorCount
        }

        $channelObj = [ordered]@{
            channel       = $c.Channel
            value         = $c.Value
            unit          = 'Custom'
            customunit    = '#'
            float         = 0
            limitmode     = 1
            limitmaxwarning = $w
            limitmaxerror   = $e
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
    param([Parameter(Mandatory)] $Health)

    if ($Health.Errors.Count -and $Health.Channels.Count -eq 0) {
        return "-1:$($Health.Errors -join ' | ')"
    }
    $first = $Health.Channels |
             Where-Object { $_.Kind -eq 'Total' } |
             Select-Object -First 1
    if (-not $first) { return "-1:no Total channel" }

    $msg = "$($first.Channel)=$($first.Value)"
    if ($Health.Errors.Count) {
        $msg += " (warn: $($Health.Errors.Count) folder error(s))"
    }
    return "$($first.Value):${msg}"
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
        $cfg = Import-SensorConfig -Path $Bound.Config
        if ($cfg) { foreach ($k in $cfg.Keys) { $effective[$k] = $cfg[$k] } }
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
                  'TenantId','ClientId','ClientSecret','CertificateThumbprint','Organization')
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
        Write-Output (Format-PrtgKeyValue -Health $health)
    }
    else {
        $fmtParams = @{
            Health           = $health
            WarningCount     = if ($effective.WarningCount)    { [int]$effective.WarningCount }    else { 25 }
            ErrorCount       = if ($effective.ErrorCount)      { [int]$effective.ErrorCount }      else { 100 }
            WarningCount1H   = if ($effective.WarningCount1H)  { [int]$effective.WarningCount1H }  else { 1 }
            ErrorCount1H     = if ($effective.ErrorCount1H)    { [int]$effective.ErrorCount1H }    else { 5 }
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
                 ($PSCommandPath)

if ($shouldAutoRun) {
    Invoke-PRTGFolderSensor -Bound $PSBoundParameters
}
