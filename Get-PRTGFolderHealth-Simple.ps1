#==========================================================================================================
# PRTG EXE/Script Advanced (EXEXML) - Mailbox folder totals via Microsoft Graph (cert app-only)
#
# Parameters (positional, quote it in PRTG):
#   "%scriptplaceholder1" "%scriptplaceholder2" "%scriptplaceholder3" "%scriptplaceholder4" "%scriptplaceholder5"
#     1 = TenantId
#     2 = ClientId
#     3 = CertificateThumbprint   (cert in LocalMachine\My OR CurrentUser\My)
#     4 = Mailbox                 (e.g. mirai.bsm@bsm.datagroup.de)
#     5 = FolderList              (';' delimited, e.g. Posteingang;Posteingang/VM Fehler)
#                                 '+' = space (so placeholder5 needs no quoting):
#                                   Posteingang/VM+Fehler  ==  "Posteingang/VM Fehler"
#                                 Literal spaces still work if you quote the field.
#                                 Per-token limits: 'Spec=warn:err' (e.g. Junk-E-Mail=3:10)
#                                 or 'Spec=0' to disable limits (e.g. Posteingang/VM Ok=0).
#                                 Bare 'Spec' uses the default warn 25 / err 100.
#                                 Token '@1h:<folder>' adds a '<folder> 1H' aging channel
#                                 (messages older than 60 min) - default warn 1 / err 5,
#                                 overridable: @1h:Posteingang=2:5 (or =0 for reference).
#                                 Special token '@quarantine' adds 5 Defender-for-O365
#                                 quarantine channels for the mailbox (Total / Recent /
#                                 Phish / Malware / Spam) via Graph Advanced Hunting.
#                                 Needs app permission ThreatHunting.Read.All (admin
#                                 consent). Only 'Quarantine Recent' (last 60 min) alerts;
#                                 the others are cumulative-over-30d references. Pass it
#                                 alone for a quarantine-only sensor, or mix with folders:
#                                   Posteingang;Junk-E-Mail;@quarantine
#
# Iron-clad rules:
#   - every arg is quote-stripped (handles ' " or none surviving PRTG's mangling)
#   - cert errors are classified: not-found / no-private-key / key-unusable
#   - each folder is isolated in try/catch; one bad folder never kills the others
#   - output is flat here-string <prtg> XML, no <?xml?>, BOM-less UTF-8
#==========================================================================================================
Param(
    [string]$scriptplaceholder1,
    [string]$scriptplaceholder2,
    [string]$scriptplaceholder3,
    [string]$scriptplaceholder4,
    [string]$scriptplaceholder5
)

# stdout BOM-less UTF-8 (PS 5.1 otherwise emits a BOM PRTG's parser chokes on -> PE231)
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false } catch {}
$OutputEncoding = New-Object System.Text.UTF8Encoding $false
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

#----------------------------------------------------------------------------------------------------------
# Helpers
#----------------------------------------------------------------------------------------------------------

# Strip a single matched pair of surrounding ' or " and trim. PRTG/cmd quoting can leave
# values like  'F80A...'  or  "Posteingang;..."  ; this normalises them back to bare text.
function Clean-Arg {
    param([string]$s)
    if ($null -eq $s) { return '' }
    $s = $s.Trim()
    while ($s.Length -ge 2 -and
          (($s[0] -eq "'" -and $s[-1] -eq "'") -or ($s[0] -eq '"' -and $s[-1] -eq '"'))) {
        $s = $s.Substring(1, $s.Length - 2).Trim()
    }
    return $s
}

function Xml-Escape {
    param([string]$s)
    if ($null -eq $s) { return '' }
    $s = $s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;'
    return ($s -replace '"','&quot;')
}

# Single exit point for fatal errors -> valid PRTG XML error envelope.
function Emit-Error {
    param([string]$Message)
    $m = Xml-Escape $Message
    Write-Output @"
<prtg>
    <error>1</error>
    <text>$m</text>
</prtg>
"@
    exit 0   # PRTG reads the XML, not the exit code; never throw past here
}

# Resolve the cert AND prove we can sign with it. Returns the X509 object or throws
# a classified, human-readable reason.
function Resolve-AuthCert {
    param([string]$Thumbprint)

    $tp = ($Thumbprint -replace '[^0-9A-Fa-f]', '').ToUpper()   # tolerate spaces/colons
    if (-not $tp) { throw "CERT_INPUT: thumbprint is empty after cleaning (got '$Thumbprint')." }

    $cert = Get-Item -Path "Cert:\CurrentUser\My\$tp"  -ErrorAction SilentlyContinue
    if (-not $cert) {
        $cert = Get-Item -Path "Cert:\LocalMachine\My\$tp" -ErrorAction SilentlyContinue
    }
    if (-not $cert) {
        throw "CERT_NOT_FOUND: thumbprint $tp is in neither CurrentUser\My nor LocalMachine\My on this probe."
    }

    # Private key object?
    $rsa = $null
    try {
        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    } catch { $rsa = $null }
    if (-not $rsa -and $cert.PrivateKey) { $rsa = $cert.PrivateKey }

    if (-not $rsa) {
        throw "CERT_NO_PRIVKEY: cert $tp found but its private key is not accessible to '$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)'. Grant :R on the key file (Crypto\Keys or Crypto\RSA\MachineKeys) to the probe service account."
    }

    # Prove the key actually signs (catches ACL-present-but-CSP-broken cases).
    try {
        [void]$rsa.SignData([Text.Encoding]::UTF8.GetBytes('probe'),
            [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.RSASignaturePadding]::Pkcs1)
    } catch {
        throw "CERT_KEY_UNUSABLE: cert $tp has a private key but signing failed ($($_.Exception.Message)). Likely ACL/CSP problem for the probe account."
    }

    return @{ Cert = $cert; Rsa = $rsa }
}

function Get-GraphToken {
    param([string]$TenantId, [string]$ClientId, $CertBundle)

    $cert = $CertBundle.Cert
    $rsa  = $CertBundle.Rsa
    $url  = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

    # Culture-invariant epoch (see Graph variant): avoids a de-DE / PS 5.1
    # [double]::Parse misread of a fractional UFormat %s value.
    $now = [int][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $hdr = @{ alg='RS256'; typ='JWT'
              x5t = ([Convert]::ToBase64String($cert.GetCertHash()) -replace '\+','-' -replace '/','_' -replace '=') } | ConvertTo-Json -Compress
    $bdy = @{ aud=$url; iss=$ClientId; sub=$ClientId; jti=[guid]::NewGuid().ToString(); nbf=$now; exp=$now+600 } | ConvertTo-Json -Compress

    $b64h = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($hdr)) -replace '\+','-' -replace '/','_' -replace '='
    $b64b = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($bdy)) -replace '\+','-' -replace '/','_' -replace '='
    $sig  = [Convert]::ToBase64String(
                $rsa.SignData([Text.Encoding]::UTF8.GetBytes("$b64h.$b64b"),
                    [Security.Cryptography.HashAlgorithmName]::SHA256,
                    [Security.Cryptography.RSASignaturePadding]::Pkcs1)
            ) -replace '\+','-' -replace '/','_' -replace '='
    $assertion = "$b64h.$b64b.$sig"

    $resp = Invoke-RestMethod -Method Post -Uri $url -ContentType 'application/x-www-form-urlencoded' -Body @{
        client_id             = $ClientId
        scope                 = 'https://graph.microsoft.com/.default'
        client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        client_assertion      = $assertion
        grant_type            = 'client_credentials'
    } -ErrorAction Stop
    return $resp.access_token
}

# Well-known DE/EN folder shortcuts -> Graph well-known id
$WellKnown = @{
    'inbox'='inbox'; 'posteingang'='inbox'; 'sentitems'='sentitems'; 'gesendete'='sentitems'
    'drafts'='drafts'; 'entwuerfe'='drafts'; 'deleteditems'='deleteditems'; 'geloescht'='deleteditems'
    'junkemail'='junkemail'; 'junk'='junkemail'; 'archive'='archive'; 'archiv'='archive'
}

# Resolve a folder spec to its totalItemCount. Path segments split on / or \.
function Get-FolderTotal {
    param([string]$Mailbox, [string]$Spec, [string]$Token)

    $h = @{ Authorization = "Bearer $Token" }
    $key = ($Spec -replace '[\s_-]','').ToLowerInvariant()

    if ($WellKnown.ContainsKey($key)) {
        $r = Invoke-RestMethod -Headers $h -ErrorAction Stop `
                -Uri "https://graph.microsoft.com/v1.0/users/$Mailbox/mailFolders/$($WellKnown[$key])"
        return [pscustomobject]@{ Name=$r.displayName; Total=[int]$r.totalItemCount; Id=$r.id }
    }

    $segments = $Spec -split '[\\/]' | Where-Object { $_ -ne '' }
    if ($segments.Count -eq 0) { throw "empty folder spec." }

    $parent = $null; $cur = $null
    foreach ($seg in $segments) {
        $segEsc = $seg.Trim() -replace "'","''"
        $uri = if ($null -eq $parent) {
            "https://graph.microsoft.com/v1.0/users/$Mailbox/mailFolders?`$filter=displayName eq '$segEsc'&`$top=10"
        } else {
            "https://graph.microsoft.com/v1.0/users/$Mailbox/mailFolders/$parent/childFolders?`$filter=displayName eq '$segEsc'&`$top=10"
        }
        $resp = Invoke-RestMethod -Headers $h -Uri $uri -ErrorAction Stop
        if (-not $resp.value -or $resp.value.Count -eq 0) {
            throw "segment '$seg' not found under '$Spec'."
        }
        $cur = $resp.value[0]; $parent = $cur.id
    }
    return [pscustomobject]@{ Name=$cur.displayName; Total=[int]$cur.totalItemCount; Id=$cur.id }
}

# 1H = count of message items older than $Minutes (default 60) in a folder -
# a queue-stuck / SLA signal. $count=true returns @odata.count server-side
# (no pagination cap). ConsistencyLevel:eventual is required for $count+$filter.
function Get-AgedMessageCount {
    param([string]$Mailbox, [string]$FolderId, [string]$Token, [int]$Minutes = 60)
    $cutoff = (Get-Date).ToUniversalTime().AddMinutes(-$Minutes).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $filter = [Uri]::EscapeDataString("receivedDateTime lt $cutoff")
    $uri    = "https://graph.microsoft.com/v1.0/users/$Mailbox/mailFolders/$FolderId/messages?`$count=true&`$top=1&`$filter=$filter&`$select=id"
    $resp   = Invoke-RestMethod -Headers @{ Authorization = "Bearer $Token"; ConsistencyLevel = 'eventual' } `
                -Uri $uri -ErrorAction Stop
    if ($null -eq $resp.'@odata.count') { throw "Graph returned no @odata.count for the 1H query." }
    return [int]$resp.'@odata.count'
}

# Defender-for-O365 quarantine counts for one mailbox via Graph Advanced Hunting
# (EmailEvents, DeliveryLocation == 'Quarantine'). Pure REST - no EXO module.
# Requires app permission ThreatHunting.Read.All (admin-consented). One KQL query
# aggregates all buckets server-side. ~15-30 min ingestion latency on the Recent
# bucket; Total is reliable.
function Get-QuarantineCountsGraph {
    param([string]$Mailbox, [string]$Token, [int]$LookbackDays = 30, [int]$RecentMinutes = 60)

    $mb  = $Mailbox -replace "'", "''"   # KQL string-literal escape
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
                -Uri 'https://graph.microsoft.com/v1.0/security/runHuntingQuery' `
                -Headers @{ Authorization = "Bearer $Token"; 'Content-Type' = 'application/json' } `
                -Body $body -ErrorAction Stop

    $r = @($resp.results) | Select-Object -First 1
    if (-not $r) { return [pscustomobject]@{ Total=0; Recent=0; Phish=0; Malware=0; Spam=0 } }
    return [pscustomobject]@{
        Total   = [int]$r.Total
        Recent  = [int]$r.Recent
        Phish   = [int]$r.Phish
        Malware = [int]$r.Malware
        Spam    = [int]$r.Spam
    }
}

# Per-token limit syntax (same as the Graph variant):
#   'Spec'           -> default limits (folders warn 25 / err 100)
#   'Spec=warn:err'  -> custom limits, e.g. Junk-E-Mail=3:10
#   'Spec=0'         -> limits OFF (reference-only), e.g. Posteingang/VM Ok=0
# For '@quarantine', the limit applies to the 'Quarantine Recent' channel
# (e.g. @quarantine=2:5); '@quarantine=0' makes Recent reference-only too.
# Returns @{ Spec; LimitMode; Warn; Err; HasLimit }.
function Parse-FolderToken {
    param([string]$Token)
    $r  = @{ Spec = $Token; LimitMode = 1; Warn = 25; Err = 100; HasLimit = $false }
    $eq = $Token.LastIndexOf('=')
    if ($eq -gt 0) {
        $r.Spec = $Token.Substring(0, $eq).Trim()
        $lim    = $Token.Substring($eq + 1).Trim()
        if ($lim -eq '0') { $r.LimitMode = 0; $r.HasLimit = $true }
        elseif ($lim -match '^(\d+):(\d+)$') { $r.Warn = [int]$Matches[1]; $r.Err = [int]$Matches[2]; $r.HasLimit = $true }
        else { throw "bad limit syntax '$lim' in token '$Token' (use =0 or =warn:err)." }
    }
    return $r
}

#----------------------------------------------------------------------------------------------------------
# Main
#----------------------------------------------------------------------------------------------------------

$TenantId   = Clean-Arg $scriptplaceholder1
$ClientId   = Clean-Arg $scriptplaceholder2
$Thumbprint = Clean-Arg $scriptplaceholder3
$Mailbox    = Clean-Arg $scriptplaceholder4
$FolderRaw  = Clean-Arg $scriptplaceholder5

# --- Argument sanity: catch PRTG quoting/space mangling BEFORE we hit Graph -------------------------------
if (-not $TenantId)   { Emit-Error "Missing TenantId (placeholder1)." }
if (-not $ClientId)   { Emit-Error "Missing ClientId (placeholder2)." }
if (-not $Thumbprint) { Emit-Error "Missing Thumbprint (placeholder3)." }
if (-not $Mailbox)    { Emit-Error "Missing Mailbox (placeholder4)." }
if (-not $FolderRaw)  { Emit-Error "Missing FolderList (placeholder5)." }

# A surviving quote char inside a value = the Parameters field quoting is wrong.
foreach ($pair in @(@('TenantId',$TenantId),@('ClientId',$ClientId),@('Thumbprint',$Thumbprint),@('Mailbox',$Mailbox))) {
    if ($pair[1] -match "['""]") {
        Emit-Error "ARG_QUOTING: $($pair[0]) still contains a quote char ('$($pair[1])'). PRTG passed the literal quotes - use straight double quotes in the Parameters field, one per placeholder."
    }
}
# Mailbox must look like an address; if it lost its tail to a space-split it won't.
if ($Mailbox -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') {
    Emit-Error "ARG_MAILBOX: '$Mailbox' is not a valid address - likely truncated by an unquoted space in the Parameters field."
}

# Split folder list. '+' -> ' ' (space placeholder, same convention as the Graph
# variant) so placeholder5 needs no quoting in the PRTG Parameters field; literal
# spaces still pass through unchanged. A stray quote = mangling signal.
$folders = @($FolderRaw -split '[;|]' | ForEach-Object { ($_ -replace '\+',' ').Trim() } | Where-Object { $_ -ne '' })
if ($folders.Count -eq 0) { Emit-Error "FOLDER_LIST: no usable folders parsed from '$FolderRaw'." }
$badFolderSyntax = @($folders | Where-Object { $_ -match "['""]" })
if ($badFolderSyntax.Count -gt 0) {
    Emit-Error "FOLDER_QUOTING: folder name(s) contain stray quotes: $($badFolderSyntax -join ' / '). Check placeholder5 quoting in PRTG."
}

# --- Auth -------------------------------------------------------------------------------------------------
try {
    $certBundle = Resolve-AuthCert -Thumbprint $Thumbprint   # throws classified CERT_* on failure
} catch {
    Emit-Error $_.Exception.Message
}
try {
    $token = Get-GraphToken -TenantId $TenantId -ClientId $ClientId -CertBundle $certBundle
} catch {
    # AAD returns the real reason (AADSTSxxxxx) in the HTTP response BODY, which
    # Invoke-RestMethod hides behind a generic 400. Read it out explicitly.
    $detail = ''
    try {
        $r = $_.Exception.Response
        if ($r) {
            $sr = New-Object System.IO.StreamReader($r.GetResponseStream())
            $detail = $sr.ReadToEnd()
            $sr.Close()
        }
    } catch {}
    if (-not $detail) { $detail = $_.ErrorDetails.Message }   # PS-version fallback
    Emit-Error "TOKEN: $($_.Exception.Message) :: $detail"
}
if (-not $token) { Emit-Error "TOKEN: Graph returned no access_token (check ClientId/Tenant/consent)." }

# --- Per-folder reads (isolated) --------------------------------------------------------------------------
$results = New-Object System.Collections.Generic.List[string]
$errors  = New-Object System.Collections.Generic.List[string]

foreach ($f in $folders) {
    try {
        $p = Parse-FolderToken -Token $f   # 'Spec', 'Spec=warn:err', or 'Spec=0'

        # Special token: '@1h:<folder>' -> aging channel (messages older than 60 min)
        # for that folder. Limits default to warn 1 / err 5, overridable on the token
        # (e.g. @1h:Posteingang=2:5); '@1h:<folder>=0' makes it reference-only.
        if ($p.Spec -match '^@1h:(.+)$') {
            $folderSpec = $Matches[1].Trim()
            $fo   = Get-FolderTotal -Mailbox $Mailbox -Spec $folderSpec -Token $token
            $aged = Get-AgedMessageCount -Mailbox $Mailbox -FolderId $fo.Id -Token $token
            $name = Xml-Escape "$($fo.Name) 1H"
            $w = if ($p.HasLimit -and $p.LimitMode -eq 1) { $p.Warn } else { 1 }
            $e = if ($p.HasLimit -and $p.LimitMode -eq 1) { $p.Err }  else { 5 }
            $limitBlock = if ($p.HasLimit -and $p.LimitMode -eq 0) {
@"

        <limitmode>0</limitmode>
"@
            } else {
@"

        <limitmode>1</limitmode>
        <limitmaxwarning>$w</limitmaxwarning>
        <limitmaxerror>$e</limitmaxerror>
"@
            }
            $results.Add(@"
    <result>
        <channel>$name</channel>
        <value>$aged</value>
        <unit>Custom</unit>
        <customunit>#</customunit>$limitBlock
    </result>
"@) | Out-Null
            continue
        }

        # Special token: '@quarantine' (or 'quarantine') -> Defender quarantine channels.
        if ($p.Spec -match '^@?quarantine$') {
            $q = Get-QuarantineCountsGraph -Mailbox $Mailbox -Token $token
            # Only 'Quarantine Recent' (last 60 min spike) alerts; Total/Phish/Malware/
            # Spam are CUMULATIVE over the 30d window, so they stay reference-only
            # (alerting on a cumulative count would mean permanent red once any exist).
            # Recent thresholds default to warn 5 / err 20, overridable on the token:
            #   @quarantine=2:5  -> warn 2 / err 5    @quarantine=0 -> Recent reference-only
            $qw = if ($p.HasLimit -and $p.LimitMode -eq 1) { $p.Warn } else { 5 }
            $qe = if ($p.HasLimit -and $p.LimitMode -eq 1) { $p.Err }  else { 20 }
            $qRecentAlerts = -not ($p.HasLimit -and $p.LimitMode -eq 0)
            $qChannels = @(
                @{ Name='Quarantine Total';   Value=$q.Total;   Alert=$false },
                @{ Name='Quarantine Recent';  Value=$q.Recent;  Alert=$qRecentAlerts },
                @{ Name='Quarantine Phish';   Value=$q.Phish;   Alert=$false },
                @{ Name='Quarantine Malware'; Value=$q.Malware; Alert=$false },
                @{ Name='Quarantine Spam';    Value=$q.Spam;    Alert=$false }
            )
            foreach ($qc in $qChannels) {
                $limitBlock = if ($qc.Alert) {
@"

        <limitmode>1</limitmode>
        <limitmaxwarning>$qw</limitmaxwarning>
        <limitmaxerror>$qe</limitmaxerror>
"@
                } else {
@"

        <limitmode>0</limitmode>
"@
                }
                $results.Add(@"
    <result>
        <channel>$($qc.Name)</channel>
        <value>$($qc.Value)</value>
        <unit>Custom</unit>
        <customunit>#</customunit>$limitBlock
    </result>
"@) | Out-Null
            }
            continue
        }

        $r    = Get-FolderTotal -Mailbox $Mailbox -Spec $p.Spec -Token $token
        $name = Xml-Escape $r.Name
        $limitBlock = if ($p.LimitMode -eq 1) {
@"

        <limitmode>1</limitmode>
        <limitmaxwarning>$($p.Warn)</limitmaxwarning>
        <limitmaxerror>$($p.Err)</limitmaxerror>
"@
        } else {
@"

        <limitmode>0</limitmode>
"@
        }
        $results.Add(@"
    <result>
        <channel>$name</channel>
        <value>$($r.Total)</value>
        <unit>Custom</unit>
        <customunit>#</customunit>$limitBlock
    </result>
"@) | Out-Null
    }
    catch {
        $errors.Add("$f -> $($_.Exception.Message)") | Out-Null
    }
}

# --- Emit ------------------------------------------------------------------------------------------------
# If nothing resolved at all, that's a hard error (so PRTG goes red, not "no data").
if ($results.Count -eq 0) {
    Emit-Error ("ALL_FOLDERS_FAILED: " + ($errors -join ' | '))
}

$body = ($results -join "`r`n")

# Channel name+value is the single source of truth. <text> only appears on partial
# failure - to carry the error reason, which has nowhere else to live.
if ($errors.Count) {
    $text = Xml-Escape ($errors -join ' | ')
    Write-Output @"
<prtg>
    <error>1</error>
$body
    <text>$text</text>
</prtg>
"@
}
else {
    Write-Output @"
<prtg>
$body
</prtg>
"@
}
