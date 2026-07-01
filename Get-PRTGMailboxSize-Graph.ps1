#===========================================================================================================
# PRTG EXE/Script Advanced (EXEXML) - Mailbox size + % of send quota via Microsoft Graph
# usage reports (reportRoot: getMailboxUsageDetail). Pure REST, certificate app-only.
# NO ExchangeOnlineManagement module.
#
# vs Get-PRTGMailboxSize.ps1 (EXO variant): this one needs only Graph Reports.Read.All and
# no EXO module / Exchange.ManageAsApp - BUT three trade-offs:
#   - PRIMARY mailbox only. The report EXCLUDES the online/In-Place archive; use the EXO
#     sensor if you need archive size.
#   - Data LAGS ~1-2 days (report ingestion) - it is not the live figure.
#   - Requires report DE-ANONYMIZATION: M365 Admin -> Settings -> Org Settings -> Reports ->
#     uncheck "Conceal user, group, and site names in all reports" (or set
#     admin/reportSettings displayConcealedNames=false). Otherwise the User Principal Name
#     column is a GUID and the mailbox cannot be matched by address.
#
# Upside: the report carries the QUOTA (Prohibit Send Quota), so a "% of quota" channel is
# free - a better warning signal than a fixed GB limit for mixed 50/100 GB mailboxes.
#
# Parameters (positional; '+' = space, quoting optional):
#   1 = TenantId
#   2 = ClientId
#   3 = CertificateThumbprint  (LocalMachine\My or CurrentUser\My on the probe)
#   4 = Mailbox                (UPN, e.g. mailbox@contoso.de)
#   5 = Options [optional]     ';'-delimited key=value, all optional:
#         warn=35  err=40      absolute GB thresholds for 'Mailbox Size'  (default 35 / 40)
#         pwarn=80 perr=90     % thresholds for 'Mailbox Size %' (of send quota; default 80 / 90)
#         period=D7            report window: D7 | D30 | D90 | D180 (default D7)
#
# Requires: Microsoft Graph application permission Reports.Read.All (admin-consented).
# Channels: 'Mailbox Size' (GB), 'Mailbox Size %' (of Prohibit Send Quota), 'Item Count' (ref).
# GB/% values are InvariantCulture-formatted so PRTG's <float> parser accepts them on de-DE.
#===========================================================================================================
Param(
    [string]$scriptplaceholder1,
    [string]$scriptplaceholder2,
    [string]$scriptplaceholder3,
    [string]$scriptplaceholder4,
    [string]$scriptplaceholder5
)

try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false } catch {}
$OutputEncoding = New-Object System.Text.UTF8Encoding $false
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$IC = [System.Globalization.CultureInfo]::InvariantCulture

#-----------------------------------------------------------------------------------------------------------
# Helpers (arg hygiene + cert auth, same battle-tested pattern as the folder sensors)
#-----------------------------------------------------------------------------------------------------------
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
    ($s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;')
}

function Emit-Error {
    param([string]$Message)
    $m = Xml-Escape $Message
    Write-Output @"
<prtg>
    <error>1</error>
    <text>$m</text>
</prtg>
"@
    exit 0
}

function Resolve-AuthCert {
    param([string]$Thumbprint)
    $tp = ($Thumbprint -replace '[^0-9A-Fa-f]', '').ToUpper()
    if (-not $tp) { throw "CERT_INPUT: thumbprint is empty after cleaning (got '$Thumbprint')." }
    $cert = Get-Item -Path "Cert:\CurrentUser\My\$tp" -ErrorAction SilentlyContinue
    if (-not $cert) { $cert = Get-Item -Path "Cert:\LocalMachine\My\$tp" -ErrorAction SilentlyContinue }
    if (-not $cert) { throw "CERT_NOT_FOUND: thumbprint $tp is in neither CurrentUser\My nor LocalMachine\My on this probe." }
    $rsa = $null
    try { $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert) } catch { $rsa = $null }
    if (-not $rsa -and $cert.PrivateKey) { $rsa = $cert.PrivateKey }
    if (-not $rsa) { throw "CERT_NO_PRIVKEY: cert $tp found but its private key is not accessible to '$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)'." }
    try {
        [void]$rsa.SignData([Text.Encoding]::UTF8.GetBytes('probe'),
            [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.RSASignaturePadding]::Pkcs1)
    } catch {
        throw "CERT_KEY_UNUSABLE: cert $tp has a private key but signing failed ($($_.Exception.Message))."
    }
    return @{ Cert = $cert; Rsa = $rsa }
}

function Get-GraphToken {
    param([string]$TenantId, [string]$ClientId, $CertBundle)
    $cert = $CertBundle.Cert
    $rsa  = $CertBundle.Rsa
    $url  = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    # Culture-invariant epoch (de-DE / PS 5.1 safe).
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
    $resp = Invoke-RestMethod -Method Post -Uri $url -ContentType 'application/x-www-form-urlencoded' -Body @{
        client_id             = $ClientId
        scope                 = 'https://graph.microsoft.com/.default'
        client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        client_assertion      = "$b64h.$b64b.$sig"
        grant_type            = 'client_credentials'
    } -ErrorAction Stop
    return $resp.access_token
}

# Robust integer parse of a plain byte-count string from the report CSV.
function To-Int64 {
    param($v)
    if ($null -eq $v) { return [int64]0 }
    $d = [regex]::Replace([string]$v, '[^\d]', '')
    if (-not $d) { return [int64]0 }
    return [int64]$d
}

#-----------------------------------------------------------------------------------------------------------
# Main
#-----------------------------------------------------------------------------------------------------------
$TenantId   = Clean-Arg $scriptplaceholder1
$ClientId   = Clean-Arg $scriptplaceholder2
$Thumbprint = Clean-Arg $scriptplaceholder3
$Mailbox    = Clean-Arg $scriptplaceholder4
$OptRaw     = Clean-Arg $scriptplaceholder5

if (-not $TenantId)   { Emit-Error "Missing TenantId (placeholder1)." }
if (-not $ClientId)   { Emit-Error "Missing ClientId (placeholder2)." }
if (-not $Thumbprint) { Emit-Error "Missing Thumbprint (placeholder3)." }
if (-not $Mailbox)    { Emit-Error "Missing Mailbox (placeholder4)." }
if ($Mailbox -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') {
    Emit-Error "ARG_MAILBOX: '$Mailbox' is not a valid address."
}

# Options
$warn = 35.0; $err = 40.0; $pwarn = 80.0; $perr = 90.0; $period = 'D7'
foreach ($kv in @($OptRaw -split '[;|]' | ForEach-Object { ($_ -replace '\+',' ').Trim() } | Where-Object { $_ })) {
    if ($kv -match '^(?<k>[a-zA-Z]+)\s*=\s*(?<v>.+)$') {
        $k = $Matches.k.ToLowerInvariant(); $v = $Matches.v.Trim()
        try {
            switch ($k) {
                'warn'   { $warn  = [double]::Parse(($v -replace ',','.'), $IC) }
                'err'    { $err   = [double]::Parse(($v -replace ',','.'), $IC) }
                'pwarn'  { $pwarn = [double]::Parse(($v -replace ',','.'), $IC) }
                'perr'   { $perr  = [double]::Parse(($v -replace ',','.'), $IC) }
                'period' { if ($v -match '^(?i)D(7|30|90|180)$') { $period = $v.ToUpper() } else { Emit-Error "OPTION: period must be D7|D30|D90|D180 (got '$v')." } }
                default  { }
            }
        } catch { Emit-Error "OPTION: bad value for '$k' ('$v')." }
    }
}

# Auth
try   { $certBundle = Resolve-AuthCert -Thumbprint $Thumbprint }
catch { Emit-Error $_.Exception.Message }
try   { $token = Get-GraphToken -TenantId $TenantId -ClientId $ClientId -CertBundle $certBundle }
catch {
    $detail = ''
    try { $r = $_.Exception.Response; if ($r) { $sr = New-Object System.IO.StreamReader($r.GetResponseStream()); $detail = $sr.ReadToEnd(); $sr.Close() } } catch {}
    if (-not $detail) { $detail = $_.ErrorDetails.Message }
    Emit-Error "TOKEN: $($_.Exception.Message) :: $detail"
}
if (-not $token) { Emit-Error "TOKEN: Graph returned no access_token." }

# Fetch the mailbox usage report (CSV). Graph 302-redirects to a download URL; IRM follows it.
try {
    $uri = "https://graph.microsoft.com/v1.0/reports/getMailboxUsageDetail(period='$period')"
    $csv = Invoke-RestMethod -Headers @{ Authorization = "Bearer $token" } -Uri $uri -ErrorAction Stop
} catch {
    Emit-Error "REPORT: $($_.Exception.Message). App needs Graph application permission Reports.Read.All (admin-consented)."
}

$rows = @($csv | ConvertFrom-Csv)
if ($rows.Count -eq 0) { Emit-Error "REPORT: getMailboxUsageDetail returned no rows for period $period." }

# Column names carry spaces/parens; match the UPN column by suffix to tolerate a BOM/rename.
$upnProp = ($rows[0].PSObject.Properties.Name | Where-Object { $_ -match 'User Principal Name' } | Select-Object -First 1)
if (-not $upnProp) { $upnProp = 'User Principal Name' }
$row = $rows | Where-Object { "$($_.$upnProp)" -ieq $Mailbox } | Select-Object -First 1

if (-not $row) {
    Emit-Error ("MAILBOX_NOT_IN_REPORT: '$Mailbox' not found in getMailboxUsageDetail. Likely causes: " +
                "report anonymization is ON (Org Settings -> Reports -> uncheck 'Conceal user, group, and site names'), " +
                "or the report has not yet ingested this mailbox (data lags ~1-2 days).")
}

$usedBytes  = To-Int64 $row.'Storage Used (Byte)'
$quotaBytes = To-Int64 $row.'Prohibit Send Quota (Byte)'
$itemCount  = To-Int64 $row.'Item Count'
$hasArchive = "$($row.'Has Archive')"

$usedGB   = [math]::Round($usedBytes / 1GB, 2)
$quotaGB  = [math]::Round($quotaBytes / 1GB, 2)
$pct      = if ($quotaBytes -gt 0) { [math]::Round(100.0 * $usedBytes / $quotaBytes, 1) } else { $null }

$usedGBs  = $usedGB.ToString($IC)
$wS = $warn.ToString($IC);  $eS = $err.ToString($IC)
$pwS = $pwarn.ToString($IC); $peS = $perr.ToString($IC)

# 'Mailbox Size %' - only meaningful when a quota is set; otherwise emit it reference-only.
if ($null -ne $pct) {
    $pctBlock = @"
    <result>
        <channel>Mailbox Size %</channel>
        <value>$($pct.ToString($IC))</value>
        <unit>Percent</unit>
        <float>1</float>
        <limitmode>1</limitmode>
        <limitmaxwarning>$pwS</limitmaxwarning>
        <limitmaxerror>$peS</limitmaxerror>
    </result>
"@
} else {
    $pctBlock = @"
    <result>
        <channel>Mailbox Size %</channel>
        <value>0</value>
        <unit>Percent</unit>
        <float>1</float>
        <limitmode>0</limitmode>
    </result>
"@
}

$text = Xml-Escape ("Used $usedGBs GB of $($quotaGB.ToString($IC)) GB quota" +
        $(if ($null -ne $pct) { " ($($pct.ToString($IC))%)" } else { " (no send quota set)" }) +
        " · items=$itemCount · archive=$hasArchive · primary only, ~1-2d lag (period $period)")

Write-Output @"
<prtg>
    <result>
        <channel>Mailbox Size</channel>
        <value>$usedGBs</value>
        <unit>Custom</unit>
        <customunit>GB</customunit>
        <float>1</float>
        <limitmode>1</limitmode>
        <limitmaxwarning>$wS</limitmaxwarning>
        <limitmaxerror>$eS</limitmaxerror>
    </result>
$pctBlock
    <result>
        <channel>Item Count</channel>
        <value>$itemCount</value>
        <unit>Custom</unit>
        <customunit>#</customunit>
        <float>0</float>
        <limitmode>0</limitmode>
    </result>
    <text>$text</text>
</prtg>
"@
