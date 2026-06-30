#==========================================================================================================
# PRTG EXE/Script Advanced (EXEXML) - Mailbox + Archive size via Exchange Online
# PowerShell (Get-MailboxStatistics, certificate app-only auth).
#
# Why EXO and NOT Graph: Microsoft Graph exposes no per-user mailbox size, and no
# archive size at all. Get-MailboxStatistics is the reliable source for both.
#
# Parameters (positional; '+' = space, quoting optional):
#   1 = TenantId               (kept for credential-set parity; not used by EXO connect)
#   2 = ClientId
#   3 = CertificateThumbprint  (LocalMachine\My or CurrentUser\My on the probe)
#   4 = Mailbox                (e.g. robo.bsm@bsm.datagroup.de)
#   5 = Options [optional]     ';'-delimited key=value, all optional:
#         warn=35  err=40        primary mailbox GB thresholds (default warn 35 / err 40)
#         awarn=35 aerr=40       archive       GB thresholds (default warn 35 / err 40)
#         org=contoso.onmicrosoft.com   EXO organization (default: the mailbox domain)
#       e.g.  warn=35;err=40;awarn=35;aerr=40
#
# Requires (one-time):
#   - ExchangeOnlineManagement module (v3+) installed on the probe.
#   - App registration with application permission
#       Office 365 Exchange Online -> Exchange.ManageAsApp   (+ admin consent)
#   - EXO RBAC role on the service principal that allows Get-MailboxStatistics:
#       Connect-ExchangeOnline; New-ManagementRoleAssignment -Role 'View-Only Recipients' -App <sp-objectid>
#   The same certificate used by the folder/quarantine sensors works here.
#
# Channels: 'Mailbox Size' (GB) and 'Archive Size' (GB). Values use an invariant '.'
# decimal so PRTG's float parser accepts them on German-locale probes. No archive
# enabled -> Archive Size reports 0 with a note (not an error).
#==========================================================================================================
Param(
    [string]$scriptplaceholder1,
    [string]$scriptplaceholder2,
    [string]$scriptplaceholder3,
    [string]$scriptplaceholder4,
    [string]$scriptplaceholder5
)

# stdout BOM-less UTF-8 (PS 5.1 emits a BOM otherwise -> PRTG PE231)
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false } catch {}
$OutputEncoding = New-Object System.Text.UTF8Encoding $false
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$IC = [System.Globalization.CultureInfo]::InvariantCulture

#----------------------------------------------------------------------------------------------------------
# Helpers
#----------------------------------------------------------------------------------------------------------
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
    exit 0   # PRTG reads the XML, not the exit code
}

# TotalItemSize is "12.34 GB (13,254,...bytes)" (locale-formatted). The parenthetical
# is the exact byte count - strip every non-digit to get it. Fall back to the leading
# "<n> <unit>" if no parenthetical is present.
function ConvertTo-Bytes {
    param($Size)
    if ($null -eq $Size) { return [int64]0 }
    $s = [string]$Size
    if ($s -match '\(([\d.,\s]+)\s*[Bb]ytes\)') {
        return [int64]([regex]::Replace($Matches[1], '[^\d]', ''))
    }
    if ($s -match '([\d.,]+)\s*([KMGT]?B)') {
        $n = [double]::Parse(($Matches[1] -replace ',','.'), $IC)
        switch ($Matches[2].ToUpper()) {
            'KB' { return [int64]($n * 1KB) }
            'MB' { return [int64]($n * 1MB) }
            'GB' { return [int64]($n * 1GB) }
            'TB' { return [int64]($n * 1TB) }
            default { return [int64]$n }
        }
    }
    return [int64]0
}

# Invariant-culture GB string (so PRTG's <float> parser always sees a '.' decimal)
function To-GbString {
    param([int64]$Bytes)
    ([math]::Round($Bytes / 1GB, 2)).ToString($IC)
}

#----------------------------------------------------------------------------------------------------------
# Main
#----------------------------------------------------------------------------------------------------------
$TenantId   = Clean-Arg $scriptplaceholder1
$ClientId   = Clean-Arg $scriptplaceholder2
$Thumbprint = Clean-Arg $scriptplaceholder3
$Mailbox    = Clean-Arg $scriptplaceholder4
$OptRaw     = Clean-Arg $scriptplaceholder5

if (-not $ClientId)   { Emit-Error "Missing ClientId (placeholder2)." }
if (-not $Thumbprint) { Emit-Error "Missing Thumbprint (placeholder3)." }
if (-not $Mailbox)    { Emit-Error "Missing Mailbox (placeholder4)." }
if ($Mailbox -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') {
    Emit-Error "ARG_MAILBOX: '$Mailbox' is not a valid address - likely truncated by an unquoted space."
}

# Options (all optional). Defaults: warn 35 / err 40 GB for both primary and archive.
$warn = 35.0; $err = 40.0; $awarn = 35.0; $aerr = 40.0
$org  = ($Mailbox -split '@')[-1]
foreach ($kv in @($OptRaw -split '[;|]' | ForEach-Object { ($_ -replace '\+',' ').Trim() } | Where-Object { $_ })) {
    if ($kv -match '^(?<k>[a-zA-Z]+)\s*=\s*(?<v>.+)$') {
        $k = $Matches.k.ToLowerInvariant(); $v = $Matches.v.Trim()
        try {
            switch ($k) {
                'warn'  { $warn  = [double]::Parse(($v -replace ',','.'), $IC) }
                'err'   { $err   = [double]::Parse(($v -replace ',','.'), $IC) }
                'awarn' { $awarn = [double]::Parse(($v -replace ',','.'), $IC) }
                'aerr'  { $aerr  = [double]::Parse(($v -replace ',','.'), $IC) }
                'org'   { $org   = $v }
                default { }
            }
        } catch { Emit-Error "OPTION: bad value for '$k' ('$v')." }
    }
}

# --- EXO connect (cert app-only) ---
if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
    Emit-Error "ExchangeOnlineManagement module not installed on the probe."
}
Import-Module ExchangeOnlineManagement -ErrorAction Stop -WarningAction SilentlyContinue

try {
    $existing = Get-ConnectionInformation -ErrorAction SilentlyContinue |
                Where-Object { $_.Organization -eq $org -and $_.State -eq 'Connected' }
    if (-not $existing) {
        Connect-ExchangeOnline -AppId $ClientId -CertificateThumbprint $Thumbprint `
            -Organization $org -ShowBanner:$false -ShowProgress:$false `
            -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
    }
} catch {
    Emit-Error "EXO_CONNECT ($org): $($_.Exception.Message). If the org is wrong, pass org=<tenant>.onmicrosoft.com in placeholder5; also check Exchange.ManageAsApp consent + the cert."
}

# --- Primary mailbox size ---
try {
    $ps = Get-MailboxStatistics -Identity $Mailbox -ErrorAction Stop
    $primaryBytes = ConvertTo-Bytes $ps.TotalItemSize
} catch {
    Emit-Error "MAILBOX_STATS: $($_.Exception.Message). The app's service principal needs an EXO role allowing Get-MailboxStatistics (e.g. 'View-Only Recipients')."
}

# --- Archive size (may not be enabled) ---
# ONLY a genuinely-absent archive is benign (report 0, stays green). Any other
# failure - throttling, a transient/session error, or an access/role problem -
# is a real measurement failure and must surface as a PRTG error; reporting 0
# would hide a large archive behind a green sensor.
$archiveBytes = [int64]0
$archiveNote  = $null
try {
    $as = Get-MailboxStatistics -Identity $Mailbox -Archive -ErrorAction Stop
    $archiveBytes = ConvertTo-Bytes $as.TotalItemSize
} catch {
    $em = $_.Exception.Message
    $noArchive = ($em -match 'archive') -and
                 ($em -match "isn.?t enabled|not enabled|isn.?t present|not present|doesn.?t exist|does not exist|no archive")
    if ($noArchive) {
        $archiveNote = "no archive enabled"
    }
    else {
        Emit-Error "ARCHIVE_STATS: $em"
    }
}

# --- Emit ---
$primGB = To-GbString $primaryBytes
$archGB = To-GbString $archiveBytes
$wS = $warn.ToString($IC);  $eS = $err.ToString($IC)
$awS = $awarn.ToString($IC); $aeS = $aerr.ToString($IC)

$text = "Mailbox $primGB GB / Archive $archGB GB"
if ($archiveNote) { $text += " ($archiveNote)" }
$text = Xml-Escape $text

Write-Output @"
<prtg>
    <result>
        <channel>Mailbox Size</channel>
        <value>$primGB</value>
        <unit>Custom</unit>
        <customunit>GB</customunit>
        <float>1</float>
        <limitmode>1</limitmode>
        <limitmaxwarning>$wS</limitmaxwarning>
        <limitmaxerror>$eS</limitmaxerror>
    </result>
    <result>
        <channel>Archive Size</channel>
        <value>$archGB</value>
        <unit>Custom</unit>
        <customunit>GB</customunit>
        <float>1</float>
        <limitmode>1</limitmode>
        <limitmaxwarning>$awS</limitmaxwarning>
        <limitmaxerror>$aeS</limitmaxerror>
    </result>
    <text>$text</text>
</prtg>
"@
