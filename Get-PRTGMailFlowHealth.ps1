<#
.SYNOPSIS
    PRTG sensor reporting mail-flow health: % failed (real) vs deferred,
    with auto-reply / NDR-bounce / mail-loop filtered into separate buckets.

.DESCRIPTION
    Built around Get-MessageTraceV2 from ExchangeOnlineManagement
    (cert-based app-only auth - no profile dependency).

    Failure classifier (cheap default, runs every poll):

      - AutoReply         : OOO / Automatic reply / Abwesenheit (DE+EN)
      - RecipientNotFound : NDR senders + 'undelivered' / 'unzustellbar'
                            subjects (single bad forwarding -> warning, NOT
                            error - so on-call is not paged)
      - MailLoop          : 'loop detected' / 'too many hops' / 'Nachrichtenschleife'
      - RealFailure       : everything else with Status=Failed -> primary alert

    Optional -DeepInspect drills into Get-MessageTraceDetail per failed
    message and uses the SMTP enhanced status codes (5.1.1, 5.4.6, 5.7.1)
    for accurate classification - slower but exact.

    PRTG channels (JSON / EXEXML mode):

      MailVolume             total count in window
      Delivered              raw count
      Pending                raw count
      Pending %              ALERT (warn 5%, err 20%)
      Failed Raw             raw count
      Real Failed            count after filtering
      Real Failed %          PRIMARY ALERT (warn 5%, err 15%)
      Auto-Replies           informational only
      Recipient-Not-Found    warning-only (no error threshold)
      Mail Loops             warn 1, err 10

    Three call patterns (same as Get-PRTGMailboxFolderHealth.ps1):
      .\Get-PRTGMailFlowHealth.ps1 -Config '...'
      . .\Get-PRTGMailFlowHealth.ps1                          # dot-source
      Import-Module .\Get-PRTGMailFlowHealth.ps1 -Force       # module

.PARAMETER Domain
    Recipient domain filter ("@contoso.de") - only messages to this domain
    are counted. Without it, the entire tenant flow is included.

.PARAMETER LookbackMinutes
    Window size for the snapshot. Default 15 (sensor poll typically 60s,
    so a 15-min trailing window smooths spikes).

.PARAMETER Direction
    Inbound | Outbound | Both. Default Both.
    Inbound = SenderAddress NOT in tenant domains.
    Outbound = SenderAddress in tenant domains.

.PARAMETER DeepInspect
    Drill into Get-MessageTraceDetail for each Failed message to read the
    SMTP enhanced status code. More accurate, slower (1 API call per Failed
    message).

.PARAMETER ClientId, CertificateThumbprint, Organization
    EXO app-only auth. Same App Registration as the folder sensor works
    (Exchange.ManageAsApp role required + admin consent).

.PARAMETER Config
    Path to the same JSON config used by the folder sensor. CredentialSource
    is honoured via Resolve-SensorCredential (loaded from the folder sensor
    if it sits next to this script).

.PARAMETER OutputFormat
    Json (default) | KeyValue (legacy single-channel: Real Failed %).

.PARAMETER WarningPctFailed, ErrorPctFailed
.PARAMETER WarningPctPending, ErrorPctPending
.PARAMETER WarningRecipientNotFound, ErrorRecipientNotFound
.PARAMETER WarningLoops, ErrorLoops
    Channel limits embedded in the JSON output.

.EXAMPLE
    .\Get-PRTGMailFlowHealth.ps1 -Config 'C:\PRTGSensorConfig\flow.json' `
                                 -LookbackMinutes 15 -Direction Both

.NOTES
    Author : DATAGROUP - Jan Hubener
    Repo   : PSScript / Get-PRTGMailFlowHealth
#>

[CmdletBinding()]
param(
    [string[]]$Domain        = @(),
    [int]$LookbackMinutes    = 15,

    [ValidateSet('Inbound','Outbound','Both')]
    [string]$Direction       = 'Both',

    [switch]$DeepInspect,

    [string]$ClientId,
    [string]$CertificateThumbprint,
    [string]$Organization,
    [string]$TenantId,

    [string]$Config,

    [ValidateSet('Json','KeyValue')]
    [string]$OutputFormat = 'Json',

    # Threshold defaults - tuned so a single bad forwarding doesn't page on-call
    [double]$WarningPctFailed         = 5.0,
    [double]$ErrorPctFailed           = 15.0,
    [double]$WarningPctPending        = 5.0,
    [double]$ErrorPctPending          = 20.0,
    [int]   $WarningRecipientNotFound = 5,
    [int]   $ErrorRecipientNotFound   = 0,        # 0 -> emitted as no error threshold
    [int]   $WarningLoops             = 1,
    [int]   $ErrorLoops               = 10,

    [int]   $MaxTracePages            = 5,        # safety cap on V2 pagination
    [int]   $TraceResultSize          = 5000,

    [hashtable]$ChannelLimits         = @{},

    [switch]$AsObject,
    [switch]$NoAutoRun
)

# =====================================================================
#  Logging - stderr only
# =====================================================================

$script:LogBuffer = New-Object System.Collections.Generic.List[string]

function Write-FlowLog {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$Message,
          [ValidateSet('Info','Warn','Error','Debug')] [string]$Level = 'Info')
    $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line  = "[$stamp][$Level] $Message"
    $script:LogBuffer.Add($line) | Out-Null
    if ($Level -eq 'Debug' -and -not $VerbosePreference) { return }
    [Console]::Error.WriteLine($line)
}


# =====================================================================
#  Classification patterns (compiled once)
# =====================================================================

$script:AutoReplyPatterns = @(
    'out of office', 'automatic reply', 'auto-reply', 'autoreply', 'auto reply',
    'auto: ', '\[auto\]', '\bautom?atic\b',
    'abwesenheit', 'abwesenheitsnotiz', 'abwesenheits[- ]?mitteilung',
    'aus dem urlaub', 'im urlaub', 'urlaub und abwesenheit',
    'außer haus', 'ausser haus', 'außer dem büro', 'ausser dem buero',
    'geschäftsreise', 'geschaeftsreise',
    'i am out', "i'm out", 'i am away', 'currently away', 'currently out',
    'ich bin (nicht|abwesend|im urlaub|au(?:ss|ß)er)',
    'ferienabwesenheit', 'sabbatical', 'parental leave', 'elternzeit',
    'mutterschutz'
) -join '|'

$script:NdrSubjectPatterns = @(
    'undeliver(?:ed|able)', 'delivery (?:failure|failed|status notification)',
    'failure notice', 'returned mail', 'mail delivery (?:system|failed)',
    'unzustellbar', 'nicht zustellbar', 'rücklauf', 'ruecklauf',
    'mail-zustellfehler', 'zustellfehler',
    'message could not be delivered'
) -join '|'

$script:LoopSubjectPatterns = @(
    'mail loop', 'loop detected', 'too many hops', 'too many recipients',
    'nachrichtenschleife', 'mailschleife', 'schleife erkannt'
) -join '|'

$script:NdrSenderRegex = '^(?:postmaster|mailer-?daemon|mail-?daemon|mailerdaemon)@'

# DSN enhanced status codes -> bucket (used by -DeepInspect)
$script:DsnMap = @{
    '5.1.1' = 'RecipientNotFound'   # Bad destination mailbox
    '5.1.10'= 'RecipientNotFound'   # Recipient does not exist
    '5.1.2' = 'RecipientNotFound'   # Bad domain
    '5.4.1' = 'RecipientNotFound'   # No answer / cannot resolve recipient
    '5.4.4' = 'RealFailure'         # DNS / routing
    '5.4.6' = 'MailLoop'            # Routing loop
    '5.4.7' = 'MailLoop'            # Delivery time expired (often loop)
    '5.7.1' = 'RealFailure'         # Delivery not authorised
    '5.7.0' = 'RealFailure'
    '4.4.7' = 'Pending'             # Deferred - delivery pending
    '4.7.0' = 'Pending'
}


# =====================================================================
#  Classifier (heuristic)
# =====================================================================

function Get-FailureBucket {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Message,
        [string]$DsnCode
    )

    # 1. DSN code wins if we have one (DeepInspect)
    if ($DsnCode -and $script:DsnMap.ContainsKey($DsnCode)) {
        return $script:DsnMap[$DsnCode]
    }
    if ($DsnCode -and $DsnCode -like '4.*') {
        return 'Pending'
    }

    $subj = if ($Message.Subject) { [string]$Message.Subject } else { '' }
    $from = if ($Message.SenderAddress) { ([string]$Message.SenderAddress).ToLowerInvariant() } else { '' }

    # 2. Mail loop
    if ($subj -match $script:LoopSubjectPatterns) { return 'MailLoop' }

    # 3. Auto-reply (subject)
    if ($subj -match $script:AutoReplyPatterns) { return 'AutoReply' }

    # 4. NDR sender + NDR subject -> RecipientNotFound
    if ($from -match $script:NdrSenderRegex -and $subj -match $script:NdrSubjectPatterns) {
        return 'RecipientNotFound'
    }

    # 5. NDR subject without NDR sender -> still likely a bounce
    if ($subj -match $script:NdrSubjectPatterns) {
        return 'RecipientNotFound'
    }

    # 6. NDR sender alone (e.g. system mailbox messaging admins) - treat as auto-reply
    if ($from -match $script:NdrSenderRegex) { return 'AutoReply' }

    # Default
    return 'RealFailure'
}


# =====================================================================
#  EXO connection (cert app-only)
# =====================================================================

function Connect-FlowEXO {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$ClientId,
        [Parameter(Mandatory)] [string]$CertificateThumbprint,
        [Parameter(Mandatory)] [string]$Organization
    )

    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        throw "ExchangeOnlineManagement module not installed on probe."
    }
    Import-Module ExchangeOnlineManagement -ErrorAction Stop

    $existing = Get-ConnectionInformation -ErrorAction SilentlyContinue |
                Where-Object { $_.Organization -eq $Organization -and $_.State -eq 'Connected' }
    if ($existing) {
        Write-FlowLog "Reusing EXO connection: $($existing.ConnectionId)" -Level Debug
        return
    }

    Connect-ExchangeOnline `
        -AppId                 $ClientId `
        -CertificateThumbprint $CertificateThumbprint `
        -Organization          $Organization `
        -ShowBanner:$false `
        -ShowProgress:$false `
        -ErrorAction Stop | Out-Null

    Write-FlowLog "Connected to EXO ($Organization)" -Level Info
}


# =====================================================================
#  Trace fetch with V2 detection + V1 fallback
# =====================================================================

function Get-FlowMessages {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [datetime]$Start,
        [Parameter(Mandatory)] [datetime]$End,
        [string[]]$RecipientDomain = @(),
        [string]$Direction         = 'Both',
        [int]$ResultSize           = 5000,
        [int]$MaxPages             = 5
    )

    $hasV2 = (Get-Command Get-MessageTraceV2 -ErrorAction SilentlyContinue) -ne $null
    $cmd   = if ($hasV2) { 'Get-MessageTraceV2' } else { 'Get-MessageTrace' }
    Write-FlowLog "Using ${cmd} (window: ${Start} -> ${End})" -Level Debug

    $all = New-Object System.Collections.Generic.List[object]

    if ($hasV2) {

        $page    = 0
        $cursor  = $null
        do {
            $page++
            $params = @{
                StartDate  = $Start
                EndDate    = $End
                ResultSize = $ResultSize
                ErrorAction = 'Stop'
            }
            if ($cursor) { $params.StartingRecipientAddress = $cursor }

            $batch = & $cmd @params
            if (-not $batch) { break }
            $batchCount = ($batch | Measure-Object).Count
            Write-FlowLog "V2 page $page : $batchCount messages" -Level Debug
            foreach ($m in $batch) { $all.Add($m) | Out-Null }

            if ($batchCount -lt $ResultSize) { break }
            $cursor = $batch[-1].RecipientAddress
        } while ($page -lt $MaxPages)

    } else {

        # V1 fallback - paginated by Page parameter
        for ($page = 1; $page -le $MaxPages; $page++) {
            $batch = & $cmd -StartDate $Start -EndDate $End -PageSize $ResultSize -Page $page -ErrorAction Stop
            if (-not $batch) { break }
            $batchCount = ($batch | Measure-Object).Count
            Write-FlowLog "V1 page $page : $batchCount messages" -Level Debug
            foreach ($m in $batch) { $all.Add($m) | Out-Null }
            if ($batchCount -lt $ResultSize) { break }
        }
    }

    # Apply filters in PowerShell (V2 lacks server-side -RecipientAddressDomain)
    $filtered = $all

    if ($RecipientDomain.Count -gt 0) {
        $domainsLower = $RecipientDomain | ForEach-Object { $_.ToLowerInvariant().TrimStart('@') }
        $filtered = $filtered | Where-Object {
            if (-not $_.RecipientAddress) { return $false }
            $rd = ($_.RecipientAddress -split '@')[-1].ToLowerInvariant()
            return ($domainsLower -contains $rd)
        }
    }

    if ($Direction -ne 'Both' -and $RecipientDomain.Count -gt 0) {
        $domainsLower = $RecipientDomain | ForEach-Object { $_.ToLowerInvariant().TrimStart('@') }
        $filtered = $filtered | Where-Object {
            if (-not $_.SenderAddress) { return $true }
            $sd = ($_.SenderAddress -split '@')[-1].ToLowerInvariant()
            $isInternalSender = ($domainsLower -contains $sd)
            if ($Direction -eq 'Inbound')  { return -not $isInternalSender }
            if ($Direction -eq 'Outbound') { return $isInternalSender }
        }
    }

    return ,@($filtered)
}


# =====================================================================
#  DSN extraction (DeepInspect)
# =====================================================================

function Get-MessageDsnCode {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Message)

    try {
        $detail = Get-MessageTraceDetail `
                    -MessageTraceId $Message.MessageTraceId `
                    -RecipientAddress $Message.RecipientAddress `
                    -ErrorAction Stop
        # Look for FAIL events first
        $fail = $detail | Where-Object { $_.Event -in 'FAIL','Fail' } | Select-Object -First 1
        if (-not $fail) {
            $fail = $detail | Where-Object { $_.Detail -match '\b\d\.\d+\.\d+\b' } | Select-Object -First 1
        }
        if (-not $fail) { return $null }

        if ($fail.Detail -match '\b(\d\.\d+\.\d+)\b') { return $matches[1] }
        return $null
    }
    catch {
        Write-FlowLog "DSN lookup failed for $($Message.MessageTraceId): $($_.Exception.Message)" -Level Debug
        return $null
    }
}


# =====================================================================
#  Public function - the actual sensor read
# =====================================================================

function Get-MailFlowHealth {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$ClientId,
        [Parameter(Mandatory)] [string]$CertificateThumbprint,
        [Parameter(Mandatory)] [string]$Organization,

        [string[]]$Domain         = @(),
        [int]$LookbackMinutes     = 15,
        [ValidateSet('Inbound','Outbound','Both')] [string]$Direction = 'Both',
        [switch]$DeepInspect,
        [int]$ResultSize          = 5000,
        [int]$MaxPages            = 5
    )

    $end   = Get-Date
    $start = $end.AddMinutes(-$LookbackMinutes)

    Connect-FlowEXO -ClientId $ClientId `
                    -CertificateThumbprint $CertificateThumbprint `
                    -Organization $Organization

    $msgs = Get-FlowMessages -Start $start -End $end `
                -RecipientDomain $Domain -Direction $Direction `
                -ResultSize $ResultSize -MaxPages $MaxPages

    $totalCount = ($msgs | Measure-Object).Count

    $delivered = ($msgs | Where-Object { $_.Status -eq 'Delivered' }     | Measure-Object).Count
    $pending   = ($msgs | Where-Object { $_.Status -in 'Pending','GettingStatus','Deferred' } | Measure-Object).Count
    $failedRaw = ($msgs | Where-Object { $_.Status -in 'Failed','Quarantined' }  | Measure-Object).Count

    $failed = $msgs | Where-Object { $_.Status -in 'Failed','Quarantined' }

    $buckets = @{
        AutoReply         = 0
        RecipientNotFound = 0
        MailLoop          = 0
        Pending           = 0   # only DeepInspect upgrades 4.x DSN to here
        RealFailure       = 0
    }

    foreach ($m in $failed) {
        $dsn = if ($DeepInspect) { Get-MessageDsnCode -Message $m } else { $null }
        $bucket = Get-FailureBucket -Message $m -DsnCode $dsn
        $buckets[$bucket]++
    }

    $realFailed   = $buckets.RealFailure
    $effectivePending = $pending + $buckets.Pending  # DeepInspect can promote some "Failed" to Pending

    $pctFailed  = if ($totalCount -gt 0) { [math]::Round(100.0 * $realFailed / $totalCount, 2) } else { 0 }
    $pctPending = if ($totalCount -gt 0) { [math]::Round(100.0 * $effectivePending / $totalCount, 2) } else { 0 }

    return [pscustomobject]@{
        WindowStart            = $start.ToString('o')
        WindowEnd              = $end.ToString('o')
        Direction              = $Direction
        Domain                 = $Domain
        DeepInspect            = [bool]$DeepInspect
        TotalCount             = $totalCount
        Delivered              = $delivered
        Pending                = $effectivePending
        FailedRaw              = $failedRaw
        RealFailed             = $realFailed
        AutoReplies            = $buckets.AutoReply
        RecipientNotFound      = $buckets.RecipientNotFound
        MailLoops              = $buckets.MailLoop
        FailedPct              = $pctFailed
        PendingPct             = $pctPending
        Timestamp              = (Get-Date).ToString('o')
    }
}


# =====================================================================
#  PRTG output formatters
# =====================================================================

function Format-FlowPrtgJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Health,
        [double]$WarningPctFailed         = 5.0,
        [double]$ErrorPctFailed           = 15.0,
        [double]$WarningPctPending        = 5.0,
        [double]$ErrorPctPending          = 20.0,
        [int]   $WarningRecipientNotFound = 5,
        [int]   $ErrorRecipientNotFound   = 0,
        [int]   $WarningLoops             = 1,
        [int]   $ErrorLoops               = 10,
        [hashtable]$ChannelLimits         = @{}
    )

    function New-Channel {
        param([string]$Name, $Value, [string]$Unit = '#', [int]$Float = 0,
              [Nullable[double]]$Warn = $null, [Nullable[double]]$Err = $null)
        $c = [ordered]@{
            channel    = $Name
            value      = $Value
            unit       = 'Custom'
            customunit = $Unit
            float      = $Float
            limitmode  = 1
        }
        if ($null -ne $Warn) { $c.limitmaxwarning = $Warn }
        if ($null -ne $Err -and $Err -gt 0) { $c.limitmaxerror = $Err }
        return [pscustomobject]$c
    }

    $channels = @(
        New-Channel 'MailVolume'              $Health.TotalCount  '#'  0
        New-Channel 'Delivered'               $Health.Delivered   '#'  0
        New-Channel 'Pending'                 $Health.Pending     '#'  0
        New-Channel 'Pending %'               $Health.PendingPct  '%'  1   $WarningPctPending  $ErrorPctPending
        New-Channel 'Failed Raw'              $Health.FailedRaw   '#'  0
        New-Channel 'Real Failed'             $Health.RealFailed  '#'  0
        New-Channel 'Real Failed %'           $Health.FailedPct   '%'  1   $WarningPctFailed   $ErrorPctFailed
        New-Channel 'Auto-Replies (filtered)' $Health.AutoReplies '#'  0
        New-Channel 'Recipient-Not-Found'     $Health.RecipientNotFound '#'  0   $WarningRecipientNotFound  $ErrorRecipientNotFound
        New-Channel 'Mail Loops'              $Health.MailLoops   '#'  0   $WarningLoops       $ErrorLoops
    )

    # Apply per-channel overrides
    foreach ($c in $channels) {
        if ($ChannelLimits.ContainsKey($c.channel)) {
            $lim = $ChannelLimits[$c.channel]
            if ($lim.Warning) { $c | Add-Member -NotePropertyName 'limitmaxwarning' -NotePropertyValue $lim.Warning -Force }
            if ($lim.Error)   { $c | Add-Member -NotePropertyName 'limitmaxerror'   -NotePropertyValue $lim.Error   -Force }
        }
    }

    $text = "OK | total=$($Health.TotalCount) deliv=$($Health.Delivered) pend=$($Health.Pending) failedReal=$($Health.RealFailed) ($($Health.FailedPct)%)"
    if ($Health.RecipientNotFound -gt 0) { $text += " | rcptNotFound=$($Health.RecipientNotFound)" }
    if ($Health.MailLoops         -gt 0) { $text += " | loops=$($Health.MailLoops)" }
    if ($Health.AutoReplies       -gt 0) { $text += " | autoReply=$($Health.AutoReplies)" }

    return (@{ prtg = @{ result = $channels; text = $text } } |
              ConvertTo-Json -Depth 6)
}

function Format-FlowPrtgKeyValue {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Health)
    return ("{0}:RealFailed%={0} (n={1}, rnf={2}, loops={3})" -f `
              $Health.FailedPct, $Health.TotalCount,
              $Health.RecipientNotFound, $Health.MailLoops)
}


# =====================================================================
#  Main entry - merges Config -> CLI, calls resolver, emits PRTG
# =====================================================================

function Invoke-PRTGMailFlowSensor {
    [CmdletBinding()]
    param([hashtable]$Bound)

    $effective = @{}

    if ($Bound.Config) {
        $cfg = $null
        try {
            $raw = Get-Content -LiteralPath $Bound.Config -Raw -ErrorAction Stop
            $obj = $raw | ConvertFrom-Json -ErrorAction Stop
            $cfg = @{}
            $obj.PSObject.Properties | ForEach-Object { $cfg[$_.Name] = $_.Value }
        }
        catch {
            Write-FlowLog "Config '$($Bound.Config)' could not be parsed: $($_.Exception.Message)" -Level Error
        }
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

    # Pull credential via Resolve-SensorCredential if it's been dot-sourced
    # alongside the folder sensor.
    if ((-not $effective.CertificateThumbprint) -and (Get-Command Resolve-SensorCredential -ErrorAction SilentlyContinue)) {
        try {
            $resolved = Resolve-SensorCredential -Config ([pscustomobject]$effective)
            if ($resolved.CertificateThumbprint) {
                $effective.CertificateThumbprint = $resolved.CertificateThumbprint
            }
            # Mail flow sensor strongly prefers cert auth - secret-based EXO
            # connect is not exposed.
            if (-not $effective.CertificateThumbprint -and $resolved.ClientSecret) {
                throw "EXO app-only auth requires a certificate. Re-provision with -Method CertLM."
            }
        }
        catch {
            $err = "Credential resolution failed: $($_.Exception.Message)"
            Write-FlowLog $err -Level Error
            if ($effective.OutputFormat -eq 'KeyValue') { Write-Output "-1:${err}" }
            else { Write-Output (@{ prtg = @{ error = 1; text = $err } } | ConvertTo-Json -Depth 4) }
            return
        }
    }

    $required = @('ClientId','CertificateThumbprint','Organization')
    foreach ($r in $required) {
        if (-not $effective[$r]) {
            $err = "Missing required parameter: ${r}"
            if ($effective.OutputFormat -eq 'KeyValue') { Write-Output "-1:${err}" }
            else { Write-Output (@{ prtg = @{ error = 1; text = $err } } | ConvertTo-Json -Depth 4) }
            return
        }
    }

    try {
        $health = Get-MailFlowHealth `
                    -ClientId              $effective.ClientId `
                    -CertificateThumbprint $effective.CertificateThumbprint `
                    -Organization          $effective.Organization `
                    -Domain                ($effective.Domain        | ForEach-Object { $_ }) `
                    -LookbackMinutes       (if ($effective.LookbackMinutes) { [int]$effective.LookbackMinutes } else { 15 }) `
                    -Direction             (if ($effective.Direction)       { [string]$effective.Direction }    else { 'Both' }) `
                    -DeepInspect:([bool]$effective.DeepInspect) `
                    -ResultSize            (if ($effective.TraceResultSize) { [int]$effective.TraceResultSize } else { 5000 }) `
                    -MaxPages              (if ($effective.MaxTracePages)   { [int]$effective.MaxTracePages }   else { 5 })
    }
    catch {
        $err = $_.Exception.Message
        Write-FlowLog $err -Level Error
        if ($effective.OutputFormat -eq 'KeyValue') { Write-Output "-1:${err}" }
        else { Write-Output (@{ prtg = @{ error = 1; text = $err } } | ConvertTo-Json -Depth 4) }
        return
    }

    if ($effective.AsObject) { return $health }

    if ($effective.OutputFormat -eq 'KeyValue') {
        Write-Output (Format-FlowPrtgKeyValue -Health $health)
    }
    else {
        $fmtParams = @{
            Health                    = $health
            WarningPctFailed          = if ($effective.WarningPctFailed)         { [double]$effective.WarningPctFailed }         else { 5.0 }
            ErrorPctFailed            = if ($effective.ErrorPctFailed)           { [double]$effective.ErrorPctFailed }           else { 15.0 }
            WarningPctPending         = if ($effective.WarningPctPending)        { [double]$effective.WarningPctPending }        else { 5.0 }
            ErrorPctPending           = if ($effective.ErrorPctPending)          { [double]$effective.ErrorPctPending }          else { 20.0 }
            WarningRecipientNotFound  = if ($effective.WarningRecipientNotFound) { [int]$effective.WarningRecipientNotFound }    else { 5 }
            ErrorRecipientNotFound    = if ($effective.ErrorRecipientNotFound)   { [int]$effective.ErrorRecipientNotFound }      else { 0 }
            WarningLoops              = if ($effective.WarningLoops)             { [int]$effective.WarningLoops }                else { 1 }
            ErrorLoops                = if ($effective.ErrorLoops)               { [int]$effective.ErrorLoops }                  else { 10 }
            ChannelLimits             = if ($effective.ChannelLimits)            { $effective.ChannelLimits }                    else { @{} }
        }
        Write-Output (Format-FlowPrtgJson @fmtParams)
    }
}


# =====================================================================
#  Auto-run guard
# =====================================================================

$shouldAutoRun = (-not $NoAutoRun) -and
                 (-not $ExecutionContext.SessionState.Module) -and
                 ($MyInvocation.InvocationName -ne '.') -and
                 ($MyInvocation.Line -notmatch '^\s*\.\s+') -and
                 ($PSCommandPath)

if ($shouldAutoRun) {
    Invoke-PRTGMailFlowSensor -Bound $PSBoundParameters
}
