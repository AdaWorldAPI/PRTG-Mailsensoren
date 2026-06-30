#==========================================================================================================
# PRTG EXE/Script Advanced (EXEXML) - Mailbox folder totals via Microsoft Graph (cert app-only)
# GRAPH ONLY. No EXO module, no Get-MailboxFolderStatistics, no well-known folder names.
# Output: legacy here-string <prtg> XML only. BOM-less UTF-8, no <?xml?> declaration.
#
# Parameters (positional). PRTG Parameters-Feld kennt NUR "" oder gar kein Quoting -
# single quotes werden von PRTG NICHT interpretiert, sondern literal durchgereicht
# (und triggern dann absichtlich den ARG_QUOTING-Guard). Dank '+'-Platzhalter und
# space-freier GUIDs/Adressen geht das gesamte Feld auch komplett OHNE Quotes.
#
# WICHTIG: PRTG substituiert nur %scriptplaceholder1-5. Die Werte kommen aus
# "Credentials for Script Sensors" (Device-/Gruppenebene, z.B. vererbt von
# 'Postfächer'): fuenf maskierte Wertefelder + Description als Klartext-Label.
# Die Substitution ist rein textuell in die Befehlszeile - Spaces IM Wert wuerden
# argv splitten, deshalb gehoert die '+'-Konvention auch IN das Placeholder-5-Feld
# (z.B. Posteingang;Posteingang/VM+Ok=0). Da die Felder maskiert sind, ist der
# diag-Modus der einzige Weg, den tatsaechlich ankommenden Wert zurueckzulesen.
#
# Position 6 und 7 existieren als Platzhalter NICHT - sie sind, falls genutzt,
# LITERAL-TEXT im Parameters-Feld (pro Sensor hardcoded). Weglassen = Feature aus.
# Feld-Layout:
#
#   %scriptplaceholder1 %scriptplaceholder2 %scriptplaceholder3 %scriptplaceholder4 %scriptplaceholder5 Parameter6 Parameter7
#
#   %scriptplaceholder1 = TenantId
#   %scriptplaceholder2 = ClientId
#   %scriptplaceholder3 = CertificateThumbprint   (LocalMachine\My or CurrentUser\My of probe account)
#   %scriptplaceholder4 = Mailbox                 (robo.bsm@bsm.datagroup.de)
#   %scriptplaceholder5 = FolderList              (';' delimited displayName paths)
#   Parameter6          = OneHourList  [optional] (Literal! ';' delimited subset -> extra "<name> 1H" channels)
#   Parameter7          = diag         [optional] (Literal! 'diag' -> resolution details in <text>)
#
# Ein unsubstituiert durchgereichter Platzhalter-String (z.B. literal '%scriptplaceholder6'
# aus einer kopierten Vorlage) wird erkannt: bei Pflichtwerten 1-5 harter Fehler
# PLACEHOLDER_UNSUBSTITUTED, bei Position 6/7 stille Selbstheilung zu 'leer'.
#
# Hinweis Kontext-Trennung: single quotes IN DIESEM SCRIPT sind normale PowerShell-
# String-Literale und voellig ok - die Einschraenkung "nur double quotes" gilt
# ausschliesslich fuer das, was im PRTG Parameters-Feld steht.
#
# FolderList syntax per token:
#   Posteingang                          -> totalItemCount, limits 25/100
#   Posteingang/VM Fehler                -> nested via displayName traversal, limits 25/100
#   Posteingang/VM Ok=0                  -> limits OFF (archive sink, 3460 items is fine)
#   Posteingang/VM Fehler=5:20           -> custom warning:error
#
# SPACE PLACEHOLDER:  '+' wird in FolderList und OneHourList zu ' ' uebersetzt.
#   Damit braucht placeholder5/6 im PRTG Parameters-Feld KEIN Quoting mehr:
#     Posteingang;Posteingang/VM+Fehler;Posteingang/VM+Ok=0;Junk-E-Mail
#   Gilt NUR fuer placeholder5/6 - Mailbox wird NICHT uebersetzt (plus-addressing
#   wie shared+tag@domain bleibt intakt). Bekannte Grenze: ein literales '+' im
#   Ordnernamen ist damit nicht mehr adressierbar (kommt in DE/EN-Mailboxen nicht vor).
#
# Counting semantics (Graph-dokumentiert):
#   Total  = mailFolder.totalItemCount   -> zählt ALLE Item-Typen, entspricht ItemsInFolder
#   1H     = /messages?$count + receivedDateTime lt (now-60min)
#            -> zählt NUR message-Items, die älter als 60 min sind (Queue-Stau-Signal).
#            Reports/MeetingRequests fehlen hier BY DESIGN -> 1H kann < Total sein, das ist korrekt.
#
# Channel name = Graph displayName des Blatt-Ordners. Blattnamen müssen je Sensor eindeutig sein.
#==========================================================================================================
Param(
    [string]$scriptplaceholder1,
    [string]$scriptplaceholder2,
    [string]$scriptplaceholder3,
    [string]$scriptplaceholder4,
    [string]$scriptplaceholder5,
    [string]$positionValue6,      # Literal im Parameters-Feld, KEIN PRTG-Platzhalter
    [string]$positionValue7       # Literal im Parameters-Feld, KEIN PRTG-Platzhalter
)

# stdout BOM-less UTF-8 (PS 5.1 emits a BOM otherwise -> PRTG PE231)
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false } catch {}
$OutputEncoding = New-Object System.Text.UTF8Encoding $false
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

#----------------------------------------------------------------------------------------------------------
# Helpers (battle-tested arg hygiene, unverändert)
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
    $s = $s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;'
    return ($s -replace '"','&quot;')
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
    if (-not $cert) {
        throw "CERT_NOT_FOUND: thumbprint $tp is in neither CurrentUser\My nor LocalMachine\My on this probe."
    }

    $rsa = $null
    try {
        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    } catch { $rsa = $null }
    if (-not $rsa -and $cert.PrivateKey) { $rsa = $cert.PrivateKey }
    if (-not $rsa) {
        throw "CERT_NO_PRIVKEY: cert $tp found but its private key is not accessible to '$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)'."
    }
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

    # Culture-invariant epoch: on Windows PowerShell 5.1 `Get-Date -UFormat %s`
    # can emit a fractional value that [double]::Parse misreads under a
    # comma-decimal locale (de-DE) -> bogus nbf/exp -> AADSTS. Use the framework.
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

# Graph GET with throttling retry (429/503 -> honor Retry-After, max 3 attempts)
function Invoke-GraphGet {
    param([string]$Uri, [string]$Token, [hashtable]$ExtraHeaders = @{})
    $h = @{ Authorization = "Bearer $Token" } + $ExtraHeaders
    for ($i = 1; $i -le 3; $i++) {
        try {
            return Invoke-RestMethod -Headers $h -Uri $Uri -ErrorAction Stop
        } catch {
            $code = 0
            try { $code = [int]$_.Exception.Response.StatusCode } catch {}
            if (($code -eq 429 -or $code -eq 503) -and $i -lt 3) {
                $wait = 5
                try { $wait = [int]$_.Exception.Response.Headers['Retry-After'] } catch {}
                if ($wait -lt 1 -or $wait -gt 30) { $wait = 5 }
                Start-Sleep -Seconds $wait
                continue
            }
            throw
        }
    }
}

#----------------------------------------------------------------------------------------------------------
# Folder resolution: pure displayName traversal. No well-known names, no id caching.
#   Level 0:  /users/{mbx}/mailFolders?$filter=displayName eq 'X'          (Kinder von msgfolderroot)
#   Level n:  /mailFolders/{parentId}/childFolders?$filter=displayName eq 'X'
# Returns the resolved mailFolder object (id, displayName, totalItemCount, ...).
#----------------------------------------------------------------------------------------------------------
function Resolve-Folder {
    param([string]$Mailbox, [string]$Spec, [string]$Token, [System.Collections.Generic.List[string]]$Warnings)

    $segments = @($Spec -split '[\\/]' | Where-Object { $_ -ne '' })
    if ($segments.Count -eq 0) { throw "empty folder spec." }

    $parentId = $null; $current = $null
    foreach ($seg in $segments) {
        $segEsc = $seg.Trim() -replace "'","''"
        $filter = [Uri]::EscapeDataString("displayName eq '$segEsc'")
        $uri = if ($null -eq $parentId) {
            "https://graph.microsoft.com/v1.0/users/${Mailbox}/mailFolders?`$filter=${filter}&`$top=5&includeHiddenFolders=true"
        } else {
            "https://graph.microsoft.com/v1.0/users/${Mailbox}/mailFolders/${parentId}/childFolders?`$filter=${filter}&`$top=5&includeHiddenFolders=true"
        }
        $resp = Invoke-GraphGet -Uri $uri -Token $Token
        if (-not $resp.value -or $resp.value.Count -eq 0) {
            throw "segment '$seg' not found under '$Spec'."
        }
        if ($resp.value.Count -gt 1) {
            $Warnings.Add("AMBIGUOUS: '$seg' matches $($resp.value.Count) folders under '$Spec', using first.") | Out-Null
        }
        $current = $resp.value[0]
        $parentId = $current.id
    }
    return $current
}

# 1H = message-Items älter als 60 min (Queue-Stau). $count=true liefert @odata.count server-seitig,
# unabhängig von $top -> kein Pagination-Cap. ConsistencyLevel schadet nicht, hilft bei advanced filters.
function Get-AgedMessageCount {
    param([string]$Mailbox, [string]$FolderId, [string]$Token)
    $cutoff = (Get-Date).ToUniversalTime().AddMinutes(-60).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $filter = [Uri]::EscapeDataString("receivedDateTime lt $cutoff")
    $uri    = "https://graph.microsoft.com/v1.0/users/${Mailbox}/mailFolders/${FolderId}/messages?`$count=true&`$top=1&`$filter=${filter}&`$select=id"
    $resp   = Invoke-GraphGet -Uri $uri -Token $Token -ExtraHeaders @{ ConsistencyLevel = 'eventual' }
    if ($null -eq $resp.'@odata.count') { throw "Graph returned no @odata.count for 1H query." }
    return [int]$resp.'@odata.count'
}

# Token "Pfad=warn:err" | "Pfad=0" | "Pfad" -> @{ Spec; LimitMode; Warn; Err }
function Parse-FolderToken {
    param([string]$Token)
    $spec = $Token; $mode = 1; $w = 25; $e = 100
    $eq = $Token.LastIndexOf('=')
    if ($eq -gt 0) {
        $spec = $Token.Substring(0, $eq).Trim()
        $lim  = $Token.Substring($eq + 1).Trim()
        if ($lim -eq '0') { $mode = 0 }
        elseif ($lim -match '^(\d+):(\d+)$') { $w = [int]$Matches[1]; $e = [int]$Matches[2] }
        else { throw "bad limit syntax '$lim' in token '$Token' (use =0 or =warn:err)." }
    }
    return @{ Spec = $spec; LimitMode = $mode; Warn = $w; Err = $e }
}

#----------------------------------------------------------------------------------------------------------
# Main
#----------------------------------------------------------------------------------------------------------
$TenantId   = Clean-Arg $scriptplaceholder1
$ClientId   = Clean-Arg $scriptplaceholder2
$Thumbprint = Clean-Arg $scriptplaceholder3
$Mailbox    = Clean-Arg $scriptplaceholder4
$FolderRaw  = Clean-Arg $scriptplaceholder5
$OneHourRaw = Clean-Arg $positionValue6
$DiagFlag   = (Clean-Arg $positionValue7) -eq 'diag'

if (-not $TenantId)   { Emit-Error "Missing TenantId (placeholder1)." }
if (-not $ClientId)   { Emit-Error "Missing ClientId (placeholder2)." }
if (-not $Thumbprint) { Emit-Error "Missing Thumbprint (placeholder3)." }
if (-not $Mailbox)    { Emit-Error "Missing Mailbox (placeholder4)." }
if (-not $FolderRaw)  { Emit-Error "Missing FolderList (placeholder5)." }

# PRTG substituiert nur %scriptplaceholder1-5. Kommt der Platzhalter-String selbst
# hier an, hat PRTG ihn nicht ersetzt (Tippfehler/Nummer>5/kopierte Vorlage):
# Pflichtwerte -> harter Fehler. Position 6/7 -> Selbstheilung zu 'leer'.
foreach ($pair in @(@('TenantId',$TenantId),@('ClientId',$ClientId),@('Thumbprint',$Thumbprint),@('Mailbox',$Mailbox),@('FolderList',$FolderRaw))) {
    if ($pair[1] -match '^%scriptplaceholder\d+$') {
        Emit-Error "PLACEHOLDER_UNSUBSTITUTED: $($pair[0]) arrived as literal '$($pair[1])' - PRTG only substitutes %scriptplaceholder1-5; check sensor settings."
    }
}
if ($OneHourRaw -match '^%scriptplaceholder\d+$') { $OneHourRaw = '' }

foreach ($pair in @(@('TenantId',$TenantId),@('ClientId',$ClientId),@('Thumbprint',$Thumbprint),@('Mailbox',$Mailbox))) {
    if ($pair[1] -match "['""]") {
        Emit-Error "ARG_QUOTING: $($pair[0]) still contains a quote char ('$($pair[1])'). PRTG only interprets straight double quotes - use ""..."" or no quotes at all; single quotes are passed literally."
    }
}
if ($Mailbox -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') {
    Emit-Error "ARG_MAILBOX: '$Mailbox' is not a valid address - likely truncated by an unquoted space."
}

# '+' -> ' ' (space placeholder, see header). Translate AFTER list split, then re-trim
# so 'VM+Ok' -> 'VM Ok' and a stray '+Posteingang+' cannot smuggle edge spaces in.
$folderTokens = @($FolderRaw -split '[;|]' | ForEach-Object { ($_ -replace '\+',' ').Trim() } | Where-Object { $_ -ne '' })
if ($folderTokens.Count -eq 0) { Emit-Error "FOLDER_LIST: no usable folders parsed from '$FolderRaw'." }
if (@($folderTokens | Where-Object { $_ -match "['""]" }).Count -gt 0) {
    Emit-Error "FOLDER_QUOTING: folder token contains stray quotes. PRTG passes single quotes literally - use ""..."" or, with '+' for spaces, no quotes at all on placeholder5."
}
$oneHourSpecs = @($OneHourRaw -split '[;|]' | ForEach-Object { ($_ -replace '\+',' ').Trim() } | Where-Object { $_ -ne '' })

# --- Auth ---
try   { $certBundle = Resolve-AuthCert -Thumbprint $Thumbprint }
catch { Emit-Error $_.Exception.Message }
try   { $token = Get-GraphToken -TenantId $TenantId -ClientId $ClientId -CertBundle $certBundle }
catch {
    $detail = ''
    try {
        $r = $_.Exception.Response
        if ($r) { $sr = New-Object System.IO.StreamReader($r.GetResponseStream()); $detail = $sr.ReadToEnd(); $sr.Close() }
    } catch {}
    if (-not $detail) { $detail = $_.ErrorDetails.Message }
    Emit-Error "TOKEN: $($_.Exception.Message) :: $detail"
}
if (-not $token) { Emit-Error "TOKEN: Graph returned no access_token (check ClientId/Tenant/consent)." }

# --- Per-folder work (isolated; one bad folder never kills the rest) ---
$results  = New-Object System.Collections.Generic.List[string]
$errors   = New-Object System.Collections.Generic.List[string]
$warnings = New-Object System.Collections.Generic.List[string]
$diag     = New-Object System.Collections.Generic.List[string]
$seenChan = @{}

foreach ($tok in $folderTokens) {
    try {
        $cfg    = Parse-FolderToken -Token $tok
        $folder = Resolve-Folder -Mailbox $Mailbox -Spec $cfg.Spec -Token $token -Warnings $warnings
        $name   = [string]$folder.displayName
        if ($seenChan.ContainsKey($name)) { throw "duplicate channel name '$name' - leaf names must be unique per sensor." }
        $seenChan[$name] = $true

        $total = [int]$folder.totalItemCount
        $nameX = Xml-Escape $name
        if ($DiagFlag) { $diag.Add("$($cfg.Spec) -> id=$($folder.id.Substring(0,16))... total=$total") | Out-Null }

        $limitBlock = if ($cfg.LimitMode -eq 1) {
@"

        <limitmode>1</limitmode>
        <limitmaxwarning>$($cfg.Warn)</limitmaxwarning>
        <limitmaxerror>$($cfg.Err)</limitmaxerror>
"@
        } else {
@"

        <limitmode>0</limitmode>
"@
        }

        $results.Add(@"
    <result>
        <channel>$nameX</channel>
        <value>$total</value>
        <unit>Custom</unit>
        <customunit>#</customunit>
        <float>0</float>$limitBlock
    </result>
"@) | Out-Null

        # optional 1H channel for this folder
        if ($oneHourSpecs -contains $cfg.Spec) {
            try {
                $aged = Get-AgedMessageCount -Mailbox $Mailbox -FolderId $folder.id -Token $token
                $results.Add(@"
    <result>
        <channel>$nameX 1H</channel>
        <value>$aged</value>
        <unit>Custom</unit>
        <customunit>#</customunit>
        <float>0</float>
        <limitmode>1</limitmode>
        <limitmaxwarning>1</limitmaxwarning>
        <limitmaxerror>5</limitmaxerror>
    </result>
"@) | Out-Null
            }
            catch { $errors.Add("$($cfg.Spec) [1H] -> $($_.Exception.Message)") | Out-Null }
        }
    }
    catch { $errors.Add("$tok -> $($_.Exception.Message)") | Out-Null }
}

# --- Emit (legacy here-string envelope, single source of truth) ---
if ($results.Count -eq 0) {
    Emit-Error ("ALL_FOLDERS_FAILED: " + (($errors + $warnings) -join ' | '))
}

$body  = ($results -join "`r`n")
$notes = @($errors + $warnings)
if ($DiagFlag) { $notes += @("DIAG: " + ($diag -join ' ; ')) }

if ($errors.Count) {
    $text = Xml-Escape ($notes -join ' | ')
    Write-Output @"
<prtg>
    <error>1</error>
$body
    <text>$text</text>
</prtg>
"@
}
elseif ($notes.Count) {
    $text = Xml-Escape ($notes -join ' | ')
    Write-Output @"
<prtg>
$body
    <text>$text</text>
</prtg>
"@
}
else {
    Write-Output @"
<prtg>
$body
    <text>OK - $($results.Count) channels - Graph</text>
</prtg>
"@
}
