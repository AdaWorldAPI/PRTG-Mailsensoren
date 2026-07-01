<#
    Probe v2: korrekte EmailEvents-Spalten. Quarantine ist DeliveryLocation,
    nicht DeliveryAction. Read-only.
#>
[CmdletBinding()]
param(
    [string]$ConfigPath  = 'C:\ProgramData\PRTGSensors\folderhealth.json',
    [string]$TestMailbox = 'mailbox@contoso.de',
    [int]$LookbackDays   = 30
)

. 'C:\Program Files (x86)\PRTG Network Monitor\Custom Sensors\EXEXML\Get-PRTGMailboxFolderHealth.ps1' -NoAutoRun

$cfg   = Get-Content $ConfigPath -Raw | ConvertFrom-Json
$cred  = Resolve-SensorCredential -Config $cfg
$token = Get-GraphAccessToken -TenantId $cfg.TenantId -ClientId $cfg.ClientId `
                              -CertificateThumbprint $cred.CertificateThumbprint
$hdr = @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' }

function Invoke-Hunt {
    param([string]$Label, [string]$Query, [string]$Api = 'v1.0')
    Write-Host ""
    Write-Host "=== $Label ===" -ForegroundColor Cyan
    Write-Host "  KQL: $Query" -ForegroundColor DarkGray
    try {
        $body = @{ Query = $Query } | ConvertTo-Json
        $resp = Invoke-RestMethod -Method POST `
                  -Uri "https://graph.microsoft.com/$Api/security/runHuntingQuery" `
                  -Headers $hdr -Body $body -ErrorAction Stop
        $rows = @($resp.results)
        Write-Host "  [OK] $($rows.Count) row(s)" -ForegroundColor Green
        if ($rows.Count -gt 0) {
            $rows | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Host $_ }
        }
        return $resp
    }
    catch {
        $code = $_.Exception.Response.StatusCode.value__
        Write-Host "  [FAIL $code] $($_.Exception.Message)" -ForegroundColor Red
        if ($_.ErrorDetails.Message) {
            try { Write-Host "  -> $(($_.ErrorDetails.Message | ConvertFrom-Json).error.message)" -ForegroundColor Yellow }
            catch { Write-Host "  -> $($_.ErrorDetails.Message)" -ForegroundColor Yellow }
        }
        return $null
    }
}

$d = $LookbackDays

# 1. SANITY: hat die EmailEvents-Tabelle ueberhaupt Daten?
Invoke-Hunt -Label "1. EmailEvents total count ($d d)" `
    -Query "EmailEvents | where Timestamp > ago(${d}d) | count"

# 2. Verteilung nach DeliveryAction - zeigt die echten Werte
Invoke-Hunt -Label "2. Verteilung nach DeliveryAction" `
    -Query "EmailEvents | where Timestamp > ago(${d}d) | summarize Count=count() by DeliveryAction | order by Count desc"

# 3. Verteilung nach DeliveryLocation - HIER taucht Quarantine auf
Invoke-Hunt -Label "3. Verteilung nach DeliveryLocation" `
    -Query "EmailEvents | where Timestamp > ago(${d}d) | summarize Count=count() by DeliveryLocation | order by Count desc"

# 4. KORREKTE Quarantine-Query: DeliveryLocation == Quarantine, tenant-wide
Invoke-Hunt -Label "4. Quarantine tenant-wide nach Empfaenger" `
    -Query "EmailEvents | where Timestamp > ago(${d}d) | where DeliveryLocation == 'Quarantine' | summarize Count=count() by RecipientEmailAddress | order by Count desc | take 20"

# 5. Quarantine fuer die Test-Mailbox, nach ThreatType
Invoke-Hunt -Label "5. Quarantine fuer $TestMailbox nach ThreatType" `
    -Query "EmailEvents | where Timestamp > ago(${d}d) | where RecipientEmailAddress == '$TestMailbox' | where DeliveryLocation == 'Quarantine' | summarize Count=count() by ThreatTypes"

# 6. Quarantine fuer Test-Mailbox, letzte 60min (Recent-Channel-Aequivalent)
Invoke-Hunt -Label "6. Quarantine fuer $TestMailbox letzte 60min" `
    -Query "EmailEvents | where Timestamp > ago(1h) | where RecipientEmailAddress == '$TestMailbox' | where DeliveryLocation == 'Quarantine' | count"

# 7. Vollstaendige Quarantine-Aggregation fuer eine Mailbox in EINEM Query
#    (das was der finale Sensor nutzen wuerde)
$aggQuery = @"
EmailEvents
| where Timestamp > ago(${d}d)
| where RecipientEmailAddress == '$TestMailbox'
| where DeliveryLocation == 'Quarantine'
| extend Bucket = case(
    ThreatTypes has 'Phish', 'Phish',
    ThreatTypes has 'Malware', 'Malware',
    ThreatTypes has 'Spam', 'Spam',
    'Other')
| summarize Total=count(),
            Recent=countif(Timestamp > ago(1h)),
            Phish=countif(Bucket == 'Phish'),
            Malware=countif(Bucket == 'Malware'),
            Spam=countif(Bucket == 'Spam')
"@
Invoke-Hunt -Label "7. Finale Aggregation (Total/Recent/Phish/Malware/Spam)" -Query $aggQuery

# 8. Sample echter Quarantine-Rows mit allen relevanten Feldern
Invoke-Hunt -Label "8. Sample Quarantine-Rows (alle Felder)" `
    -Query "EmailEvents | where Timestamp > ago(${d}d) | where DeliveryLocation == 'Quarantine' | project Timestamp, RecipientEmailAddress, SenderFromAddress, Subject, ThreatTypes, ThreatNames, DeliveryAction | take 5"

Write-Host ""
Write-Host "=== DONE ===" -ForegroundColor Cyan
