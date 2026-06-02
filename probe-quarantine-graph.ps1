<#
    Probe-Harness: testet welche Graph-Endpoints die Defender-Quarantäne
    2026 tatsächlich liefern. Read-only, keine Remediation-Actions.

    Voraussetzung: App Reg hat ThreatHunting.Read.All + ThreatSubmission.Read.All
    (application permissions, admin-consented).
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = 'C:\ProgramData\PRTGSensors\folderhealth.json',
    [string]$TestMailbox = 'mirai.bsm@bsm.datagroup.de'
)

Import-Module 'C:\Program Files (x86)\PRTG Network Monitor\Custom Sensors\EXEXML\Get-PRTGMailboxFolderHealth.ps1' `
    -Force -DisableNameChecking

$cfg   = Get-Content $ConfigPath -Raw | ConvertFrom-Json
$cred  = Resolve-SensorCredential -Config $cfg
$token = Get-GraphAccessToken -TenantId $cfg.TenantId -ClientId $cfg.ClientId `
                              -CertificateThumbprint $cred.Cert.Thumbprint

$hdrV1   = @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' }
$hdrBeta = @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' }

function Test-Endpoint {
    param([string]$Label, [string]$Method, [string]$Uri, $Body, $Headers)
    Write-Host ""
    Write-Host "=== $Label ===" -ForegroundColor Cyan
    Write-Host "  $Method $Uri"
    try {
        $params = @{ Method = $Method; Uri = $Uri; Headers = $Headers; ErrorAction = 'Stop' }
        if ($Body) { $params.Body = ($Body | ConvertTo-Json -Depth 10) }
        $resp = Invoke-RestMethod @params
        Write-Host "  [OK]" -ForegroundColor Green
        # Zeige Struktur kompakt
        if ($resp.value) {
            Write-Host "  -> value[] count: $(@($resp.value).Count)"
            if (@($resp.value).Count -gt 0) {
                Write-Host "  -> first item keys: $(($resp.value[0].PSObject.Properties.Name) -join ', ')"
            }
        }
        elseif ($resp.results) {
            Write-Host "  -> results[] count: $(@($resp.results).Count)"
            if (@($resp.results).Count -gt 0) {
                Write-Host "  -> first result keys: $(($resp.results[0].PSObject.Properties.Name) -join ', ')"
            }
        }
        else {
            Write-Host "  -> keys: $(($resp.PSObject.Properties.Name) -join ', ')"
        }
        return $resp
    }
    catch {
        $code = $_.Exception.Response.StatusCode.value__
        Write-Host "  [FAIL $code] $($_.Exception.Message)" -ForegroundColor Red
        if ($_.ErrorDetails.Message) {
            $err = $_.ErrorDetails.Message
            # Extract just the error.message if JSON
            try {
                $parsed = $err | ConvertFrom-Json
                Write-Host "  -> $($parsed.error.code): $($parsed.error.message)" -ForegroundColor Yellow
            } catch {
                Write-Host "  -> $($err.Substring(0,[Math]::Min(300,$err.Length)))" -ForegroundColor Yellow
            }
        }
        return $null
    }
}

Write-Host "Token acquired (length=$($token.Length))" -ForegroundColor Green
Write-Host "Decoding token scopes/roles..."
# JWT payload dekodieren um zu sehen welche roles tatsaechlich drin sind
$payload = $token.Split('.')[1]
switch ($payload.Length % 4) { 2 { $payload += '==' } 3 { $payload += '=' } }
$claims = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload.Replace('-','+').Replace('_','/'))) | ConvertFrom-Json
Write-Host "  roles in token: $($claims.roles -join ', ')" -ForegroundColor Magenta

# ============================================================
#  ADVANCED HUNTING (ThreatHunting.Read.All)
# ============================================================

# 1. EmailEvents - alle Mail-Events inkl. Delivery-Action
Test-Endpoint -Label "Hunting: EmailEvents (Quarantine delivery)" -Method POST `
    -Uri "https://graph.microsoft.com/v1.0/security/runHuntingQuery" -Headers $hdrV1 `
    -Body @{ Query = "EmailEvents | where DeliveryAction == 'Quarantined' | where Timestamp > ago(30d) | summarize Count=count() by RecipientEmailAddress | top 20 by Count" }

# 2. EmailEvents fuer spezifische Mailbox
Test-Endpoint -Label "Hunting: EmailEvents fuer $TestMailbox" -Method POST `
    -Uri "https://graph.microsoft.com/v1.0/security/runHuntingQuery" -Headers $hdrV1 `
    -Body @{ Query = "EmailEvents | where RecipientEmailAddress == '$TestMailbox' | where DeliveryAction == 'Quarantined' | where Timestamp > ago(30d) | summarize Count=count() by ThreatTypes" }

# 3. Beta-Variante des gleichen
Test-Endpoint -Label "Hunting BETA: EmailEvents" -Method POST `
    -Uri "https://graph.microsoft.com/beta/security/runHuntingQuery" -Headers $hdrBeta `
    -Body @{ Query = "EmailEvents | where DeliveryAction == 'Quarantined' | where Timestamp > ago(7d) | count" }

# ============================================================
#  THREAT SUBMISSION / ANALYZED EMAIL (ThreatSubmission.Read.All)
# ============================================================

# 4. analyzedEmail (beta) - das was die Q&A als "funktioniert teilweise" nannte
Test-Endpoint -Label "Beta: security/collaboration/analyzedEmails" -Method GET `
    -Uri "https://graph.microsoft.com/beta/security/collaboration/analyzedEmails?`$top=5" -Headers $hdrBeta

# 5. emailThreats (beta) - der "kaputte" Endpoint laut alter Q&A
Test-Endpoint -Label "Beta: threatSubmission/emailThreats" -Method GET `
    -Uri "https://graph.microsoft.com/beta/security/threatSubmission/emailThreats?`$top=5" -Headers $hdrBeta

# 6. emailThreatSubmissions (anderer moeglicher Name)
Test-Endpoint -Label "Beta: threatSubmission/emailThreatSubmissions" -Method GET `
    -Uri "https://graph.microsoft.com/beta/security/threatSubmission/emailThreatSubmissions?`$top=5" -Headers $hdrBeta

# 7. v1.0 threatSubmission
Test-Endpoint -Label "v1.0: threatSubmission/emailThreats" -Method GET `
    -Uri "https://graph.microsoft.com/v1.0/security/threatSubmission/emailThreats?`$top=5" -Headers $hdrV1

Write-Host ""
Write-Host "=== DONE - welche Endpoints [OK] zeigen, koennen wir fuer Monitoring nutzen ===" -ForegroundColor Cyan
