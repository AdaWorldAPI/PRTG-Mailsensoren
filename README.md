# PRTG-Mailsensoren

Microsoft 365 Mailbox-Sensoren für PRTG Network Monitor — cloud-natives Monitoring für Postfach-Ordner und Mail-Flow-Health über Microsoft Graph und Exchange Online.

## Inhalt

| Datei | Zweck |
|---|---|
| `Get-PRTGMailboxFolderHealth.ps1` | Folder-Sensor (Inbox / Custom Folders, ItemCount + 1H-Aging) — Graph primär, Get-MailboxFolderStatistics als Backup |
| `Get-PRTGMailFlowHealth.ps1`      | Mail-Flow-Sensor (% Failed/Pending) mit Klassifikator für Auto-Replies, NDR-Bounces, Mail-Loops |
| `New-PRTGSensorCredential.ps1`    | Credential-Provisioning-Helper (Cert-Erzeugung + 6 Speicherformen) |
| `samples/folderhealth.sample.json`| Beispiel-Config für Folder-Sensor |
| `samples/flow.sample.json`        | Beispiel-Config für Mail-Flow-Sensor |
| `doc/PRTG-MailboxSensoren-Dokumentation.pdf` | Vollständige technische Dokumentation (~12 Seiten) |

## Schnellstart

### 1. App Registration im Tenant

- Single-Tenant App Registration anlegen
- API-Permissions: `Microsoft Graph → Application → Mail.Read` + Tenant-Admin-Consent
- Für Mail-Flow zusätzlich: `Office 365 Exchange Online → Application → Exchange.ManageAsApp`
- Service Principal in EXO der Rolle `View-Only Recipients` zuweisen (sonst leere `Get-MessageTraceV2`-Ergebnisse)

### 2. Credential-Provisionierung auf der PRTG-Probe

```powershell
.\New-PRTGSensorCredential.ps1 -Method CertLM `
    -TenantId 00000000-0000-0000-0000-000000000000 `
    -ClientId 11111111-1111-1111-1111-111111111111
```

Erzeugt:
- Self-Signed Cert (RSA-2048, SHA-256, 2 Jahre) in `Cert:\LocalMachine\My`
- `.cer` auf dem Desktop für den Upload in die App Registration
- `C:\ProgramData\PRTGSensors\folderhealth.json` mit Thumbprint + ACL-Härtung

### 3. Sensoren im EXEXML-Verzeichnis ablegen

```
C:\Program Files (x86)\PRTG Network Monitor\Custom Sensors\EXEXML\
    Get-PRTGMailboxFolderHealth.ps1
    Get-PRTGMailFlowHealth.ps1
```

### 4. Sensor in PRTG anlegen

Sensor-Typ: **EXE/Script Advanced** — Parameter siehe Dokumentation Abschnitt 5.2 und 6.4.

## Credential-Speicherformen (Resilienz gegen Profile-Reset)

| Methode | Profile-Reset | Pwd-Drift | Empfehlung |
|---|---|---|---|
| **CertLM** (LocalMachine) | ✅ | ✅ | **Standard** |
| Plain (ACL'd JSON in ProgramData) | ✅ | ✅ | Einfache Alternative |
| DPAPI-LM (Machine-Scope) | ✅ | ✅ | Komplex, gleiche Resilienz wie Plain |
| XOR (Obfuscation + Keyfile) | ✅ | ✅ | Wenn DPAPI ausgeschlossen |
| Registry-LM (HKLM) | ✅ | ✅ | Alternative zu Plain/DPAPI |
| CertCU / DPAPI-CU / Registry-CU / CredMgr | ❌ | ❌ | Nur für Tests |

Service-Account-Betrieb: ausschließlich `*-LM`-Methoden einsetzen.

## Drei Aufrufpfade

```powershell
# 1. Direkt (PRTG-Standard)
.\Get-PRTGMailboxFolderHealth.ps1 -Mailbox bsm@contoso.de -Folders Inbox -Config '...'

# 2. Modul-Import (Pipeline-Integration)
Import-Module .\Get-PRTGMailboxFolderHealth.ps1 -Force
Get-Command -Module Get-PRTGMailboxFolderHealth

# 3. Dot-Source (Tests / REPL)
. .\Get-PRTGMailboxFolderHealth.ps1
$h = Get-MailboxFolderHealth -Mailbox bsm@contoso.de -Folders Inbox -AsObject
```

## Schwellwert-Design (Mail-Flow)

Der `Recipient-Not-Found`-Channel hat absichtlich **keine** Error-Schwelle. Auch bei dauerhaft hohem NDR-Aufkommen durch eine fehlerhafte Forwarding-Konfiguration bleibt PRTG gelb und triggert nicht die 24/7-Bereitschaft. Roter Alarm kommt ausschließlich über `Real Failed %` (Warn 5%, Err 15%) und `Mail Loops` (Err 10).

## Output-Formate

- **JSON** (Default): PRTG EXE/Script Advanced (EXEXML), multi-channel
- **KeyValue**: Legacy EXE/Script, single-channel — nur für Migrationsphasen sinnvoll

## Voraussetzungen

- Windows Server 2019+ (Windows PowerShell 5.1 oder PowerShell 7.x)
- PowerShell-Modul `ExchangeOnlineManagement` (mind. v3.5) — nur für Mail-Flow-Sensor und Folder-Sensor im Legacy-Modus
- Lokale Admin-Rechte für die Provisionierung; im laufenden Betrieb genügt der PRTG-Probe-Service-Account

---

**Version**: 1.0 · Mai 2026
