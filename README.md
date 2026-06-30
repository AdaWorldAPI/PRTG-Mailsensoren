# PRTG-Mailsensoren

Microsoft 365 Mailbox-Sensoren für PRTG Network Monitor — cloud-natives Monitoring für Postfach-Ordner und Mail-Flow-Health über Microsoft Graph und Exchange Online.

## Inhalt

| Datei | Zweck |
|---|---|
| `Get-PRTGMailboxFolderHealth.ps1` | Unified Folder-Sensor (Inbox / Custom Folders, ItemCount + 1H-Aging, Quarantäne) — Graph primär, `Get-MailboxFolderStatistics` als Legacy-Backup; config-/named-parameter-getrieben; JSON / XML / KeyValue |
| `Get-PRTGFolderHealth-Graph.ps1`  | Standalone **positional** Graph-Folder-Sensor (nur Graph). Per-Token-Limits (`=warn:err` / `=0`), `+`=Space, `@1h:`-Aging, `diag`-Modus. Für PRTG-Platzhalter optimiert |
| `Get-PRTGFolderHealth-Simple.ps1` | Standalone **positional** Graph-Folder-Sensor mit Well-Known-Namen, Per-Token-Limits, `+`=Space, **`@1h:`**-Aging und **`@quarantine`**-Kanälen (Defender Advanced Hunting) |
| `Get-PRTGMailboxSize.ps1`         | Postfach- **und Archiv**-Größe (GB) via EXO `Get-MailboxStatistics` (cert app-only). Warn 35 / Err 40 GB default, per-Channel überschreibbar |
| `Get-PRTGMailFlowHealth.ps1`      | Mail-Flow-Sensor (% Failed/Pending) mit Klassifikator für Auto-Replies, NDR-Bounces, Mail-Loops |
| `New-PRTGSensorCredential.ps1`    | Credential-Provisioning-Helper (Cert-Erzeugung + 6 Speicherformen) |
| `Grant-PRTGSensorAccess.ps1`      | Vergibt dem PRTG-Probe-Service-Account Read auf Config-JSON + Cert-Private-Key (nur nötig, wenn die Probe **nicht** als LocalSystem läuft) |
| `samples/folderhealth.sample.json`| Beispiel-Config für Folder-Sensor |
| `samples/flow.sample.json`        | Beispiel-Config für Mail-Flow-Sensor |
| `doc/PRTG-MailboxSensoren-Dokumentation.pdf` | Vollständige technische Dokumentation (~12 Seiten) |

> Token-Syntax der Standalone-Sensoren (`Get-PRTGFolderHealth-Graph/-Simple.ps1`), in der `FolderList` (Platzhalter 5):
> `Spec` (Default warn 25 / err 100) · `Spec=warn:err` · `Spec=0` (Limits aus) · `+` = Leerzeichen ·
> `@1h:Ordner[=warn:err]` (E-Mails älter als 60 min) · `@quarantine[=warn:err]` (5 Defender-Kanäle, nur *Recent* alarmiert).
> Beispiel: `Posteingang=5:10;@1h:Posteingang=2:5;Posteingang/VM+Fehler;Junk-E-Mail=3:10;@quarantine=2:5`

## Schnellstart

### 1. App Registration im Tenant — Berechtigungen nach Sensor (Least-Privilege)

Nur die Permissions vergeben, die der jeweils eingesetzte Sensor wirklich braucht. **Alle Permissions sind `Application`-Typ und erfordern Tenant-Admin-Consent.**

| Sensor | Benötigte Permission / Rolle | Hinweis |
|---|---|---|
| Folder-Sensoren (Graph) | `Microsoft Graph → Mail.Read` | ⚠️ **tenantweit**: erlaubt Lesen der **Inhalte aller Postfächer**, nicht nur Ordner-Counts. Bei Bedarf via *Application Access Policy* auf eine Mailbox-Gruppe einschränken. |
| `@quarantine` / Quarantäne | `Microsoft Graph → ThreatHunting.Read.All` | Advanced Hunting (`runHuntingQuery`). ~15–30 min Ingestion-Latenz auf dem *Recent*-Bucket. |
| `Get-PRTGMailboxSize.ps1` | `Office 365 Exchange Online → Exchange.ManageAsApp` **+** EXO-RBAC-Rolle `View-Only Recipients` | RBAC: `New-ManagementRoleAssignment -Role 'View-Only Recipients' -App <sp-objectid>` |
| `Get-PRTGMailFlowHealth.ps1` | `Office 365 Exchange Online → Exchange.ManageAsApp` **+** EXO-RBAC-Rolle `View-Only Recipients` | sonst leere `Get-MessageTraceV2`-Ergebnisse |

- Single-Tenant App Registration; das Cert (`.cer`) aus Schritt 2 unter *Certificates & secrets* hochladen.
- Eine App kann mehrere/alle Sensoren bedienen — dann die Permissions kombinieren.

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

## Betriebshinweise (wichtig)

- **PRTG importiert Channel-Limits nur EINMAL — beim Anlegen des Channels.** Spätere Änderungen der `=warn:err`-Werte im Parameters-Feld werden **ignoriert**; danach werden Limits in den **Channel-Settings im PRTG-Web-UI** verwaltet. Limits also gleich richtig setzen, oder den Channel/Sensor neu anlegen.
- **Teil-Fehler nehmen den Sensor nicht mehr komplett herunter.** Schlägt nur *ein* Ordner/Call fehl (z. B. transientes 429), bleiben alle erfolgreichen Channels erhalten und der Grund steht in `<text>`. Erst wenn **kein** Channel auflöst, geht der Sensor auf Down.
- **Probe-Identität:** Läuft der PRTG-Probe-Service als **LocalSystem**, hat er bereits Zugriff auf den Cert-Private-Key — kein `Grant-PRTGSensorAccess.ps1` nötig. Nur bei einem dedizierten Service-Account das Skript ausführen.
- **Empfohlene Poll-Intervalle:** Folder/1H 60–300 s · Quarantäne 300–900 s (Advanced-Hunting-Latenz) · Mailbox-Größe 3600 s (Daten ändern sich langsam, Größenberichte sind grob stündlich/täglich).
- **Locale:** Sensoren laufen sauber unter Windows PowerShell 5.1 mit deutschem Gebietsschema (Epoch/Float werden kulturinvariant formatiert).

## Voraussetzungen

- Windows Server 2019+ (Windows PowerShell 5.1 oder PowerShell 7.x)
- PowerShell-Modul `ExchangeOnlineManagement` (mind. v3.5) — nur für Mail-Flow-Sensor, Mailbox-Size-Sensor und Folder-Sensor im Legacy-Modus
- Lokale Admin-Rechte für die Provisionierung; im laufenden Betrieb genügt der PRTG-Probe-Service-Account

---

**Version**: 1.1 · Juni 2026 — siehe `CHANGELOG.md`
