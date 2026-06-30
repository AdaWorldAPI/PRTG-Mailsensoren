# Changelog

All notable changes to the PRTG-Mailsensoren suite. Newest first.

## [Unreleased]

### Fixed
- **Partial failures no longer take the whole sensor Down and discard data.** The
  standalone `Get-PRTGFolderHealth-Graph.ps1` and `Get-PRTGFolderHealth-Simple.ps1`
  emitted `<error>1</error>` alongside the result channels when a single folder/1H/
  quarantine call failed (e.g. a transient 429); PRTG then marked the sensor Down
  **and discarded every good channel's value** for that scan. Now `<error>1</error>`
  is emitted only when *no* channel resolves; partial failures keep all channel data
  and report the reason in `<text>` (matches the unified sensor's rule).

### Docs
- README: full inventory of all sensors, **least-privilege permission matrix per
  sensor** (incl. the warning that Graph `Mail.Read` is tenant-wide content read, and
  that quarantine needs `ThreatHunting.Read.All`), the **limits-are-imported-once**
  PRTG gotcha, recommended polling intervals, and the standalone-sensor token syntax.
- Added this CHANGELOG.

## PR #5 — Mailbox + archive size sensor
- **Added `Get-PRTGMailboxSize.ps1`**: primary mailbox and archive size (GB) via EXO
  `Get-MailboxStatistics` (cert app-only). Default warn 35 / err 40 GB per channel,
  overridable via placeholder-5 options (`warn=`/`err=`/`awarn=`/`aerr=`/`org=`).
  Byte count taken from the exact `TotalItemSize` parenthetical (locale-independent);
  GB values formatted InvariantCulture so PRTG's `<float>` parser accepts them on
  de-DE probes.
- Archive lookup: only a genuinely-absent archive is benign (0 GB + note); throttling/
  transient/access failures now surface as a PRTG error instead of a false green 0
  (Codex P2).

## PR #4 — Simple sensor: `@1h:` aging + `+`=space
- `@1h:<folder>[=warn:err|=0]` channel: count of messages older than 60 min
  (queue-stuck / SLA signal), default warn 1 / err 5.
- `+` is translated to a space in the folder list (matches the Graph variant), so the
  PRTG Parameters field needs no quoting. Literal spaces still work.

## PR #3 — Simple sensor: per-token limits
- `Spec=warn:err` (e.g. `Junk-E-Mail=3:10`), `Spec=0` (limits off), and
  `@quarantine=2:5` (overrides the *Quarantine Recent* threshold). New
  `Parse-FolderToken` helper.

## PR #2 — Simple sensor: quarantine
- `@quarantine` token: 5 Defender-for-O365 channels (Total/Recent/Phish/Malware/Spam)
  via Graph Advanced Hunting (`runHuntingQuery`, `ThreatHunting.Read.All`). Only
  *Quarantine Recent* alerts; the cumulative buckets are reference-only.

## PR #1 — Bug fixes (P0–P2) + standalone sensors
- **P0:** `Get-PRTGMailFlowHealth.ps1` crashed every poll — `(if …)` in argument
  position throws at runtime; replaced with a splat.
- **P1:** the `-1` "not supported" sentinel now turns the channel red via
  `limitminerror` (a max-limit of 0 never fired on `-1`); KeyValue `Auto` skips
  negative sentinels; `-Direction` no longer silently no-ops without `-Domain`;
  culture-invariant JWT epoch (`DateTimeOffset`) for PS 5.1 + de-DE; a clear error
  when the cert private key is missing/unusable instead of a null-cascade.
- **P2:** `Status='Quarantined'` is no longer counted as a mail-flow failure;
  `PtrToStringBSTR` instead of `PtrToStringAuto`.
- **Added** the standalone `Get-PRTGFolderHealth-Graph.ps1` and
  `Get-PRTGFolderHealth-Simple.ps1` sensors.
