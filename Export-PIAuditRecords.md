# Export-PIAuditRecords.ps1

Scheduled export of PI Data Archive logs for compliance and SIEM ingestion. NodeIT AS.

Two log types, selected per run: the audit database (pibasess, pisnapss, piarchss) and the PI Message Log. Two output formats, selected per run: one well-formed XML document per day per log type, or one CSV file per run per log type with a fixed header for QRadar. One script, one set of checkpoints, the same extraction and deduplication whichever format is written.

## 1. Requirements

| Item | Requirement |
|---|---|
| Host | The PI Data Archive server itself. Audit files can only be read where they live; the message log can also be read from another server with `-PigetmsgExtraArguments '-node <host> -windows'` |
| PowerShell | Windows PowerShell 5.1 (also runs on PowerShell 7) |
| PI tools | `pidiag.exe` and `piartool.exe` (audit), `pigetmsg.exe` (message log), all in `<PI root>\adm`. Nothing else: no PI SDK, no AuditViewer library, no VSS |
| Account | Read access to `<PI root>\log`; a PI identity allowed to start and stop backups (audit) and to read the message log (message log); write access to the output root |
| Auditing | EnableAudit set on the Data Archive for the databases to be exported. The exporter reads what PI records; it does not switch auditing on |
| Output disk | Local disk. Audit volumes are small; the message log on a busy server produces tens of MB per day in either format |

## 2. Installation

1. Copy `Export-PIAuditRecords.ps1` and `Register-PIAuditExportTask.ps1` together to a script directory on the server, for example `D:\NodeIT\Script`. The task runs the exporter from wherever the two scripts are placed.
2. Choose an output root, for example `D:\Logs\Audit`. The exporter creates `Exports`, `State`, `Logs` and `Work` under it.
3. Run once in Inspect mode as an administrator and read the report (section 6).
4. Run once in Export mode by hand with `-Verbose`, compare counts with PI AuditViewer and PI SMT for the same window, run again and confirm nothing is appended.
5. Register the task (section 8).

## 3. How it works

A source is one audit subsystem or the message log. Each source has its own checkpoint, so a failure on one never holds back the others. Per run, per source:

1. Read the checkpoint. The query window starts at the checkpoint minus `-OverlapMinutes`, or `-InitialLookbackHours` back on the first run, and ends at the current time.
2. Acquire. Audit: `piartool -systembackup start -subsystem <name>`, copy the live audit file and any rotated files not yet processed to `Work\<subsystem>`, `piartool -systembackup end` in a finally block whatever happens. The subsystem is in backup mode only for the copy, a few hundred milliseconds; while its audit file is closed, PI buffers new audit records in memory and writes them when the file reopens. Message log: nothing to acquire, pigetmsg queries the PI Message Subsystem directly.
3. Extract. The window is split into chunks of `-MaxDaysPerChunk`. Per chunk: `pidiag -xa <copy> -st <start> -et <end>` for each copy, or `pigetmsg -st <start> -et <end> -fx -oa`. Output is parsed from raw bytes, honouring BOM and XML declaration and falling back to `-PidiagFallbackEncoding` for 8-bit output.
4. Key. Every record gets a content hash (its own serialisation, namespace declarations removed, whitespace between tags collapsed) plus an occurrence index among identical records in the same tool output. Identical content implies identical timestamp, so a set of repeats is always wholly inside or wholly outside a window and the indices line up across runs. Three identical message log lines in one second stay three; the same audit record seen from both a live and a rotated copy is one.
5. Route by the record's own time: PITime/@UTCSeconds for audit records, MessageTime for messages. The tool's window is only an optimisation; correctness never depends on it.
6. Write (section 4 or 5), then advance the checkpoint to the chunk end. Only then, and only after the output is durably on disk.

Single instance is enforced with a named mutex. Exit codes and logging are in section 7.

## 4. XML output (`-OutputFormat Xml`, default)

One file per calendar day per log type in `Exports`: `PIAudit_yyyy-MM-dd.xml` and `PIMessageLog_yyyy-MM-dd.xml`. The date is the server's local date of the record, so a run that straddles midnight writes into two files, and the first run after midnight adds late records stamped before midnight to yesterday's file. After that a day's file does not change unless a checkpoint is reset.

Each file is a complete document at all times. Every run streams the existing file into a temp file, appends the new records, rewrites the record count, validates the temp file by a full read and swaps it in with File.Replace on the same volume. Existing records are copied through as raw markup; only those not older than the earliest new record are parsed and compared, so the per-run cost follows the window, not the size of the day.

Audit layout mirrors pidiag's own output, so anything written for pidiag output reads the daily file unchanged:

    <PIAudit xmlns="xml.osisoft.com-schemas-piaudit" xmlns:xsi=... xsi:schemaLocation=...>
      <PIServer IPHost=... IPAddress=.../>          once, from the first export
      <AuditRecords>
        <AuditRecord AuditRecordID="...">...</AuditRecord>
        ...
        <RecordsExported>N</RecordsExported>        the file's record count
      </AuditRecords>
    </PIAudit>

Message log layout mirrors pigetmsg's: `<PIMessages Type=... MachineName=... Collective=... CultureInfo=...><PIMessageList><PIMessage>...</PIMessage>...</PIMessageList></PIMessages>`.

Per-export metadata (ExportDate, OSUser, the AuditRecords attributes) is not carried into a merged file. Encoding is UTF-8 without BOM. Records within a run's batch are in time order; across runs, batches follow each other. Nothing is deleted unless `-ExportRetentionDays` is set.

## 5. CSV output (`-OutputFormat Csv`)

Files go to `Exports`, one set per log type, in one of two file modes chosen with `-CsvFileMode`. A run creates files only for the log types it was given. In both modes rows for a chunk are written in one flush before that chunk's checkpoint moves, so a crash cannot separate the two.

`PerRun` (default): one file per run, `PIAudit_yyyy-MM-dd_NNN.csv` and `PIMessagelog_yyyy-MM-dd_NNN.csv`. The date is the run's local date; NNN is a serial starting at 001 for each date and incrementing per run, independently per log type (three digits, growing past 999 if needed). Serials are kept in `State\csvserial_<prefix>.json` and cross-checked against the files present. A file is written as `.csv.tmp` and renamed when the run ends, so a file matching the collector's pattern is always complete. A run that finds nothing new still leaves a header-only file so every run is accounted for; `-SkipEmptyCsv` suppresses the file (the serial is still consumed). The next run renames a leftover `.tmp` from a crashed run to its final name, complete up to where that run stopped. Suited to collectors that pick up whole files once, such as the QRadar Log File protocol.

`PerDay`: one file per run date, `PIAudit_yyyy-MM-dd.csv` and `PIMessagelog_yyyy-MM-dd.csv`. The first run of the day creates it with the header; every later run appends its rows, one write per chunk, so a reader never sees a torn line. ExportRun in each row is `yyyy-MM-dd_HHmmss` of the run that appended it. If a day file already exists with a header other than the one this version writes (after an upgrade that changed the columns), the run does not append to it and fails with exit 7 until the file is moved aside or the day rolls over. Suited to collectors that tail a growing file, such as WinCollect File Forwarder; a collector that reads a file once and then ignores it would miss everything appended afterwards.

Deduplication without a daily file: the exporter keeps, per source, the keys of records emitted around the last checkpoint (`State\recentkeys_<source>.json`, pruned to twice the overlap) and skips them when the overlapping window returns them again.

### 5.1 Header and columns

Identical in every file, always all 40 columns, never changed at run time. The CSV contains no XML.

| Column | Filled by | Content |
|---|---|---|
| LogType | both | Audit or MessageLog |
| Server, ServerAddress | both | PIServer IPHost and IPAddress from the audit export; MachineName for messages |
| Collective | messages | the collective the server belongs to; empty on a standalone server |
| Timestamp | both | record time, ISO 8601 with the server's UTC offset |
| TimestampUtc | both | the same instant as yyyy-MM-ddTHH:mm:ssZ |
| UTCSeconds | both | the same instant as seconds since 1970 |
| Source | both | pibasess, pisnapss, piarchss or messagelog |
| AuditRecordID | audit | the record's GUID |
| UserID, UserName | both | PIUser for audit; User for messages |
| Database, Table | audit | PIConfigurationDB or PITimeSeriesDB; PIPoints, PISnapshot, PIArchive, or the element name of another audited table |
| Action | audit | Add, Edit, EditAttempt, Remove |
| ObjectID, ObjectName | audit | the ID and Name of the changed object (PointID and point name for points) |
| EventTimestamp | audit | for snapshot and archive changes, the edited data event's own time |
| ValueBefore, ValueAfter, ValueType | audit | the primary change: the Value pair for data changes, the single change for single-attribute edits |
| ChangeCount | audit | number of Before/After pairs in the record |
| Changes | audit | every change as `name: before -> after`, joined by a vertical bar |
| MessageID, Severity, ProcessName, ProcessHost, ProcessOSUser, ProcessPIUser, PID, Priority | messages | the pigetmsg fields |
| Category, Source1, Source2, Source3 | messages | interface and category fields, present on some messages |
| OriginatingHost, OriginatingPIUser, OriginatingOSUser | messages | the originating fields, when pigetmsg supplies them |
| Message | messages | the message text |
| ExportRun | both | yyyy-MM-dd_NNN of the file the row was written to |
| Extra | both | name=value pairs for anything the record carried that no column is defined for |

Coverage against the documentation: the generalised audit record (PIUser, PITime, Database, Action, AuditRecordID, Name, ID, Changes of Property/Before/After, plus TimeStamp and Flags on data changes) and all nineteen message log fields (Severity, Program, Time, Message, Server, Collective, ID, Category, OriginatingHost, OriginatingOSUser, OriginatingPIUser, Priority, ProcessHost, ProcessOSUser, ProcessPIUser, ProcessID, Source1, Source2, Source3) have columns. Sources: OSIsoft "Auditing the PI Server", the pigetmsg reference, the PowerShell Tools Get-PIMessage reference.

Unforeseen fields: an element or attribute the flattener has no column for is written to Extra as `name=value` (with a path such as `PIUser.@Domain` or `PIPoint/Comment` for audit records), and the run log carries one warning per new field name. The header does not change; a column can be added in the next version. Extra is empty for every record shape observed so far.

### 5.2 Format

UTF-8 without BOM, CRLF line endings, comma delimiter (`-CsvDelimiter` for another single character). Fields containing the delimiter, a double quote or leading or trailing spaces are quoted with inner quotes doubled, RFC 4180; `-CsvQuoteAll` quotes every field. Line breaks inside a value are folded to the two characters backslash-n, so one record is always exactly one line. `-CsvMaxFieldLength` truncates any longer field and marks it.

Row sizes: a point Add with 43 attribute changes is about 1.4 KB; edits, data changes and messages are well under 1 KB.

## 6. Inspect mode

    .\Export-PIAuditRecords.ps1 -Mode Inspect -OutputRoot D:\Logs\Audit
    .\Export-PIAuditRecords.ps1 -Mode Inspect -LogTypes MessageLog -InitialLookbackHours 24
    .\Export-PIAuditRecords.ps1 -Mode Inspect -InspectFile D:\TMP\pibasessAudit.dat

Gets a sample the same way Export would (audit files copied under backup mode, or a pigetmsg query) and writes `Logs\Inspect_<timestamp>.txt` with, per source: the tool command, exit code and stderr, any text before the XML, encoding decision, root element and children, record container and how it was chosen, record element, the first record's fields, every timestamp candidate with its parsed value, the selected timestamp field with earliest and latest parsed values, the dedupe key, identical records within the export, and the first record's XML. Raw tool output is saved in `Work\inspect`. For an audit file whose records all predate the window, it repeats without a time window so the structure is always shown. Nothing is written to Exports or State.

Use it on a new server before the first export, and whenever a PI upgrade might have changed the tool output.

## 7. Exit codes, logging, monitoring

| Code | Meaning | Action |
|---|---|---|
| 0 | success | none |
| 1 | unhandled error | read the log; the first line of the stack trace is logged |
| 2 | configuration error, nothing exported | missing tool, directory or output drive, unknown log type; the log names it |
| 3 | another instance is running | none; the next scheduled run proceeds |
| 4 | backup mode could not be exited | act now: run `piartool -systembackup end -subsystem <name>` and check the PI message log; the subsystem may still be in backup mode |
| 5 | extraction tool failure on every source | pidiag or pigetmsg failed or timed out; checkpoints held |
| 6 | XML structure failure on every source | tool output not parseable or no timestamp field found; run Inspect |
| 7 | output file failure on every source | daily file or CSV run file could not be written or validated; checkpoints held |
| 8 | partial: some sources failed, some succeeded | read the per-source lines in the log |
| 9 | deferred: PI backup in progress or backup mode busy | none; the next run retries |

Log: `Logs\PIAuditExport_yyyy-MM-dd.log`, one line per event, DEBUG lines included (tool bytes and seconds, keying time, daily file streamed and compared counts). `-Verbose` echoes DEBUG to the console. Logs older than `-LogRetentionDays` (90) are deleted. One Application event per run from source PIAuditExport: Information on 0, Warning on 8 and 9, Error otherwise; the source is created by the registration script.

Alert on any exit code other than 0, or on Warning and Error events. Exit 9 twice in a row means backup mode is persistently busy; exit 8 or 5 once is usually transient, three in a row is not. A WARN line naming a field written to Extra means the CSV columns should be reviewed.

## 8. Scheduling

    .\Register-PIAuditExportTask.ps1

Run as a local administrator. The script asks for what it needs and confirms before registering:

1. Output mode: XML (one file per day per log type, rewritten each run), CSV one file per run, or CSV one file per day appended each run.
2. Log types: audit database and message log, audit only, or message log only.
3. Output path: the exporter's output root. It must be a full path with a drive letter (or a UNC path), and the drive must exist; the folder is created if missing.
4. Account, if `-UserName` was not given. A gMSA is given with a trailing `$`; any other account prompts for its password.

A summary with the exact task command line is shown and must be confirmed with y. Any prompt is skipped when its parameter is given (`-Mode Xml|CsvPerRun|CsvPerDay`, `-LogTypes`, `-OutputRoot`, `-UserName`), and `-NoPrompt` takes the defaults for the rest (Xml, both log types, D:\Logs\Audit) for unattended use:

    .\Register-PIAuditExportTask.ps1 -Mode CsvPerDay -LogTypes Audit,MessageLog -OutputRoot 'E:\PI Export' -UserName 'DOMAIN\svc-piaudit$' -NoPrompt
    .\Register-PIAuditExportTask.ps1 -Unregister

Other exporter parameters go through `-ScriptArguments` unchanged, for example `-ScriptArguments '-BackupBusyPattern "busy"'`; the four settings above are owned by the registration script and are refused there. The task runs the `Export-PIAuditRecords.ps1` that sits in the same directory as the registration script, by full path, whatever the current directory is when it is run; `-ScriptPath` overrides that, `-IntervalMinutes` sets the cadence (default 60), `-TaskName` allows more than one task on a server.

The task repeats from the next quarter hour, ignores a new start while a run is still going, stops a run after two hours, runs with highest privileges, and the event log source is created on registration. After registering, start it once with `Start-ScheduledTask -TaskName 'NodeIT PI Audit Export'` and read the run log; the script prints both commands.

Hourly is the recommended cadence for audit sources: each run costs one backup mode start and end per subsystem, logged in the PI message log, so fifteen-minute runs add about 300 such transitions a day. The message log has no such cost; a second task with its own `-TaskName` and message log only can run more often. Both tasks can share the output root; the exporter's mutex serialises them if they coincide.

## 9. Operations

Resetting a source: move `State\checkpoint_<source>.json` aside (and, in CSV mode, `State\recentkeys_<source>.json`) and run with `-InitialLookbackHours` set to the gap. In XML mode the daily files recognise what they already hold and nothing is duplicated; in CSV mode the window is re-emitted, which is what a reset means. The message log's reach is bounded by the Data Archive's MessageLog_DayLimit (35 days by default).

Retention: `-ExportRetentionDays N` deletes daily files or run files whose file name date is older than N days, for the selected log types, at the end of each run. Default 0, nothing deleted.

Rotated audit files: when the live file exceeds AuditMaxKBytes or AuditMaxRecords, PI closes it under a new name and starts a fresh one. The exporter copies every file matching `<subsystem>Audit*.dat*` (also the alternate `pisubsystemAudit~UTCSeconds.dat` PI writes if it cannot open its file), exports each once and remembers it by name, size and modification time. The interval must be shorter than the time PI keeps rotated generations.

Daylight saving: checkpoints are stored with their UTC offset. The local time strings passed to the tools are ambiguous for one hour on the autumn transition; the overlap and the dedupe make an under-fetch self-healing on the next run.

Message log volume: at a test system's rate of 144 000 messages a day, mostly pinetmgr connection lifecycle, a day is about 75 MB of XML or 50 MB of CSV. Keep everything when the export is the connection record; otherwise `-MessageLogSeverity Information` drops the Debug lines. pigetmsg's own filters (`-pn`, `-msg`) can be passed through `-PigetmsgExtraArguments` but are positive filters.

## 10. QRadar

- Collection, PerRun files: two Log File protocol log sources pulling from the PI server over SFTP or SCP, Remote Directory = Exports, file patterns `PIAudit_\d{4}-\d{2}-\d{2}_\d+\.csv` and `PIMessagelog_\d{4}-\d{2}-\d{2}_\d+\.csv` (case sensitive), Event Generator LineByLine, Processor None, File Encoding UTF-8, Ignore Previously Processed File(s) on, Recurrence matching the task with an offset of a few minutes. Files appear under their final name only when complete. Leave them in place and let `-ExportRetentionDays` age them out.
- Collection, PerDay files: a WinCollect agent on the PI server with a File Forwarder log source per file type, Root Directory = Exports, file patterns `PIAudit_\d{4}-\d{2}-\d{2}\.csv` and `PIMessagelog_\d{4}-\d{2}-\d{2}\.csv`, monitoring the file for growth so each appended run is forwarded as it lands. The Log File protocol is not suitable here: with "ignore previously processed files" it reads a day file once and misses later appends, and without it re-reads the whole file on every poll and duplicates.
- The header line is an event to QRadar: accept one unparsed event per file, or drop payloads matching `^LogType,Server,ServerAddress,` with a routing rule.
- Parsing: a custom log source type in the DSM Editor. Generic List with the comma delimiter and 1-based indices works for every column that never contains a comma; Message, Changes, ObjectName and Extra can, and are then quoted. Use regex properties for those, or run with a tab delimiter so no field is ever quoted. Event time from TimestampUtc (`yyyy-MM-dd'T'HH:mm:ss'Z'`) or Timestamp (`yyyy-MM-dd'T'HH:mm:ssXXX`). Log Source Identifier from Server, username from UserName. Event ID: LogType plus Database, Table and Action for audit rows, LogType plus MessageID for messages; source IP and port for pinetmgr connection messages from the Message text, `(\d{1,3}(?:\.\d{1,3}){3}): (\d+)`.
- Event size: all rows are under QRadar's default 4096-byte payload.
- Volume: hourly bursts of the past hour's rows; set the log source's EPS Throttle with the burst in mind.

## 11. Parameters

General

| Parameter | Default | Description |
|---|---|---|
| -Mode | Export | Export or Inspect |
| -LogTypes | Audit,MessageLog | one, the other, or both; arrays or a comma-separated string |
| -OutputFormat | Xml | Xml or Csv |
| -OutputRoot | D:\Logs\Audit | parent of Exports, State, Logs, Work; a missing drive is exit 2 |
| -ExportDirectory, -StateDirectory, -LogDirectory, -WorkDirectory | derived | individual overrides |
| -PIRoot | $env:PISERVER, else D:\Program Files\PI | PI installation root |
| -PidiagPath, -PiartoolPath, -PigetmsgPath | `<PIRoot>\adm\*.exe` | tool locations |
| -AuditLogDirectory | `<PIRoot>\log` | where the audit files live |
| -Subsystems | pibasess,pisnapss,piarchss | audit subsystems to export |
| -InitialLookbackHours | 24 | first-run window per source (1 to 87600) |
| -OverlapMinutes | 15 | window overlap with the previous run |
| -MaxDaysPerChunk | 7 | chunk size; fractions allowed (0.25 = six hours) |
| -ToolTimeoutSeconds | 900 | pidiag or pigetmsg killed and the source failed on timeout (alias -PidiagTimeoutSeconds) |
| -PiartoolTimeoutSeconds | 120 | piartool timeout |
| -ExportRetentionDays | 0 | rolling window over output files; 0 never deletes |
| -LogRetentionDays | 90 | run log retention |
| -EventLogSource | PIAuditExport | Application event log source |
| -MutexName | Global\NodeIT_PIAuditExport | single-instance mutex |

Audit

| Parameter | Default | Description |
|---|---|---|
| -DbMask | 0 (all) | pidiag -dbMask |
| -IncludeRotated | true | export rotated audit files once |
| -RotatedFilter | `<subsystem>Audit*.dat*` | rotated file pattern |
| -SkipBackupMode | off | copy without backup mode; test systems and offline copies only |
| -BackupBusyPattern | empty | regex on `piartool -backup -query` output; a match defers the audit sources (exit 9) |
| -RecordTimeSelector | auto (PITime/@UTCSeconds) | timestamp field: @Attr, Child/@Attr or Child, matched by local name |
| -RecordContainer, -CountElement, -HeaderElements | AuditRecords, RecordsExported, PIServer | the pidiag envelope |
| -AuditFilePrefix | PIAudit | XML daily file prefix |
| -StrictRootElement | off | fail instead of warn when root elements differ |

Message log

| Parameter | Default | Description |
|---|---|---|
| -MessageLogSeverity | Debug | minimum severity: Debug, Information, Warning, Error, Critical |
| -MessageLogAllFields | true | pigetmsg -oa |
| -PigetmsgExtraArguments | empty | appended verbatim, for example `-node otherserver -windows` |
| -MessageTimeSelector | auto (MessageTime) | timestamp field |
| -MessageRecordContainer, -MessageCountElement, -MessageHeaderElements | PIMessageList, none, none | the pigetmsg envelope; 'auto' available |
| -MessageLogFilePrefix | PIMessageLog | XML daily file prefix |

Encoding

| Parameter | Default | Description |
|---|---|---|
| -PidiagOutputEncoding | auto | force decoding of tool stdout |
| -PidiagFallbackEncoding | windows-1252 | used when output has no declaration and is not valid UTF-8 |
| -PITimeFormat | dd-MMM-yyyy HH:mm:ss | format of the -st/-et strings |

CSV

| Parameter | Default | Description |
|---|---|---|
| -CsvFileMode | PerRun | PerRun: one file per run with a serial; PerDay: one file per run date, appended each run |
| -CsvAuditFilePrefix, -CsvMessageLogFilePrefix | PIAudit, PIMessagelog | file prefixes |
| -CsvSerialDigits | 3 | serial width |
| -CsvDelimiter | , | single delimiter character |
| -CsvQuoteAll | off | quote every field |
| -CsvMaxFieldLength | 0 | truncate longer fields (0 = never) |
| -SkipEmptyCsv | off | PerRun: write no file when a run has no new records |

Inspect

| Parameter | Default | Description |
|---|---|---|
| -InspectFile | none | inspect an offline audit file instead of copying live ones |

## 12. Files written

| Path | Content |
|---|---|
| Exports\PIAudit_yyyy-MM-dd.xml, PIMessageLog_yyyy-MM-dd.xml | XML daily files |
| Exports\PIAudit_yyyy-MM-dd_NNN.csv, PIMessagelog_yyyy-MM-dd_NNN.csv | CSV run files (PerRun) |
| Exports\PIAudit_yyyy-MM-dd.csv, PIMessagelog_yyyy-MM-dd.csv | CSV day files (PerDay) |
| State\checkpoint_<source>.json | LastExportedTo (ISO 8601 with offset), LastRunUtc, LastResult, processed rotated files |
| State\recentkeys_<source>.json | CSV mode: keys emitted around the last checkpoint |
| State\csvserial_<prefix>.json | CSV mode: last serial per date |
| Logs\PIAuditExport_yyyy-MM-dd.log | run log |
| Logs\Inspect_<timestamp>.txt | Inspect reports |
| Work\<subsystem>, Work\inspect | temporary audit file copies, removed after a successful source |

## 13. Reference: PI tool behaviours the design relies on

- `pidiag -xa <path> [-st <start>] [-et <end>] [-uid <id>] [-xh <schema>] [-dbMask <mask>]`: the path is the input audit file; XML goes to stdout, declared UTF-8, CRLF. Missing file: error 2; empty file: error 38; live file: error 32 (sharing violation). The window returns the first record on or before the start time through the last record on or after the end time.
- Live audit files are released for copying by `piartool -systembackup start -subsystem <name>`; `end` reopens them. While closed, the subsystem buffers audit records in memory and writes them on reopen. This is the mechanism PI AuditViewer uses internally.
- Audit XML: `PIAudit` root with PIServer, ExportDate, OSUser and an AuditRecords container ending in RecordsExported; each AuditRecord has AuditRecordID (GUID), PIUser (UserID, Name), PITime (UTCSeconds, LocalDate) and one database element (PIConfigurationDB or PITimeSeriesDB) holding one table element (PIPoints, PISnapshot, PIArchive) with an Action, an object with an ID and usually a Name, and Before/After pairs. On Add and Remove the record carries the whole object; on Edit only the changed properties. Archive records carry UserID 0; the user is in the matching snapshot record. The nested TimeStamp is the edited data event's time, not the change time.
- Audited databases (EnableAudit bitmask): Point, Digital State, Attribute Set, Point Class, User, Group, Trust, Modules, Headings, Server, Collective, Identity, Identity Mapping, Database Security, Campaign, Batches, Unit Batches, Transfer Records, Snapshot, Archive.
- Rotation: a file shift at AuditMaxKBytes or AuditMaxRecords closes the file under a name with the date and time appended; a file that cannot be opened is replaced by `pisubsystemAudit~UTCSeconds.dat`.
- `pigetmsg -st <start> -et <end> -fx -oa`: XML to stdout, `<?xml version="1.0" standalone="no"?>`, `PIMessages` root (Type, MachineName, Collective, CultureInfo) with a `PIMessageList` wrapper of `PIMessage` elements; MessageTime as dd-MMM-yy HH:mm:ss in the root's culture, one second resolution. Severity switches -si, -sw, -se, -sc; -node and -windows for a remote server. Messages expire after MessageLog_DayLimit days.

## 14. Test kit

`test\Run-Tests.ps1` runs the exporter as a child process against `test\fakes\pidiag`, `piartool` and `pigetmsg` (bash scripts, PowerShell 7 on Linux), which reproduce the observed argument forms, error codes and the real envelopes and record shapes. 114 assertions over 19 scenarios: first run across midnight, re-run, rotated file overlap, tool failures holding checkpoints, backup mode busy and stuck, encoding fallback and forced encoding, truncated daily file recovery, sub-day chunking, empty and missing sources, Inspect with and without a time window, tool timeout, concurrent instance, message log with identical repeats, both log types together with partial failure and selection, retention, CSV run files with serials, recovery, escaping, alternative delimiter and unknown fields, and CSV day files appended across runs with a header check. `test\samples` holds three real pidiag exports.

    pwsh -File test/Run-Tests.ps1
