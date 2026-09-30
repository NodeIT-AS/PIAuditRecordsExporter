# Test harness for Export-PIAuditRecords.ps1 using the fake pidiag/piartool in .\fakes.
# Runs under PowerShell 7 on Linux (the fakes are bash scripts). Usage: pwsh -File test/Run-Tests.ps1
param([string]$Pwsh = 'pwsh')
$ErrorActionPreference = 'Stop'
$root   = Split-Path -Parent $PSScriptRoot
$script = Join-Path $root 'Export-PIAuditRecords.ps1'
$T      = Join-Path ([System.IO.Path]::GetTempPath()) 'piaudit-test'
if (Test-Path $T) { Remove-Item $T -Recurse -Force }
Write-Host "run directory: $T"
# the fakes are copied to the run directory and made executable, so the harness works from any checkout or share
$fakes  = Join-Path $T 'fakes'
New-Item -ItemType Directory -Path $fakes -Force | Out-Null
Copy-Item (Join-Path $PSScriptRoot 'fakes/*') $fakes
if (-not $IsWindows) { & chmod +x (Join-Path $fakes 'pidiag') (Join-Path $fakes 'piartool') (Join-Path $fakes 'pigetmsg') }
$live   = Join-Path $T 'pi/log'
$exp    = Join-Path $T 'Exports'; $state = Join-Path $T 'State'; $logs = Join-Path $T 'Logs'; $work = Join-Path $T 'Work'; $markers = Join-Path $T 'markers'
foreach ($d in $live, $markers) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
$env:FAKE_LIVE_DIR = $live
$env:FAKE_MARKER_DIR = $markers
$env:FAKE_PIARTOOL_LOG = Join-Path $T 'piartool.log'
$env:FAKE_ASSERT_COPY = $work
$env:FAKE_MSG_FILE = Join-Path $T 'messages.dat'

$script:Pass = 0; $script:Fail = 0
function Get-Guid { param([string]$id) $md5 = [System.Security.Cryptography.MD5]::Create(); $h = ([System.BitConverter]::ToString($md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($id))) -replace '-','').ToLowerInvariant(); return ('{0}-{1}-{2}-{3}-{4}' -f $h.Substring(0,8), $h.Substring(8,4), $h.Substring(12,4), $h.Substring(16,4), $h.Substring(20,12)) }
function Get-User { param($r) $r.PIUser.Name }
function Get-Detail { param($r) $n = $r.SelectSingleNode(".//*[local-name()='After']"); if ($n) { $n.InnerText } else { $null } }
function Get-Ids { param($records) @($records | ForEach-Object { Get-RecordId $_ } | Sort-Object) }
function Expect-Ids { param([string[]]$lineIds) @($lineIds | ForEach-Object { Get-Guid $_ } | Sort-Object) }
function Assert { param([bool]$Cond, [string]$Name) if ($Cond) { $script:Pass++; Write-Host "  PASS $Name" -ForegroundColor Green } else { $script:Fail++; Write-Host "  FAIL $Name" -ForegroundColor Red } }

function Invoke-Exporter {
    param([string[]]$Extra = @(), [string[]]$LogTypes = @('Audit'), [string]$PidiagPath = "$fakes/pidiag")
    $args = @('-NoProfile', '-File', $script, '-PidiagPath', $PidiagPath, '-PiartoolPath', "$fakes/piartool", '-PigetmsgPath', "$fakes/pigetmsg",
              '-AuditLogDirectory', $live, '-ExportDirectory', $exp, '-StateDirectory', $state, '-LogDirectory', $logs, '-WorkDirectory', $work,
              '-InitialLookbackHours', '48', '-MutexName', 'NodeIT_PIAuditExport_Test', '-LogTypes', ($LogTypes -join ',')) + $Extra
    $out = & $Pwsh @args 2>&1
    $code = $LASTEXITCODE
    $script:LastOutput = ($out | Out-String)
    return $code
}

function Get-RecordsFromDoc {
    param([System.Xml.XmlDocument]$Doc)
    $container = $Doc.DocumentElement.ChildNodes | Where-Object { $_ -is [System.Xml.XmlElement] -and $_.LocalName -eq 'AuditRecords' } | Select-Object -First 1
    if (-not $container) { return @() }
    return @($container.ChildNodes | Where-Object { $_ -is [System.Xml.XmlElement] -and $_.LocalName -ne 'RecordsExported' })
}
function Get-DailyRecords {
    param([datetime]$Day)
    $p = Join-Path $exp ('PIAudit_{0}.xml' -f $Day.ToString('yyyy-MM-dd'))
    if (-not (Test-Path $p)) { return @() }
    $doc = New-Object System.Xml.XmlDocument; $doc.Load($p)
    return @(Get-RecordsFromDoc $doc)
}
function Get-AllRecords { $all = @(); Get-ChildItem $exp -Filter 'PIAudit_*.xml' | ForEach-Object { $doc = New-Object System.Xml.XmlDocument; $doc.Load($_.FullName); $all += @(Get-RecordsFromDoc $doc) }; return $all }
function Get-AllMessages { $all = @(); Get-ChildItem $exp -Filter 'PIMessageLog_*.xml' | ForEach-Object { $doc = New-Object System.Xml.XmlDocument; $doc.Load($_.FullName); $list = $doc.DocumentElement.ChildNodes | Where-Object { $_ -is [System.Xml.XmlElement] -and $_.LocalName -eq 'PIMessageList' } | Select-Object -First 1; $all += @($list.ChildNodes | Where-Object { $_ -is [System.Xml.XmlElement] }) }; return $all }
function Write-MessageFile { param([string[]]$Lines) [System.IO.File]::WriteAllText($env:FAKE_MSG_FILE, (($Lines -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding($false))) }
function Get-RecordId { param($r) $r.GetAttribute('AuditRecordID').ToLowerInvariant() }
function Test-AllFilesWellFormedAndRouted {
    # well-formed, every record filed under its own LocalDate, RecordsExported equals the record count,
    # exactly one PIServer header, no per-export ExportDate/OSUser carried into the merged file
    $ok = $true
    Get-ChildItem $exp -Filter 'PIAudit_*.xml' | ForEach-Object {
        try { $doc = New-Object System.Xml.XmlDocument; $doc.Load($_.FullName) } catch { $ok = $false; Write-Host "    not well-formed: $($_.Name)"; return }
        $day = $_.BaseName.Substring(8)
        $records = @(Get-RecordsFromDoc $doc)
        foreach ($r in $records) {
            $t = [datetimeoffset]::Parse($r.PITime.LocalDate, [Globalization.CultureInfo]::InvariantCulture).LocalDateTime
            if ($t.ToString('yyyy-MM-dd') -ne $day) { $ok = $false; Write-Host "    misfiled $($r.GetAttribute('AuditRecordID')) $t in $day" }
        }
        $rootKids = @($doc.DocumentElement.ChildNodes | Where-Object { $_ -is [System.Xml.XmlElement] })
        $container = $rootKids | Where-Object { $_.LocalName -eq 'AuditRecords' }
        $count = $container.ChildNodes | Where-Object { $_ -is [System.Xml.XmlElement] -and $_.LocalName -eq 'RecordsExported' }
        if (-not $count -or [int]$count.InnerText -ne $records.Count) { $ok = $false; Write-Host "    RecordsExported mismatch in $($_.Name): $($count.InnerText) vs $($records.Count)" }
        if (@($rootKids | Where-Object { $_.LocalName -eq 'PIServer' }).Count -ne 1) { $ok = $false; Write-Host "    PIServer header count wrong in $($_.Name)" }
        if (@($rootKids | Where-Object { $_.LocalName -in 'ExportDate','OSUser' }).Count -ne 0) { $ok = $false; Write-Host "    per-export metadata leaked into $($_.Name)" }
        if ($container.HasAttribute('ExportFileName')) { $ok = $false; Write-Host "    per-export container attributes leaked into $($_.Name)" }
    }
    return $ok
}
function Get-Checkpoint { param($sub) $p = Join-Path $state "checkpoint_$sub.json"; if (Test-Path $p) { Get-Content $p -Raw | ConvertFrom-Json } else { $null } }
function Write-AuditFile { param([string]$Name, [string[]]$Lines) [System.IO.File]::WriteAllText((Join-Path $live $Name), (($Lines -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding($false))) }
function TS { param([datetime]$d) $d.ToString('yyyy-MM-dd HH:mm:ss') }

$now = Get-Date
$today = $now.Date
$yesterday = $today.AddDays(-1)

# ------------------------------------------------------------------ Scenario 1: first run
Write-Host "`n# Scenario 1: first run, 48h lookback, records across midnight, one record outside window"
Write-AuditFile 'pibasessAudit.dat' @(
    "b1;$(TS $now.AddHours(-60));olduser;PointEdit;too old",
    "b2;$(TS $now.AddHours(-30));dasive;PointCreate;sinusoid",
    "b3;$(TS $now.AddHours(-2));Bjørn Ålesund;PointEdit;descriptor endret",
    "b4;$(TS $yesterday.AddHours(23).AddMinutes(59).AddSeconds(30));dasive;PointEdit;before midnight",
    "b5;$(TS $today.AddSeconds(30));dasive;PointEdit;after midnight"
)
Write-AuditFile 'pisnapssAudit.dat' @(
    "s1;$(TS $now.AddHours(-10));dasive;SnapshotEdit;x",
    "s2;$(TS $now.AddHours(-1));dasive;SnapshotEdit;y"
)
Write-AuditFile 'piarchssAudit.dat' @(
    "a1;$(TS $now.AddHours(-5));dasive;ArchiveEdit;x",
    "a2;$(TS $now.AddHours(-3));dasive;ArchiveEdit;y",
    "a3;$(TS $now.AddHours(-1));dasive;ArchiveDelete;z"
)
# b4/b5 only fall inside 48h if now is past 00:00:30, which it always is at least by run time; b2 is 30h back
$expectedIds = @('b2','b3','b4','b5','s1','s2','a1','a2','a3') | Where-Object { $_ }
$code = Invoke-Exporter
Assert ($code -eq 0) "exit code 0 (got $code)"
$all = Get-AllRecords
$ids = Get-Ids $all
Assert (($ids -join ',') -eq ((Expect-Ids $expectedIds) -join ',')) "exported exactly the in-window records ($($all.Count) records)"
Assert (Test-AllFilesWellFormedAndRouted) "all daily files well-formed, routed by LocalDate, counts and headers correct"
Assert ((Get-DailyRecords $yesterday | Where-Object { (Get-RecordId $_) -eq (Get-Guid 'b4') }).Count -eq 1) "b4 (23:59:30) in yesterday's file"
Assert ((Get-DailyRecords $today | Where-Object { (Get-RecordId $_) -eq (Get-Guid 'b5') }).Count -eq 1) "b5 (00:00:30) in today's file"
Assert ((Get-DailyRecords $today | Where-Object { (Get-RecordId $_) -eq (Get-Guid 'a3') }).Count -eq 1) "archive record routed by its own LocalDate, not by the edited event's Timestamp child"
$b3 = $all | Where-Object { (Get-RecordId $_) -eq (Get-Guid 'b3') }
Assert ((Get-User $b3) -eq 'Bjørn Ålesund') "Norwegian characters preserved (utf-8 path)"
$todayDoc = New-Object System.Xml.XmlDocument; $todayDoc.Load((Join-Path $exp ('PIAudit_{0}.xml' -f $today.ToString('yyyy-MM-dd'))))
Assert ($todayDoc.DocumentElement.LocalName -eq 'PIAudit' -and $todayDoc.DocumentElement.NamespaceURI -eq 'xml.osisoft.com-schemas-piaudit') "root element and namespace preserved"
Assert ($todayDoc.DocumentElement.GetAttribute('schemaLocation', 'http://www.w3.org/2001/XMLSchema-instance') -like 'xml.osisoft.com-schemas-piaudit *') "xsi:schemaLocation preserved on root"
$raw = Get-Content (Join-Path $exp ('PIAudit_{0}.xml' -f $today.ToString('yyyy-MM-dd'))) -Raw
Assert (([regex]::Matches($raw, 'xmlns=')).Count -eq 1) "default namespace declared exactly once (no per-record xmlns bloat)"
Assert ($script:LastOutput -match 'auto-detected as PITime/@UTCSeconds') "timestamp auto-detected as PITime/@UTCSeconds, not the nested event TimeStamp"
foreach ($s in 'pibasess','pisnapss','piarchss') { Assert ($null -ne (Get-Checkpoint $s)) "checkpoint written for $s" }
$plog = Get-Content $env:FAKE_PIARTOOL_LOG
Assert ((@($plog | Where-Object { $_ -match 'systembackup start' }).Count -eq 3) -and (@($plog | Where-Object { $_ -match 'systembackup end' }).Count -eq 3)) "backup mode entered and left once per subsystem"
Assert ((Get-ChildItem $markers).Count -eq 0) "no subsystem left in backup mode"
Assert ((Get-ChildItem $work -ErrorAction SilentlyContinue | Measure-Object).Count -eq 0) "work directory cleaned"

# ------------------------------------------------------------------ Scenario 2: re-run, nothing new
Write-Host "`n# Scenario 2: immediate re-run"
$code = Invoke-Exporter
Assert ($code -eq 0) "exit code 0 (got $code)"
$after = Get-AllRecords
Assert ($after.Count -eq $all.Count) "no duplicates on re-run ($($after.Count) records)"
Assert ($script:LastOutput -match 'pibasess=Success\(0/0\)') "summary reports 0 seen, 0 appended"

# ------------------------------------------------------------------ Scenario 3: new records plus a rotated file overlapping the live one
Write-Host "`n# Scenario 3: new live records and a rotated file with overlap"
Write-AuditFile 'pibasessAudit.dat' @(
    "b3;$(TS $now.AddHours(-2));Bjørn Ålesund;PointEdit;descriptor endret",
    "b5;$(TS $today.AddSeconds(30));dasive;PointEdit;after midnight",
    "b6;$(TS $now.AddMinutes(-5));dasive;PointEdit;new after run 1"
)
Write-AuditFile 'pibasessAudit.dat.1' @(
    "b2;$(TS $now.AddHours(-30));dasive;PointCreate;sinusoid",
    "b4;$(TS $yesterday.AddHours(23).AddMinutes(59).AddSeconds(30));dasive;PointEdit;before midnight",
    "b7;$(TS $now.AddMinutes(-8));dasive;PointEdit;only in rotated file"
)
$code = Invoke-Exporter -Extra @('-Verbose')
Assert ($code -eq 0) "exit code 0 (got $code)"
Assert ($script:LastOutput -match 'existing records \((\d+) streamed, 0 compared\)' -and [int]$Matches[1] -gt 0) "existing records older than the new ones are streamed via the raw fast path, not parsed"
$ids = Get-Ids (Get-AllRecords)
Assert (($ids -join ',') -eq ((Expect-Ids @('a1','a2','a3','b2','b3','b4','b5','b6','b7','s1','s2')) -join ',')) "b6 and b7 appended, overlapping records not duplicated ($($ids.Count) records)"
Assert (Test-AllFilesWellFormedAndRouted) "files still well-formed and correctly routed"
$cp = Get-Checkpoint pibasess
Assert (@($cp.ProcessedRotated).Count -eq 1 -and $cp.ProcessedRotated[0] -like 'pibasessAudit.dat.1|*') "rotated file recorded as processed"
$code = Invoke-Exporter
Assert ($script:LastOutput -notmatch 'unprocessed rotated file') "rotated file not reprocessed on the next run"

# ------------------------------------------------------------------ Scenario 4: pidiag failure holds the checkpoint
Write-Host "`n# Scenario 4: pidiag failure on every subsystem"
$before = @('pibasess','pisnapss','piarchss' | ForEach-Object { (Get-Checkpoint $_).LastExportedTo })
$env:FAKE_PIDIAG_FAIL = '99'
$code = Invoke-Exporter
Remove-Item Env:FAKE_PIDIAG_FAIL
Assert ($code -eq 5) "exit code 5 (got $code)"
$afterCp = @('pibasess','pisnapss','piarchss' | ForEach-Object { (Get-Checkpoint $_).LastExportedTo })
Assert (($before -join '|') -eq ($afterCp -join '|')) "checkpoints held"
Assert ((Get-ChildItem $markers).Count -eq 0) "backup mode left despite failure"
Assert ((Get-ChildItem $exp -Filter '*.tmp').Count -eq 0) "no temp files left behind"

# ------------------------------------------------------------------ Scenario 5: backup mode cannot be entered for one subsystem
Write-Host "`n# Scenario 5: backup mode busy for pisnapss"
$env:FAKE_PIARTOOL_FAIL_START = 'pisnapss'
$code = Invoke-Exporter
Remove-Item Env:FAKE_PIARTOOL_FAIL_START
Assert ($code -eq 9) "exit code 9 deferred (got $code)"
Assert ($script:LastOutput -match 'pisnapss=Deferred' -and $script:LastOutput -match 'pibasess=Success' -and $script:LastOutput -match 'piarchss=Success') "other subsystems still exported"

# ------------------------------------------------------------------ Scenario 6: backup mode cannot be exited: critical
Write-Host "`n# Scenario 6: systembackup end fails for piarchss"
$env:FAKE_PIARTOOL_FAIL_END = 'piarchss'
$code = Invoke-Exporter
Remove-Item Env:FAKE_PIARTOOL_FAIL_END
Assert ($code -eq 4) "exit code 4 (got $code)"
Assert ($script:LastOutput -match 'CRITICAL: could not leave backup mode for piarchss') "critical message names the subsystem and the manual command"
Remove-Item (Join-Path $markers 'backupmode_piarchss') -ErrorAction SilentlyContinue

# ------------------------------------------------------------------ Scenario 7: ANSI output without declaration, preamble text
Write-Host "`n# Scenario 7: windows-1252 output with no declaration plus banner text"
Write-AuditFile 'pibasessAudit.dat' @(
    "b6;$(TS $now.AddMinutes(-5));dasive;PointEdit;new after run 1",
    "b8;$(TS $now.AddMinutes(-2));Åse Bø;PointEdit;æøå i detalj"
)
$env:FAKE_PIDIAG_ENCODING = 'ansi-nodecl'; $env:FAKE_PIDIAG_PREAMBLE = '1'
$code = Invoke-Exporter
Remove-Item Env:FAKE_PIDIAG_ENCODING; Remove-Item Env:FAKE_PIDIAG_PREAMBLE
Assert ($code -eq 0) "exit code 0 (got $code)"
$b8 = Get-AllRecords | Where-Object { (Get-RecordId $_) -eq (Get-Guid 'b8') }
Assert ((Get-User $b8) -eq 'Åse Bø' -and (Get-Detail $b8) -eq 'æøå i detalj') "ANSI bytes decoded via fallback, characters intact"
Assert ($script:LastOutput -match 'decoded with fallback') "fallback decoding warned"
Assert ((Get-AllRecords | Where-Object { (Get-RecordId $_) -eq (Get-Guid 'b6') }).Count -eq 1) "b6 still present once (dedupe survives encoding change)"

Write-Host "`n# Scenario 7b: windows-1252 with declaration, forced encoding parameter"
Write-AuditFile 'pibasessAudit.dat' @("b9;$(TS $now.AddMinutes(-1));Øyvind;PointEdit;x")
$env:FAKE_PIDIAG_ENCODING = 'ansi'
$code = Invoke-Exporter -Extra @('-PidiagOutputEncoding', 'windows-1252')
Remove-Item Env:FAKE_PIDIAG_ENCODING
$b9 = Get-AllRecords | Where-Object { (Get-RecordId $_) -eq (Get-Guid 'b9') }
Assert ($code -eq 0 -and (Get-User $b9) -eq 'Øyvind') "forced encoding path works"

# ------------------------------------------------------------------ Scenario 8: corrupt daily file
Write-Host "`n# Scenario 8: truncated daily file"
$todayPath = Join-Path $exp ('PIAudit_{0}.xml' -f $today.ToString('yyyy-MM-dd'))
$good = [System.IO.File]::ReadAllBytes($todayPath)
[System.IO.File]::WriteAllBytes($todayPath, $good[0..([int]($good.Length * 0.7))])
Write-AuditFile 'pibasessAudit.dat' @("b10;$(TS $now.AddSeconds(-30));dasive;PointEdit;x")
$cpBefore = (Get-Checkpoint pibasess).LastExportedTo
$code = Invoke-Exporter -Extra @('-Subsystems', 'pibasess')
Assert ($code -eq 7) "exit code 7 (got $code)"
Assert ((Get-Checkpoint pibasess).LastExportedTo -eq $cpBefore) "checkpoint held on daily file failure"
[System.IO.File]::WriteAllBytes($todayPath, $good)
$code = Invoke-Exporter -Extra @('-Subsystems', 'pibasess')
Assert ($code -eq 0 -and (Get-AllRecords | Where-Object { (Get-RecordId $_) -eq (Get-Guid 'b10') }).Count -eq 1) "recovers after the file is restored"

# ------------------------------------------------------------------ Scenario 9: chunking from scratch
Write-Host "`n# Scenario 9: fresh state, 1-day chunks, results identical"
$expected = Get-Ids (Get-AllRecords)
Remove-Item $exp -Recurse -Force; Remove-Item $state -Recurse -Force
Write-AuditFile 'pibasessAudit.dat' @(
    "b3;$(TS $now.AddHours(-2));Bjørn Ålesund;PointEdit;descriptor endret",
    "b4;$(TS $yesterday.AddHours(23).AddMinutes(59).AddSeconds(30));dasive;PointEdit;before midnight",
    "b5;$(TS $today.AddSeconds(30));dasive;PointEdit;after midnight",
    "b6;$(TS $now.AddMinutes(-5));dasive;PointEdit;new after run 1",
    "b8;$(TS $now.AddMinutes(-2));Åse Bø;PointEdit;æøå i detalj",
    "b9;$(TS $now.AddMinutes(-1));Øyvind;PointEdit;x",
    "b10;$(TS $now.AddSeconds(-30));dasive;PointEdit;x"
)
Remove-Item (Join-Path $live 'pibasessAudit.dat.1')
$code = Invoke-Exporter -Extra @('-MaxDaysPerChunk', '1')
$ids = Get-Ids (Get-AllRecords)
Assert ($code -eq 0) "exit code 0 (got $code)"
Assert (($ids -join ',') -eq ((Expect-Ids @('a1','a2','a3','b10','b3','b4','b5','b6','b8','b9','s1','s2')) -join ',')) "chunked run exports the same set ($($ids.Count) records)"
Assert (($script:LastOutput -split 'checkpoint advanced').Count -gt 3) "checkpoint advanced per chunk"
Assert (Test-AllFilesWellFormedAndRouted) "chunked files well-formed and routed"

# ------------------------------------------------------------------ Scenario 10: empty live file, missing subsystem
Write-Host "`n# Scenario 10: zero-byte live file and a subsystem with no file"
[System.IO.File]::WriteAllBytes((Join-Path $live 'pisnapssAudit.dat'), @())
Remove-Item (Join-Path $live 'piarchssAudit.dat')
$code = Invoke-Exporter
Assert ($code -eq 0) "exit code 0 (got $code)"
Assert ($script:LastOutput -match 'pisnapss=Success\(0/0\)') "zero-byte file treated as no records"
Assert ($script:LastOutput -match 'piarchss=NoSource') "missing file reported as NoSource"

# ------------------------------------------------------------------ Scenario 11: inspect mode
Write-Host "`n# Scenario 11: inspect mode"
Remove-Item Env:FAKE_ASSERT_COPY
$code = Invoke-Exporter -Extra @('-Mode', 'Inspect', '-Subsystems', 'pibasess')
Assert ($code -eq 0) "exit code 0 (got $code)"
Assert ($script:LastOutput -match 'timestamp selector: PITime/@UTCSeconds \(auto-detected\)') "inspect detects the timestamp attribute"
Assert ($script:LastOutput -match 'root element: <PIAudit>' -and $script:LastOutput -match 'record container: <AuditRecords>') "inspect reports root and container"
Assert ($script:LastOutput -match 'PITime/@LocalDate = .* -> ') "inspect lists every timestamp candidate so a wrong pick is visible"
Assert ((Get-ChildItem $logs -Filter 'Inspect_*.txt').Count -eq 1) "inspect report written"

# ------------------------------------------------------------------ Scenario 12: pidiag timeout
Write-Host "`n# Scenario 12: pidiag hang"
$env:FAKE_PIDIAG_HANG = '1'
$code = Invoke-Exporter -Extra @('-Subsystems', 'pibasess', '-PidiagTimeoutSeconds', '10')
Remove-Item Env:FAKE_PIDIAG_HANG
Assert ($code -eq 5) "timeout surfaces as pidiag failure (got $code)"
Assert ($script:LastOutput -match 'timed out') "timeout logged"

# ------------------------------------------------------------------ Scenario 13: inspect fallback to a full export
Write-Host "`n# Scenario 13: inspect on a file whose records are all outside the window"
Write-AuditFile 'pibasessAudit.dat' @("old1;$(TS $now.AddDays(-90));dasive;PointEdit;ancient")
$code = Invoke-Exporter -Extra @('-Mode', 'Inspect', '-Subsystems', 'pibasess')
Assert ($code -eq 0) "exit code 0 (got $code)"
Assert ($script:LastOutput -match 'file holds 1 records, none inside the window: repeating without a time window') "inspect explains the second pass"
Assert ($script:LastOutput -match 'pidiag pass: no time window' -and $script:LastOutput -match 'timestamp selector: PITime/@UTCSeconds') "second pass yields a structure sample"

# ------------------------------------------------------------------ Scenario 14: message log
Write-Host "`n# Scenario 14: message log export with repeated identical messages across midnight"
Write-MessageFile @(
    "$(TS $yesterday.AddHours(23).AddMinutes(59).AddSeconds(50));Informational;pinetmgr;Connection from client A",
    "$(TS $today.AddSeconds(10));Warning;pinetmgr;Connection from client B",
    "$(TS $now.AddMinutes(-5));Error;pisnapss;Snapshot write failed for point 15992",
    "$(TS $now.AddMinutes(-5));Error;pisnapss;Snapshot write failed for point 15992",
    "$(TS $now.AddMinutes(-5));Error;pisnapss;Snapshot write failed for point 15992",
    "$(TS $now.AddMinutes(-30));Informational;pibasess;Point sinusoid edited by NODEITLAB\andre æøå"
)
$env:FAKE_PIGETMSG_ARGS_LOG = Join-Path $T 'pigetmsg.args'
$piartoolLinesBefore = (Get-Content $env:FAKE_PIARTOOL_LOG).Count
$code = Invoke-Exporter -LogTypes @('MessageLog') -Extra @('-Verbose')
Assert ($code -eq 0) "exit code 0 (got $code)"
$msgs = Get-AllMessages
Assert ($msgs.Count -eq 6) "all 6 messages exported including the 3 identical repeats ($($msgs.Count))"
Assert ((Get-ChildItem $exp -Filter 'PIMessageLog_*.xml').Count -eq 2) "messages split into two daily files across midnight"
Assert ($script:LastOutput -match 'messagelog: record element <PIMessage>, timestamp field auto-detected as MessageTime') "MessageTime auto-detected"
Assert ($script:LastOutput -match 'record container <PIMessageList>') "PIMessageList wrapper used as the record container"
# single-message output, container left to auto: the wrapper rule must still find PIMessageList
Write-MessageFile @("$(TS $now.AddMinutes(-1));Informational;pinetmgr;lonely message")
Remove-Item (Join-Path $state 'checkpoint_messagelog.json') -ErrorAction SilentlyContinue
$code = Invoke-Exporter -LogTypes @('MessageLog') -Extra @('-MessageRecordContainer', 'auto', '-Verbose')
Assert ($code -eq 0 -and $script:LastOutput -match 'record container <PIMessageList>') "auto container resolves the wrapper even when only one message is present"
Remove-Item (Join-Path $state 'checkpoint_messagelog.json') -ErrorAction SilentlyContinue
Remove-Item (Join-Path $exp 'PIMessageLog_*.xml')
Write-MessageFile @(
    "$(TS $yesterday.AddHours(23).AddMinutes(59).AddSeconds(50));Informational;pinetmgr;Connection from client A",
    "$(TS $today.AddSeconds(10));Warning;pinetmgr;Connection from client B",
    "$(TS $now.AddMinutes(-5));Error;pisnapss;Snapshot write failed for point 15992",
    "$(TS $now.AddMinutes(-5));Error;pisnapss;Snapshot write failed for point 15992",
    "$(TS $now.AddMinutes(-5));Error;pisnapss;Snapshot write failed for point 15992",
    "$(TS $now.AddMinutes(-30));Informational;pibasess;Point sinusoid edited by NODEITLAB\andre æøå"
)
$code = Invoke-Exporter -LogTypes @('MessageLog')
$msgs = Get-AllMessages
Assert (((Get-Content $env:FAKE_PIGETMSG_ARGS_LOG) | Select-Object -Last 1) -match '-fx -oa$') "pigetmsg called with -fx -oa and no severity switch"
Assert ((Get-Content $env:FAKE_PIARTOOL_LOG).Count -eq $piartoolLinesBefore) "piartool never called for a message log run (no backup mode)"
$aæ = $msgs | Where-Object { $_.Message -like '*NODEITLAB*' }
Assert ($aæ.Message -eq 'Point sinusoid edited by NODEITLAB\andre æøå') "message text with Norwegian characters intact"
$code = Invoke-Exporter -LogTypes @('MessageLog')
Assert ($code -eq 0 -and (Get-AllMessages).Count -eq 6) "re-run adds nothing (repeats not duplicated further)"
# the same three repeats are inside the overlap window again, plus a fourth identical one (same second) and a new message
Write-MessageFile @(
    "$(TS $now.AddMinutes(-5));Error;pisnapss;Snapshot write failed for point 15992",
    "$(TS $now.AddMinutes(-5));Error;pisnapss;Snapshot write failed for point 15992",
    "$(TS $now.AddMinutes(-5));Error;pisnapss;Snapshot write failed for point 15992",
    "$(TS $now.AddMinutes(-5));Error;pisnapss;Snapshot write failed for point 15992",
    "$(TS $now.AddMinutes(-2));Critical;piarchss;Archive file corrupt"
)
$code = Invoke-Exporter -LogTypes @('MessageLog')
$msgs = Get-AllMessages
Assert ($code -eq 0 -and $msgs.Count -eq 8) "a fourth identical repeat and a new message are appended, the first three repeats are not ($($msgs.Count))"
Assert (@($msgs | Where-Object { $_.Message -eq 'Snapshot write failed for point 15992' }).Count -eq 4) "exactly four copies of the repeated message"
$code = Invoke-Exporter -LogTypes @('MessageLog') -Extra @('-MessageLogSeverity', 'Error')
Assert (((Get-Content $env:FAKE_PIGETMSG_ARGS_LOG) | Select-Object -Last 1) -match '-fx -oa -se$') "severity Error maps to -se"
$env:FAKE_PIGETMSG_FAIL = '-10401'
$code = Invoke-Exporter -LogTypes @('MessageLog')
Remove-Item Env:FAKE_PIGETMSG_FAIL
Assert ($code -eq 5) "pigetmsg failure surfaces as tool failure exit 5 (got $code)"

# ------------------------------------------------------------------ Scenario 15: both log types in one run, and selection
Write-Host "`n# Scenario 15: both log types together, partial failure, and selection"
Write-AuditFile 'pibasessAudit.dat' @("b11;$(TS $now.AddSeconds(-20));dasive;PointEdit;both types")
Write-MessageFile @("$(TS $now.AddSeconds(-15));Informational;pibasess;both types message")
$code = Invoke-Exporter -LogTypes @('Audit', 'MessageLog')
Assert ($code -eq 0) "exit code 0 (got $code)"
Assert ($script:LastOutput -match 'pibasess=Success\(1/1\)' -and $script:LastOutput -match 'messagelog=Success\(1/1\)') "audit and message log both exported in one run"
$env:FAKE_PIGETMSG_FAIL = '-1'
$code = Invoke-Exporter -LogTypes @('Audit', 'MessageLog')
Remove-Item Env:FAKE_PIGETMSG_FAIL
Assert ($code -eq 8) "message log failure with audit success is partial, exit 8 (got $code)"
$before = (Get-ChildItem $exp -Filter 'PIMessageLog_*.xml' | Measure-Object -Property Length -Sum).Sum
$code = Invoke-Exporter -LogTypes @('Audit')
$after = (Get-ChildItem $exp -Filter 'PIMessageLog_*.xml' | Measure-Object -Property Length -Sum).Sum
Assert ($code -eq 0 -and $before -eq $after -and $script:LastOutput -notmatch 'messagelog=') "-LogTypes Audit leaves the message log alone"
$code = Invoke-Exporter -LogTypes @('MessageLog') -PidiagPath '/nonexistent/pidiag'
Assert ($code -eq 0) "a missing pidiag is not a configuration error when only the message log is requested (got $code)"

# ------------------------------------------------------------------ Scenario 16: export retention
Write-Host "`n# Scenario 16: export retention"
$old = Join-Path $exp ('PIAudit_{0}.xml' -f $today.AddDays(-400).ToString('yyyy-MM-dd'))
$oldMsg = Join-Path $exp ('PIMessageLog_{0}.xml' -f $today.AddDays(-400).ToString('yyyy-MM-dd'))
$unrelated = Join-Path $exp 'PIAudit_notadate.xml'
Copy-Item (Get-ChildItem $exp -Filter 'PIAudit_*.xml' | Select-Object -First 1).FullName $old
Copy-Item (Get-ChildItem $exp -Filter 'PIMessageLog_*.xml' | Select-Object -First 1).FullName $oldMsg
'<x/>' | Set-Content $unrelated
$code = Invoke-Exporter -LogTypes @('Audit', 'MessageLog')
Assert ((Test-Path $old) -and (Test-Path $oldMsg)) "nothing deleted by default"
$code = Invoke-Exporter -LogTypes @('Audit', 'MessageLog') -Extra @('-ExportRetentionDays', '365')
Assert (-not (Test-Path $old) -and -not (Test-Path $oldMsg)) "files older than the retention window deleted for both log types"
Assert ((Test-Path $unrelated) -and ((Get-ChildItem $exp -Filter 'PIAudit_20*.xml').Count -gt 0)) "current files and non-dated files untouched"
Remove-Item $unrelated

# ------------------------------------------------------------------ Scenario 17: CSV output for the SIEM
Write-Host "`n# Scenario 17: CSV run files"
Remove-Item (Join-Path $state '*') -Force; Remove-Item (Join-Path $exp '*') -Force
$expectedHeader = 'LogType,Server,ServerAddress,Collective,Timestamp,TimestampUtc,UTCSeconds,Source,AuditRecordID,UserID,UserName,Database,Table,Action,ObjectID,ObjectName,EventTimestamp,ValueBefore,ValueAfter,ValueType,ChangeCount,Changes,MessageID,Severity,ProcessName,ProcessHost,ProcessOSUser,ProcessPIUser,PID,Priority,Category,Source1,Source2,Source3,OriginatingHost,OriginatingPIUser,OriginatingOSUser,Message,ExportRun,Extra'
Write-AuditFile 'pibasessAudit.dat' @(
    "c1;$(TS $now.AddMinutes(-40));NODEITLAB\dasive;Edit;beskrivelse, med komma og ""sitat""",
    "c2;$(TS $now.AddMinutes(-20));NODEITLAB\dasive;Add;ny tag"
)
Write-AuditFile 'pisnapssAudit.dat' @("c3;$(TS $now.AddMinutes(-10));piadmin;Remove;x")
Write-AuditFile 'piarchssAudit.dat' @()
Write-MessageFile @(
    "$(TS $now.AddMinutes(-9));Error;pisnapss;Snapshot write failed for point 15992",
    "$(TS $now.AddMinutes(-9));Error;pisnapss;Snapshot write failed for point 15992",
    "$(TS $now.AddMinutes(-9));Error;pisnapss;Snapshot write failed for point 15992",
    "$(TS $now.AddMinutes(-8));Informational;pinetmgr;He said ""hi"", twice; then left"
)
$csvArgs = @('-OutputFormat', 'Csv')
$code = Invoke-Exporter -LogTypes @('Audit', 'MessageLog') -Extra $csvArgs
Assert ($code -eq 0) "exit code 0 (got $code)"
$f1 = Join-Path $exp ('PIAudit_{0}_001.csv' -f $today.ToString('yyyy-MM-dd'))
$g1 = Join-Path $exp ('PIMessagelog_{0}_001.csv' -f $today.ToString('yyyy-MM-dd'))
Assert ((Test-Path $f1) -and (Test-Path $g1)) "run files PIAudit_<date>_001.csv and PIMessagelog_<date>_001.csv created"
Assert ((Get-ChildItem $exp -Filter '*.tmp').Count -eq 0) "no temp file left"
Assert (([System.IO.File]::ReadAllLines($f1))[0] -eq $expectedHeader -and ([System.IO.File]::ReadAllLines($g1))[0] -eq $expectedHeader) "the same fixed header in both files"
$rows = @(Import-Csv $f1) + @(Import-Csv $g1)
Assert (@(Import-Csv $f1).Count -eq 3 -and @(Import-Csv $g1).Count -eq 4) "3 audit rows in the audit file, 4 message rows including the 3 identical repeats in the message file"
Assert (@($rows | Where-Object { $_.LogType -eq 'Audit' -and $_.Source -eq 'messagelog' }).Count -eq 0 -and @(Import-Csv $f1 | Where-Object { $_.LogType -ne 'Audit' }).Count -eq 0) "no cross-contamination between the two files"
Assert (@($rows | Where-Object { $_.Message -eq 'Snapshot write failed for point 15992' }).Count -eq 3) "identical messages kept as separate rows"
$c1 = $rows | Where-Object { $_.LogType -eq 'Audit' -and $_.Action -eq 'Edit' }
Assert ($c1.Source -eq 'pibasess' -and $c1.UserName -eq 'NODEITLAB\dasive' -and $c1.Database -eq 'PIConfigurationDB' -and $c1.Table -eq 'PIPoints' -and $c1.ObjectID -eq '17838' -and $c1.ObjectName -eq 'sinusoid') "audit edit flattened: source, user, database, table, object"
Assert ($c1.ValueAfter -eq 'beskrivelse, med komma og "sitat"' -and $c1.ChangeCount -eq '1' -and $c1.Changes -like 'descriptor: * -> beskrivelse, med komma og "sitat"') "comma and quotes inside a value survive the round trip"
Assert ($c1.Timestamp -match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}$' -and $c1.TimestampUtc -match 'Z$' -and $c1.UTCSeconds -match '^\d{10}$') "ISO local, ISO UTC and epoch columns filled"
Assert (-not ($c1.PSObject.Properties.Name -contains 'RecordXml') -and (Get-Content $f1 -Raw) -notmatch '<AuditRecord') "no XML anywhere in the CSV"
$c3 = $rows | Where-Object { $_.LogType -eq 'Audit' -and $_.Action -eq 'Remove' }
Assert ($c3.Table -eq 'PISnapshot' -and $c3.EventTimestamp -match '^\d{4}-' -and $c3.ValueType -eq 'xs:string') "snapshot record: table, event timestamp and value type"
$m = $rows | Where-Object { $_.ProcessName -eq 'pinetmgr' }
Assert ($m.Message -eq 'He said "hi", twice; then left' -and $m.Severity -eq 'Informational' -and $m.MessageID -eq '7004' -and $m.UserName -eq 'pinetmgr' -and $m.Server -eq 'nodeitpi') "message flattened with quotes and delimiter intact"
Assert (($rows | ForEach-Object { $_.ExportRun } | Sort-Object -Unique) -eq ('{0}_001' -f $today.ToString('yyyy-MM-dd'))) "ExportRun identifies the file"
Assert ((Get-Content $g1 -Raw) -notmatch [char]0xFEFF -and ([System.IO.File]::ReadAllBytes($g1)[0] -eq 76)) "message file UTF-8 without BOM too"
Assert ((Get-Content $f1 -Raw) -notmatch [char]0xFEFF -and ([System.IO.File]::ReadAllBytes($f1)[0] -eq 76)) "UTF-8 without BOM"

$code = Invoke-Exporter -LogTypes @('Audit', 'MessageLog') -Extra $csvArgs
$f2 = Join-Path $exp ('PIAudit_{0}_002.csv' -f $today.ToString('yyyy-MM-dd'))
$g2 = Join-Path $exp ('PIMessagelog_{0}_002.csv' -f $today.ToString('yyyy-MM-dd'))
Assert ($code -eq 0 -and (Test-Path $f2) -and (Test-Path $g2) -and ([System.IO.File]::ReadAllLines($f2)).Count -eq 1 -and ([System.IO.File]::ReadAllLines($g2)).Count -eq 1) "second run creates _002 of each with the header only, nothing re-emitted from the overlap"
$code = Invoke-Exporter -LogTypes @('Audit', 'MessageLog') -Extra ($csvArgs + @('-SkipEmptyCsv'))
Assert ($code -eq 0 -and -not (Test-Path (Join-Path $exp ('PIAudit_{0}_003.csv' -f $today.ToString('yyyy-MM-dd')))) -and -not (Test-Path (Join-Path $exp ('PIMessagelog_{0}_003.csv' -f $today.ToString('yyyy-MM-dd'))))) "-SkipEmptyCsv writes no file when nothing is new"
Write-MessageFile @(
    "$(TS $now.AddMinutes(-9));Error;pisnapss;Snapshot write failed for point 15992",
    "$(TS $now.AddMinutes(-9));Error;pisnapss;Snapshot write failed for point 15992",
    "$(TS $now.AddMinutes(-9));Error;pisnapss;Snapshot write failed for point 15992",
    "$(TS $now.AddMinutes(-9));Error;pisnapss;Snapshot write failed for point 15992",
    "$(TS $now.AddMinutes(-1));Critical;piarchss;Archive file corrupt"
)
$code = Invoke-Exporter -LogTypes @('MessageLog') -Extra $csvArgs
$g4 = Join-Path $exp ('PIMessagelog_{0}_004.csv' -f $today.ToString('yyyy-MM-dd'))
$rows4 = @(Import-Csv $g4)
Assert ($code -eq 0 -and $rows4.Count -eq 2 -and @($rows4 | Where-Object { $_.Message -like 'Snapshot*' }).Count -eq 1 -and @($rows4 | Where-Object { $_.Severity -eq 'Critical' }).Count -eq 1) "serial skips the number the empty run consumed; only the fourth repeat and the new message are emitted"
Assert (-not (Test-Path (Join-Path $exp ('PIAudit_{0}_003.csv' -f $today.ToString('yyyy-MM-dd'))))) "a message-log-only run creates no audit file; audit serial untouched"
# orphan recovery: a crashed run left a temp file with committed rows
$orphan = Join-Path $exp ('PIMessagelog_{0}_005.csv.tmp' -f $today.ToString('yyyy-MM-dd'))
[System.IO.File]::WriteAllLines($orphan, @($expectedHeader, 'MessageLog,nodeitpi,,,2026-09-21T01:00:00+02:00,2026-09-20T23:00:00Z,1789945200,messagelog,,,,,,,,,,,,,,,7004,Debug,pinetmgr,localhost,pinetmgr,1,10,orphan row,x'))
$code = Invoke-Exporter -LogTypes @('MessageLog') -Extra $csvArgs
Assert ((Test-Path (Join-Path $exp ('PIMessagelog_{0}_005.csv' -f $today.ToString('yyyy-MM-dd')))) -and (Test-Path (Join-Path $exp ('PIMessagelog_{0}_006.csv' -f $today.ToString('yyyy-MM-dd')))) -and -not (Test-Path $orphan)) "orphaned temp file recovered under its own serial and the run took the next one"
$code = Invoke-Exporter -LogTypes @('Audit', 'MessageLog') -Extra ($csvArgs + @('-CsvDelimiter', ';', '-CsvQuoteAll'))
$f4 = Join-Path $exp ('PIAudit_{0}_004.csv' -f $today.ToString('yyyy-MM-dd'))   # 003 was consumed by the -SkipEmptyCsv run
$g7 = Join-Path $exp ('PIMessagelog_{0}_007.csv' -f $today.ToString('yyyy-MM-dd'))
Assert ((Test-Path $f4) -and (Test-Path $g7) -and ([System.IO.File]::ReadAllLines($g7))[0] -eq ('"' + ($expectedHeader -replace ',', '";"') + '"')) "serials advance independently per log type; alternative delimiter and quote-all honoured"
Assert ((Get-ChildItem $exp -Filter '*.xml').Count -eq 0) "CSV mode writes no XML daily files"
# a future PI build adds fields the columns do not know: they must land in Extra, with a warning, header unchanged
Write-AuditFile 'pibasessAudit.dat' @("c9;$(TS $now.AddSeconds(-30));NODEITLAB\dasive;Edit;extra fields")
Write-AuditFile 'pisnapssAudit.dat' @()   # the extra attribute would change the old record's content and re-emit it, which is not what this step tests
Write-MessageFile @("$(TS $now.AddSeconds(-20));Informational;pinetmgr;extra field message")
$env:FAKE_PIDIAG_EXTRA = '1'; $env:FAKE_PIGETMSG_EXTRA = '1'
$code = Invoke-Exporter -LogTypes @('Audit', 'MessageLog') -Extra $csvArgs
Remove-Item Env:FAKE_PIDIAG_EXTRA; Remove-Item Env:FAKE_PIGETMSG_EXTRA
$fx = Get-ChildItem $exp -Filter ('PIAudit_{0}_*.csv' -f $today.ToString('yyyy-MM-dd')) | Sort-Object Name | Select-Object -Last 1
$gx = Get-ChildItem $exp -Filter ('PIMessagelog_{0}_*.csv' -f $today.ToString('yyyy-MM-dd')) | Sort-Object Name | Select-Object -Last 1
$ax = @(Import-Csv $fx.FullName); $mx = @(Import-Csv $gx.FullName)
Assert ($code -eq 0 -and ([System.IO.File]::ReadAllLines($fx.FullName))[0] -eq $expectedHeader -and ([System.IO.File]::ReadAllLines($gx.FullName))[0] -eq $expectedHeader) "unknown fields do not change the header"
Assert ($ax.Count -eq 1 -and $ax[0].Extra -eq 'PIUser.@Domain=NODEITLAB | PIPoint/Comment=hello' -and $ax[0].UserName -eq 'NODEITLAB\dasive' -and $ax[0].ChangeCount -eq '1') "unknown audit attribute and element land in Extra, known columns unaffected"
Assert ($mx.Count -eq 1 -and $mx[0].Extra -eq 'Correlation=abc123' -and $mx[0].Message -eq 'extra field message') "unknown message field lands in Extra"
Assert (($script:LastOutput -split 'no column of its own').Count -eq 4) "one warning per new field name (three fields, three warnings)"

# ------------------------------------------------------------------ Scenario 18: CSV one file per day, appended each run
Write-Host "`n# Scenario 18: CSV per-day files"
Remove-Item (Join-Path $state '*') -Force; Remove-Item (Join-Path $exp '*') -Force
Write-AuditFile 'pibasessAudit.dat' @("d1;$(TS $now.AddMinutes(-3));NODEITLAB\dasive;Edit;first run")
Write-AuditFile 'pisnapssAudit.dat' @(); Write-AuditFile 'piarchssAudit.dat' @()
Write-MessageFile @("$(TS $now.AddMinutes(-2));Informational;pinetmgr;first run message")
$dayArgs = @('-OutputFormat', 'Csv', '-CsvFileMode', 'PerDay')
$code = Invoke-Exporter -LogTypes @('Audit', 'MessageLog') -Extra $dayArgs
$fd = Join-Path $exp ('PIAudit_{0}.csv' -f $today.ToString('yyyy-MM-dd')); $gd = Join-Path $exp ('PIMessagelog_{0}.csv' -f $today.ToString('yyyy-MM-dd'))
Assert ($code -eq 0 -and (Test-Path $fd) -and (Test-Path $gd)) "day files PIAudit_<date>.csv and PIMessagelog_<date>.csv created (got $code)"
Assert ((Get-ChildItem $exp).Count -eq 2 -and (Get-ChildItem $exp -Filter '*.tmp').Count -eq 0) "no serial files and no temp files in per-day mode"
Write-AuditFile 'pibasessAudit.dat' @("d1;$(TS $now.AddMinutes(-3));NODEITLAB\dasive;Edit;first run", "d2;$(TS $now.AddMinutes(-1));NODEITLAB\dasive;Edit;second run")
Write-MessageFile @("$(TS $now.AddMinutes(-2));Informational;pinetmgr;first run message", "$(TS $now.AddSeconds(-30));Warning;pinetmgr;second run message")
$code = Invoke-Exporter -LogTypes @('Audit', 'MessageLog') -Extra $dayArgs
$code = Invoke-Exporter -LogTypes @('Audit', 'MessageLog') -Extra $dayArgs
$la = [System.IO.File]::ReadAllLines($fd); $lm = [System.IO.File]::ReadAllLines($gd)
Assert ($code -eq 0 -and $la.Count -eq 3 -and $lm.Count -eq 3 -and $la[0] -eq $expectedHeader -and $lm[0] -eq $expectedHeader) "three runs: header once, two rows each, nothing duplicated by the overlap or the empty third run"
$ra = @(Import-Csv $fd); Assert (($ra | ForEach-Object { $_.ExportRun } | Sort-Object -Unique).Count -eq 2 -and ($ra[0].ExportRun -match ('^{0}_\d{{6}}$' -f $today.ToString('yyyy-MM-dd')))) "ExportRun identifies the run within the day"
Assert ((Get-ChildItem $exp).Count -eq 2) "still only the two day files after three runs"
# a day file with a different header must not be appended to
[System.IO.File]::WriteAllLines($gd, @('Different,Header', 'x,y'))
Write-MessageFile @("$(TS $now.AddSeconds(-10));Error;pinetmgr;after header change")
$code = Invoke-Exporter -LogTypes @('MessageLog') -Extra $dayArgs
Assert ($code -eq 7 -and ([System.IO.File]::ReadAllLines($gd)).Count -eq 2 -and $script:LastOutput -match 'different header') "existing day file with another header is left untouched and the run fails closed with exit 7"

Write-Host "`nPassed $script:Pass, failed $script:Fail"
if ($script:Fail -gt 0) { exit 1 }
