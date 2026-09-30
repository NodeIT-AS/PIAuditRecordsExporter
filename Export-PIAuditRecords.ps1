<#
.SYNOPSIS
    Scheduled export of PI Data Archive logs into one well-formed XML file per calendar day.
    Log types: the audit database (pibasess, pisnapss, piarchss) and the PI Message Log.

.DESCRIPTION
    Uses only shipped, supported PI Data Archive tooling.

    Audit (per subsystem):
        piartool -systembackup start -subsystem <name>    releases the live audit file
        <copy live and rotated audit files to the work directory>
        piartool -systembackup end   -subsystem <name>    (always runs, in finally)
        pidiag -xa <copy> -st <start> -et <end> [-dbMask <n>]   exports records from the copy to stdout

    MessageLog:
        pigetmsg -st <start> -et <end> -fx [-oa] [severity]   queries the PI Message Subsystem, XML to stdout

    Correctness does not depend on the tools' time windows. Every record is routed to a daily file by its
    own timestamp (PITime for audit records, MessageTime for messages) and deduplicated by a canonical
    content hash against the records already in that file, with an occurrence index so genuinely
    repeated identical messages are kept. The -st/-et window is only an optimisation, so overlapping
    windows, re-runs and rotations mid-window cannot produce duplicates or misfiled records.

    Each source (each audit subsystem, and the message log) has its own checkpoint. A failure on one
    source never stalls the others. A checkpoint advances only after every daily file touched by a chunk
    has been written and atomically swapped into place.

    Backup mode is a state change on the Data Archive. This script keeps a subsystem in backup mode only
    for the duration of the file copy and always leaves it, even when the copy throws. The message log
    path needs no backup mode.

.PARAMETER Mode
    Export  (default) scheduled export run.
    Inspect diagnostic run: exports a sample from each selected source, reports the XML structure,
            detected time field and encoding, and writes nothing to Exports or State.

.PARAMETER LogTypes
    Which logs to export: Audit, MessageLog, or both (default both). The same script serves a server
    that needs only one. List parameters accept either PowerShell arrays or a comma separated string,
    so a scheduled task command line can pass -LogTypes Audit,MessageLog.

.PARAMETER Subsystems
    Audit subsystems to export. The live audit file for each is <AuditLogDirectory>\<subsystem>Audit.dat.

.PARAMETER OutputFormat
    Xml (default): one well-formed XML document per calendar day per log type, appended to and rewritten
    atomically on every run (PIAudit_yyyy-MM-dd.xml, PIMessageLog_yyyy-MM-dd.xml).
    Csv: CSV files per log type for the SIEM, with one fixed header that always lists every column.
    -CsvFileMode PerRun (default): one file per run, PIAudit_yyyy-MM-dd_NNN.csv and
    PIMessagelog_yyyy-MM-dd_NNN.csv, date = run date, NNN a serial per run within the date; written under
    a temporary name and renamed when the run ends, so a collector never sees a partial file.
    -CsvFileMode PerDay: one file per run date, PIAudit_yyyy-MM-dd.csv and PIMessagelog_yyyy-MM-dd.csv,
    created with the header by the first run of the day and appended to by every later run. The
    collector must tail a growing file for this mode (WinCollect File Forwarder does; the QRadar Log
    File protocol with "ignore previously processed files" does not). Records are never emitted twice: the exporter remembers the keys of records around the last
    checkpoint and skips them when the overlapping window returns them again.

.PARAMETER CsvDelimiter
    Single delimiter character, default comma. Fields containing the delimiter, a quote or (after line
    break folding) nothing else special are quoted RFC 4180 style; -CsvQuoteAll quotes every field.
    Line breaks inside a value are always folded to the two characters backslash-n, so one record is
    always one line, which is what a line-based collector such as the QRadar Log File protocol needs.

.PARAMETER CsvMaxFieldLength
    Csv: truncate any field longer than that many characters (0 = never) and mark it. The CSV holds no
    XML; an audit record's content is flattened entirely into the columns, every Before/After pair into
    Changes.

.PARAMETER SkipEmptyCsv
    Csv, PerRun: do not leave a header-only file behind when a run found no new records. Default is to
    write it, so every run produces a file. In PerDay mode the day file exists from the first run of the
    day regardless.

.PARAMETER OutputRoot
    Parent of the four output directories: <OutputRoot>\Exports (daily XML), \State (checkpoints),
    \Logs (run logs, inspect reports) and \Work (temporary copies). Each can be overridden
    individually with -ExportDirectory, -StateDirectory, -LogDirectory and -WorkDirectory.

.PARAMETER OverlapMinutes
    Each run queries from (last checkpoint - OverlapMinutes). Dedupe makes the overlap harmless.

.PARAMETER MaxDaysPerChunk
    A long window (first run, or after an outage) is split into chunks of this many days so that
    memory stays bounded and the checkpoint advances after every chunk. Fractions are allowed: on a
    server whose message log runs to hundreds of thousands of lines a day, 0.25 keeps each pigetmsg
    output and its in-memory document to six hours.

.PARAMETER MessageLogSeverity
    Minimum severity to export from the message log: Debug (everything, default), Information,
    Warning, Error or Critical. Maps to pigetmsg -si, -sw, -se, -sc.

.PARAMETER MessageLogAllFields
    Pass -oa to pigetmsg so every field (PID, process and originating users and hosts, category,
    priority) is exported, not only the default columns. Default on.

.PARAMETER PigetmsgExtraArguments
    Appended verbatim to every pigetmsg call, for example '-node piserver2 -windows' to export a
    remote Data Archive's message log, or '-pn pibasess' to restrict by process.

.PARAMETER RecordTimeSelector
    Relative XPath from an audit record element to its timestamp, when auto-detection picks the wrong
    field. On Data Archive 2018 and later the record is <AuditRecord AuditRecordID=...> with a
    <PITime UTCSeconds=... LocalDate=.../> child, and auto-detection selects PITime/@UTCSeconds. A bare
    name is matched by local name regardless of namespace; an attribute is written @Name; a simple
    path such as PITime/@UTCSeconds is accepted. Run -Mode Inspect to see the record structure and every
    candidate the auto-detection considered.

.PARAMETER MessageTimeSelector
    The same, for message log records. Auto-detection looks for MessageTime and similar names.

.PARAMETER RecordContainer
    Audit: the element under the root that holds the records. pidiag -xa emits
    <PIAudit><PIServer/><ExportDate/><OSUser/><AuditRecords>...records...<RecordsExported>N</RecordsExported>
    </AuditRecords></PIAudit>, so the default is AuditRecords. An empty value means records are direct
    children of the root; 'auto' picks the element whose children repeat.

.PARAMETER CountElement
    Audit: element inside the container that carries a record count rather than a record. It is
    excluded from the records and rewritten in every daily file as the number of records the file holds.

.PARAMETER HeaderElements
    Audit: root children copied verbatim from the first export into a new daily file (server identity).
    Per-export metadata such as ExportDate and OSUser is deliberately not carried into a merged file.

.PARAMETER MessageRecordContainer
    MessageLog: as RecordContainer. pigetmsg -fx emits <PIMessages><PIMessageList>...messages...
    </PIMessageList></PIMessages> (observed on NODEITPI), so the default is PIMessageList.
    -MessageCountElement and -MessageHeaderElements likewise; 'auto' is available for a build that
    differs, and -Mode Inspect shows what it resolves to.

.PARAMETER PidiagOutputEncoding
    Force the decoding of pidiag and pigetmsg stdout (for example windows-1252). Default: honour BOM and
    XML declaration, and if that fails decode with PidiagFallbackEncoding.

.PARAMETER PidiagFallbackEncoding
    Encoding used when tool output has no BOM or declaration and is not valid UTF-8, which is what an
    8-bit console tool produces for æ ø å. Default windows-1252, the ANSI code page on Norwegian
    Windows servers.

.PARAMETER ExportRetentionDays
    Delete daily files older than this many days (by the date in the file name) at the end of a run.
    0 (default) never deletes anything.

.PARAMETER SkipBackupMode
    Copy the audit files without entering backup mode. Only for offline copies or test systems.
    On a live Data Archive the copy will fail with a sharing violation.

.PARAMETER BackupBusyPattern
    Regex evaluated against the output of "piartool -backup -query". When it matches, the audit
    sources are deferred (exit 9) so the exporter never overlaps a PI backup. Empty disables the check;
    the query output is always written to the log so the pattern can be chosen from real output.

.OUTPUTS
    Exit codes
        0   success
        1   unhandled error
        2   configuration error, nothing exported
        3   another instance is running
        4   backup mode could not be exited: the subsystem may still be in backup mode, act now
        5   extraction tool (pidiag or pigetmsg) failure on every source
        6   XML structure failure on every source
        7   daily file write failure on every source
        8   partial: at least one source failed, at least one succeeded
        9   deferred: a PI backup is in progress or backup mode could not be entered

.NOTES
    NodeIT AS. PowerShell 5.1 compatible. No PI SDK, no AuditViewer library, no VSS.
#>
[CmdletBinding()]
param(
    [ValidateSet('Export', 'Inspect')]
    [string]$Mode = 'Export',

    [string[]]$LogTypes = @('Audit', 'MessageLog'),

    [string]$PIRoot,
    [string]$PidiagPath,
    [string]$PiartoolPath,
    [string]$PigetmsgPath,
    [string]$AuditLogDirectory,

    [ValidateNotNullOrEmpty()]
    [string[]]$Subsystems = @('pibasess', 'pisnapss', 'piarchss'),

    [string]$OutputRoot = 'D:\Logs\Audit',
    [string]$ExportDirectory,
    [string]$StateDirectory,
    [string]$LogDirectory,
    [string]$WorkDirectory,
    [string]$AuditFilePrefix = 'PIAudit',
    [string]$MessageLogFilePrefix = 'PIMessageLog',

    [ValidateSet('Xml', 'Csv')]
    [string]$OutputFormat = 'Xml',
    [ValidateSet('PerRun', 'PerDay')]
    [string]$CsvFileMode = 'PerRun',
    [string]$CsvAuditFilePrefix = 'PIAudit',
    [string]$CsvMessageLogFilePrefix = 'PIMessagelog',
    [ValidateLength(1, 1)]
    [string]$CsvDelimiter = ',',
    [switch]$CsvQuoteAll,
    [ValidateRange(0, 1000000)]
    [int]$CsvMaxFieldLength = 0,
    [ValidateRange(1, 9)]
    [int]$CsvSerialDigits = 3,
    [switch]$SkipEmptyCsv,

    [ValidateRange(0, [int]::MaxValue)]
    [int]$DbMask = 0,

    [ValidateSet('Debug', 'Information', 'Warning', 'Error', 'Critical')]
    [string]$MessageLogSeverity = 'Debug',
    [bool]$MessageLogAllFields = $true,
    [string]$PigetmsgExtraArguments = '',

    [ValidateRange(1, 87600)]
    [int]$InitialLookbackHours = 24,

    [ValidateRange(0, 1440)]
    [int]$OverlapMinutes = 15,

    [ValidateRange(0.01, 90.0)]
    [double]$MaxDaysPerChunk = 7,

    [Alias('PidiagTimeoutSeconds')]
    [ValidateRange(10, 86400)]
    [int]$ToolTimeoutSeconds = 900,

    [ValidateRange(10, 3600)]
    [int]$PiartoolTimeoutSeconds = 120,

    [bool]$IncludeRotated = $true,
    [string]$RotatedFilter,
    [switch]$SkipBackupMode,
    [string]$BackupBusyPattern,

    [string]$RecordTimeSelector,
    [string]$RecordContainer = 'AuditRecords',
    [string]$CountElement = 'RecordsExported',
    [string[]]$HeaderElements = @('PIServer'),

    [string]$MessageTimeSelector,
    [string]$MessageRecordContainer = 'PIMessageList',
    [string]$MessageCountElement = '',
    [string[]]$MessageHeaderElements = @(),

    [string]$PidiagOutputEncoding,
    [string]$PidiagFallbackEncoding = 'windows-1252',
    [string]$PITimeFormat = 'dd-MMM-yyyy HH:mm:ss',
    [switch]$StrictRootElement,

    [string]$InspectFile,

    [ValidateRange(0, 3650)]
    [int]$ExportRetentionDays = 0,

    [ValidateRange(1, 3650)]
    [int]$LogRetentionDays = 90,

    [string]$EventLogSource = 'PIAuditExport',
    [string]$MutexName = 'Global\NodeIT_PIAuditExport'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------------------------------

$EXIT_SUCCESS        = 0
$EXIT_UNHANDLED      = 1
$EXIT_CONFIG         = 2
$EXIT_INSTANCE       = 3
$EXIT_BACKUPMODE     = 4
$EXIT_TOOL           = 5
$EXIT_XML            = 6
$EXIT_DAILYFILE      = 7
$EXIT_PARTIAL        = 8
$EXIT_DEFERRED       = 9

$script:RunStamp     = Get-Date
$script:LogFile      = $null
$script:OnWindows    = ($env:OS -eq 'Windows_NT')
$script:Invariant    = [System.Globalization.CultureInfo]::InvariantCulture
$script:Utf8NoBom    = New-Object System.Text.UTF8Encoding($false)
$script:XmlNsUri     = 'http://www.w3.org/2000/xmlns/'

# ---------------------------------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------------------------------

function Write-Log {
    param(
        [ValidateSet('DEBUG', 'INFO', 'WARN', 'ERROR')]
        [string]$Level = 'INFO',
        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    $line = '{0} [{1,-5}] {2}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff'), $Level, $Message
    if ($script:LogFile) {
        try { [System.IO.File]::AppendAllText($script:LogFile, $line + [Environment]::NewLine, [System.Text.Encoding]::UTF8) } catch { }
    }
    switch ($Level) {
        'ERROR' { Write-Host $line -ForegroundColor Red }
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        'DEBUG' { Write-Verbose $line }
        default { Write-Host $line }
    }
}

function Write-AppEvent {
    param([string]$Message, [int]$ExitCode)
    if (-not $script:OnWindows -or [string]::IsNullOrWhiteSpace($EventLogSource)) { return }
    try {
        if ([System.Diagnostics.EventLog]::SourceExists($EventLogSource)) {
            $type = if ($ExitCode -eq 0) { 'Information' } elseif ($ExitCode -in 8, 9) { 'Warning' } else { 'Error' }
            [System.Diagnostics.EventLog]::WriteEntry($EventLogSource, $Message, $type, 1000 + $ExitCode)
        }
    } catch { }
}

# ---------------------------------------------------------------------------------------------------
# External process execution: raw stdout bytes, decoded stderr, timeout
# ---------------------------------------------------------------------------------------------------

function Invoke-External {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string]$Arguments,
        [int]$TimeoutSeconds = 300,
        [string]$WorkingDirectory
    )
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName               = $FilePath
    $psi.Arguments              = $Arguments
    $psi.UseShellExecute        = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.CreateNoWindow         = $true
    if ($WorkingDirectory) { $psi.WorkingDirectory = $WorkingDirectory }

    Write-Log -Level DEBUG -Message ('exec: "{0}" {1}' -f $FilePath, $Arguments)

    $process  = [System.Diagnostics.Process]::Start($psi)
    $stdout   = New-Object System.IO.MemoryStream
    $outTask  = $process.StandardOutput.BaseStream.CopyToAsync($stdout)
    $errTask  = $process.StandardError.ReadToEndAsync()
    $timedOut = $false

    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        $timedOut = $true
        try { $process.Kill($true) } catch { try { $process.Kill() } catch { } }   # Kill(true) = whole tree on .NET Core; Framework has Kill() only
        $process.WaitForExit()
    }
    try { [void]$outTask.Wait(10000) } catch { }
    try { [void]$errTask.Wait(10000) } catch { }

    $stderrText = ''
    if ($errTask.Status -eq 'RanToCompletion') { $stderrText = $errTask.Result }

    $result = New-Object PSObject -Property @{
        ExitCode    = $process.ExitCode
        StdOutBytes = $stdout.ToArray()
        StdErr      = $stderrText
        TimedOut    = $timedOut
    }
    $process.Dispose()
    $stdout.Dispose()
    return $result
}

function ConvertTo-ConsoleText {
    param([byte[]]$Bytes)
    if (-not $Bytes -or $Bytes.Length -eq 0) { return '' }
    return [System.Text.Encoding]::Default.GetString($Bytes)
}

function Get-QuotedArgument {
    param([string]$Value)
    if ($Value -match '[\s"]') { return '"' + ($Value -replace '"', '\"') + '"' }
    return $Value
}

# ---------------------------------------------------------------------------------------------------
# PI time and record timestamp parsing
# ---------------------------------------------------------------------------------------------------

function Format-PITime {
    param([datetime]$Value)
    return $Value.ToString($PITimeFormat, $script:Invariant)
}

$script:TimeFormats = @(
    'dd-MMM-yy HH:mm:ss', 'dd-MMM-yyyy HH:mm:ss', 'dd-MMM-yy HH:mm:ss.fff', 'dd-MMM-yyyy HH:mm:ss.fff',
    'dd-MMM-yy HH:mm:ss.ffffff', 'dd-MMM-yyyy HH:mm:ss.ffffff', 'dd-MMM-yy HH:mm:ss.fffff', 'dd-MMM-yyyy HH:mm:ss.fffff', 'dd-MMM-yy HH:mm:ss.ffff', 'dd-MMM-yyyy HH:mm:ss.ffff',
    'dd-MMM-yy HH:mm:ss.ff', 'dd-MMM-yyyy HH:mm:ss.ff', 'dd-MMM-yy HH:mm:ss.f', 'dd-MMM-yyyy HH:mm:ss.f',
    'd-MMM-yy HH:mm:ss', 'd-MMM-yyyy HH:mm:ss',
    'yyyy-MM-ddTHH:mm:ss', 'yyyy-MM-ddTHH:mm:ss.fff', 'yyyy-MM-ddTHH:mm:ssK', 'yyyy-MM-ddTHH:mm:ss.fffK',
    'yyyy-MM-ddTHH:mm:ss.fffffffK', 'yyyy-MM-dd HH:mm:ss', 'yyyy-MM-dd HH:mm:ss.fff',
    'M/d/yyyy h:mm:ss tt', 'M/d/yyyy H:mm:ss', 'dd.MM.yyyy HH:mm:ss'
)

$script:LastGoodTimeFormat = $null

function ConvertTo-LocalDateTime {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $t = $Text.Trim()

    # UTC seconds since 1970 (PI internal time, what pidiag writes in UTCSeconds), optionally with fraction.
    # Checked first because it is the common case and the string parsers below all have to fail on it.
    $epoch = 0.0
    if ($t -match '^\d{9,11}(\.\d+)?$' -and [double]::TryParse($t, [System.Globalization.NumberStyles]::Float, $script:Invariant, [ref]$epoch)) {
        return ([datetime]'1970-01-01T00:00:00Z').AddSeconds($epoch).ToLocalTime()
    }

    $parsed = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AssumeLocal -bor [System.Globalization.DateTimeStyles]::AllowWhiteSpaces
    if ($script:LastGoodTimeFormat -and [datetime]::TryParseExact($t, $script:LastGoodTimeFormat, $script:Invariant, $styles, [ref]$parsed)) {
        return $parsed.ToLocalTime()
    }
    foreach ($fmt in $script:TimeFormats) {
        if ([datetime]::TryParseExact($t, $fmt, $script:Invariant, $styles, [ref]$parsed)) {
            $script:LastGoodTimeFormat = $fmt
            return $parsed.ToLocalTime()
        }
    }
    $dto = [datetimeoffset]::MinValue
    if ([datetimeoffset]::TryParse($t, $script:Invariant, $styles, [ref]$dto)) {
        return $dto.LocalDateTime
    }
    if ([datetime]::TryParse($t, $script:Invariant, $styles, [ref]$parsed)) {
        return $parsed.ToLocalTime()
    }
    return $null
}

# ---------------------------------------------------------------------------------------------------
# XML helpers
# ---------------------------------------------------------------------------------------------------

function New-SafeReaderSettings {
    $settings = New-Object System.Xml.XmlReaderSettings
    $settings.DtdProcessing   = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver     = $null
    $settings.IgnoreComments  = $false
    $settings.CloseInput      = $true
    return $settings
}

function Get-EncodingByName {
    param([string]$Name)
    try { return [System.Text.Encoding]::GetEncoding($Name) } catch { }
    try {
        [System.Text.Encoding]::RegisterProvider([System.Text.CodePagesEncodingProvider]::Instance)
        return [System.Text.Encoding]::GetEncoding($Name)
    } catch {
        throw ('Encoding "{0}" is not available on this system: {1}' -f $Name, $_.Exception.Message)
    }
}

function ConvertTo-XmlDocumentFromBytes {
    # Returns a hashtable: Document, Encoding (description), Preamble (text before the XML), RecordCount hint
    param([byte[]]$Bytes)

    $result = @{ Document = $null; Encoding = 'none'; Preamble = ''; IsEmpty = $true }
    if (-not $Bytes -or $Bytes.Length -eq 0) { return $result }

    # Locate the XML start. pidiag may print a banner or messages before the document.
    $firstLt = [Array]::IndexOf($Bytes, [byte]60)   # '<'
    if ($firstLt -lt 0) {
        $result.Preamble = (ConvertTo-ConsoleText -Bytes $Bytes).Trim()
        return $result
    }
    if ($firstLt -gt 0) {
        # Skip a UTF-8 BOM without calling it a preamble
        [byte[]]$lead = New-Object byte[] $firstLt
        [Array]::Copy($Bytes, 0, $lead, 0, $firstLt)
        if (-not ($lead.Length -eq 3 -and $lead[0] -eq 0xEF -and $lead[1] -eq 0xBB -and $lead[2] -eq 0xBF)) {
            $result.Preamble = (ConvertTo-ConsoleText -Bytes $lead).Trim()
        }
    }
    $lastGt = [Array]::LastIndexOf($Bytes, [byte]62)  # '>'
    if ($lastGt -le $firstLt) {
        $result.Preamble = (ConvertTo-ConsoleText -Bytes $Bytes).Trim()
        return $result
    }
    $xmlLength = $lastGt - $firstLt + 1
    [byte[]]$xmlBytes = New-Object byte[] $xmlLength
    [Array]::Copy($Bytes, $firstLt, $xmlBytes, 0, $xmlLength)
    $result.IsEmpty = $false

    $doc = New-Object System.Xml.XmlDocument
    $doc.PreserveWhitespace = $false
    $doc.XmlResolver = $null

    if (-not [string]::IsNullOrWhiteSpace($PidiagOutputEncoding)) {
        $enc  = Get-EncodingByName -Name $PidiagOutputEncoding
        $text = $enc.GetString($xmlBytes)
        $doc.LoadXml($text)
        $result.Encoding = 'forced:' + $enc.WebName
        $result.Document = $doc
        return $result
    }

    try {
        $ms = New-Object System.IO.MemoryStream(,$xmlBytes)
        $reader = [System.Xml.XmlReader]::Create($ms, (New-SafeReaderSettings))
        $doc.Load($reader)
        $reader.Close()
        $declared = 'declaration/BOM'
        if ($doc.FirstChild -is [System.Xml.XmlDeclaration] -and $doc.FirstChild.Encoding) { $declared = 'declared:' + $doc.FirstChild.Encoding }
        elseif (-not ($doc.FirstChild -is [System.Xml.XmlDeclaration])) { $declared = 'default:utf-8' }
        $result.Encoding = $declared
        $result.Document = $doc
        return $result
    } catch {
        $firstError = $_.Exception.Message
    }

    # Fall back to the configured 8-bit code page: pidiag output with no declaration and 8-bit
    # characters (æ ø å in user names or descriptors) is not valid UTF-8 and fails above.
    $ansi = Get-EncodingByName -Name $PidiagFallbackEncoding
    $text = $ansi.GetString($xmlBytes)
    $doc = New-Object System.Xml.XmlDocument
    $doc.PreserveWhitespace = $false
    $doc.XmlResolver = $null
    try {
        $doc.LoadXml($text)
    } catch {
        throw ('pidiag output is not well-formed XML. Strict parse: {0}. ANSI ({1}) parse: {2}' -f $firstError, $ansi.WebName, $_.Exception.Message)
    }
    $result.Encoding = 'fallback:' + $ansi.WebName
    $result.Document = $doc
    return $result
}

function Get-ChildElementByLocalName {
    param([System.Xml.XmlElement]$Parent, [string]$LocalName)
    if ($null -eq $Parent -or [string]::IsNullOrEmpty($LocalName)) { return $null }
    foreach ($child in $Parent.ChildNodes) {
        if ($child -is [System.Xml.XmlElement] -and $child.LocalName -eq $LocalName) { return $child }
    }
    return $null
}

function ConvertTo-LocalNameXPath {
    # Bare names, @names and simple paths (Child/@Attr, Child/Grandchild) are matched by local name so a
    # default namespace never gets in the way. Anything else is used as a literal XPath.
    param([string]$Selector)
    $s = $Selector.Trim()
    $segments = @()
    foreach ($seg in ($s -split '/')) {
        if ($seg -match '^@([A-Za-z_][\w\-\.]*)$')     { $segments += "@*[local-name()='$($Matches[1])']" }
        elseif ($seg -match '^([A-Za-z_][\w\-\.]*)$')  { $segments += "*[local-name()='$($Matches[1])']" }
        else { return $s }
    }
    return ($segments -join '/')
}

function Get-TimeRegex {
    # Builds a regex that pulls the timestamp text out of a record's raw markup, for the simple selector
    # shapes (@Attr, Child/@Attr, Child, or a bare element name). Anything else returns $null and the
    # record is parsed instead. Element names are matched exactly so PITime never matches PITimeSeriesDB.
    param([string]$Selector)
    if ([string]::IsNullOrWhiteSpace($Selector)) { return $null }
    $sel = $Selector.Trim()
    $name = '[A-Za-z_][\w\-\.]*'
    $attrValue = '(?:"([^"]*)"|''([^'']*)'')'
    if ($sel -match ('^@(' + $name + ')$'))                          { return [regex]('^<[^>]*?\s' + [regex]::Escape($Matches[1]) + '=' + $attrValue) }
    if ($sel -match ('^(' + $name + ')/@(' + $name + ')$'))            { return [regex]('<' + [regex]::Escape($Matches[1]) + '(?=[\s/>])[^>]*?\s' + [regex]::Escape($Matches[2]) + '=' + $attrValue) }
    if ($sel -match ('^(' + $name + ')$'))                            { return [regex]('<' + [regex]::Escape($Matches[1]) + '(?=[\s>])[^>]*>([^<]*)<') }
    return $null
}

function Get-NodeValue {
    param([System.Xml.XmlElement]$Element, [string]$XPath)
    $node = $Element.SelectSingleNode($XPath)
    if ($null -eq $node) { return $null }
    if ($node -is [System.Xml.XmlAttribute]) { return $node.Value }
    return $node.InnerText
}

function Get-CompiledValue {
    # Same as Get-NodeValue with a precompiled expression; used on the per-record path.
    param([System.Xml.XmlElement]$Element, [System.Xml.XPath.XPathExpression]$Expression)
    $nav = $Element.CreateNavigator().SelectSingleNode($Expression)
    if ($null -eq $nav) { return $null }
    return $nav.Value
}

# Order matters. UTCSeconds and LocalDate are the pidiag envelope's own convention (see ExportDate) and
# are tried first. A plain Timestamp is tried late because snapshot and archive audit records carry the
# edited event's Timestamp as a field, which is not the time the change was made.
$script:TimeNamePatterns = @(
    '^utcseconds$', '^localdate$', '^recordtime$', '^audittime$', '^eventtime$', '^changetime$',
    '^actiontime$', '^datetime$', '^recorddate$', '^time_?stamp$', '^time$', '^date$', 'time$', 'date$', 'time', 'date'
)

function Get-TimeCandidates {
    # Attributes, child elements, and child element attributes, in that order (attributes on the record win).
    param([System.Xml.XmlElement]$Sample)
    $candidates = New-Object System.Collections.Generic.List[object]
    foreach ($attr in $Sample.Attributes) {
        if ($attr.NamespaceURI -eq $script:XmlNsUri) { continue }
        $candidates.Add(@{ Name = $attr.LocalName; Value = $attr.Value; Selector = '@' + $attr.LocalName })
    }
    foreach ($child in $Sample.ChildNodes) {
        if ($child -isnot [System.Xml.XmlElement]) { continue }
        $candidates.Add(@{ Name = $child.LocalName; Value = $child.InnerText; Selector = $child.LocalName })
        foreach ($attr in $child.Attributes) {
            if ($attr.NamespaceURI -eq $script:XmlNsUri) { continue }
            $candidates.Add(@{ Name = $attr.LocalName; Value = $attr.Value; Selector = ('{0}/@{1}' -f $child.LocalName, $attr.LocalName) })
        }
    }
    return ,$candidates
}

function Find-TimeSelector {
    # Picks the first candidate, in pattern priority order, whose name looks like a timestamp and whose value parses.
    param([System.Xml.XmlElement]$Sample)
    $candidates = Get-TimeCandidates -Sample $Sample
    foreach ($pattern in $script:TimeNamePatterns) {
        foreach ($c in $candidates) {
            if ($c.Name -imatch $pattern) {
                $dt = ConvertTo-LocalDateTime -Text $c.Value
                if ($null -ne $dt) { return $c.Selector }
            }
        }
    }
    return $null
}

$script:Sha256 = [System.Security.Cryptography.SHA256]::Create()
$script:KeyStripNamespaces = [regex]'\sxmlns(?::[A-Za-z_][\w\-\.]*)?\s*=\s*(?:"[^"]*"|''[^'']*'')'
$script:KeyCollapseGaps    = [regex]'>\s+<'

function Get-RecordKey {
    # Content hash of a record. The rendering is the element's own serialisation (native, no per-node
    # PowerShell work) with namespace declarations removed and whitespace between tags collapsed, so a
    # record hashes the same whether it came straight from the tool or was read back from a daily file.
    # Both paths serialise through the same .NET writer, so escaping and attribute order agree.
    param([System.Xml.XmlElement]$Element)
    $text = $script:KeyCollapseGaps.Replace($script:KeyStripNamespaces.Replace($Element.OuterXml, ''), '><')
    $hash = $script:Sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($text))
    return [System.BitConverter]::ToString($hash).Replace('-', '')
}

function Remove-NamespaceDeclarations {
    param([System.Xml.XmlElement]$Element)
    $toRemove = @()
    foreach ($attr in $Element.Attributes) { if ($attr.NamespaceURI -eq $script:XmlNsUri) { $toRemove += $attr } }
    foreach ($attr in $toRemove) { [void]$Element.Attributes.Remove($attr) }
}

function Get-InScopeDeclarations {
    # The namespace declaration strings XmlReader.ReadOuterXml adds to a fragment's start tag for the
    # namespaces in scope. Written back inside the same root they are redundant and are removed again.
    param([System.Xml.XmlNamespaceManager]$NsManager)
    $list = New-Object System.Collections.Generic.List[string]
    foreach ($prefix in $NsManager) {
        if ($prefix -eq 'xml' -or $prefix -eq 'xmlns') { continue }
        $uri = $NsManager.LookupNamespace($prefix)
        if ([string]::IsNullOrEmpty($uri)) { continue }
        $name = if ($prefix) { 'xmlns:' + $prefix } else { 'xmlns' }
        $list.Add(' ' + $name + '="' + $uri + '"')
        $list.Add(' ' + $name + "='" + $uri + "'")
    }
    return ,$list
}

function Test-RepeatedChildren {
    # True when the element has at least two element children sharing a local name.
    param([System.Xml.XmlElement]$Element)
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($child in $Element.ChildNodes) {
        if ($child -isnot [System.Xml.XmlElement]) { continue }
        if (-not $seen.Add($child.LocalName)) { return $true }
    }
    return $false
}

function Resolve-RecordContainer {
    <#
        The element whose children are the records, for a tool output document and a source profile.
        Returns @{ Element; Name } where Name is the container's local name, or '' when the records sit
        directly under the root. Profile.Container is an explicit name, '' for the root, or 'auto':
        the root if its children repeat, otherwise the root child with the most repeated children.
    #>
    param([System.Xml.XmlDocument]$Document, [hashtable]$Profile)
    if ($null -eq $Document -or $null -eq $Document.DocumentElement) { return $null }
    $root = $Document.DocumentElement
    $configured = $Profile.Container
    if ($configured -and $configured -ne 'auto') {
        $c = Get-ChildElementByLocalName -Parent $root -LocalName $configured
        if ($null -ne $c) { return @{ Element = $c; Name = $configured } }
        return @{ Element = $root; Name = '' }
    }
    if ($configured -eq 'auto') {
        if (Test-RepeatedChildren -Element $root) { return @{ Element = $root; Name = '' } }
        $best = $null
        $bestCount = 0
        $elementChildren = @($root.ChildNodes | Where-Object { $_ -is [System.Xml.XmlElement] })
        foreach ($child in $elementChildren) {
            if (-not (Test-RepeatedChildren -Element $child)) { continue }
            $n = @($child.ChildNodes | Where-Object { $_ -is [System.Xml.XmlElement] }).Count
            if ($n -gt $bestCount) { $best = $child; $bestCount = $n }
        }
        if ($null -ne $best) { return @{ Element = $best; Name = $best.LocalName } }
        # A single wrapper child holding a single record (nothing repeats anywhere): take the wrapper.
        # A flat layout with one record would be misread here, but then the timestamp detection fails
        # loudly rather than a record being misfiled, and an explicit container setting resolves it.
        if ($elementChildren.Count -eq 1 -and @($elementChildren[0].ChildNodes | Where-Object { $_ -is [System.Xml.XmlElement] }).Count -gt 0) {
            return @{ Element = $elementChildren[0]; Name = $elementChildren[0].LocalName }
        }
    }
    return @{ Element = $root; Name = '' }
}

function Get-RecordElements {
    param([System.Xml.XmlDocument]$Document, [hashtable]$Profile)
    # Returned with the comma operator so PowerShell does not unroll the list into the pipeline.
    $list = New-Object System.Collections.Generic.List[System.Xml.XmlElement]
    $container = Resolve-RecordContainer -Document $Document -Profile $Profile
    if ($null -eq $container) { return ,$list }
    foreach ($child in $container.Element.ChildNodes) {
        if ($child -is [System.Xml.XmlElement]) {
            if ($Profile.CountElement -and $child.LocalName -eq $Profile.CountElement) { continue }
            $list.Add($child)
        }
    }
    return ,$list
}

# ---------------------------------------------------------------------------------------------------
# Daily file maintenance: stream existing records through, append the new ones, swap atomically
# ---------------------------------------------------------------------------------------------------

function Get-DailyFilePath {
    param([hashtable]$Profile, [datetime]$Day)
    return Join-Path $ExportDirectory ('{0}_{1}.xml' -f $Profile.Prefix, $Day.ToString('yyyy-MM-dd'))
}

$script:EpochBase = [datetime]'1970-01-01T00:00:00Z'
$script:RecordIndent = [Environment]::NewLine + '    '

function Copy-ExistingRecords {
    <#
        Reader is positioned on the first node inside the record container (or inside the root for a flat
        layout). Streams every record through to the writer and returns when the container's end element
        is reached, leaving the reader on it.

        Each record's raw markup is taken (which advances the reader past it) and written back unchanged
        apart from redundant namespace declarations, so records are never re-serialised. When the
        timestamp pulled from the raw text proves a record cannot collide with any new record, that is all
        that happens. Otherwise the fragment is parsed with the file's namespaces in scope and its dedupe
        key recorded. One call per file: PowerShell 5.1 function calls are too expensive per record.
        Returns @{ Existing; Streamed }.
    #>
    param($Reader, $Writer, $ExistingKeys, [hashtable]$KeyCounter, [regex]$TimeRegex, [datetime]$MinNewTime,
          [System.Xml.XmlParserContext]$ParserContext, [System.Collections.Generic.List[string]]$InScopeDeclarations, [string]$CountElement)
    $existing = 0
    $streamed = 0
    $indent = $script:RecordIndent
    $epochBase = $script:EpochBase
    $invariant = $script:Invariant
    $fragmentSettings = New-SafeReaderSettings
    $fragmentSettings.ConformanceLevel = [System.Xml.ConformanceLevel]::Fragment
    $endElement = [System.Xml.XmlNodeType]::EndElement
    $element = [System.Xml.XmlNodeType]::Element
    $comment = [System.Xml.XmlNodeType]::Comment
    $pi = [System.Xml.XmlNodeType]::ProcessingInstruction

    while (-not $Reader.EOF -and $Reader.NodeType -ne $endElement) {
        $nodeType = $Reader.NodeType
        if ($nodeType -eq $element) {
            if ($CountElement -and $Reader.LocalName -eq $CountElement) { $Reader.Skip(); continue }
            $raw = $Reader.ReadOuterXml()
            $tagEnd = $raw.IndexOf('>')          # XmlWriter escapes '>' inside attribute values, so this is the start tag's end
            if ($tagEnd -gt 0 -and $InScopeDeclarations.Count -gt 0) {
                $tag = $raw.Substring(0, $tagEnd + 1)
                $cleaned = $tag
                foreach ($d in $InScopeDeclarations) { $cleaned = $cleaned.Replace($d, '') }
                if ($cleaned -ne $tag) { $raw = $cleaned + $raw.Substring($tagEnd + 1) }
            }
            $Writer.WriteWhitespace($indent)
            $Writer.WriteRaw($raw)
            $existing++
            if ($TimeRegex) {
                $m = $TimeRegex.Match($raw)
                if ($m.Success) {
                    $text = $m.Groups[1].Value
                    if (-not $text -and $m.Groups.Count -gt 2) { $text = $m.Groups[2].Value }
                    $t = $null
                    if ($text -match '^\d{9,11}(\.\d+)?$') { $t = $epochBase.AddSeconds([double]::Parse($text, $invariant)).ToLocalTime() }
                    else { $t = ConvertTo-LocalDateTime -Text $text }
                    if ($null -ne $t -and $t -lt $MinNewTime) { $streamed++; continue }
                }
            }
            $fragmentReader = [System.Xml.XmlReader]::Create((New-Object System.IO.StringReader($raw)), $fragmentSettings, $ParserContext)
            $doc = New-Object System.Xml.XmlDocument
            $doc.PreserveWhitespace = $false
            $doc.XmlResolver = $null
            $doc.Load($fragmentReader)
            $fragmentReader.Close()
            $hash = Get-RecordKey -Element $doc.DocumentElement
            $n = 0
            if ($KeyCounter.ContainsKey($hash)) { $n = $KeyCounter[$hash] }
            $KeyCounter[$hash] = $n + 1
            [void]$ExistingKeys.Add($hash + '#' + $n)
        } elseif ($nodeType -eq $comment -or $nodeType -eq $pi) {
            $Writer.WriteNode($Reader, $false)
        } else {
            [void]$Reader.Read()
        }
    }
    return @{ Existing = $existing; Streamed = $streamed }
}

function Write-NewRecords {
    # Appends the new records whose key is not already present, then the count element when the layout
    # has one. Returns the number of records appended.
    param($Writer, $NewRecords, $ExistingKeys, [string]$ContainerNs, [int]$ExistingCount, [hashtable]$Profile, [string]$ContainerName)
    $count = 0
    foreach ($record in $NewRecords) {
        if ($ExistingKeys.Contains($record.Key)) { continue }
        [void]$ExistingKeys.Add($record.Key)
        $record.Element.WriteTo($Writer)
        $count++
    }
    if ($ContainerName -and $Profile.CountElement) {
        $Writer.WriteElementString($Profile.CountElement, $ContainerNs, [string]($ExistingCount + $count))
    }
    return $count
}

function Update-DailyFile {
    <#
        Rewrites the daily file into a temp file. Layout for the audit profile:

            <PIAudit xmlns=...>                      root, namespace declarations from the first export
              <PIServer .../>                        HeaderElements, copied once from the first export
              <AuditRecords>                         container, no per-export attributes
                ...records...                        existing records streamed, new ones appended
                <RecordsExported>N</RecordsExported> CountElement, rewritten as the file's record count
              </AuditRecords>
            </PIAudit>

        With an empty ContainerName the records sit directly under the root and no count is written.
        Existing records are streamed through and their keys collected; new records whose key is not
        present are appended. The temp file is validated by a full read and swapped into place.
        Returns the number of records appended.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][System.Xml.XmlElement]$RootTemplate,
        [Parameter(Mandatory = $true)][System.Collections.Generic.List[object]]$NewRecords,
        [Parameter(Mandatory = $true)][hashtable]$Profile,
        [string]$ContainerName,
        [string]$TimeSelector
    )
    $tempPath = $Path + '.tmp'
    if (Test-Path -LiteralPath $tempPath) { Remove-Item -LiteralPath $tempPath -Force }
    $fileWatch = [System.Diagnostics.Stopwatch]::StartNew()

    $existingKeys  = New-Object 'System.Collections.Generic.HashSet[string]'
    $keyCounter    = @{}
    $existingCount = 0
    $appended      = 0
    $fastCopied    = 0
    $countElement  = $Profile.CountElement

    # An existing record whose timestamp is earlier than every new record cannot be a duplicate of any
    # of them (equal content implies equal timestamp), so it is streamed through without being parsed.
    # This keeps the per-run cost proportional to the query window, not to the size of the day.
    $minNewTime = [datetime]::MaxValue
    foreach ($r in $NewRecords) { if ($r.Time -lt $minNewTime) { $minNewTime = $r.Time } }
    $timeRegex = Get-TimeRegex -Selector $TimeSelector
    $parserContext = $null

    $containerTemplate = $null
    if ($ContainerName) { $containerTemplate = Get-ChildElementByLocalName -Parent $RootTemplate -LocalName $ContainerName }
    $containerNs = if ($containerTemplate) { $containerTemplate.NamespaceURI } else { $RootTemplate.NamespaceURI }

    $writerSettings = New-Object System.Xml.XmlWriterSettings
    $writerSettings.Indent = $true
    $writerSettings.Encoding = $script:Utf8NoBom
    $writerSettings.CloseOutput = $true

    $writer = [System.Xml.XmlWriter]::Create($tempPath, $writerSettings)
    try {
        $writer.WriteStartDocument()
        if (Test-Path -LiteralPath $Path) {
            $reader = [System.Xml.XmlReader]::Create($Path, (New-SafeReaderSettings))
            try {
                [void]$reader.MoveToContent()
                if ($reader.NodeType -ne [System.Xml.XmlNodeType]::Element) { throw "Daily file $Path has no root element" }
                if ($reader.LocalName -ne $RootTemplate.LocalName) {
                    $msg = ('Root element mismatch in {0}: file has <{1}>, export has <{2}>' -f $Path, $reader.LocalName, $RootTemplate.LocalName)
                    if ($StrictRootElement) { throw $msg } else { Write-Log -Level WARN -Message $msg }
                }
                # namespaces in scope on the root, so existing record fragments can be parsed standalone
                $nsManager = New-Object System.Xml.XmlNamespaceManager($reader.NameTable)
                if ($reader.MoveToFirstAttribute()) {
                    do {
                        if ($reader.NamespaceURI -eq $script:XmlNsUri) {
                            $prefix = if ($reader.Prefix -eq 'xmlns') { $reader.LocalName } else { '' }
                            $nsManager.AddNamespace($prefix, $reader.Value)
                        }
                    } while ($reader.MoveToNextAttribute())
                    [void]$reader.MoveToElement()
                }
                $parserContext = New-Object System.Xml.XmlParserContext($null, $nsManager, $null, [System.Xml.XmlSpace]::None)
                $inScopeDeclarations = Get-InScopeDeclarations -NsManager $nsManager
                $writer.WriteStartElement($reader.Prefix, $reader.LocalName, $reader.NamespaceURI)
                $writer.WriteAttributes($reader, $true)
                $containerSeen = $false
                if ($reader.IsEmptyElement) {
                    [void]$reader.Read()
                } else {
                    [void]$reader.Read()
                    while (-not $reader.EOF -and $reader.NodeType -ne [System.Xml.XmlNodeType]::EndElement) {
                        if ($reader.NodeType -eq [System.Xml.XmlNodeType]::Element) {
                            if ($ContainerName -and $reader.LocalName -eq $ContainerName) {
                                # the records live here: stream existing, skip the old count, append new, write the count
                                $containerSeen = $true
                                $writer.WriteStartElement($reader.Prefix, $reader.LocalName, $reader.NamespaceURI)
                                $writer.WriteAttributes($reader, $true)
                                if ($reader.IsEmptyElement) {
                                    [void]$reader.Read()
                                } else {
                                    [void]$reader.Read()
                                    $copied = Copy-ExistingRecords -Reader $reader -Writer $writer -ExistingKeys $existingKeys -KeyCounter $keyCounter -TimeRegex $timeRegex -MinNewTime $minNewTime -ParserContext $parserContext -InScopeDeclarations $inScopeDeclarations -CountElement $countElement
                                    $existingCount += $copied.Existing
                                    $fastCopied += $copied.Streamed
                                    [void]$reader.Read()   # past the container end
                                }
                                $appended = Write-NewRecords -Writer $writer -NewRecords $NewRecords -ExistingKeys $existingKeys -ContainerNs $containerNs -ExistingCount $existingCount -Profile $Profile -ContainerName $ContainerName
                                $writer.WriteEndElement()
                            } elseif (-not $ContainerName) {
                                # flat layout: records are root children; this consumes them all up to the root end
                                $copied = Copy-ExistingRecords -Reader $reader -Writer $writer -ExistingKeys $existingKeys -KeyCounter $keyCounter -TimeRegex $timeRegex -MinNewTime $minNewTime -ParserContext $parserContext -InScopeDeclarations $inScopeDeclarations -CountElement ''
                                $existingCount += $copied.Existing
                                $fastCopied += $copied.Streamed
                            } else {
                                # header or other root child: pass through untouched
                                $writer.WriteNode($reader, $false)
                            }
                        } elseif ($reader.NodeType -eq [System.Xml.XmlNodeType]::Comment -or $reader.NodeType -eq [System.Xml.XmlNodeType]::ProcessingInstruction) {
                            $writer.WriteNode($reader, $false)
                        } else {
                            [void]$reader.Read()
                        }
                    }
                }
                if ($ContainerName -and -not $containerSeen) {
                    $writer.WriteStartElement('', $ContainerName, $containerNs)
                    $appended = Write-NewRecords -Writer $writer -NewRecords $NewRecords -ExistingKeys $existingKeys -ContainerNs $containerNs -ExistingCount $existingCount -Profile $Profile -ContainerName $ContainerName
                    $writer.WriteEndElement()
                } elseif (-not $ContainerName) {
                    $appended = Write-NewRecords -Writer $writer -NewRecords $NewRecords -ExistingKeys $existingKeys -ContainerNs $containerNs -ExistingCount $existingCount -Profile $Profile -ContainerName $ContainerName
                }
            } finally {
                $reader.Close()
            }
        } else {
            $writer.WriteStartElement($RootTemplate.Prefix, $RootTemplate.LocalName, $RootTemplate.NamespaceURI)
            foreach ($attr in $RootTemplate.Attributes) {
                # the default namespace is already declared by WriteStartElement; prefixed ones (xsi etc.) are copied
                if ($attr.NamespaceURI -eq $script:XmlNsUri -and $attr.Prefix -eq '' -and $attr.Value -eq $RootTemplate.NamespaceURI) { continue }
                $writer.WriteAttributeString($attr.Prefix, $attr.LocalName, $attr.NamespaceURI, $attr.Value)
            }
            foreach ($name in $Profile.HeaderElements) {
                $h = Get-ChildElementByLocalName -Parent $RootTemplate -LocalName $name
                if ($null -ne $h) {
                    $copy = $h.CloneNode($true)
                    Remove-NamespaceDeclarations -Element $copy
                    $copy.WriteTo($writer)
                }
            }
            if ($ContainerName) {
                $writer.WriteStartElement('', $ContainerName, $containerNs)
                $appended = Write-NewRecords -Writer $writer -NewRecords $NewRecords -ExistingKeys $existingKeys -ContainerNs $containerNs -ExistingCount 0 -Profile $Profile -ContainerName $ContainerName
                $writer.WriteEndElement()
            } else {
                $appended = Write-NewRecords -Writer $writer -NewRecords $NewRecords -ExistingKeys $existingKeys -ContainerNs $containerNs -ExistingCount 0 -Profile $Profile -ContainerName $ContainerName
            }
        }
        $writer.WriteEndElement()
        $writer.WriteEndDocument()
    } finally {
        $writer.Close()
    }

    # Validate the temp file by reading it fully and counting records
    $verifyCount = 0
    $verifyReader = [System.Xml.XmlReader]::Create($tempPath, (New-SafeReaderSettings))
    try {
        [void]$verifyReader.MoveToContent()
        $inContainer = (-not $ContainerName)
        $recordDepth = if ($ContainerName) { 2 } else { 1 }
        while ($verifyReader.Read()) {
            if ($verifyReader.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
            if ($ContainerName -and $verifyReader.Depth -eq 1) { $inContainer = ($verifyReader.LocalName -eq $ContainerName); continue }
            if ($inContainer -and $verifyReader.Depth -eq $recordDepth) {
                if ($countElement -and $verifyReader.LocalName -eq $countElement) { continue }
                $verifyCount++
            }
        }
    } finally { $verifyReader.Close() }
    if ($verifyCount -ne ($existingCount + $appended)) {
        throw ('Validation of {0} failed: expected {1} records, read {2}' -f $tempPath, ($existingCount + $appended), $verifyCount)
    }
    Write-Log -Level DEBUG -Message ('{0}: {1} existing records ({2} streamed, {3} compared), {4} appended, {5:0.0}s' -f (Split-Path -Leaf $Path), $existingCount, $fastCopied, ($existingCount - $fastCopied), $appended, $fileWatch.Elapsed.TotalSeconds)

    if ($appended -eq 0) {
        Remove-Item -LiteralPath $tempPath -Force
        return 0
    }

    if (Test-Path -LiteralPath $Path) {
        $replaced = $false
        try {
            [System.IO.File]::Replace($tempPath, $Path, $null)
            $replaced = $true
        } catch {
            Write-Log -Level DEBUG -Message ('File.Replace unavailable ({0}); falling back to Move' -f $_.Exception.Message)
        }
        if (-not $replaced) { Move-Item -LiteralPath $tempPath -Destination $Path -Force }
    } else {
        Move-Item -LiteralPath $tempPath -Destination $Path -Force
    }
    return $appended
}

function Remove-ExpiredExports {
    # Optional rolling window over the daily files, by the date in the file name. Off unless -ExportRetentionDays is set.
    param([array]$Profiles)
    if ($ExportRetentionDays -le 0) { return }
    $cutoff = (Get-Date).Date.AddDays(-$ExportRetentionDays)
    $prefixes = @($Profiles | ForEach-Object { $_.Prefix } | Sort-Object -Unique)
    if ($OutputFormat -eq 'Csv') { $prefixes = @($script:CsvFiles.Values | ForEach-Object { $_.Prefix } | Sort-Object -Unique) }
    foreach ($prefix in $prefixes) {
        $filter = if ($OutputFormat -eq 'Csv') { '{0}_*.csv' -f $prefix } else { '{0}_*.xml' -f $prefix }
        foreach ($f in (Get-ChildItem -LiteralPath $ExportDirectory -Filter $filter -File)) {
            if ($f.BaseName -match '_(\d{4}-\d{2}-\d{2})(_\d+(_recovered)?)?$') {
                $day = [datetime]::MinValue
                if ([datetime]::TryParseExact($Matches[1], 'yyyy-MM-dd', $script:Invariant, [System.Globalization.DateTimeStyles]::None, [ref]$day) -and $day -lt $cutoff) {
                    Remove-Item -LiteralPath $f.FullName -Force
                    Write-Log -Message ('retention: deleted {0} (older than {1} days)' -f $f.Name, $ExportRetentionDays)
                }
            }
        }
    }
}

# ---------------------------------------------------------------------------------------------------
# CSV output: one file per run, fixed header, records flattened to columns
# ---------------------------------------------------------------------------------------------------

# The header is identical in every file. Every column a record of either log type can populate is here.
$script:CsvColumns = @(
    'LogType', 'Server', 'ServerAddress', 'Collective', 'Timestamp', 'TimestampUtc', 'UTCSeconds', 'Source',
    'AuditRecordID', 'UserID', 'UserName', 'Database', 'Table', 'Action', 'ObjectID', 'ObjectName',
    'EventTimestamp', 'ValueBefore', 'ValueAfter', 'ValueType', 'ChangeCount', 'Changes',
    'MessageID', 'Severity', 'ProcessName', 'ProcessHost', 'ProcessOSUser', 'ProcessPIUser', 'PID', 'Priority',
    'Category', 'Source1', 'Source2', 'Source3', 'OriginatingHost', 'OriginatingPIUser', 'OriginatingOSUser', 'Message',
    'ExportRun', 'Extra'
)
# Names of fields that landed in Extra this run, so each is warned about once
$script:CsvExtraWarned = New-Object 'System.Collections.Generic.HashSet[string]'

function Add-CsvExtra {
    # Anything a record carries that no column is defined for goes here as name=value, and the run log
    # says so once per field name, so a new field in a future PI build is never lost and gets noticed.
    param([hashtable]$Row, [string]$Name, [string]$Value, [string]$LogType)
    if ($Row.ContainsKey('Extra') -and $Row.Extra) { $Row.Extra += ' | ' } elseif (-not $Row.ContainsKey('Extra')) { $Row.Extra = '' }
    $Row.Extra += ('{0}={1}' -f $Name, $Value)
    if ($script:CsvExtraWarned.Add($LogType + ':' + $Name)) {
        Write-Log -Level WARN -Message ('csv: {0} record carries a field with no column of its own, "{1}"; it is written to the Extra column. Consider a column for it in the next version.' -f $LogType, $Name)
    }
}
# One run file per log type: $script:CsvFiles[<Type>] = @{ Prefix; Out; Rows; TempPath; FinalPath; RunId }
$script:CsvFiles = @{}
$script:MessageCollective = $null

function ConvertTo-CsvField {
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { if ($CsvQuoteAll) { return '""' } else { return '' } }
    $v = $Value
    if ($v.IndexOf("`r") -ge 0 -or $v.IndexOf("`n") -ge 0) { $v = $v.Replace("`r`n", '\n').Replace("`r", '\n').Replace("`n", '\n') }
    if ($CsvMaxFieldLength -gt 0 -and $v.Length -gt $CsvMaxFieldLength) { $v = $v.Substring(0, $CsvMaxFieldLength) + '...[truncated]' }
    if ($CsvQuoteAll -or $v.IndexOf($CsvDelimiter) -ge 0 -or $v.IndexOf('"') -ge 0 -or $v.StartsWith(' ') -or $v.EndsWith(' ')) {
        return '"' + $v.Replace('"', '""') + '"'
    }
    return $v
}

function ConvertTo-CsvLine {
    # Same escaping as ConvertTo-CsvField, inlined: 31 function calls per row is too slow for a message
    # log on PowerShell 5.1.
    param([hashtable]$Row)
    $sb = New-Object System.Text.StringBuilder
    $first = $true
    $quoteAll = [bool]$CsvQuoteAll
    $maxLen = $CsvMaxFieldLength
    $delim = $CsvDelimiter
    foreach ($c in $script:CsvColumns) {
        if ($first) { $first = $false } else { [void]$sb.Append($delim) }
        $v = $null
        if ($Row.ContainsKey($c)) { $v = [string]$Row[$c] }
        if ([string]::IsNullOrEmpty($v)) { if ($quoteAll) { [void]$sb.Append('""') }; continue }
        if ($v.IndexOf("`r") -ge 0 -or $v.IndexOf("`n") -ge 0) { $v = $v.Replace("`r`n", '\n').Replace("`r", '\n').Replace("`n", '\n') }
        if ($maxLen -gt 0 -and $v.Length -gt $maxLen) { $v = $v.Substring(0, $maxLen) + '...[truncated]' }
        if ($quoteAll -or $v.IndexOf($delim) -ge 0 -or $v.IndexOf('"') -ge 0 -or $v[0] -eq ' ' -or $v[$v.Length - 1] -eq ' ') {
            [void]$sb.Append('"').Append($v.Replace('"', '""')).Append('"')
        } else {
            [void]$sb.Append($v)
        }
    }
    return $sb.ToString()
}

function Get-ChangeValueText {
    # Text of a Before or After element; digital states and other attribute-only values render their attributes.
    param([System.Xml.XmlElement]$Element)
    if ($null -eq $Element) { return $null }
    $t = $Element.InnerText
    if ([string]::IsNullOrEmpty($t) -and $Element.HasAttributes) {
        $pairs = @()
        foreach ($a in $Element.Attributes) { if ($a.LocalName -ne 'Type') { $pairs += ('{0}={1}' -f $a.LocalName, $a.Value) } }
        if ($pairs.Count -gt 0) { return ($pairs -join ' ') }
    }
    return $t
}

function ConvertTo-AuditCsvRow {
    # Flattens one AuditRecord (section 4.11 shape) into the fixed columns. The object is found generically
    # (first element carrying an ID attribute) and every Before/After pair anywhere in the record goes into
    # Changes, so other audited databases (users, trusts, identities, digital sets) flatten the same way.
    param([System.Xml.XmlElement]$Record, [datetime]$Time, [hashtable]$Source, [string]$ServerHost, [string]$ServerAddress)
    $row = @{ LogType = 'Audit'; Server = $ServerHost; ServerAddress = $ServerAddress; Source = $Source.Name; ExportRun = $script:CsvFiles['Audit'].RunId }
    $row.AuditRecordID = $Record.GetAttribute('AuditRecordID')
    # Coverage accounting: elements whose content the columns represent, and per element the attributes
    # consumed. Whatever is left at the end goes to Extra.
    $coveredElements = New-Object 'System.Collections.Generic.HashSet[object]'
    $consumedAttrs = @{}
    $consume = { param($el, [string[]]$attrs) [void]$coveredElements.Add($el); $consumedAttrs[$el] = $attrs }
    & $consume $Record @('AuditRecordID')
    $utc = $null
    $database = $null
    foreach ($child in $Record.ChildNodes) {
        if ($child -isnot [System.Xml.XmlElement]) { continue }
        switch ($child.LocalName) {
            'PIUser' { $row.UserID = $child.GetAttribute('UserID'); $row.UserName = $child.GetAttribute('Name'); & $consume $child @('UserID', 'Name') }
            'PITime' { $row.Timestamp = $child.GetAttribute('LocalDate'); $utc = $child.GetAttribute('UTCSeconds'); & $consume $child @('LocalDate', 'UTCSeconds') }
            default  { if ($null -eq $database) { $database = $child } }
        }
    }
    if (-not $row.ContainsKey('Timestamp') -or -not $row.Timestamp) { $row.Timestamp = $Time.ToString('yyyy-MM-ddTHH:mm:sszzz', $script:Invariant) }
    if ($utc) { $row.UTCSeconds = $utc; $row.TimestampUtc = $script:EpochBase.AddSeconds([double]::Parse($utc, $script:Invariant)).ToString('yyyy-MM-ddTHH:mm:ssZ', $script:Invariant) }
    else { $row.UTCSeconds = [string][int64][math]::Floor(($Time.ToUniversalTime() - $script:EpochBase).TotalSeconds); $row.TimestampUtc = $Time.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', $script:Invariant) }

    if ($null -ne $database) {
        $row.Database = $database.LocalName
        & $consume $database @()
        $table = $null
        foreach ($c in $database.ChildNodes) { if ($c -is [System.Xml.XmlElement]) { $table = $c; break } }
        if ($null -ne $table) {
            $row.Table = $table.LocalName
            $action = $table.GetAttribute('Action')
            & $consume $table @('Action')
            $obj = $null
            foreach ($c in $table.ChildNodes) { if ($c -is [System.Xml.XmlElement]) { $obj = $c; break } }
            if ($null -ne $obj) {
                $objAttrs = @()
                if (-not $action) { $action = $obj.GetAttribute('Action'); $objAttrs += 'Action' }
                # the object is the first element carrying an ID attribute (PIPoint PointID=, PIUser UserID=, ...)
                $idHolder = $null
                $idAttr = $null
                foreach ($e in @($obj) + @($obj.SelectNodes('.//*') | ForEach-Object { $_ })) {
                    foreach ($a in $e.Attributes) { if ($a.LocalName -match 'ID$' -and $a.LocalName -ne 'AuditRecordID') { $idHolder = $e; $idAttr = $a.LocalName; $row.ObjectID = $a.Value; break } }
                    if ($null -ne $idHolder) { break }
                }
                if ($null -ne $idHolder) { $row.ObjectName = $idHolder.GetAttribute('Name'); & $consume $idHolder @($idAttr, 'Name') }
                if (-not $row.ContainsKey('ObjectName') -or -not $row.ObjectName) { $n = $obj.GetAttribute('Name'); if ($n) { $row.ObjectName = $n; $objAttrs += 'Name' } }
                if (-not $coveredElements.Contains($obj)) { & $consume $obj $objAttrs } elseif ($objAttrs.Count -gt 0) { $consumedAttrs[$obj] = @($consumedAttrs[$obj]) + $objAttrs }
            }
            $row.Action = $action
        }
        $evt = $database.SelectSingleNode(".//*[local-name()='TimeStamp']")
        if ($null -ne $evt) { $row.EventTimestamp = $evt.GetAttribute('LocalDate'); & $consume $evt @('LocalDate', 'UTCSeconds') }

        # Before/After pairs anywhere below the database element
        $changes = New-Object System.Collections.Generic.List[string]
        $primaryBefore = $null; $primaryAfter = $null; $primaryType = $null; $havePrimary = $false
        foreach ($holder in $database.SelectNodes(".//*[*[local-name()='Before'] or *[local-name()='After']]")) {
            $before = $null; $after = $null
            foreach ($c in $holder.ChildNodes) {
                if ($c -isnot [System.Xml.XmlElement]) { continue }
                if ($c.LocalName -eq 'Before') { $before = $c; & $consume $c @('*') } elseif ($c.LocalName -eq 'After') { $after = $c; & $consume $c @('*') }
            }
            & $consume $holder @('Name')
            if ($holder.ParentNode -is [System.Xml.XmlElement] -and $holder.ParentNode.HasAttribute('Name') -and -not $coveredElements.Contains($holder.ParentNode)) { & $consume $holder.ParentNode @('Name') }
            $label = $holder.LocalName
            $named = $holder.GetAttribute('Name')
            if ($named) { $label = $named }
            elseif ($holder.LocalName -eq 'Value' -and $holder.ParentNode -is [System.Xml.XmlElement] -and $holder.ParentNode.GetAttribute('Name')) { $label = $holder.ParentNode.GetAttribute('Name') }
            $bText = Get-ChangeValueText -Element $before
            $aText = Get-ChangeValueText -Element $after
            $changes.Add(('{0}: {1} -> {2}' -f $label, $bText, $aText))
            $isPrimary = ($holder.LocalName -eq 'Value' -and -not $named -and $label -eq 'Value')
            if ($isPrimary -or (-not $havePrimary -and $changes.Count -eq 1)) {
                $primaryBefore = $bText; $primaryAfter = $aText
                $typeEl = if ($null -ne $after) { $after } else { $before }
                $primaryType = if ($null -ne $typeEl) { $typeEl.GetAttribute('Type') } else { $null }
                $havePrimary = $isPrimary
            }
        }
        $row.ChangeCount = [string]$changes.Count
        if ($changes.Count -gt 0) { $row.Changes = ($changes -join ' | ') }
        if ($changes.Count -eq 1 -or $havePrimary) { $row.ValueBefore = $primaryBefore; $row.ValueAfter = $primaryAfter; $row.ValueType = $primaryType }
    }

    # Sweep: any attribute not consumed on a covered element, and any uncovered element that carries
    # text or attributes of its own (pure containers are structure, not data), goes to Extra.
    foreach ($e in @($Record) + @($Record.SelectNodes('.//*') | ForEach-Object { $_ })) {
        $path = $e.LocalName
        if ($e -ne $Record -and $e.ParentNode -ne $Record -and $e.ParentNode -is [System.Xml.XmlElement]) { $path = $e.ParentNode.LocalName + '/' + $e.LocalName }
        if ($coveredElements.Contains($e)) {
            $known = $consumedAttrs[$e]
            if ($known -contains '*') { continue }
            foreach ($a in $e.Attributes) {
                if ($a.NamespaceURI -eq $script:XmlNsUri -or $known -contains $a.LocalName) { continue }
                Add-CsvExtra -Row $row -Name ($path + '.@' + $a.LocalName) -Value $a.Value -LogType 'Audit'
            }
            continue
        }
        $ownText = ''
        foreach ($c in $e.ChildNodes) { if ($c -is [System.Xml.XmlText] -or $c -is [System.Xml.XmlCDataSection]) { $ownText += $c.Value } }
        $ownText = $ownText.Trim()
        $hasData = ($ownText.Length -gt 0)
        foreach ($a in $e.Attributes) { if ($a.NamespaceURI -ne $script:XmlNsUri) { $hasData = $true } }
        if (-not $hasData) { continue }
        $parts = @()
        foreach ($a in $e.Attributes) { if ($a.NamespaceURI -ne $script:XmlNsUri) { $parts += ('@{0}={1}' -f $a.LocalName, $a.Value) } }
        if ($ownText) { $parts += $ownText }
        Add-CsvExtra -Row $row -Name $path -Value ($parts -join ' ') -LogType 'Audit'
    }
    return $row
}

function ConvertTo-MessageCsvRow {
    param([System.Xml.XmlElement]$Record, [datetime]$Time, [hashtable]$Source, [string]$ServerHost, [string]$ServerAddress)
    $row = @{ LogType = 'MessageLog'; Server = $ServerHost; ServerAddress = $ServerAddress; Collective = $script:MessageCollective; Source = $Source.Name; ExportRun = $script:CsvFiles['MessageLog'].RunId }
    $row.Timestamp    = $Time.ToString('yyyy-MM-ddTHH:mm:sszzz', $script:Invariant)
    $row.TimestampUtc = $Time.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', $script:Invariant)
    $row.UTCSeconds   = [string][int64][math]::Floor(($Time.ToUniversalTime() - $script:EpochBase).TotalSeconds)
    foreach ($child in $Record.ChildNodes) {
        if ($child -isnot [System.Xml.XmlElement]) { continue }
        switch ($child.LocalName) {
            'MessageID'       { $row.MessageID = $child.InnerText }
            'MessageSeverity' { $row.Severity = $child.InnerText }
            'ProcessName'     { $row.ProcessName = $child.InnerText }
            'ProcessHost'     { $row.ProcessHost = $child.InnerText }
            'User'            { $row.UserName = $child.InnerText }
            'ProcessOSUser'   { $row.ProcessOSUser = $child.InnerText }
            'ProcessPIUser'   { $row.ProcessPIUser = $child.InnerText }
            'PID'             { $row.PID = $child.InnerText }
            'Priority'        { $row.Priority = $child.InnerText }
            'Category'        { $row.Category = $child.InnerText }
            'Source1'         { $row.Source1 = $child.InnerText }
            'Source2'         { $row.Source2 = $child.InnerText }
            'Source3'         { $row.Source3 = $child.InnerText }
            'OriginatingHost'   { $row.OriginatingHost = $child.InnerText }
            'OriginatingPIUser' { $row.OriginatingPIUser = $child.InnerText }
            'OriginatingOSUser' { $row.OriginatingOSUser = $child.InnerText }
            'Message'         { $row.Message = $child.InnerText }
            'MessageTime'     { }
            default           { Add-CsvExtra -Row $row -Name $child.LocalName -Value $child.InnerText -LogType 'MessageLog' }
        }
    }
    foreach ($a in $Record.Attributes) { if ($a.NamespaceURI -ne $script:XmlNsUri) { Add-CsvExtra -Row $row -Name ('@' + $a.LocalName) -Value $a.Value -LogType 'MessageLog' } }
    return $row
}

function Open-CsvRunFile {
    # For one log type. PerDay: opens (or creates with the header) today's file for appending.
    # PerRun: recovers any temp file a crashed run left behind, allocates the next serial for today,
    # opens the run file under a temporary name and writes the header.
    param([string]$Type, [string]$Prefix)
    $header = (($script:CsvColumns | ForEach-Object { ConvertTo-CsvField -Value $_ }) -join $CsvDelimiter)
    if ($CsvFileMode -eq 'PerDay') {
        $date = $script:RunStamp.ToString('yyyy-MM-dd')
        $finalPath = Join-Path $ExportDirectory ('{0}_{1}.csv' -f $Prefix, $date)
        $exists = Test-Path -LiteralPath $finalPath
        if ($exists) {
            $firstLine = $null
            $probe = New-Object System.IO.StreamReader($finalPath, $script:Utf8NoBom)
            try { $firstLine = $probe.ReadLine() } finally { $probe.Close() }
            if ($null -ne $firstLine -and $firstLine -ne $header) {
                throw ('{0} exists with a different header than this version writes; move it aside (or start on a new day) before appending' -f (Split-Path -Leaf $finalPath))
            }
            if ($null -eq $firstLine) { $exists = $false }
        }
        $out = New-Object System.IO.StreamWriter($finalPath, $exists, $script:Utf8NoBom)
        $out.NewLine = "`r`n"
        if (-not $exists) { $out.WriteLine($header); $out.Flush() }
        $script:CsvFiles[$Type] = @{ Prefix = $Prefix; Out = $out; Rows = 0; TempPath = $null; FinalPath = $finalPath; RunId = $script:RunStamp.ToString('yyyy-MM-dd_HHmmss') }
        Write-Log -Message ('csv: {0} day file {1} ({2})' -f $Type, (Split-Path -Leaf $finalPath), $(if ($exists) { 'appending' } else { 'created' }))
        return
    }
    foreach ($orphan in (Get-ChildItem -LiteralPath $ExportDirectory -Filter ('{0}_*.csv.tmp' -f $Prefix) -File)) {
        $final = $orphan.FullName.Substring(0, $orphan.FullName.Length - 4)
        if (Test-Path -LiteralPath $final) { $final = $final -replace '\.csv$', '_recovered.csv' }
        Move-Item -LiteralPath $orphan.FullName -Destination $final -Force
        Write-Log -Level WARN -Message ('csv: recovered an unfinished file from an earlier run as {0}; its records were committed, so it is complete up to where that run stopped' -f (Split-Path -Leaf $final))
    }
    $date = $script:RunStamp.ToString('yyyy-MM-dd')
    $serial = 0
    $pattern = '^' + [regex]::Escape($Prefix + '_' + $date + '_') + '(\d+)(_recovered)?\.csv(\.tmp)?$'
    foreach ($f in (Get-ChildItem -LiteralPath $ExportDirectory -Filter ('{0}_{1}_*' -f $Prefix, $date) -File)) {
        if ($f.Name -match $pattern) { $n = [int]$Matches[1]; if ($n -gt $serial) { $serial = $n } }
    }
    $statePath = Join-Path $StateDirectory ('csvserial_{0}.json' -f $Prefix.ToLowerInvariant())
    if (Test-Path -LiteralPath $statePath) {
        try {
            $st = Get-Content -LiteralPath $statePath -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($st.Date -eq $date -and [int]$st.Serial -gt $serial) { $serial = [int]$st.Serial }
        } catch { }
    }
    $serial++
    [System.IO.File]::WriteAllText($statePath + '.tmp', ([ordered]@{ Date = $date; Serial = $serial } | ConvertTo-Json), $script:Utf8NoBom)
    Move-Item -LiteralPath ($statePath + '.tmp') -Destination $statePath -Force

    $runId = '{0}_{1}' -f $date, $serial.ToString('D' + $CsvSerialDigits)
    $finalPath = Join-Path $ExportDirectory ('{0}_{1}.csv' -f $Prefix, $runId)
    $tempPath = $finalPath + '.tmp'
    $out = New-Object System.IO.StreamWriter($tempPath, $false, $script:Utf8NoBom)
    $out.NewLine = "`r`n"
    $out.WriteLine($header)
    $out.Flush()
    $script:CsvFiles[$Type] = @{ Prefix = $Prefix; Out = $out; Rows = 0; TempPath = $tempPath; FinalPath = $finalPath; RunId = $runId }
    Write-Log -Message ('csv: {0} run file {1}' -f $Type, (Split-Path -Leaf $finalPath))
}

function Close-CsvRunFiles {
    foreach ($type in @($script:CsvFiles.Keys)) {
        $f = $script:CsvFiles[$type]
        if ($null -eq $f.Out) { continue }
        $f.Out.Flush()
        $f.Out.Close()
        $f.Out = $null
        if ($null -eq $f.TempPath) {
            Write-Log -Message ('csv: {0}: {1} records appended' -f (Split-Path -Leaf $f.FinalPath), $f.Rows)
            continue
        }
        if ($f.Rows -eq 0 -and $SkipEmptyCsv) {
            Remove-Item -LiteralPath $f.TempPath -Force
            Write-Log -Message ('csv: {0}: no new records, no file written (-SkipEmptyCsv)' -f $type)
            continue
        }
        Move-Item -LiteralPath $f.TempPath -Destination $f.FinalPath -Force
        Write-Log -Message ('csv: {0} written with {1} records' -f (Split-Path -Leaf $f.FinalPath), $f.Rows)
    }
}

function Get-RecentKeysPath { param([string]$Source) return Join-Path $StateDirectory ('recentkeys_{0}.json' -f $Source.ToLowerInvariant()) }

function Read-RecentKeys {
    # Keys (hash#occurrence) of records emitted around the last checkpoint, with their times. Used only in
    # Csv mode, where there is no daily file to compare against.
    param([string]$Source)
    $dict = @{}
    $path = Get-RecentKeysPath -Source $Source
    if (-not (Test-Path -LiteralPath $path)) { return $dict }
    try {
        $json = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($e in @($json.Keys)) { $dict[[string]$e.K] = [int64]$e.T }
    } catch {
        Write-Log -Level WARN -Message ('{0}: recent keys file unreadable ({1}); the next overlap window may re-emit a few records' -f $Source, $_.Exception.Message)
    }
    return $dict
}

function Write-RecentKeys {
    param([string]$Source, [hashtable]$Keys, [datetime]$WindowEnd)
    # keep what could reappear in the next window (twice the overlap, for margin) and drop the rest
    $cutoff = $WindowEnd.AddMinutes(-2 * $OverlapMinutes).ToUniversalTime().Ticks
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($k in @($Keys.Keys)) {
        if ($Keys[$k] -ge $cutoff) { $list.Add([ordered]@{ K = $k; T = $Keys[$k] }) } else { $Keys.Remove($k) }
    }
    $path = Get-RecentKeysPath -Source $Source
    [System.IO.File]::WriteAllText($path + '.tmp', ([ordered]@{ Source = $Source; WindowEnd = ([datetimeoffset]$WindowEnd).ToString('o', $script:Invariant); Keys = $list.ToArray() } | ConvertTo-Json -Depth 4 -Compress), $script:Utf8NoBom)
    Move-Item -LiteralPath ($path + '.tmp') -Destination $path -Force
}

# ---------------------------------------------------------------------------------------------------
# Checkpoints (one per source)
# ---------------------------------------------------------------------------------------------------

function Get-CheckpointPath { param([string]$Subsystem) return Join-Path $StateDirectory ('checkpoint_{0}.json' -f $Subsystem.ToLowerInvariant()) }

function Read-Checkpoint {
    param([string]$Subsystem)
    $path = Get-CheckpointPath -Subsystem $Subsystem
    $cp = @{ LastExportedTo = $null; ProcessedRotated = @(); LastRunUtc = $null; LastResult = $null }
    if (-not (Test-Path -LiteralPath $path)) { return $cp }
    try {
        $json = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        throw ('Checkpoint {0} is unreadable: {1}. Move it aside to restart from InitialLookbackHours, or restore it.' -f $path, $_.Exception.Message)
    }
    if ($json.PSObject.Properties['LastExportedTo'] -and $json.LastExportedTo) {
        $cp.LastExportedTo = ([datetimeoffset]::Parse($json.LastExportedTo, $script:Invariant)).LocalDateTime
    }
    if ($json.PSObject.Properties['ProcessedRotated'] -and $json.ProcessedRotated) { $cp.ProcessedRotated = @($json.ProcessedRotated) }
    return $cp
}

function Write-Checkpoint {
    param([string]$Subsystem, [datetime]$LastExportedTo, [string[]]$ProcessedRotated, [string]$Result)
    $path = Get-CheckpointPath -Subsystem $Subsystem
    $obj = [ordered]@{
        Subsystem        = $Subsystem
        LastExportedTo   = ([datetimeoffset]$LastExportedTo).ToString('o', $script:Invariant)
        LastRunUtc       = (Get-Date).ToUniversalTime().ToString('o', $script:Invariant)
        LastResult       = $Result
        ProcessedRotated = @($ProcessedRotated)
    }
    $temp = $path + '.tmp'
    [System.IO.File]::WriteAllText($temp, ($obj | ConvertTo-Json -Depth 4), $script:Utf8NoBom)
    Move-Item -LiteralPath $temp -Destination $path -Force
}

function Get-FileIdentity {
    param([System.IO.FileInfo]$File)
    return ('{0}|{1}|{2}' -f $File.Name, $File.Length, $File.LastWriteTimeUtc.Ticks)
}

# ---------------------------------------------------------------------------------------------------
# Backup mode and audit file collection
# ---------------------------------------------------------------------------------------------------

function Test-PIToolError {
    # PI command line tools often exit 0 and report errors as "[code] message". Returns the code or $null.
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $m = [regex]::Match($Text, '\[(-?\d+)\]')
    if ($m.Success) {
        $code = [int]$m.Groups[1].Value
        if ($code -eq 0) { return $null }
        return $code
    }
    if ($Text -imatch '\b(error|failed|failure|cannot|unable)\b') { return -1 }
    return $null
}

function Invoke-Piartool {
    param([string]$Arguments)
    $r = Invoke-External -FilePath $PiartoolPath -Arguments $Arguments -TimeoutSeconds $PiartoolTimeoutSeconds
    $out = (ConvertTo-ConsoleText -Bytes $r.StdOutBytes).Trim()
    $err = $r.StdErr.Trim()
    $combined = (@($out, $err) | Where-Object { $_ }) -join ' | '
    $ok = (-not $r.TimedOut) -and ($r.ExitCode -eq 0) -and ($null -eq (Test-PIToolError -Text $combined))
    return New-Object PSObject -Property @{ Ok = $ok; Output = $combined; ExitCode = $r.ExitCode; TimedOut = $r.TimedOut }
}

function Enter-BackupMode {
    param([string]$Subsystem)
    $r = Invoke-Piartool -Arguments ('-systembackup start -subsystem {0}' -f $Subsystem)
    Write-Log -Level DEBUG -Message ('systembackup start {0}: exit {1}; {2}' -f $Subsystem, $r.ExitCode, $r.Output)
    return $r
}

function Exit-BackupMode {
    param([string]$Subsystem)
    $r = Invoke-Piartool -Arguments ('-systembackup end -subsystem {0}' -f $Subsystem)
    Write-Log -Level DEBUG -Message ('systembackup end {0}: exit {1}; {2}' -f $Subsystem, $r.ExitCode, $r.Output)
    return $r
}

function Get-AuditSourceFiles {
    # Returns @{ Live = FileInfo or $null; Rotated = FileInfo[] } for a subsystem
    param([string]$Subsystem, [string[]]$AlreadyProcessed)
    $liveName = '{0}Audit.dat' -f $Subsystem
    $livePath = Join-Path $AuditLogDirectory $liveName
    $live = $null
    if (Test-Path -LiteralPath $livePath) { $live = Get-Item -LiteralPath $livePath }

    $rotated = @()
    if ($IncludeRotated) {
        $filter = if ($RotatedFilter) { $RotatedFilter } else { '{0}Audit*.dat*' -f $Subsystem }
        $processed = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($p in $AlreadyProcessed) { [void]$processed.Add($p) }
        $rotated = @(Get-ChildItem -LiteralPath $AuditLogDirectory -Filter $filter -File |
            Where-Object { $_.Name -ne $liveName -and $_.Name -notlike '*.tmp' } |
            Where-Object { -not $processed.Contains((Get-FileIdentity -File $_)) } |
            Sort-Object LastWriteTimeUtc)
    }
    return @{ Live = $live; Rotated = $rotated }
}

function Copy-AuditFilesInBackupMode {
    <#
        Enters backup mode for the subsystem, copies the live and rotated files to the work directory,
        leaves backup mode in finally. Returns a hashtable with Copies (list of @{Source; Copy; Identity})
        and WindowEnd (time captured immediately before backup mode was entered).
        Throws with a BackupModeExitFailed property set when systembackup end fails.
    #>
    param([string]$Subsystem, [hashtable]$Sources, [string]$TargetDirectory)

    $copies = New-Object System.Collections.Generic.List[object]
    $windowEnd = Get-Date
    $entered = $false

    if (-not $SkipBackupMode) {
        $r = Enter-BackupMode -Subsystem $Subsystem
        if (-not $r.Ok) {
            $ex = New-Object System.Exception(('Could not enter backup mode for {0}: {1}' -f $Subsystem, $r.Output))
            $ex.Data['Deferred'] = $true
            throw $ex
        }
        $entered = $true
    }
    try {
        $all = @()
        if ($Sources.Live) { $all += $Sources.Live }
        $all += $Sources.Rotated
        foreach ($f in $all) {
            $dest = Join-Path $TargetDirectory $f.Name
            Copy-Item -LiteralPath $f.FullName -Destination $dest -Force
            $copies.Add(@{ Source = $f.FullName; Copy = $dest; Identity = (Get-FileIdentity -File $f); IsLive = ($Sources.Live -and $f.FullName -eq $Sources.Live.FullName) })
            Write-Log -Level DEBUG -Message ('copied {0} ({1} bytes) to {2}' -f $f.FullName, $f.Length, $dest)
        }
    } finally {
        if ($entered) {
            $r = Exit-BackupMode -Subsystem $Subsystem
            if (-not $r.Ok) {
                $ex = New-Object System.Exception(('CRITICAL: could not leave backup mode for {0}: {1}. Run "piartool -systembackup end -subsystem {0}" manually and check the PI message log.' -f $Subsystem, $r.Output))
                $ex.Data['BackupModeExitFailed'] = $true
                throw $ex
            }
        }
    }
    return @{ Copies = $copies; WindowEnd = $windowEnd }
}

# ---------------------------------------------------------------------------------------------------
# Extraction tools: pidiag (audit copy) and pigetmsg (message subsystem)
# ---------------------------------------------------------------------------------------------------

function Get-PidiagArguments {
    param([string]$FilePath, [datetime]$Start, [datetime]$End, [bool]$NoWindow = $false)
    $a = '-xa {0}' -f (Get-QuotedArgument $FilePath)
    if (-not $NoWindow) { $a += ' -st {0} -et {1}' -f (Get-QuotedArgument (Format-PITime $Start)), (Get-QuotedArgument (Format-PITime $End)) }
    if ($DbMask -gt 0) { $a += ' -dbMask {0}' -f $DbMask }
    return $a
}

function Get-PigetmsgArguments {
    param([datetime]$Start, [datetime]$End)
    $a = '-st {0} -et {1} -fx' -f (Get-QuotedArgument (Format-PITime $Start)), (Get-QuotedArgument (Format-PITime $End))
    if ($MessageLogAllFields) { $a += ' -oa' }
    switch ($MessageLogSeverity) {
        'Information' { $a += ' -si' }
        'Warning'     { $a += ' -sw' }
        'Error'       { $a += ' -se' }
        'Critical'    { $a += ' -sc' }
    }
    if (-not [string]::IsNullOrWhiteSpace($PigetmsgExtraArguments)) { $a += ' ' + $PigetmsgExtraArguments.Trim() }
    return $a
}

function ConvertTo-ExportResult {
    # Turns a tool run into @{ Status = 'Records'|'Empty'|'Failed'; Kind; Document; RecordCount; Encoding; Message }
    param([string]$ToolName, $Run, [hashtable]$Profile, [string]$Label)
    if ($Run.TimedOut) {
        return @{ Status = 'Failed'; Kind = 'tool'; Message = ('{0} timed out after {1}s on {2}' -f $ToolName, $ToolTimeoutSeconds, $Label) }
    }
    $stderr = $Run.StdErr.Trim()
    if ($stderr) { Write-Log -Level DEBUG -Message ($ToolName + ' stderr: ' + $stderr) }

    try {
        $parsed = ConvertTo-XmlDocumentFromBytes -Bytes $Run.StdOutBytes
    } catch {
        return @{ Status = 'Failed'; Kind = 'xml'; Message = ('{0} output for {1} could not be parsed: {2}' -f $ToolName, $Label, $_.Exception.Message) }
    }
    if ($parsed.Preamble) { Write-Log -Level DEBUG -Message ($ToolName + ' preamble: ' + $parsed.Preamble) }

    if ($parsed.IsEmpty) {
        $text = ($parsed.Preamble + ' ' + $stderr).Trim()
        $code = Test-PIToolError -Text $text
        if ($code -eq 38) {
            return @{ Status = 'Empty'; Message = ('{0} reported end of file (38): no records in source' -f $ToolName) }
        }
        if ($null -ne $code -or $Run.ExitCode -ne 0) {
            return @{ Status = 'Failed'; Kind = 'tool'; Message = ('{0} exit {1}: {2}' -f $ToolName, $Run.ExitCode, $text) }
        }
        return @{ Status = 'Empty'; Message = ('{0} produced no output' -f $ToolName) }
    }

    $records = Get-RecordElements -Document $parsed.Document -Profile $Profile
    return @{ Status = 'Records'; Document = $parsed.Document; RecordCount = $records.Count; Encoding = $parsed.Encoding; Message = ('{0} records' -f $records.Count) }
}

function Invoke-PidiagExport {
    param([string]$FilePath, [datetime]$Start, [datetime]$End, [hashtable]$Profile)
    $args = Get-PidiagArguments -FilePath $FilePath -Start $Start -End $End
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $r = Invoke-External -FilePath $PidiagPath -Arguments $args -TimeoutSeconds $ToolTimeoutSeconds -WorkingDirectory (Split-Path -Parent $PidiagPath)
    $toolSeconds = $sw.Elapsed.TotalSeconds
    $result = ConvertTo-ExportResult -ToolName 'pidiag' -Run $r -Profile $Profile -Label (Split-Path -Leaf $FilePath)
    Write-Log -Level DEBUG -Message ('pidiag: {0} bytes in {1:0.0}s, parsed in {2:0.0}s' -f $r.StdOutBytes.Length, $toolSeconds, ($sw.Elapsed.TotalSeconds - $toolSeconds))
    return $result
}

function Invoke-PigetmsgExport {
    param([datetime]$Start, [datetime]$End, [hashtable]$Profile)
    $args = Get-PigetmsgArguments -Start $Start -End $End
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $r = Invoke-External -FilePath $PigetmsgPath -Arguments $args -TimeoutSeconds $ToolTimeoutSeconds -WorkingDirectory (Split-Path -Parent $PigetmsgPath)
    $toolSeconds = $sw.Elapsed.TotalSeconds
    $result = ConvertTo-ExportResult -ToolName 'pigetmsg' -Run $r -Profile $Profile -Label 'message log'
    Write-Log -Level DEBUG -Message ('pigetmsg: {0} bytes in {1:0.0}s, parsed in {2:0.0}s' -f $r.StdOutBytes.Length, $toolSeconds, ($sw.Elapsed.TotalSeconds - $toolSeconds))
    return $result
}

# ---------------------------------------------------------------------------------------------------
# Source profiles: one per audit subsystem, one for the message log
# ---------------------------------------------------------------------------------------------------

function New-SourceProfiles {
    $list = @()
    if ($LogTypes -contains 'Audit') {
        foreach ($sub in $Subsystems) {
            $list += @{ Name = $sub; Type = 'Audit'; Tool = 'pidiag'; Prefix = $AuditFilePrefix
                        Container = $RecordContainer; CountElement = $CountElement; HeaderElements = @($HeaderElements); TimeSelector = $RecordTimeSelector }
        }
    }
    if ($LogTypes -contains 'MessageLog') {
        $list += @{ Name = 'messagelog'; Type = 'MessageLog'; Tool = 'pigetmsg'; Prefix = $MessageLogFilePrefix
                    Container = $MessageRecordContainer; CountElement = $MessageCountElement; HeaderElements = @($MessageHeaderElements); TimeSelector = $MessageTimeSelector }
    }
    return ,$list
}

# ---------------------------------------------------------------------------------------------------
# Export one source
# ---------------------------------------------------------------------------------------------------

function Export-Source {
    param([hashtable]$Source)

    $name = $Source.Name
    $status = New-Object PSObject -Property @{ Source = $name; Result = 'Success'; ExitCode = 0; Appended = 0; Seen = 0; Message = '' }
    $checkpoint = Read-Checkpoint -Subsystem $name

    # Acquire: audit files are copied under backup mode; the message log is queried live
    $targets = @()
    $sources = $null
    if ($Source.Type -eq 'Audit') {
        $work = Join-Path $WorkDirectory $name
        if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
        New-Item -ItemType Directory -Path $work -Force | Out-Null

        $sources = Get-AuditSourceFiles -Subsystem $name -AlreadyProcessed $checkpoint.ProcessedRotated
        if ($null -eq $sources.Live -and $sources.Rotated.Count -eq 0) {
            $status.Result = 'NoSource'
            $status.Message = ('no audit file {0}Audit.dat in {1} and no unprocessed rotated files; is auditing enabled for this subsystem?' -f $name, $AuditLogDirectory)
            Write-Log -Level WARN -Message ('{0}: {1}' -f $name, $status.Message)
            return $status
        }
        if ($sources.Live) { Write-Log -Message ('{0}: live file {1} ({2} bytes, modified {3:yyyy-MM-dd HH:mm:ss})' -f $name, $sources.Live.Name, $sources.Live.Length, $sources.Live.LastWriteTime) }
        foreach ($rf in $sources.Rotated) { Write-Log -Message ('{0}: unprocessed rotated file {1} ({2} bytes, modified {3:yyyy-MM-dd HH:mm:ss})' -f $name, $rf.Name, $rf.Length, $rf.LastWriteTime) }

        try {
            $copyResult = Copy-AuditFilesInBackupMode -Subsystem $name -Sources $sources -TargetDirectory $work
        } catch {
            if ($_.Exception.Data.Contains('BackupModeExitFailed')) { throw }
            if ($_.Exception.Data.Contains('Deferred')) {
                $status.Result = 'Deferred'; $status.ExitCode = $EXIT_DEFERRED
            } else {
                $status.Result = 'Failed'; $status.ExitCode = $EXIT_TOOL
            }
            $status.Message = $_.Exception.Message
            Write-Log -Level WARN -Message ('{0}: {1}' -f $name, $status.Message)
            return $status
        }
        $windowEnd = $copyResult.WindowEnd
        foreach ($c in $copyResult.Copies) { $targets += @{ Label = (Split-Path -Leaf $c.Copy); Path = $c.Copy; IsLive = $c.IsLive; Identity = $c.Identity } }
    } else {
        $windowEnd = Get-Date
        $targets += @{ Label = 'message log'; Path = $null; IsLive = $true; Identity = $null }
    }

    # Window
    if ($checkpoint.LastExportedTo) {
        $windowStart = $checkpoint.LastExportedTo.AddMinutes(-$OverlapMinutes)
    } else {
        $windowStart = $windowEnd.AddHours(-$InitialLookbackHours)
        Write-Log -Message ('{0}: no checkpoint, starting {1} hours back' -f $name, $InitialLookbackHours)
    }
    if ($windowStart -ge $windowEnd) { $windowStart = $windowEnd.AddMinutes(-1) }
    Write-Log -Message ('{0}: window {1} to {2}' -f $name, (Format-PITime $windowStart), (Format-PITime $windowEnd))

    $timeSelector = if ($Source.TimeSelector) { $Source.TimeSelector } else { $null }
    $timeXPath = if ($Source.TimeSelector) { ConvertTo-LocalNameXPath $Source.TimeSelector } else { $null }
    $timeExpr = if ($timeXPath) { [System.Xml.XPath.XPathExpression]::Compile($timeXPath) } else { $null }
    $rootTemplate = $null
    $containerName = $null
    $chunkStart = $windowStart
    $processedRotated = @($checkpoint.ProcessedRotated)
    $csvMode = ($OutputFormat -eq 'Csv')
    $recentKeys = $null
    $serverHost = $null
    $serverAddress = $null
    if ($csvMode) { $recentKeys = Read-RecentKeys -Source $name }

    while ($chunkStart -lt $windowEnd) {
        $chunkEnd = $chunkStart.AddDays($MaxDaysPerChunk)
        if ($chunkEnd -gt $windowEnd) { $chunkEnd = $windowEnd }

        $byDay = @{}
        $seenThisChunk = New-Object 'System.Collections.Generic.HashSet[string]'
        $chunkRecords = 0
        $csvRows = New-Object System.Collections.Generic.List[string]
        $csvEmitted = @{}

        foreach ($target in $targets) {
            if ($Source.Type -eq 'Audit') { $export = Invoke-PidiagExport -FilePath $target.Path -Start $chunkStart -End $chunkEnd -Profile $Source }
            else { $export = Invoke-PigetmsgExport -Start $chunkStart -End $chunkEnd -Profile $Source }
            Write-Log -Message ('{0}: {1} {2} [{3} to {4}]: {5}' -f $name, $Source.Tool, $target.Label, (Format-PITime $chunkStart), (Format-PITime $chunkEnd), $export.Message)

            if ($export.Status -eq 'Failed') {
                $status.Result = 'Failed'; $status.Message = $export.Message
                $status.ExitCode = if ($export.Kind -eq 'xml') { $EXIT_XML } else { $EXIT_TOOL }
                Write-Log -Level ERROR -Message ('{0}: {1}; checkpoint held at {2}' -f $name, $export.Message, $(if ($checkpoint.LastExportedTo) { Format-PITime $checkpoint.LastExportedTo } else { 'none' }))
                return $status
            }
            if ($export.Status -eq 'Empty') { continue }

            if ($export.Encoding -and $export.Encoding -like 'fallback:*') {
                Write-Log -Level WARN -Message ('{0}: {1} output decoded with {2}; set -PidiagOutputEncoding explicitly once confirmed' -f $name, $Source.Tool, $export.Encoding)
            }

            $doc = $export.Document
            if ($null -eq $rootTemplate) {
                $rootTemplate = $doc.DocumentElement
                $containerName = (Resolve-RecordContainer -Document $doc -Profile $Source).Name
                $piServer = Get-ChildElementByLocalName -Parent $rootTemplate -LocalName 'PIServer'
                if ($null -ne $piServer) { $serverHost = $piServer.GetAttribute('IPHost'); $serverAddress = $piServer.GetAttribute('IPAddress') }
                if (-not $serverHost -and $rootTemplate.HasAttribute('MachineName')) { $serverHost = $rootTemplate.GetAttribute('MachineName') }
                $script:MessageCollective = if ($rootTemplate.HasAttribute('Collective')) { $rootTemplate.GetAttribute('Collective') } else { $null }
                if (-not $serverHost) { $serverHost = [Environment]::MachineName }
                Write-Log -Level DEBUG -Message ('{0}: root <{1}>, record container {2}' -f $name, $rootTemplate.LocalName, $(if ($containerName) { '<' + $containerName + '>' } else { 'root' }))
            } elseif ($rootTemplate.LocalName -ne $doc.DocumentElement.LocalName) {
                $msg = ('{0}: root element <{1}> differs from <{2}>' -f $name, $doc.DocumentElement.LocalName, $rootTemplate.LocalName)
                if ($StrictRootElement) { $status.Result = 'Failed'; $status.ExitCode = $EXIT_XML; $status.Message = $msg; Write-Log -Level ERROR -Message $msg; return $status }
                Write-Log -Level WARN -Message $msg
            }

            $records = Get-RecordElements -Document $doc -Profile $Source
            if ($records.Count -eq 0) { continue }

            if (-not $timeXPath) {
                $detected = Find-TimeSelector -Sample $records[0]
                if (-not $detected) {
                    $msg = ('{0}: cannot find a timestamp field on <{1}>; run -Mode Inspect and set the time selector parameter for this log type' -f $name, $records[0].LocalName)
                    $status.Result = 'Failed'; $status.ExitCode = $EXIT_XML; $status.Message = $msg
                    Write-Log -Level ERROR -Message $msg
                    return $status
                }
                $timeSelector = $detected
                $timeXPath = ConvertTo-LocalNameXPath $detected
                $timeExpr = [System.Xml.XPath.XPathExpression]::Compile($timeXPath)
                Write-Log -Message ('{0}: record element <{1}>, timestamp field auto-detected as {2}' -f $name, $records[0].LocalName, $detected)
            }

            # Per-record loop. Kept flat on purpose: PowerShell 5.1 function calls cost about 0.1 ms each and
            # a busy message log delivers well over 100 000 records a day.
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $occurrence = @{}
            $hasher = $script:Sha256
            foreach ($el in $records) {
                $tsText = Get-CompiledValue -Element $el -Expression $timeExpr
                $ts = ConvertTo-LocalDateTime -Text $tsText
                if ($null -eq $ts) {
                    $msg = ('{0}: record timestamp "{1}" could not be parsed (selector {2})' -f $name, $tsText, $timeXPath)
                    $status.Result = 'Failed'; $status.ExitCode = $EXIT_XML; $status.Message = $msg
                    Write-Log -Level ERROR -Message $msg
                    return $status
                }
                $text = $script:KeyCollapseGaps.Replace($script:KeyStripNamespaces.Replace($el.OuterXml, ''), '><')
                $hash = [System.BitConverter]::ToString($hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($text))).Replace('-', '')
                $n = 0
                if ($occurrence.ContainsKey($hash)) { $n = $occurrence[$hash] }
                $occurrence[$hash] = $n + 1
                $key = $hash + '#' + $n
                if (-not $seenThisChunk.Add($key)) { continue }
                if ($csvMode) {
                    if ($recentKeys.ContainsKey($key) -or $csvEmitted.ContainsKey($key)) { continue }
                    if ($Source.Type -eq 'Audit') { $row = ConvertTo-AuditCsvRow -Record $el -Time $ts -Source $Source -ServerHost $serverHost -ServerAddress $serverAddress }
                    else { $row = ConvertTo-MessageCsvRow -Record $el -Time $ts -Source $Source -ServerHost $serverHost -ServerAddress $serverAddress }
                    $csvRows.Add((ConvertTo-CsvLine -Row $row))
                    $csvEmitted[$key] = $ts.ToUniversalTime().Ticks
                    $chunkRecords++
                    continue
                }
                if ($el.HasAttributes) { Remove-NamespaceDeclarations -Element $el }
                $dayKey = $ts.Date.ToString('yyyy-MM-dd')
                if (-not $byDay.ContainsKey($dayKey)) { $byDay[$dayKey] = New-Object System.Collections.Generic.List[object] }
                $byDay[$dayKey].Add(@{ Element = $el; Key = $key; Time = $ts })
                $chunkRecords++
            }
            Write-Log -Level DEBUG -Message ('{0}: keyed {1} records in {2:0.0}s' -f $name, $records.Count, $sw.Elapsed.TotalSeconds)
        }

        $status.Seen += $chunkRecords

        if ($csvMode) {
            # Rows for this chunk go to the run file only now that every record of the chunk parsed, and
            # they are flushed before the checkpoint moves, so a crash never separates the two.
            try {
                $csvFile = $script:CsvFiles[$Source.Type]
                if ($csvRows.Count -gt 0) {
                    # one write and one flush per chunk, so a collector tailing a day file never sees a torn line
                    $csvFile.Out.Write(($csvRows -join "`r`n") + "`r`n")
                    $csvFile.Out.Flush()
                }
                $csvFile.Rows += $csvRows.Count
                foreach ($k in $csvEmitted.Keys) { $recentKeys[$k] = $csvEmitted[$k] }
                Write-RecentKeys -Source $name -Keys $recentKeys -WindowEnd $chunkEnd
            } catch {
                $status.Result = 'Failed'; $status.ExitCode = $EXIT_DAILYFILE
                $status.Message = ('csv run file: {0}' -f $_.Exception.Message)
                Write-Log -Level ERROR -Message ('{0}: {1}; checkpoint held' -f $name, $status.Message)
                return $status
            }
            $status.Appended += $csvRows.Count
            Write-Log -Message ('{0}: {1} records written to the run file' -f $name, $csvRows.Count)
        }

        # Write daily files for this chunk; any failure holds the checkpoint at the last committed chunk
        foreach ($dayKey in ($byDay.Keys | Sort-Object)) {
            $day = [datetime]::ParseExact($dayKey, 'yyyy-MM-dd', $script:Invariant)
            $path = Get-DailyFilePath -Profile $Source -Day $day
            $ordered = New-Object System.Collections.Generic.List[object]
            foreach ($r in ($byDay[$dayKey] | Sort-Object { $_.Time })) { $ordered.Add($r) }
            try {
                $added = Update-DailyFile -Path $path -RootTemplate $rootTemplate -NewRecords $ordered -Profile $Source -ContainerName $containerName -TimeSelector $timeSelector
            } catch {
                $status.Result = 'Failed'; $status.ExitCode = $EXIT_DAILYFILE
                $status.Message = ('daily file {0}: {1}' -f $path, $_.Exception.Message)
                Write-Log -Level ERROR -Message ('{0}: {1}; checkpoint held' -f $name, $status.Message)
                return $status
            }
            $status.Appended += $added
            Write-Log -Message ('{0}: {1}: {2} candidate records, {3} appended, {4} already present' -f $name, (Split-Path -Leaf $path), $byDay[$dayKey].Count, $added, ($byDay[$dayKey].Count - $added))
        }

        # Commit
        if ($chunkEnd -ge $windowEnd) {
            foreach ($t in $targets) { if ($t.Identity -and -not $t.IsLive) { $processedRotated += $t.Identity } }
        }
        Write-Checkpoint -Subsystem $name -LastExportedTo $chunkEnd -ProcessedRotated $processedRotated -Result 'Success'
        Write-Log -Message ('{0}: checkpoint advanced to {1}' -f $name, (Format-PITime $chunkEnd))

        $chunkStart = $chunkEnd
    }

    if ($Source.Type -eq 'Audit') {
        if ($sources.Live -and $sources.Live.Length -gt 0) {
            # Rotation warning: the live file is close to AuditMaxKBytes (64000 KB default)
            $kb = [math]::Round($sources.Live.Length / 1024)
            if ($kb -gt 56000) { Write-Log -Level WARN -Message ('{0}: live audit file is {1} KB, rotation is near; make sure the rotated file is picked up by the filter' -f $name, $kb) }
        }
        Remove-Item -LiteralPath (Join-Path $WorkDirectory $name) -Recurse -Force -ErrorAction SilentlyContinue
    }
    $status.Message = ('{0} records seen, {1} appended' -f $status.Seen, $status.Appended)
    return $status
}

# ---------------------------------------------------------------------------------------------------
# Inspect mode
# ---------------------------------------------------------------------------------------------------

function Invoke-Inspect {
    param([array]$Profiles)
    $report = New-Object System.Text.StringBuilder
    $add = { param($s) [void]$report.AppendLine($s); Write-Host $s }

    $targets = @()
    $work = Join-Path $WorkDirectory 'inspect'
    New-Item -ItemType Directory -Path $work -Force | Out-Null

    if ($InspectFile) {
        if (-not (Test-Path -LiteralPath $InspectFile)) { throw "InspectFile not found: $InspectFile" }
        $auditProfile = $Profiles | Where-Object { $_.Type -eq 'Audit' } | Select-Object -First 1
        if (-not $auditProfile) { $auditProfile = @{ Name = 'file'; Type = 'Audit'; Tool = 'pidiag'; Prefix = $AuditFilePrefix; Container = $RecordContainer; CountElement = $CountElement; HeaderElements = @($HeaderElements); TimeSelector = $RecordTimeSelector } }
        $targets += @{ Name = (Split-Path -Leaf $InspectFile); Path = $InspectFile; Profile = $auditProfile }
    } else {
        foreach ($p in $Profiles) {
            if ($p.Type -eq 'Audit') {
                $sources = Get-AuditSourceFiles -Subsystem $p.Name -AlreadyProcessed @()
                if ($null -eq $sources.Live) { & $add ('{0}: no live audit file found' -f $p.Name); continue }
                $subWork = Join-Path $work $p.Name
                New-Item -ItemType Directory -Path $subWork -Force | Out-Null
                $copyResult = Copy-AuditFilesInBackupMode -Subsystem $p.Name -Sources @{ Live = $sources.Live; Rotated = @() } -TargetDirectory $subWork
                foreach ($c in $copyResult.Copies) { $targets += @{ Name = ('{0} ({1})' -f $p.Name, (Split-Path -Leaf $c.Copy)); Path = $c.Copy; Profile = $p } }
            } else {
                $targets += @{ Name = 'messagelog (pigetmsg)'; Path = $null; Profile = $p }
            }
        }
    }

    $end = Get-Date
    $start = $end.AddHours(-$InitialLookbackHours)
    foreach ($t in $targets) {
        $p = $t.Profile
        & $add ''
        & $add ('=== {0} ===' -f $t.Name)
        if ($t.Path) { & $add ('file: {0} ({1} bytes)' -f $t.Path, (Get-Item -LiteralPath $t.Path).Length) }

        # First pass with the lookback window. For an audit file that yields no records but holds some,
        # a second pass with no window shows the real record structure. The message log is queried live,
        # so the window is the only bound; widen -InitialLookbackHours if it comes back empty.
        $records = $null
        $noWindow = $false
        for ($pass = 1; $pass -le 2; $pass++) {
            $label = if ($noWindow) { 'no time window (all records in file)' } else { 'window {0} to {1}' -f (Format-PITime $start), (Format-PITime $end) }
            & $add ('{0} pass: {1}' -f $p.Tool, $label)
            if ($p.Type -eq 'Audit') {
                $args = Get-PidiagArguments -FilePath $t.Path -Start $start -End $end -NoWindow $noWindow
                $r = Invoke-External -FilePath $PidiagPath -Arguments $args -TimeoutSeconds $ToolTimeoutSeconds -WorkingDirectory (Split-Path -Parent $PidiagPath)
            } else {
                $args = Get-PigetmsgArguments -Start $start -End $end
                $r = Invoke-External -FilePath $PigetmsgPath -Arguments $args -TimeoutSeconds $ToolTimeoutSeconds -WorkingDirectory (Split-Path -Parent $PigetmsgPath)
            }
            & $add ('  command: {0} {1}' -f $p.Tool, $args)
            $rawPath = Join-Path $work (($t.Name -replace '[^\w\.-]', '_') + $(if ($noWindow) { '.all' } else { '' }) + '.raw.xml')
            [System.IO.File]::WriteAllBytes($rawPath, $r.StdOutBytes)
            & $add ('  exit code: {0}  timed out: {1}  stdout bytes: {2}  raw saved: {3}' -f $r.ExitCode, $r.TimedOut, $r.StdOutBytes.Length, $rawPath)
            if ($r.StdErr.Trim()) { & $add ('  stderr: ' + $r.StdErr.Trim()) }

            try { $parsed = ConvertTo-XmlDocumentFromBytes -Bytes $r.StdOutBytes } catch { & $add ('  PARSE FAILURE: ' + $_.Exception.Message); continue }
            if ($parsed.Preamble) { & $add ('  preamble before XML: ' + $parsed.Preamble) }
            if ($parsed.IsEmpty) { & $add '  no XML in output'; continue }
            & $add ('  encoding decision: ' + $parsed.Encoding)

            $doc = $parsed.Document
            $root = $doc.DocumentElement
            & $add ('  root element: <{0}> namespace "{1}"' -f $root.Name, $root.NamespaceURI)
            foreach ($a in $root.Attributes) { & $add ('    root attribute {0}="{1}"' -f $a.Name, $a.Value) }
            $shown = 0
            foreach ($c in $root.ChildNodes) {
                if ($c -isnot [System.Xml.XmlElement]) { continue }
                if ($shown -ge 6) { & $add '  root child ... (more)'; break }
                $attrs = ($c.Attributes | ForEach-Object { '{0}="{1}"' -f $_.Name, $_.Value }) -join ' '
                & $add ('  root child <{0}> {1}' -f $c.LocalName, $attrs)
                $shown++
            }
            $container = Resolve-RecordContainer -Document $doc -Profile $p
            & $add ('  record container: {0} (profile setting "{1}")' -f $(if ($container.Name) { '<' + $container.Name + '>' } else { 'root' }), $p.Container)
            $records = Get-RecordElements -Document $doc -Profile $p
            $names = $records | ForEach-Object { $_.LocalName } | Group-Object | ForEach-Object { '{0} x{1}' -f $_.Name, $_.Count }
            & $add ('  record elements: ' + $(if ($names) { $names -join ', ' } else { 'none' }))
            if ($records.Count -gt 0) { break }

            if ($noWindow -or $p.Type -ne 'Audit') {
                if ($p.Type -ne 'Audit') { & $add '  no records inside the window; rerun with a larger -InitialLookbackHours to see the structure' }
                break
            }
            $countAttr = $null
            if ($container.Element.HasAttribute('RecordCount')) { $countAttr = $container.Element.GetAttribute('RecordCount') }
            if ($countAttr -and [int]$countAttr -gt 0) {
                & $add ('  file holds {0} records, none inside the window: repeating without a time window for the structure sample' -f $countAttr)
            } else {
                & $add '  no records inside the window: repeating without a time window for the structure sample'
            }
            $noWindow = $true
        }
        if ($null -eq $records -or $records.Count -eq 0) { continue }

        $sample = $records[0]
        & $add 'first record structure:'
        foreach ($a in $sample.Attributes) { & $add ('  @{0} = "{1}"' -f $a.LocalName, $a.Value) }
        foreach ($c in $sample.ChildNodes) {
            if ($c -isnot [System.Xml.XmlElement]) { continue }
            $attrs = ($c.Attributes | ForEach-Object { '{0}="{1}"' -f $_.Name, $_.Value }) -join ' '
            & $add ('  <{0}> {1} = "{2}"' -f $c.LocalName, $attrs, ($c.InnerText -replace '\s+', ' ').Trim())
        }

        & $add 'timestamp candidates (selector = value -> parsed local time):'
        foreach ($c in (Get-TimeCandidates -Sample $sample)) {
            $looksLikeTime = $false
            foreach ($pattern in $script:TimeNamePatterns) { if ($c.Name -imatch $pattern) { $looksLikeTime = $true; break } }
            if (-not $looksLikeTime) { continue }
            $dt = ConvertTo-LocalDateTime -Text $c.Value
            & $add ('  {0} = "{1}" -> {2}' -f $c.Selector, $c.Value, $(if ($dt) { $dt.ToString('yyyy-MM-dd HH:mm:ss') } else { 'not parseable' }))
        }
        $detected = if ($p.TimeSelector) { $p.TimeSelector } else { Find-TimeSelector -Sample $sample }
        if ($detected) {
            $xp = ConvertTo-LocalNameXPath $detected
            $times = @()
            $unparsed = 0
            foreach ($el in $records) { $dt = ConvertTo-LocalDateTime -Text (Get-NodeValue -Element $el -XPath $xp); if ($dt) { $times += $dt } else { $unparsed++ } }
            & $add ('timestamp selector: {0} ({1})  parsed {2} of {3}' -f $detected, $(if ($p.TimeSelector) { 'given' } else { 'auto-detected' }), $times.Count, $records.Count)
            if ($times.Count -gt 0) { & $add ('  earliest {0:yyyy-MM-dd HH:mm:ss}  latest {1:yyyy-MM-dd HH:mm:ss}' -f ($times | Sort-Object | Select-Object -First 1), ($times | Sort-Object | Select-Object -Last 1)) }
            if ($unparsed -gt 0) { & $add ('  WARNING: {0} records had an unparseable timestamp' -f $unparsed) }
        } else {
            & $add 'timestamp selector: NOT DETECTED. Set -RecordTimeSelector (audit) or -MessageTimeSelector (message log) from the structure above.'
        }
        & $add ('dedupe key of first record: ' + (Get-RecordKey -Element $sample))
        $keys = New-Object 'System.Collections.Generic.HashSet[string]'
        $dupes = 0
        foreach ($el in $records) { if (-not $keys.Add((Get-RecordKey -Element $el))) { $dupes++ } }
        & $add ('identical records within this export: {0} (kept apart by occurrence index)' -f $dupes)
        & $add ('first record XML:')
        & $add ($sample.OuterXml)
    }

    $reportPath = Join-Path $LogDirectory ('Inspect_{0}.txt' -f $script:RunStamp.ToString('yyyyMMdd_HHmmss'))
    [System.IO.File]::WriteAllText($reportPath, $report.ToString(), [System.Text.Encoding]::UTF8)
    Write-Log -Message ('inspect report written to ' + $reportPath)
}

# ---------------------------------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------------------------------

function Expand-ListParameter {
    # powershell.exe -File passes "a,b" as one string; accept both that and real arrays.
    param([string[]]$Value)
    $out = @()
    foreach ($v in @($Value)) { foreach ($part in ($v -split ',')) { if ($part.Trim()) { $out += $part.Trim() } } }
    return ,$out
}

function Invoke-Main {
    $exitCode = $EXIT_UNHANDLED
    $mutex = $null
    $haveMutex = $false

    try {
        $script:LogTypes = Expand-ListParameter $LogTypes
        $script:Subsystems = Expand-ListParameter $Subsystems
        $script:HeaderElements = Expand-ListParameter $HeaderElements
        $script:MessageHeaderElements = Expand-ListParameter $MessageHeaderElements
        foreach ($lt in $LogTypes) {
            if ($lt -notin 'Audit', 'MessageLog') { Write-Log -Level ERROR -Message ('unknown log type "{0}"; use Audit, MessageLog or both' -f $lt); return $EXIT_CONFIG }
        }
        if ($LogTypes.Count -eq 0) { Write-Log -Level ERROR -Message 'no log types selected'; return $EXIT_CONFIG }
        # Output locations: derive from OutputRoot unless given individually, and make sure the drive
        # exists before anything else, since an absent or not-ready drive would otherwise surface as an
        # unhandled error with no log file to read.
        if (-not $ExportDirectory) { $script:ExportDirectory = [System.IO.Path]::Combine($OutputRoot, 'Exports') }
        if (-not $StateDirectory)  { $script:StateDirectory  = [System.IO.Path]::Combine($OutputRoot, 'State') }
        if (-not $LogDirectory)    { $script:LogDirectory    = [System.IO.Path]::Combine($OutputRoot, 'Logs') }
        if (-not $WorkDirectory)   { $script:WorkDirectory   = [System.IO.Path]::Combine($OutputRoot, 'Work') }
        foreach ($d in @($ExportDirectory, $StateDirectory, $LogDirectory, $WorkDirectory)) {
            $driveRoot = [System.IO.Path]::GetPathRoot($d)
            if ($driveRoot -and -not [System.IO.Directory]::Exists($driveRoot)) {   # Directory.Exists never throws, even on a not-ready drive
                Write-Log -Level ERROR -Message ('output drive {0} for {1} does not exist or is not ready; set -OutputRoot (or the individual -*Directory parameters) to a local disk' -f $driveRoot, $d)
                return $EXIT_CONFIG
            }
            if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
        }
        $script:LogFile = Join-Path $LogDirectory ('PIAuditExport_{0}.log' -f $script:RunStamp.ToString('yyyy-MM-dd'))
        Write-Log -Message ('=== PIAuditExport start: mode {0}, log types {1}, host {2}, user {3}, PowerShell {4} ===' -f $Mode, ($LogTypes -join ','), [Environment]::MachineName, [Environment]::UserName, $PSVersionTable.PSVersion)

        # Single instance
        $mutex = New-Object System.Threading.Mutex($false, $MutexName)
        try { $haveMutex = $mutex.WaitOne(0) } catch [System.Threading.AbandonedMutexException] { $haveMutex = $true }
        if (-not $haveMutex) {
            Write-Log -Level WARN -Message 'another instance holds the mutex; exiting'
            return $EXIT_INSTANCE
        }

        # Resolve PI paths
        if (-not $PIRoot) {
            if ($env:PISERVER) { $script:PIRoot = $env:PISERVER; Write-Log -Level DEBUG -Message ('PI root from PISERVER: ' + $PIRoot) }
            else { $script:PIRoot = 'D:\Program Files\PI'; Write-Log -Level DEBUG -Message ('PI root defaulted to ' + $PIRoot) }
        }
        # Path.Combine rather than Join-Path: Join-Path throws on a drive letter that does not exist, which
        # would turn a wrong default into an unhandled error instead of the configuration message below.
        if (-not $PidiagPath)        { $script:PidiagPath        = [System.IO.Path]::Combine($PIRoot, 'adm', 'pidiag.exe') }
        if (-not $PiartoolPath)      { $script:PiartoolPath      = [System.IO.Path]::Combine($PIRoot, 'adm', 'piartool.exe') }
        if (-not $PigetmsgPath)      { $script:PigetmsgPath      = [System.IO.Path]::Combine($PIRoot, 'adm', 'pigetmsg.exe') }
        if (-not $AuditLogDirectory) { $script:AuditLogDirectory = [System.IO.Path]::Combine($PIRoot, 'log') }

        $wantAudit = ($LogTypes -contains 'Audit')
        $wantMessages = ($LogTypes -contains 'MessageLog')
        $configErrors = @()
        if ($wantAudit) {
            if (-not (Test-Path -LiteralPath $PidiagPath))        { $configErrors += "pidiag not found at $PidiagPath" }
            if (-not $SkipBackupMode -and -not (Test-Path -LiteralPath $PiartoolPath)) { $configErrors += "piartool not found at $PiartoolPath" }
            if (-not (Test-Path -LiteralPath $AuditLogDirectory)) { $configErrors += "audit log directory not found: $AuditLogDirectory" }
        }
        if ($wantMessages -and -not (Test-Path -LiteralPath $PigetmsgPath)) { $configErrors += "pigetmsg not found at $PigetmsgPath" }
        if ($Mode -eq 'Inspect' -and $InspectFile -and -not (Test-Path -LiteralPath $InspectFile)) { $configErrors += "InspectFile not found: $InspectFile" }
        if ($configErrors.Count -gt 0) {
            foreach ($e in $configErrors) { Write-Log -Level ERROR -Message $e }
            return $EXIT_CONFIG
        }
        if ($wantAudit)    { Write-Log -Message ('audit: pidiag {0}; piartool {1}; audit dir {2}; subsystems {3}' -f $PidiagPath, $PiartoolPath, $AuditLogDirectory, ($Subsystems -join ',')) }
        if ($wantMessages) { Write-Log -Message ('message log: pigetmsg {0}; severity {1}; all fields {2}{3}' -f $PigetmsgPath, $MessageLogSeverity, $MessageLogAllFields, $(if ($PigetmsgExtraArguments) { '; extra ' + $PigetmsgExtraArguments } else { '' })) }
        Write-Log -Message ('output root {0}' -f $OutputRoot)

        $profiles = New-SourceProfiles

        if ($Mode -eq 'Inspect') {
            Invoke-Inspect -Profiles $profiles
            return $EXIT_SUCCESS
        }

        # PI backup status (diagnostic, and optional deferral) matters only when backup mode will be used
        $auditDeferred = $false
        if ($wantAudit -and -not $SkipBackupMode) {
            $q = Invoke-Piartool -Arguments '-backup -query'
            Write-Log -Message ('piartool -backup -query: ' + ($q.Output -replace '\s+', ' '))
            if ($BackupBusyPattern -and $q.Output -imatch $BackupBusyPattern) {
                Write-Log -Level WARN -Message 'a PI backup appears to be in progress; deferring the audit sources this run'
                $auditDeferred = $true
            }
        }

        if ($OutputFormat -eq 'Csv') {
            try {
                if ($wantAudit)    { Open-CsvRunFile -Type 'Audit' -Prefix $CsvAuditFilePrefix }
                if ($wantMessages) { Open-CsvRunFile -Type 'MessageLog' -Prefix $CsvMessageLogFilePrefix }
            } catch { Write-Log -Level ERROR -Message ('csv: cannot open the run file: ' + $_.Exception.Message); try { Close-CsvRunFiles } catch { }; return $EXIT_DAILYFILE }
        }

        # Export each source independently
        $results = @()
        foreach ($src in $profiles) {
            Write-Log -Message ('--- {0} ---' -f $src.Name)
            if ($src.Type -eq 'Audit' -and $auditDeferred) {
                $results += New-Object PSObject -Property @{ Source = $src.Name; Result = 'Deferred'; ExitCode = $EXIT_DEFERRED; Appended = 0; Seen = 0; Message = 'PI backup in progress' }
                continue
            }
            try {
                $results += Export-Source -Source $src
            } catch {
                if ($_.Exception.Data.Contains('BackupModeExitFailed')) {
                    Write-Log -Level ERROR -Message $_.Exception.Message
                    if ($OutputFormat -eq 'Csv') { try { Close-CsvRunFiles } catch { } }
                    Write-AppEvent -Message $_.Exception.Message -ExitCode $EXIT_BACKUPMODE
                    return $EXIT_BACKUPMODE
                }
                Write-Log -Level ERROR -Message ('{0}: unhandled: {1}' -f $src.Name, $_.Exception.Message)
                Write-Log -Level ERROR -Message ('at ' + (($_.ScriptStackTrace -split "`r?`n")[0]))
                $results += New-Object PSObject -Property @{ Source = $src.Name; Result = 'Failed'; ExitCode = $EXIT_UNHANDLED; Appended = 0; Seen = 0; Message = $_.Exception.Message }
            }
        }

        if ($OutputFormat -eq 'Csv') {
            try { Close-CsvRunFiles } catch { Write-Log -Level ERROR -Message ('csv: could not finish the run files: ' + $_.Exception.Message); $results += New-Object PSObject -Property @{ Source = 'csv'; Result = 'Failed'; ExitCode = $EXIT_DAILYFILE; Appended = 0; Seen = 0; Message = $_.Exception.Message } }
        }

        # Housekeeping
        try {
            Get-ChildItem -LiteralPath $LogDirectory -Filter 'PIAuditExport_*.log' -File |
                Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$LogRetentionDays) } |
                Remove-Item -Force -ErrorAction SilentlyContinue
        } catch { }
        try { Remove-ExpiredExports -Profiles $profiles } catch { Write-Log -Level WARN -Message ('retention: ' + $_.Exception.Message) }

        # Summary and exit code
        $summary = ($results | ForEach-Object { '{0}={1}({2}/{3})' -f $_.Source, $_.Result, $_.Appended, $_.Seen }) -join '; '
        $failed   = @($results | Where-Object { $_.Result -eq 'Failed' })
        $deferred = @($results | Where-Object { $_.Result -eq 'Deferred' })
        $ok       = @($results | Where-Object { $_.Result -in 'Success', 'NoSource' })
        $noSource = @($results | Where-Object { $_.Result -eq 'NoSource' })

        if ($results.Count -gt 0 -and $noSource.Count -eq $results.Count) {
            $exitCode = $EXIT_CONFIG
            Write-Log -Level ERROR -Message ('no audit files found for any subsystem in {0}' -f $AuditLogDirectory)
        } elseif ($failed.Count -gt 0) {
            $codes = @($failed | ForEach-Object { $_.ExitCode } | Sort-Object -Unique)
            if ($ok.Count -eq 0 -and $deferred.Count -eq 0 -and $codes.Count -eq 1) { $exitCode = $codes[0] } else { $exitCode = $EXIT_PARTIAL }
        } elseif ($deferred.Count -gt 0) {
            $exitCode = $EXIT_DEFERRED
        } else {
            $exitCode = $EXIT_SUCCESS
        }
        $level = if ($exitCode -eq 0) { 'INFO' } elseif ($exitCode -in 8, 9) { 'WARN' } else { 'ERROR' }
        Write-Log -Level $level -Message ('=== PIAuditExport end: exit {0}; {1} ===' -f $exitCode, $summary)
        Write-AppEvent -Message ('PIAuditExport exit {0}: {1}' -f $exitCode, $summary) -ExitCode $exitCode
        return $exitCode
    }
    catch {
        Write-Log -Level ERROR -Message ('unhandled: ' + $_.Exception.Message)
        Write-Log -Level ERROR -Message ('at ' + (($_.ScriptStackTrace -split "`r?`n")[0]))
        Write-AppEvent -Message ('PIAuditExport unhandled error: ' + $_.Exception.Message) -ExitCode $EXIT_UNHANDLED
        return $EXIT_UNHANDLED
    }
    finally {
        if ($haveMutex -and $mutex) { try { $mutex.ReleaseMutex() } catch { } }
        if ($mutex) { $mutex.Dispose() }
    }
}

$mainExitCode = [int](@(Invoke-Main) | Select-Object -Last 1)
exit $mainExitCode

# /DASIVE
