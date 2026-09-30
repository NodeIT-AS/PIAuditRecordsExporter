<#
.SYNOPSIS
    Registers (or removes) the Windows scheduled task that runs Export-PIAuditRecords.ps1.

.DESCRIPTION
    Asks for what the task should produce and where, then creates a repeating task under an account
    that can run piartool -systembackup and read the PI log directory (audit), or read the PI message
    log (message log).

    Prompts, each skipped when the matching parameter is given:
        Output mode   XML daily files, CSV one file per run, or CSV one file per day appended each run
        Log types     audit database, message log, or both
        Output path   the exporter's -OutputRoot; the drive must exist, the folder is created if missing
        Account       the task account, when -UserName is not given
    A summary is shown and confirmed before anything is registered. -NoPrompt takes the defaults for
    anything not given, for unattended use.

    Also registers the PIAuditExport event log source so the exporter can write a summary event
    per run (Information on exit 0, Warning on 8 and 9, Error otherwise).

.PARAMETER ScriptPath
    The exporter the task runs. Default: Export-PIAuditRecords.ps1 in the same directory as this
    registration script, so keep the two scripts together and run this one from where they live.

.PARAMETER Mode
    Xml, CsvPerRun or CsvPerDay. Maps to the exporter's -OutputFormat and -CsvFileMode.

.PARAMETER LogTypes
    Audit, MessageLog, or both.

.PARAMETER OutputRoot
    Output root for the exporter (Exports, State, Logs and Work are created under it).

.PARAMETER ScriptArguments
    Further exporter parameters passed through unchanged, for example '-BackupBusyPattern "busy"'.
    The output mode, log types and output root are set by this script and must not be repeated here.

.PARAMETER UserName
    Account to run the task as. For a group managed service account give the name with a trailing $
    (DOMAIN\svc-piaudit$); no password is requested. For any other account you are prompted for the
    password. The account needs local rights to read the PI log directory and a PI identity with
    permission to start and stop backups (a PI administrator mapping is the usual choice).

.PARAMETER NoPrompt
    Do not ask; use the defaults (Xml, both log types, D:\Logs\Audit) for anything not given.

.EXAMPLE
    .\Register-PIAuditExportTask.ps1
    Asks for everything.

.EXAMPLE
    .\Register-PIAuditExportTask.ps1 -Mode CsvPerDay -OutputRoot 'E:\PI Export' -UserName 'NODEIT\svc-piaudit$'
    Asks only for the log types, then confirms.

.EXAMPLE
    .\Register-PIAuditExportTask.ps1 -Mode CsvPerRun -LogTypes Audit,MessageLog -OutputRoot D:\Logs\Audit -UserName 'NODEIT\svc-piaudit$' -NoPrompt
    Unattended.

.EXAMPLE
    .\Register-PIAuditExportTask.ps1 -Unregister
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$TaskName = 'NodeIT PI Audit Export',
    [string]$ScriptPath,

    [ValidateSet('Xml', 'CsvPerRun', 'CsvPerDay')]
    [string]$Mode,
    [ValidateSet('Audit', 'MessageLog')]
    [string[]]$LogTypes,
    [string]$OutputRoot,
    [string]$ScriptArguments = '',

    [ValidateRange(5, 1440)]
    [int]$IntervalMinutes = 60,
    [string]$UserName,
    [int]$ExecutionTimeLimitMinutes = 120,
    [string]$EventLogSource = 'PIAuditExport',
    [switch]$NoPrompt,
    [switch]$Unregister
)

$ErrorActionPreference = 'Stop'

if ($Unregister) {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        if ($PSCmdlet.ShouldProcess($TaskName, 'Unregister scheduled task')) {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
            Write-Host "Removed task '$TaskName'"
        }
    } else {
        Write-Host "Task '$TaskName' does not exist"
    }
    return
}

# The exporter lives next to this script unless told otherwise; resolved to a full path because the
# task runs with its own working directory.
if (-not $ScriptPath) { $ScriptPath = Join-Path $PSScriptRoot 'Export-PIAuditRecords.ps1' }
if (-not (Test-Path -LiteralPath $ScriptPath)) { throw "Export-PIAuditRecords.ps1 not found at $ScriptPath; keep it in the same directory as this script, or set -ScriptPath" }
$ScriptPath = (Resolve-Path -LiteralPath $ScriptPath).ProviderPath

# ---------------------------------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------------------------------

function Read-Choice {
    # Numbered menu; Enter takes the default. Returns the chosen item's Value.
    param([string]$Title, [array]$Items, [int]$Default = 1)
    Write-Host ''
    Write-Host $Title
    for ($i = 0; $i -lt $Items.Count; $i++) {
        $mark = if ($i + 1 -eq $Default) { ' (default)' } else { '' }
        Write-Host ('  {0}. {1}{2}' -f ($i + 1), $Items[$i].Label, $mark)
    }
    while ($true) {
        $answer = Read-Host ('Choice [1-{0}, Enter = {1}]' -f $Items.Count, $Default)
        if ([string]::IsNullOrWhiteSpace($answer)) { return $Items[$Default - 1].Value }
        $n = 0
        if ([int]::TryParse($answer.Trim(), [ref]$n) -and $n -ge 1 -and $n -le $Items.Count) { return $Items[$n - 1].Value }
        Write-Host '  Not a valid choice.'
    }
}

function Read-OutputRoot {
    param([string]$Default)
    while ($true) {
        Write-Host ''
        $answer = Read-Host ('Output path for the exported files [Enter = {0}]' -f $Default)
        $path = if ([string]::IsNullOrWhiteSpace($answer)) { $Default } else { $answer.Trim().Trim('"').Trim("'") }
        $problem = Test-OutputRoot -Path $path
        if (-not $problem) { return $path }
        Write-Host ('  ' + $problem)
    }
}

function Test-OutputRoot {
    # Returns $null when usable, otherwise the reason. Relative paths are refused: the task's working
    # directory is the script directory, not where this prompt was answered.
    param([string]$Path)
    if (-not [System.IO.Path]::IsPathRooted($Path)) { return 'Give a full path, for example D:\Logs\Audit.' }
    $root = [System.IO.Path]::GetPathRoot($Path)
    if ($env:OS -eq 'Windows_NT' -and $root -notmatch '^([A-Za-z]:\\|\\\\)') { return 'Give a full path with a drive letter, for example D:\Logs\Audit.' }
    if (-not [System.IO.Directory]::Exists($root)) { return ('Drive {0} does not exist or is not ready on this server.' -f $root) }
    if ($Path -match '["*?<>|]') { return 'The path contains characters that are not allowed.' }
    return $null
}

$prompting = -not $NoPrompt
$modes = @(
    @{ Label = 'XML   one file per day per log type, rewritten each run (PIAudit_yyyy-MM-dd.xml)';           Value = 'Xml' },
    @{ Label = 'CSV   one file per run per log type (PIAudit_yyyy-MM-dd_NNN.csv)';                           Value = 'CsvPerRun' },
    @{ Label = 'CSV   one file per day per log type, appended each run (PIAudit_yyyy-MM-dd.csv)';           Value = 'CsvPerDay' }
)
$logTypeChoices = @(
    @{ Label = 'Audit database and PI Message Log'; Value = @('Audit', 'MessageLog') },
    @{ Label = 'Audit database only';               Value = @('Audit') },
    @{ Label = 'PI Message Log only';               Value = @('MessageLog') }
)

if (-not $Mode)       { $Mode = if ($prompting) { Read-Choice -Title 'Output mode:' -Items $modes -Default 1 } else { 'Xml' } }
if (-not $LogTypes)   { $LogTypes = if ($prompting) { Read-Choice -Title 'Log types to export:' -Items $logTypeChoices -Default 1 } else { @('Audit', 'MessageLog') } }
if (-not $OutputRoot) { $OutputRoot = if ($prompting) { Read-OutputRoot -Default 'D:\Logs\Audit' } else { 'D:\Logs\Audit' } }
else {
    $problem = Test-OutputRoot -Path $OutputRoot
    if ($problem) { throw ('OutputRoot {0}: {1}' -f $OutputRoot, $problem) }
}
if (-not $UserName) {
    if (-not $prompting) { throw 'UserName is required with -NoPrompt' }
    Write-Host ''
    while (-not $UserName) { $UserName = (Read-Host 'Account to run the task as (gMSA with a trailing $, for example DOMAIN\svc-piaudit$)').Trim() }
}

# The settings this script owns must not also come in through -ScriptArguments
foreach ($owned in 'OutputFormat', 'CsvFileMode', 'LogTypes', 'OutputRoot') {
    if ($ScriptArguments -match ('(^|\s)-' + $owned + '(\s|:|$)')) {
        throw ('-{0} is set by this script; remove it from -ScriptArguments' -f $owned)
    }
}

# ---------------------------------------------------------------------------------------------------
# Exporter command line
# ---------------------------------------------------------------------------------------------------

$modeArguments = switch ($Mode) {
    'Xml'       { '-OutputFormat Xml' }
    'CsvPerRun' { '-OutputFormat Csv -CsvFileMode PerRun' }
    'CsvPerDay' { '-OutputFormat Csv -CsvFileMode PerDay' }
}
$modeText = ($modes | Where-Object { $_.Value -eq $Mode }).Label -replace '\s{2,}', ' '
# A trailing backslash would escape the closing quote on the task's command line; a drive root keeps
# its meaning as D:\. rather than becoming the drive-relative D:
$quotedRoot = $OutputRoot.TrimEnd('\')
if ($quotedRoot -match '^[A-Za-z]:$') { $quotedRoot += '\.' }
$exporterArguments = ('{0} -LogTypes {1} -OutputRoot "{2}" {3}' -f $modeArguments, ($LogTypes -join ','), $quotedRoot, $ScriptArguments).Trim()

$systemRoot = if ($env:SystemRoot) { $env:SystemRoot } else { 'C:\Windows' }
$powershell = [System.IO.Path]::Combine($systemRoot, 'System32\WindowsPowerShell\v1.0\powershell.exe')
$argument   = ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" {1}' -f $ScriptPath, $exporterArguments).Trim()

# Start on the next whole quarter hour and repeat indefinitely
$now   = Get-Date
$start = $now.Date.AddHours($now.Hour).AddMinutes(15 * [math]::Ceiling(($now.Minute + 1) / 15))

Write-Host ''
Write-Host 'Summary'
Write-Host ('  Task          {0}' -f $TaskName)
Write-Host ('  Script        {0}' -f $ScriptPath)
Write-Host ('  Output mode   {0}' -f $modeText)
Write-Host ('  Log types     {0}' -f ($LogTypes -join ', '))
Write-Host ('  Output path   {0}  (Exports, State, Logs, Work)' -f $OutputRoot)
Write-Host ('  Account       {0}' -f $UserName)
Write-Host ('  Schedule      every {0} minutes from {1}' -f $IntervalMinutes, $start.ToString('yyyy-MM-dd HH:mm'))
Write-Host ('  Command       {0} {1}' -f $powershell, $argument)
if ($Mode -eq 'CsvPerDay') {
    Write-Host '  Note          day files grow during the day; the collector must tail them (WinCollect File Forwarder),'
    Write-Host '                not read each file once (QRadar Log File protocol).'
}

if ($prompting -and -not $WhatIfPreference) {
    Write-Host ''
    $confirm = Read-Host 'Register this task? [y/N]'
    if ($confirm -notmatch '^(y|yes|j|ja)$') { Write-Host 'Nothing registered.'; return }
}

if (-not $PSCmdlet.ShouldProcess($TaskName, "Register scheduled task as $UserName every $IntervalMinutes minutes")) { return }

# ---------------------------------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------------------------------

if (-not (Test-Path -LiteralPath $OutputRoot)) {
    New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
    Write-Host "Created $OutputRoot"
}

# Event log source (one-off, needs local admin)
try {
    if (-not [System.Diagnostics.EventLog]::SourceExists($EventLogSource)) {
        New-EventLog -LogName Application -Source $EventLogSource
        Write-Host "Created event log source '$EventLogSource' in the Application log"
    }
} catch {
    Write-Warning "Could not create event log source '$EventLogSource': $($_.Exception.Message). The exporter will still run; it just cannot write events."
}

$action   = New-ScheduledTaskAction -Execute $powershell -Argument $argument -WorkingDirectory (Split-Path -Parent $ScriptPath)
$trigger  = New-ScheduledTaskTrigger -Once -At $start -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)
$settings = New-ScheduledTaskSettingsSet `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Minutes $ExecutionTimeLimitMinutes) `
    -StartWhenAvailable `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -RestartCount 0
$description = 'NodeIT AS: exports PI Data Archive logs ({0}; {1}) to {2}' -f ($LogTypes -join ', '), $modeText, $OutputRoot

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}
if ($UserName.TrimEnd().EndsWith('$')) {
    $principal = New-ScheduledTaskPrincipal -UserId $UserName -LogonType Password -RunLevel Highest
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description $description | Out-Null
} else {
    $cred = Get-Credential -UserName $UserName -Message "Password for the account that will run '$TaskName'"
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -User $cred.UserName -Password $cred.GetNetworkCredential().Password -RunLevel Highest -Description $description | Out-Null
}
Write-Host ''
Write-Host "Registered '$TaskName': first run $($start.ToString('yyyy-MM-dd HH:mm')), then every $IntervalMinutes minutes, as $UserName"
Write-Host "Run it once now and read the log before trusting the schedule:"
Write-Host "  Start-ScheduledTask -TaskName '$TaskName'"
Write-Host ("  Get-Content '{0}' -Tail 20" -f [System.IO.Path]::Combine($OutputRoot, 'Logs', ('PIAuditExport_{0}.log' -f (Get-Date).ToString('yyyy-MM-dd'))))

# /DASIVE
