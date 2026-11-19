[CmdletBinding(DefaultParameterSetName = 'Install')]
param(
    [Parameter(ParameterSetName = 'Install')][string]$PluginDll,
    [Parameter(ParameterSetName = 'Install')][switch]$Upgrade,
    [Parameter(Mandatory, ParameterSetName = 'Verify')][switch]$VerifyOnly,
    [Parameter(Mandatory, ParameterSetName = 'Rollback')][string]$Rollback,
    [string]$ResultPath
)

$ErrorActionPreference = 'Stop'
$PluginDll = if ($PluginDll) { $PluginDll } else { Join-Path $PSScriptRoot 'build\TMVPNPlugin.dll' }
$env:PSModulePath = "$env:WINDIR\System32\WindowsPowerShell\v1.0\Modules;$env:ProgramFiles\WindowsPowerShell\Modules"
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = ([Security.Principal.WindowsPrincipal]$identity).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
$local = [Environment]::GetFolderPath('LocalApplicationData')
$guard = Join-Path $local 'ClashSubscriptionGuard'
$guardLock = Join-Path $guard 'guard.lock'
$stopFile = Join-Path $guard 'stop.request'
$legacyName = 'ClashVergeSubscriptionGuard'
$autorunPath = '\TrafficMonitor\'
$autorunName = "Autorun for $env:USERNAME"
$hostExe = Join-Path $local 'Programs\TrafficMonitor\TrafficMonitor.exe'
$plugins = Join-Path (Split-Path -Parent $hostExe) 'plugins'
$backupRoot = Join-Path $guard 'plugin-migration-backups'
$files = @('TMVPNPlugin.dll', 'TMVPNPluginRecovery\guard.py', 'TMVPNPluginRecovery\verge_ui.ps1')
$report = [ordered]@{ ok = $false; operation = $(if ($Upgrade) { 'Upgrade' } else { $PSCmdlet.ParameterSetName }); backup = $null }

function Initialize-Native {
    if ('TMVPNDeployment' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

public static class TMVPNDeployment {
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern IntPtr FindWindow(string className, IntPtr noTitle);
    [DllImport("user32.dll")]
    public static extern IntPtr GetShellWindow();
    [DllImport("user32.dll")]
    public static extern uint GetWindowThreadProcessId(IntPtr window, out uint pid);
    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool PostMessage(IntPtr window, uint message, IntPtr wParam, IntPtr lParam);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool QueryFullProcessImageName(IntPtr process, uint flags, StringBuilder path, ref uint size);
    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(SafeFileHandle handle, StringBuilder path, uint size, uint flags);

    public static string ProcessPath(uint pid) {
        IntPtr process = OpenProcess(0x1000, false, pid);
        if (process == IntPtr.Zero) throw new Win32Exception();
        try {
            var path = new StringBuilder(32768);
            uint size = (uint)path.Capacity;
            if (!QueryFullProcessImageName(process, 0, path, ref size)) throw new Win32Exception();
            return path.ToString();
        } finally { CloseHandle(process); }
    }
    public static string FilePath(SafeFileHandle handle) {
        var path = new StringBuilder(32768);
        uint size = GetFinalPathNameByHandle(handle, path, (uint)path.Capacity, 0);
        if (size == 0 || size >= path.Capacity) throw new Win32Exception();
        return path.ToString().Substring(4); // GetFinalPathNameByHandle prefixes a local DOS path with \\?\
    }
}
'@
}

function Wait-Condition([scriptblock]$Condition, [int]$Seconds, [string]$Failure) {
    $timer = [Diagnostics.Stopwatch]::StartNew()
    do {
        if (& $Condition) { return }
        Start-Sleep -Milliseconds 300
    } while ($timer.Elapsed.TotalSeconds -lt $Seconds)
    throw $Failure
}

function Get-HostProcess {
    $session = (Get-Process -Id $PID).SessionId
    $matching = @(Get-Process -Name TrafficMonitor -ErrorAction SilentlyContinue |
        Where-Object { $_.SessionId -eq $session -and [TMVPNDeployment]::ProcessPath($_.Id) -eq $hostExe })
    if ($matching.Count -gt 1) { throw 'Multiple installed TrafficMonitor processes in this session.' }
    if ($matching.Count -eq 1) { return $matching[0] }
}

function Test-PluginReady($Process) {
    if (-not $Process -or $Process.HasExited) { return $false }
    $eventName = "Local\TMVPNPlugin.GuardReady.$(Get-HostKey $Process)"
    try {
        $event = [Threading.EventWaitHandle]::OpenExisting($eventName, [Security.AccessControl.EventWaitHandleRights]::Synchronize)
        try { return $event.WaitOne(0) } finally { $event.Dispose() }
    } catch [Threading.WaitHandleCannotBeOpenedException] { return $false }
}

function Get-HostKey($Process) {
    if ($Process -and !$Process.HasExited) {
        $stamp = $Process.StartTime.ToUniversalTime().ToFileTimeUtc()
        return "$($Process.Id).$stamp"
    }
}

function Test-HelperExited([string]$HostKey) {
    if (!$HostKey) { return $true }
    try {
        $handle = [Threading.Mutex]::OpenExisting(
            "Local\TMVPNPlugin.Guard.$HostKey", [Security.AccessControl.MutexRights]::Synchronize)
        $handle.Dispose()
        return $false
    } catch [Threading.WaitHandleCannotBeOpenedException] { return $true }
}

function Get-LegacyTask { Get-ScheduledTask -TaskPath '\' -TaskName $legacyName }

function Assert-NativeDirectory([string]$Path) {
    $candidate = Join-Path $Path ('.tmvpn-deploy-' + [Guid]::NewGuid().ToString('N'))
    $stream = [IO.File]::Open($candidate, 'CreateNew', 'ReadWrite', 'None')
    try {
        if ([TMVPNDeployment]::FilePath($stream.SafeFileHandle) -ne $candidate) {
            throw "Deployment is seeing redirected AppData: $Path"
        }
    } finally {
        $stream.Dispose()
        [IO.File]::Delete($candidate)
    }
}

function Test-GuardIdle {
    try {
        $handle = [IO.File]::Open($guardLock, 'Open', 'ReadWrite', 'ReadWrite')
        try {
            $handle.Lock(0, 1)
            $handle.Unlock(0, 1)
            return $true
        } finally { $handle.Dispose() }
    } catch [IO.IOException] { return $false }
}

function Stop-Host {
    $running = Get-HostProcess
    if (-not $running) { return }
    $window = [TMVPNDeployment]::FindWindow('TrafficMonitor_r7XZaS4p', [IntPtr]::Zero)
    [uint32]$windowOwner = 0
    $null = [TMVPNDeployment]::GetWindowThreadProcessId($window, [ref]$windowOwner)
    if ($windowOwner -ne $running.Id -or $window -eq [IntPtr]::Zero) {
        throw 'Could not identify the installed TrafficMonitor main window.'
    }
    if (-not [TMVPNDeployment]::PostMessage($window, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)) {
        throw 'Windows refused the normal TrafficMonitor exit request.'
    }
    Wait-Condition { $running.HasExited } 30 'TrafficMonitor did not exit normally. It was not forcibly stopped.'
}

function Start-Host([switch]$ExpectPlugin) {
    if (-not (Get-HostProcess)) {
        Wait-Condition {
            (Get-HostProcess) -or (Get-ScheduledTask -TaskPath $autorunPath -TaskName $autorunName).State -eq 'Ready'
        } 15 'The existing TrafficMonitor task did not become ready to start.'
        if (-not (Get-HostProcess)) {
            Start-ScheduledTask -TaskPath $autorunPath -TaskName $autorunName
        }
    }
    Wait-Condition {
        $running = Get-HostProcess
        $running -and (!$ExpectPlugin -or (Test-PluginReady $running))
    } 45 'TrafficMonitor or its recovery helper did not become ready.'
}

function Get-FileDigest([string]$Path) {
    $algorithm = [Security.Cryptography.SHA256]::Create()
    $stream = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
    try { return [BitConverter]::ToString($algorithm.ComputeHash($stream)).Replace('-', '') }
    finally {
        $stream.Dispose()
        $algorithm.Dispose()
    }
}

function Copy-VerifiedFile([string]$Source, [string]$Destination) {
    $null = [IO.Directory]::CreateDirectory((Split-Path -Parent $Destination))
    [IO.File]::Copy($Source, $Destination, $true)
    if ((Get-FileDigest $Source) -ne (Get-FileDigest $Destination)) {
        throw "File contents differ after copy: $Destination"
    }
}

function Restore-PluginFiles([string]$BackupPath) {
    foreach ($relative in $files) {
        $saved = Join-Path (Join-Path $BackupPath 'previous') $relative
        $installed = Join-Path $plugins $relative
        if ([IO.File]::Exists($saved)) {
            Copy-VerifiedFile $saved $installed
        } elseif ($relative -ne 'TMVPNPlugin.dll') {
            [IO.File]::Delete($installed)
        } else {
            throw 'Backup DLL is missing. Plugin files were not restored.'
        }
    }
}

function Resume-Legacy {
    if ((Get-LegacyTask).State -eq 'Disabled') {
        $null = Enable-ScheduledTask -TaskPath '\' -TaskName $legacyName
    }
    [IO.File]::Delete($stopFile)
    if ((Get-LegacyTask).State -ne 'Running') {
        Start-ScheduledTask -TaskPath '\' -TaskName $legacyName
    }
    Wait-Condition { (Get-LegacyTask).State -eq 'Running' } 20 'The legacy guard did not restart.'
}

function Restore-OldSetup([string]$BackupPath) {
    $hostKey = Get-HostKey (Get-HostProcess)
    Stop-Host
    Wait-Condition { (Test-HelperExited $hostKey) -and (Test-GuardIdle) } 240 `
        'Recovery has not released its lock. Old files and task were left alone.'
    Restore-PluginFiles $BackupPath
    Resume-Legacy
    Start-Host
}

function Test-NoPendingTransaction {
    $stream = [IO.File]::Open((Join-Path $guard 'state.json'), 'Open', 'Read', 'ReadWrite, Delete')
    try {
        $reader = New-Object IO.StreamReader($stream, [Text.Encoding]::UTF8)
        $state = $reader.ReadToEnd() | ConvertFrom-Json
    } finally {
        $stream.Dispose()
    }
    if (!$state -or !$state.PSObject.Properties['transaction']) {
        throw 'Could not confirm the recovery transaction state.'
    }
    return $null -eq $state.transaction
}

function Stop-PluginHost {
    Wait-Condition { Test-NoPendingTransaction } 240 'The plugin still has a pending recovery transaction.'
    $hostKey = Get-HostKey (Get-HostProcess)
    Stop-Host
    Wait-Condition { (Test-HelperExited $hostKey) -and (Test-GuardIdle) -and (Test-NoPendingTransaction) } 240 `
        'The helper has not exited with a clean recovery state. Plugin files were left alone.'
}

function Restore-PreviousPlugin([string]$BackupPath) {
    if ((Get-LegacyTask).State -ne 'Disabled') { throw 'The legacy guard task must stay disabled for plugin rollback.' }
    try {
        Stop-PluginHost
    } catch {
        Start-Host -ExpectPlugin
        throw
    }
    Restore-PluginFiles $BackupPath
    Start-Host -ExpectPlugin
}

function Assert-TaskPrincipal($Task, [string]$RunLevel, [string]$Executable) {
    $taskUser = $Task.Principal.UserId
    if ($taskUser -notlike 'S-1-*') {
        $taskUser = (New-Object Security.Principal.NTAccount($taskUser)).Translate([Security.Principal.SecurityIdentifier]).Value
    }
    if ($taskUser -ne $identity.User.Value -or $Task.Principal.RunLevel -ne $RunLevel -or
        $Task.Principal.LogonType -ne 'Interactive' -or @($Task.Actions).Count -ne 1 -or
        $Task.Actions.Execute.Trim('"') -ne $Executable) {
        throw "Unexpected task identity or action: $($Task.TaskPath)$($Task.TaskName)"
    }
}

$deployLock = $null
$ownsDeployLock = $false
try {
    Initialize-Native
    $legacy = Get-LegacyTask
    $autorun = Get-ScheduledTask -TaskPath $autorunPath -TaskName $autorunName
    $python = 'C:\Python314\pythonw.exe'
    Assert-TaskPrincipal $autorun 'Highest' $hostExe
    Assert-TaskPrincipal $legacy 'Limited' $python
    if ($autorun.State -eq 'Disabled' -or ('' + $autorun.Actions.Arguments).Trim() -ne '' -or
        $legacy.Actions.Arguments -ne ('"{0}" --watch' -f (Join-Path $guard 'guard.py'))) {
        throw 'The existing TrafficMonitor or legacy task configuration does not match this installation.'
    }
    $report.legacyTask = [string]$legacy.State
    $report.trafficMonitorPid = (Get-HostProcess).Id
    $report.pluginReady = Test-PluginReady (Get-HostProcess)
    $report.paused = [IO.File]::Exists((Join-Path $guard 'monitor.pause'))
    $installedDll = Join-Path $plugins 'TMVPNPlugin.dll'
    if ([IO.File]::Exists($installedDll)) { $report.installedDllSha256 = Get-FileDigest $installedDll }
    if (!$VerifyOnly) {
        if (!$isAdmin -or [TMVPNDeployment]::GetShellWindow() -eq [IntPtr]::Zero) {
            throw 'Use an elevated PowerShell in the signed-in Windows desktop session.'
        }
        $deployLock = New-Object Threading.Mutex($false, 'Local\TMVPNPlugin.Deployment')
        try { $ownsDeployLock = $deployLock.WaitOne(0) } catch [Threading.AbandonedMutexException] { $ownsDeployLock = $true }
        if (!$ownsDeployLock) { throw 'Another TMVPNPlugin deployment is already running.' }
        Assert-NativeDirectory $guard
        Assert-NativeDirectory $plugins
        $installedPayload = Join-Path $plugins 'TMVPNPluginRecovery'
        if ([IO.Directory]::Exists($installedPayload)) { Assert-NativeDirectory $installedPayload }
        if ([IO.Directory]::Exists($backupRoot)) { Assert-NativeDirectory $backupRoot }
        if (![IO.File]::Exists($python) -or ![IO.File]::Exists($guardLock)) {
            throw 'Python 3.14 or the existing guard lock is missing.'
        }
        if ($Rollback) {
            $backup = (Resolve-Path -LiteralPath $Rollback).ProviderPath
            $isMigrationBackup = [IO.File]::Exists((Join-Path $backup 'ClashVergeSubscriptionGuard.xml'))
            $isUpgradeBackup = [IO.File]::Exists((Join-Path $backup 'plugin-upgrade')) -and
                @($files | Where-Object { ![IO.File]::Exists((Join-Path (Join-Path $backup 'previous') $_)) }).Count -eq 0
            if ((Split-Path -Parent $backup) -ne $backupRoot -or
                (!$isMigrationBackup -and !$isUpgradeBackup) -or
                ![IO.File]::Exists((Join-Path $backup 'previous\TMVPNPlugin.dll'))) {
                throw 'Choose a complete backup from this installation.'
            }
            Assert-NativeDirectory $backup
            $report.backup = $backup
            if ($isUpgradeBackup) {
                Restore-PreviousPlugin $backup
            } else {
                Restore-OldSetup $backup
            }
        } else {
            if ($Upgrade) {
                if ($legacy.State -ne 'Disabled' -or !$report.pluginReady -or !(Get-HostProcess)) {
                    throw 'Expected the installed plugin to be running and the legacy guard task to be disabled.'
                }
                foreach ($relative in $files) {
                    if (![IO.File]::Exists((Join-Path $plugins $relative))) { throw "Missing installed plugin file: $relative" }
                }
            } elseif ($legacy.State -ne 'Running' -or $report.pluginReady -or !(Get-HostProcess)) {
                throw 'Expected the old guard and TrafficMonitor to be running before first migration.'
            }
            $sourceDll = (Resolve-Path -LiteralPath $PluginDll).ProviderPath
            $sources = @($sourceDll, (Join-Path $PSScriptRoot 'recovery\guard.py'), (Join-Path $PSScriptRoot 'recovery\verge_ui.ps1'))
            if (![IO.File]::Exists($installedDll) -or $sourceDll -eq $installedDll) {
                throw 'A current installed DLL and a separate staged DLL are required.'
            }
            foreach ($source in $sources) {
                if (![IO.File]::Exists($source)) { throw "Missing staged file: $source" }
            }
            if ((Get-FileDigest $sourceDll) -eq (Get-FileDigest $installedDll)) {
                throw 'The staged DLL is identical to the installed DLL. Build the new plugin first.'
            }
            $backup = Join-Path $backupRoot ([DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fff'))
            $null = [IO.Directory]::CreateDirectory($backup)
            Assert-NativeDirectory $backup
            $report.backup = $backup
            if (!$Upgrade) {
                Export-ScheduledTask -TaskPath '\' -TaskName $legacyName |
                    Set-Content -LiteralPath (Join-Path $backup 'ClashVergeSubscriptionGuard.xml') -Encoding Unicode
            }
            for ($i = 0; $i -lt $files.Count; $i++) {
                $relative = $files[$i]
                $staged = Join-Path (Join-Path $backup 'staged') $relative
                $previous = Join-Path (Join-Path $backup 'previous') $relative
                $installed = Join-Path $plugins $relative
                Copy-VerifiedFile $sources[$i] $staged
                if ([IO.File]::Exists($installed)) {
                    Copy-VerifiedFile $installed $previous
                }
            }
            if ($Upgrade) { [IO.File]::WriteAllText((Join-Path $backup 'plugin-upgrade'), '1') }
            $filesChanging = $false
            $hostClosing = $false
            try {
                if ($Upgrade) {
                    $hostClosing = $true
                    Stop-PluginHost
                } else {
                    [IO.File]::WriteAllText($stopFile, 'stop')
                    Wait-Condition { (Get-LegacyTask).State -eq 'Ready' -and (Test-GuardIdle) } 240 `
                        'The legacy guard has not finished its current operation. It was not forcibly stopped.'
                    if (!(Test-NoPendingTransaction)) { throw 'The legacy guard still has a pending recovery transaction.' }
                    $null = Disable-ScheduledTask -TaskPath '\' -TaskName $legacyName
                    $hostClosing = $true
                    Stop-Host
                }
                if ((Get-LegacyTask).State -ne 'Disabled') { throw 'The legacy guard task must be disabled before replacing plugin files.' }
                $filesChanging = $true
                foreach ($relative in $files) {
                    $installed = Join-Path $plugins $relative
                    Copy-VerifiedFile (Join-Path (Join-Path $backup 'staged') $relative) $installed
                }
                Start-Host -ExpectPlugin
            } catch {
                $deploymentError = $_.Exception.Message
                try {
                    if ($Upgrade) {
                        if ($filesChanging) {
                            Restore-PreviousPlugin $backup
                        } elseif ($hostClosing) {
                            Start-Host -ExpectPlugin
                        }
                    } elseif ($filesChanging) {
                        Restore-OldSetup $backup
                    } else {
                        Resume-Legacy
                        if ($hostClosing) { Start-Host }
                    }
                    $report.rolledBack = $true
                } catch {
                    $report.rollbackError = $_.Exception.Message
                }
                throw $deploymentError
            }
        }
    }
    $report.legacyTask = [string](Get-LegacyTask).State
    $report.trafficMonitorPid = (Get-HostProcess).Id
    $report.pluginReady = Test-PluginReady (Get-HostProcess)
    if ([IO.File]::Exists($installedDll)) { $report.installedDllSha256 = Get-FileDigest $installedDll }
    $report.ok = $true
} catch {
    $report.error = $_.Exception.Message
} finally {
    if ($deployLock) {
        if ($ownsDeployLock) { $deployLock.ReleaseMutex() }
        $deployLock.Dispose()
    }
}

$json = [pscustomobject]$report | ConvertTo-Json -Compress
if ($ResultPath) {
    $fullResult = [IO.Path]::GetFullPath($ResultPath)
    $temporary = "$fullResult.$PID.tmp"
    [IO.File]::WriteAllText($temporary, $json, (New-Object Text.UTF8Encoding($false)))
    if ([IO.File]::Exists($fullResult)) {
        [IO.File]::Replace($temporary, $fullResult, $null)
    } else {
        [IO.File]::Move($temporary, $fullResult)
    }
}
$json
if (!$report.ok) { exit 1 }
