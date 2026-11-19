[CmdletBinding(DefaultParameterSetName = 'Package')]
param(
    [string]$ToolCache = "$PSScriptRoot\build\package-cache",
    [Parameter(ParameterSetName = 'Vendor', Mandatory)][switch]$PrepareVendor,
    [Parameter(ParameterSetName = 'Vendor', Mandatory)][string]$StageDir,
    [Parameter(ParameterSetName = 'Package')][string]$Commit = 'HEAD',
    [Parameter(ParameterSetName = 'Package')][string]$OutputDir = "$PSScriptRoot\build",
    [Parameter(ParameterSetName = 'Package')][string]$InnoCompiler,
    [Parameter(ParameterSetName = 'Package')][string]$VSRedist = 'C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Redist\MSVC\14.51.36231\vc_redist.x64.exe'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$ToolCache = [IO.Path]::GetFullPath($ToolCache)
$null = [IO.Directory]::CreateDirectory($ToolCache)

function Assert-Hash([string]$File, [string]$Sha256) {
    if ((Get-FileHash -LiteralPath $File -Algorithm SHA256).Hash -ne $Sha256) {
        throw "SHA-256 mismatch: $File"
    }
}

function Get-PinnedFile([string]$Name, [string]$Url, [string]$Sha256) {
    $file = Join-Path $ToolCache $Name
    if (!(Test-Path -LiteralPath $file -PathType Leaf)) {
        $temporary = "$file.$PID.download"
        Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $temporary
        Assert-Hash $temporary $Sha256
        Move-Item -LiteralPath $temporary -Destination $file
    }
    Assert-Hash $file $Sha256
    return $file
}

function Invoke-Native([string]$Executable, [string[]]$Arguments) {
    & $Executable @Arguments | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "Command failed ($LASTEXITCODE): $Executable" }
}

function Install-Yaml([string]$RecoveryDir) {
    $name = 'pyyaml-6.0.3.tar.gz'
    $sourceUrl = 'https://files.pythonhosted.org/packages/05/8e/961c0007c59b8dd7729d542c61a4d537767a59645b82a0b521206e1e25c2/pyyaml-6.0.3.tar.gz'
    $archive = Get-PinnedFile $name $sourceUrl 'd76623373421df22fb4cf8817020cbb7ef15c725b9d5e45f17e189bfc384190f'
    $source = Join-Path $ToolCache ('pyyaml-' + [guid]::NewGuid().ToString('N'))
    $null = [IO.Directory]::CreateDirectory($source)
    Invoke-Native tar.exe @('-xf', $archive, '-C', $source, 'pyyaml-6.0.3/lib/yaml', 'pyyaml-6.0.3/LICENSE')
    $vendor = Join-Path $RecoveryDir 'vendor'
    $yaml = Join-Path $vendor 'yaml'
    if (Test-Path -LiteralPath $yaml) { throw "Choose a fresh vendor directory: $yaml" }
    $null = [IO.Directory]::CreateDirectory($yaml)
    Get-ChildItem -LiteralPath (Join-Path $source 'pyyaml-6.0.3\lib\yaml') -Filter '*.py' -File |
        ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $yaml }
    Copy-Item -LiteralPath (Join-Path $source 'pyyaml-6.0.3\LICENSE') -Destination (Join-Path $vendor 'PyYAML-LICENSE.txt')
}

if ($PrepareVendor) {
    Install-Yaml ([IO.Path]::GetFullPath($StageDir))
    return
}

if (!$InnoCompiler) {
    $InnoCompiler = Join-Path $ToolCache 'inno\ISCC.exe'
    if (!(Test-Path -LiteralPath $InnoCompiler -PathType Leaf)) {
        $InnoCompiler = Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'
    }
}
if (!(Test-Path -LiteralPath $InnoCompiler -PathType Leaf)) {
    throw 'Install Inno Setup 6.5.4 and pass -InnoCompiler with its ISCC.exe path.'
}
Assert-Hash $VSRedist '843068991daaA1f73ad9f6239bce4d0f6a07a51f18c37ea2a867e9beca71295c'
$signature = Get-AuthenticodeSignature -LiteralPath $VSRedist
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch '^CN=Microsoft Corporation,') {
    throw 'The Microsoft Visual C++ redistributable signature could not be verified.'
}

$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$sha = & git -C $root rev-parse --verify --end-of-options "$Commit^{commit}"
if ($LASTEXITCODE -ne 0 -or $sha -cnotmatch '^[a-f0-9]{40}$') { throw 'Invalid source commit.' }
$stage = Join-Path $ToolCache ('stage-' + [guid]::NewGuid().ToString('N'))
$snapshot = Join-Path $stage 'source'
$bin = Join-Path $stage 'bin'
foreach ($path in @($snapshot, $bin)) { $null = [IO.Directory]::CreateDirectory($path) }
$sourceArchive = Join-Path $stage 'source.zip'
Invoke-Native git @('-C', $root, 'archive', '--format=zip', "--output=$sourceArchive", $sha,
    'TMVPNPlugin', 'include', 'LICENSE', 'LICENSE_CN')
Expand-Archive -LiteralPath $sourceArchive -DestinationPath $snapshot
$plugin = Join-Path $snapshot 'TMVPNPlugin'
Invoke-Native (Join-Path $plugin 'build.bat') @($bin)

$appZip = Get-PinnedFile 'TrafficMonitor_V1.86_x64.zip' 'https://github.com/zhongyang219/TrafficMonitor/releases/download/V1.86/TrafficMonitor_V1.86_x64.zip' '948ddc12cc582e8cf0b7b32e0064544f6f711265a7671c2e47343a6a0ff4908e'
$pythonZip = Get-PinnedFile 'python-3.14.10-embed-amd64.zip' 'https://www.python.org/ftp/python/3.14.10/python-3.14.10-embed-amd64.zip' '90905e64a840557d8c1bc4f5b74db3d7ee85e3ffb217611cac1c7813acea4159'
Expand-Archive -LiteralPath $appZip -DestinationPath $stage
$payload = Join-Path $stage 'TrafficMonitor'
$plugins = Join-Path $payload 'plugins'
$recovery = Join-Path $plugins 'TMVPNPluginRecovery'
$null = [IO.Directory]::CreateDirectory($recovery)
Copy-Item -LiteralPath (Join-Path $bin 'TMVPNPlugin.dll') -Destination $plugins
Copy-Item -LiteralPath (Join-Path $plugin 'recovery\verge_ui.ps1') -Destination $recovery
Get-ChildItem -LiteralPath (Join-Path $plugin 'recovery') -Filter '*.py' -File |
    Where-Object { $_.Name -notlike 'test_*' } |
    ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $recovery }
Expand-Archive -LiteralPath $pythonZip -DestinationPath (Join-Path $recovery 'python')
Install-Yaml $recovery

Copy-Item -LiteralPath (Join-Path $snapshot 'LICENSE') -Destination (Join-Path $payload 'LICENSE.txt')
Copy-Item -LiteralPath (Join-Path $snapshot 'LICENSE_CN') -Destination (Join-Path $payload 'LICENSE_CN.txt')
Copy-Item -LiteralPath (Join-Path $plugin 'README.md') -Destination (Join-Path $payload 'README.md')
Set-Content -LiteralPath (Join-Path $payload 'package-commit.txt') -Value $sha -Encoding Ascii
Set-Content -LiteralPath (Join-Path $payload 'global_cfg.ini') -Value @('[config]', 'portable_mode=true') -Encoding Ascii
Set-Content -LiteralPath (Join-Path $payload 'config.ini') -Encoding Ascii -Value @(
    '[general]', 'check_update_when_start=false', '[config]', 'show_task_bar_wnd=true', '[task_bar]',
    'tbar_display_item=0', 'plugin_display_item=vpn_node_delay,vpn_net_speed,vpn_conn_status')

$OutputDir = [IO.Path]::GetFullPath($OutputDir)
$null = [IO.Directory]::CreateDirectory($OutputDir)
$basename = 'TrafficMonitor-VPN-x64-Setup'
Copy-Item -LiteralPath $VSRedist -Destination (Join-Path $stage 'vc_redist.x64.exe')
Invoke-Native $InnoCompiler @("/O$OutputDir", "/F$basename", "/DPayload=$payload", "/DStage=$stage", (Join-Path $plugin 'installer.iss'))
$installer = Join-Path $OutputDir "$basename.exe"
[pscustomobject]@{
    Installer = $installer
    Payload = $payload
    TestHost = Join-Path $bin 'test_host.exe'
    Commit = $sha
    SHA256 = (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash
} | ConvertTo-Json -Compress
