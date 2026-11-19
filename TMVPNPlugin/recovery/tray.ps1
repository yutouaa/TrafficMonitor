param(
    [Parameter(Mandatory = $true)][string]$PythonExecutable,
    [Parameter(Mandatory = $true)][string]$GuardScript,
    [Parameter(Mandatory = $true)][string]$StorageDirectory,
    [Parameter(Mandatory = $true)][int]$OwnerPid
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
Add-Type -TypeDefinition @'
using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.Runtime.InteropServices;
using System.Windows.Forms;
public sealed class ClashTaskbarBadge : Form {
    [StructLayout(LayoutKind.Sequential)] struct RECT { public int Left, Top, Right, Bottom; }
    [StructLayout(LayoutKind.Sequential)] struct POINT { public int X, Y; }
    [StructLayout(LayoutKind.Sequential)] struct SIZE { public int Width, Height; }
    [StructLayout(LayoutKind.Sequential, Pack=1)] struct BLEND { public byte Operation, Flags, Alpha, Format; }
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern IntPtr FindWindow(string c, string n);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern IntPtr FindWindowEx(IntPtr p, IntPtr a, string c, string n);
    [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr w, out RECT r);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr w);
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
    [DllImport("user32.dll")] static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] static extern bool SetWindowPos(IntPtr w, IntPtr after, int x, int y, int cx, int cy, uint flags);
    [DllImport("user32.dll")] static extern uint GetDpiForWindow(IntPtr w);
    [DllImport("user32.dll")] static extern IntPtr GetDC(IntPtr w);
    [DllImport("user32.dll")] static extern int ReleaseDC(IntPtr w, IntPtr dc);
    [DllImport("gdi32.dll")] static extern IntPtr CreateCompatibleDC(IntPtr dc);
    [DllImport("gdi32.dll")] static extern IntPtr SelectObject(IntPtr dc, IntPtr obj);
    [DllImport("gdi32.dll")] static extern bool DeleteObject(IntPtr obj);
    [DllImport("gdi32.dll")] static extern bool DeleteDC(IntPtr dc);
    [DllImport("user32.dll", SetLastError=true)] static extern bool UpdateLayeredWindow(IntPtr w, IntPtr dst,
        ref POINT position, ref SIZE size, IntPtr src, ref POINT origin, uint key, ref BLEND blend, uint flags);
    string caption="", paintedCaption=null;
    Size paintedSize;
    float renderDpi=96;
    readonly Font badgeFont=new Font("Segoe UI",10,FontStyle.Regular);
    public string BadgeText { get { return caption; } set { caption=value ?? ""; } }
    protected override bool ShowWithoutActivation { get { return true; } }
    protected override CreateParams CreateParams {
        get { var p=base.CreateParams; p.ExStyle |= 0x08000000 | 0x00000080 | 0x00080000; return p; }
    }
    public ClashTaskbarBadge() {
        Text="Clash 节点延迟";
        FormBorderStyle=FormBorderStyle.None;
        ShowInTaskbar=false;
        AutoScaleMode=AutoScaleMode.None;
        StartPosition=FormStartPosition.Manual;
        Font=badgeFont;
        Cursor=Cursors.Hand;
    }
    public static Bitmap RenderText(string text, Font font, Size size, float dpi) {
        var bitmap=new Bitmap(size.Width,size.Height,PixelFormat.Format32bppPArgb);
        try {
            bitmap.SetResolution(dpi,dpi);
            using(var graphics=Graphics.FromImage(bitmap))
            using(var format=new StringFormat()) {
                graphics.Clear(Color.Transparent);
                graphics.TextRenderingHint=System.Drawing.Text.TextRenderingHint.AntiAliasGridFit;
                format.Alignment=StringAlignment.Center;
                format.LineAlignment=StringAlignment.Center;
                format.FormatFlags=StringFormatFlags.NoWrap;
                format.Trimming=StringTrimming.EllipsisCharacter;
                graphics.DrawString(text,font,Brushes.White,new RectangleF(0,0,size.Width,size.Height),format);
            }
            return bitmap;
        } catch { bitmap.Dispose(); throw; }
    }
    public void RefreshSurface() {
        if(caption==paintedCaption && ClientSize==paintedSize) return;
        using(var bitmap=RenderText(caption,Font,ClientSize,renderDpi)) {
            IntPtr screen=GetDC(IntPtr.Zero), dc=IntPtr.Zero, image=IntPtr.Zero, previous=IntPtr.Zero;
            try {
                dc=CreateCompatibleDC(screen);
                image=bitmap.GetHbitmap(Color.FromArgb(0));
                previous=SelectObject(dc,image);
                if(screen==IntPtr.Zero || dc==IntPtr.Zero || previous==IntPtr.Zero || previous==new IntPtr(-1))
                    throw new InvalidOperationException("badge_surface_unavailable");
                var position=new POINT { X=Left,Y=Top };
                var size=new SIZE { Width=Width,Height=Height };
                var origin=new POINT();
                var blend=new BLEND { Alpha=255,Format=1 };
                if(!UpdateLayeredWindow(Handle,screen,ref position,ref size,dc,ref origin,0,ref blend,2))
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                paintedCaption=caption;
                paintedSize=ClientSize;
            } finally {
                if(previous!=IntPtr.Zero && previous!=new IntPtr(-1)) SelectObject(dc,previous);
                if(image!=IntPtr.Zero) DeleteObject(image);
                if(dc!=IntPtr.Zero) DeleteDC(dc);
                if(screen!=IntPtr.Zero) ReleaseDC(IntPtr.Zero,screen);
            }
        }
    }
    protected override void Dispose(bool disposing) {
        base.Dispose(disposing);
        if(disposing) badgeFont.Dispose();
    }
    public void AnchorToTaskbar() {
        var bar=FindWindow("Shell_TrayWnd", null);
        RECT r, n;
        if(bar==IntPtr.Zero || !IsWindowVisible(bar) || !GetWindowRect(bar,out r) || r.Bottom-r.Top<8) { Hide(); return; }
        var notify=FindWindowEx(bar,IntPtr.Zero,"TrayNotifyWnd",null);
        if(notify==IntPtr.Zero || !GetWindowRect(notify,out n)) { Hide(); return; }
        // shortcut: 主屏水平任务栏的通知区域左侧叠放；垂直任务栏仅保留托盘入口。
        if(r.Right-r.Left < r.Bottom-r.Top) { Hide(); return; }
        var screen=Screen.FromRectangle(new Rectangle(r.Left,r.Top,r.Right-r.Left,r.Bottom-r.Top)).Bounds;
        RECT foreground;
        var front=GetForegroundWindow();
        if(r.Top>=screen.Bottom-2 || (front!=Handle && front!=bar && GetWindowRect(front,out foreground) &&
           foreground.Left<=screen.Left && foreground.Top<=screen.Top && foreground.Right>=screen.Right && foreground.Bottom>=screen.Bottom)) { Hide(); return; }
        int height=r.Bottom-r.Top;
        int width=Math.Min(240,Math.Max(160,height*4));
        var dpi=GetDpiForWindow(bar);
        if(dpi!=0 && renderDpi!=dpi) { renderDpi=dpi; paintedCaption=null; }
        Bounds=new Rectangle(Math.Max(r.Left,n.Left-width-6),r.Top+2,width,height-4);
        RefreshSurface();
        if(!Visible) Show();
        SetWindowPos(Handle,new IntPtr(-1),Left,Top,Width,Height,0x0010 | 0x0040);
    }
}
'@ -ReferencedAssemblies System.Windows.Forms,System.Drawing
[void][ClashTaskbarBadge]::SetProcessDPIAware()
$directory = $StorageDirectory
$pauseFile = Join-Path $directory 'monitor.pause'
try { $trayLock = [System.IO.File]::Open((Join-Path $directory 'tray.lock'), 'OpenOrCreate', 'ReadWrite', 'None') } catch { exit }
$owner = Get-Process -Id $OwnerPid -ErrorAction Stop
$ownerStarted = $owner.StartTime.ToUniversalTime().Ticks

$script:sample = $null
$script:probe = $null
$script:report = Join-Path $directory ('tray-status-' + $PID + '.json')
$script:probeStarted = [DateTime]::MinValue
$script:nextProbe = [DateTime]::MinValue
$script:lastError = $null
$icon = New-Object System.Windows.Forms.NotifyIcon
$menu = New-Object System.Windows.Forms.ContextMenuStrip
$titleItem = $menu.Items.Add('Clash 订阅守护')
$titleItem.Enabled = $false
$statusItem = $menu.Items.Add('自动检查：正在读取状态')
$nodeItem = $menu.Items.Add('当前节点：正在读取')
$delayItem = $menu.Items.Add('节点延迟：正在读取')
$timeItem = $menu.Items.Add('刷新时间：等待首次测量')
$timeItem.Enabled = $false
$statusItem.Enabled = $false
$nodeItem.Enabled = $false
$delayItem.Enabled = $false
[void]$menu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator))
$toggleItem = $menu.Items.Add('自动检查与恢复（每 10 秒）')
$toggleItem.CheckOnClick = $false
$refreshItem = $menu.Items.Add('立即刷新延迟')
$icon.ContextMenuStrip = $menu
$icon.Icon = [System.Drawing.SystemIcons]::Information
$icon.Text = 'Clash 订阅守护：正在读取状态'
$icon.Visible = $true
$badge = New-Object ClashTaskbarBadge
$badge.ContextMenuStrip = $menu
$badgeTip = New-Object System.Windows.Forms.ToolTip
$badge.add_MouseClick({
    param($sender, $eventArgs)
    if ($eventArgs.Button -eq [System.Windows.Forms.MouseButtons]::Left) { $menu.Show([System.Windows.Forms.Cursor]::Position) }
})

function Update-Tray {
    $enabled = -not [System.IO.File]::Exists($pauseFile)
    $toggleItem.Checked = $enabled
    $stateText = if ($enabled) { '已开启，每 10 秒检查' } else { '已暂停（延迟显示仍刷新）' }
    $watchState = $null
    try { $watchState = [System.IO.File]::ReadAllText((Join-Path $directory 'state.json')) | ConvertFrom-Json } catch { }
    if ($watchState -and $watchState.transaction) {
        $stateText += $(if ($enabled) { '，正在恢复' } else { '，本次恢复完成后暂停' })
    }
    $statusItem.Text = '自动检查：' + $stateText
    $nodeText = if ($script:sample -and $script:sample.selected) { [string]$script:sample.selected } elseif ($script:sample -and $script:sample.mode -ne 'global') { '当前模式无单一全局节点' } else { '未获取' }
    $delayText = if ($script:sample -and $null -ne $script:sample.latency_ms) {
        [string]$script:sample.latency_ms + ' ms'
    } elseif ($script:lastError) {
        $script:lastError
    } elseif ($script:sample -and $script:sample.latency_status) {
        [string]$script:sample.latency_status
    } else { '正在测量' }
    $nodeItem.Text = '当前节点：' + $nodeText
    $delayItem.Text = '节点延迟：' + $delayText
    $statusItem.ToolTipText = if ($watchState) { [string]$watchState.last_status } else { '' }
    $delayItem.ToolTipText = '到测试地址的连通延迟；每 10 秒刷新，测速期间保留上一结果。'
    if ($script:sample -and $script:sample.sampled_at) {
        $sampleTime = [DateTimeOffset]::FromUnixTimeSeconds([long]$script:sample.sampled_at)
        $timeItem.Text = '刷新时间：' + $sampleTime.LocalDateTime.ToString('HH:mm:ss')
    } else { $timeItem.Text = '刷新时间：等待有效测量' }
    $text = 'Clash 检查' + $(if ($enabled) { '开启' } else { '暂停' }) + ' | ' + $delayText + "`n" + $nodeText
    $icon.Text = $text.Substring(0, [Math]::Min(63, $text.Length))
    $icon.Icon = if (-not $enabled) { [System.Drawing.SystemIcons]::Application } elseif ($script:lastError) {
        [System.Drawing.SystemIcons]::Warning
    } else { [System.Drawing.SystemIcons]::Information }
    if ($badge) {
        $shortNode = if ($nodeText -eq 'PRO | 日本家宽S VL03 | 2倍') { '日本家宽VL03' } elseif ($nodeText -match 'VL\d+') { $Matches[0] } else { $nodeText.Substring(0, [Math]::Min(12, $nodeText.Length)) }
        $shortDelay = if ($script:sample -and $null -ne $script:sample.latency_ms) { [string]$script:sample.latency_ms + ' ms' } elseif ($script:lastError) { '不可用' } else { '-- ms' }
        $badge.BadgeText = $(if ($enabled) { '' } else { '暂停 | ' }) + $shortNode + ' · ' + $shortDelay
        $badgeTip.SetToolTip($badge, $statusItem.Text + "`n" + $nodeItem.Text + "`n" + $delayItem.Text + "`n点击开关自动检查")
    }
}

function Remove-ProbeFiles {
    if ($script:report) {
        Remove-Item -LiteralPath $script:report -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath ([System.IO.Path]::ChangeExtension($script:report, '.tmp')) -Force -ErrorAction SilentlyContinue
    }
}

function Start-Probe {
    Remove-ProbeFiles
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = $PythonExecutable
    $start.Arguments = '"' + $GuardScript + '" --tray-status --report "' + $script:report + '"'
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    $script:probe = [System.Diagnostics.Process]::Start($start)
    $script:probeStarted = [DateTime]::UtcNow
    $script:nextProbe = $script:probeStarted.AddSeconds(10)
}

function Stop-Probe {
    if ($script:probe) {
        if (-not $script:probe.HasExited) {
            # 连同管道读写子进程退出，避免只杀测速父进程后留下阻塞的 worker。
            $stop = New-Object System.Diagnostics.ProcessStartInfo
            $stop.FileName = Join-Path $env:WINDIR 'System32\taskkill.exe'
            $stop.Arguments = '/PID ' + $script:probe.Id + ' /T /F'
            $stop.UseShellExecute = $false
            $stop.CreateNoWindow = $true
            $stop.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
            $killer = [System.Diagnostics.Process]::Start($stop)
            [void]$killer.WaitForExit(2000)
            $killer.Dispose()
        }
        $script:probe.Dispose()
        $script:probe = $null
    }
    Remove-ProbeFiles
}

$toggleItem.add_Click({
    try {
        if ([System.IO.File]::Exists($pauseFile)) { [System.IO.File]::Delete($pauseFile) }
        else { [System.IO.File]::WriteAllText($pauseFile, 'paused') }
        Update-Tray
    } catch {
        $icon.ShowBalloonTip(5000, '无法切换自动检查', '请检查安装目录写入权限。', [System.Windows.Forms.ToolTipIcon]::Error)
    }
})
$refreshItem.add_Click({ $script:nextProbe = [DateTime]::MinValue })
$menu.add_Opening({ Update-Tray })
$icon.add_MouseClick({
    param($sender, $eventArgs)
    if ($eventArgs.Button -eq [System.Windows.Forms.MouseButtons]::Left) {
        $menu.Show([System.Windows.Forms.Cursor]::Position)
    }
})
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 500
$timer.add_Tick({
    $ownerNow = Get-Process -Id $OwnerPid -ErrorAction SilentlyContinue
    if (-not $ownerNow -or $ownerNow.StartTime.ToUniversalTime().Ticks -ne $ownerStarted) { [System.Windows.Forms.Application]::Exit(); return }
    try {
        if ($script:probe) {
            if ($script:probe.HasExited) {
                try {
                    $data = [System.IO.File]::ReadAllText($script:report) | ConvertFrom-Json
                    if (-not $data.ok) { throw 'status_unavailable' }
                    $script:sample = $data
                    $script:lastError = $null
                } catch { $script:sample = $null; $script:lastError = '内核未运行或状态不可用' }
                $script:probe.Dispose()
                $script:probe = $null
                Update-Tray
            } elseif (([DateTime]::UtcNow - $script:probeStarted).TotalSeconds -gt 30) {
                Stop-Probe
                $script:sample = $null
                $script:lastError = '测速超时'
                Update-Tray
            }
        }
        if (-not $script:probe -and [DateTime]::UtcNow -ge $script:nextProbe) { Start-Probe }
        Update-Tray
        $badge.AnchorToTaskbar()
    } catch {
        $script:sample = $null
        $script:lastError = '无法读取守护状态'
        $script:nextProbe = [DateTime]::UtcNow.AddSeconds(10)
        Update-Tray
    }
})
try {
    Update-Tray
    $badge.AnchorToTaskbar()
    $timer.Start()
    [System.Windows.Forms.Application]::Run()
} finally {
    $timer.Stop()
    $timer.Dispose()
    $icon.Visible = $false
    $icon.Dispose()
    $menu.Dispose()
    $badgeTip.Dispose()
    $badge.Dispose()
    Stop-Probe
    $trayLock.Dispose()
}
