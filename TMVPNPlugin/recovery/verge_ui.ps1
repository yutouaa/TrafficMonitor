param(
    [Parameter(Mandatory = $true)][ValidateSet('probe', 'snapshot', 'prepare', 'protect', 'update', 'restore')][string]$Action,
    [Parameter(Mandatory = $true)][string]$ProfileName,
    [string]$SnapshotJson = ''
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$env:PSModulePath = "$env:WINDIR\System32\WindowsPowerShell\v1.0\Modules;$env:ProgramFiles\WindowsPowerShell\Modules"
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$script:MenuOpened = $false
$script:UpdateInvoked = $false
$script:PreparedInput = $null

function Fail([string]$Code, [string]$Message) {
    $failure = New-Object System.InvalidOperationException($Message)
    $failure.Data['guard_code'] = $Code
    throw $failure
}

try {
    Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes, WindowsBase
    Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Collections.Generic;
public static class GuardWindow {
    public delegate bool EnumProc(IntPtr hwnd, IntPtr param);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc callback, IntPtr param);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetWindowText(IntPtr hwnd, StringBuilder text, int count);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern IntPtr FindWindow(string className, string windowName);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
    [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr hwnd);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hwnd);
    [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr hwnd);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hwnd, int mode);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hwnd);
    [StructLayout(LayoutKind.Sequential)] struct LastInputInfo { public uint Size, Tick; }
    [DllImport("user32.dll")] static extern bool GetLastInputInfo(ref LastInputInfo info);
    [DllImport("kernel32.dll")] static extern uint GetCurrentThreadId();
    [DllImport("user32.dll")] static extern bool AttachThreadInput(uint source, uint target, bool attach);
    [DllImport("user32.dll")] static extern IntPtr OpenInputDesktop(uint flags, bool inherit, uint access);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern bool GetUserObjectInformation(IntPtr obj, int index, StringBuilder info, int size, out int needed);
    [DllImport("user32.dll")] static extern bool CloseDesktop(IntPtr desktop);
    [DllImport("user32.dll")] public static extern IntPtr GetAncestor(IntPtr hwnd, uint flags);
    [StructLayout(LayoutKind.Sequential)] public struct Point { public int X; public int Y; }
    static Point previousPointer, injectedPointer;
    static bool pointerPending;
    [DllImport("user32.dll")] static extern bool GetCursorPos(out Point p);
    [DllImport("user32.dll")] static extern bool SetCursorPos(int x, int y);
    [DllImport("user32.dll")] static extern IntPtr WindowFromPoint(Point p);
    [StructLayout(LayoutKind.Sequential)] struct MouseInput { public int dx, dy; public uint mouseData, flags, time; public UIntPtr extra; }
    [StructLayout(LayoutKind.Sequential)] struct Input { public uint type; public MouseInput mouse; }
    [DllImport("user32.dll", SetLastError=true)] static extern uint SendInput(uint count, Input[] input, int size);
    [DllImport("user32.dll")] static extern void keybd_event(byte key, byte scan, uint flags, UIntPtr extra);
    public static int Pid(IntPtr hwnd) { uint pid; GetWindowThreadProcessId(hwnd, out pid); return (int)pid; }
    public static long GetLastInputTick() {
        var info = new LastInputInfo { Size = (uint)Marshal.SizeOf(typeof(LastInputInfo)) };
        return GetLastInputInfo(ref info) ? (long)info.Tick : -1;
    }
    public static IntPtr Taskbar() {
        IntPtr hwnd = FindWindow("Shell_TrayWnd", null);
        if (hwnd == IntPtr.Zero || !IsWindowVisible(hwnd)) return IntPtr.Zero;
        try { return Process.GetProcessById(Pid(hwnd)).ProcessName == "explorer" ? hwnd : IntPtr.Zero; }
        catch { return IntPtr.Zero; }
    }
    public static bool IsShellWindow(IntPtr hwnd) {
        if (hwnd == IntPtr.Zero) return true;
        try { return Process.GetProcessById(Pid(hwnd)).ProcessName.Equals("explorer", StringComparison.OrdinalIgnoreCase); }
        catch { return false; }
    }
    public static bool TryForeground(IntPtr hwnd, int targetPid, IntPtr expectedForeground) {
        uint currentThread = 0, foregroundThread = 0;
        bool attached = false;
        try {
            if (!Unlocked() || !IsWindow(hwnd) || Pid(hwnd) != targetPid) return false;
            IntPtr foreground = GetForegroundWindow();
            if (Pid(foreground) == targetPid) return true;
            if (foreground != expectedForeground && !IsShellWindow(foreground)) return false;
            uint ignored;
            foregroundThread = GetWindowThreadProcessId(foreground, out ignored);
            currentThread = GetCurrentThreadId();
            if (foregroundThread != 0 && foregroundThread != currentThread) {
                attached = AttachThreadInput(currentThread, foregroundThread, true);
                if (!attached) return false;
            }
            // The foreground can change while input queues are being attached.
            if (!Unlocked() || !IsWindow(hwnd) || Pid(hwnd) != targetPid) return false;
            foreground = GetForegroundWindow();
            if (Pid(foreground) == targetPid) return true;
            if (foreground != expectedForeground && !IsShellWindow(foreground)) return false;
            SetForegroundWindow(hwnd);
            return Pid(GetForegroundWindow()) == targetPid;
        }
        finally {
            if (attached) AttachThreadInput(currentThread, foregroundThread, false);
        }
    }
    public static IntPtr[] Windows() {
        var found = new List<IntPtr>();
        EnumWindows(delegate(IntPtr hwnd, IntPtr ignored) {
            var title = new StringBuilder(512); GetWindowText(hwnd, title, title.Capacity);
            if (title.ToString() != "Clash Verge") return true;
            try { if (Process.GetProcessById(Pid(hwnd)).ProcessName == "clash-verge") found.Add(hwnd); } catch { }
            return true;
        }, IntPtr.Zero);
        if (found.Count == 0) {
            EnumWindows(delegate(IntPtr hwnd, IntPtr ignored) {
                if (!IsWindowVisible(hwnd)) return true;
                try { if (Process.GetProcessById(Pid(hwnd)).ProcessName == "clash-verge") found.Add(hwnd); } catch { }
                return true;
            }, IntPtr.Zero);
        }
        return found.ToArray();
    }
    public static bool Unlocked() {
        IntPtr desk = OpenInputDesktop(0, false, 1);
        if (desk == IntPtr.Zero) return false;
        try { int needed; var name = new StringBuilder(256); return GetUserObjectInformation(desk, 2, name, name.Capacity * 2, out needed) && name.ToString() == "Default"; }
        finally { CloseDesktop(desk); }
    }
    public static bool RightClick(IntPtr hwnd, int x, int y) {
        var target = new Point { X=x, Y=y };
        if (!Unlocked() || Pid(GetForegroundWindow()) != Pid(hwnd) || GetAncestor(WindowFromPoint(target), 2) != hwnd) return false;
        Point old; if (!GetCursorPos(out old) || !SetCursorPos(x, y)) return false;
        previousPointer = old; injectedPointer = target; pointerPending = true;
        if (!Unlocked() || Pid(GetForegroundWindow()) != Pid(hwnd) || GetAncestor(WindowFromPoint(target), 2) != hwnd) return false;
        var input = new Input[] { new Input { type=0, mouse=new MouseInput { flags=0x0008 } }, new Input { type=0, mouse=new MouseInput { flags=0x0010 } } };
        return SendInput(2, input, Marshal.SizeOf(typeof(Input))) == 2;
    }
    public static bool LeftClick(IntPtr hwnd, int x, int y) {
        var target = new Point { X=x, Y=y };
        if (!Unlocked() || GetAncestor(WindowFromPoint(target), 2) != hwnd) return false;
        Point old; if (!GetCursorPos(out old) || !SetCursorPos(x, y)) return false;
        previousPointer = old; injectedPointer = target; pointerPending = true;
        if (!Unlocked() || GetAncestor(WindowFromPoint(target), 2) != hwnd) return false;
        var input = new Input[] { new Input { type=0, mouse=new MouseInput { flags=0x0002 } }, new Input { type=0, mouse=new MouseInput { flags=0x0004 } } };
        return SendInput(2, input, Marshal.SizeOf(typeof(Input))) == 2;
    }
    public static void RestorePointer() {
        if (!pointerPending) return;
        Point current;
        bool unchanged = GetCursorPos(out current) && current.X == injectedPointer.X && current.Y == injectedPointer.Y;
        pointerPending = false;
        if (unchanged && Unlocked()) SetCursorPos(previousPointer.X, previousPointer.Y);
    }
    public static void DismissOwnMenu(IntPtr hwnd) {
        if (!Unlocked() || Pid(GetForegroundWindow()) != Pid(hwnd)) return;
        keybd_event(0x1B, 0, 0, UIntPtr.Zero);
        keybd_event(0x1B, 0, 2, UIntPtr.Zero);
    }
}
'@

    if ($Action -eq 'probe') {
        $sessionId = [Diagnostics.Process]::GetCurrentProcess().SessionId
        $running = @(Get-Process -Name 'clash-verge' -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq $sessionId })
        if ($running.Count -eq 0) { Fail 'app_not_running' 'Clash Verge 未运行。' }
        @{ ok = $true; unlocked = [GuardWindow]::Unlocked() } | ConvertTo-Json -Compress
        exit 0
    }

    $candidates = @([GuardWindow]::Windows())
    if ($candidates.Count -eq 0) { Fail 'window_unavailable' '未找到可操作的 Clash Verge 窗口。' }
    if ($candidates.Count -ne 1) { Fail 'ambiguous_window' '无法唯一确认 Clash Verge 窗口。' }
    $script:Hwnd = $candidates[0]
    $script:TargetPid = [GuardWindow]::Pid($script:Hwnd)
    $script:Started = [Diagnostics.Stopwatch]::StartNew()

    function Root {
        if (-not [GuardWindow]::IsWindow($script:Hwnd) -or [GuardWindow]::Pid($script:Hwnd) -ne $script:TargetPid) {
            Fail 'app_changed' 'Clash Verge 已退出或重新启动。'
        }
        return [System.Windows.Automation.AutomationElement]::FromHandle($script:Hwnd)
    }

    function Check-Interactive([switch]$Passive) {
        if (-not [GuardWindow]::Unlocked()) { Fail 'desktop_locked' '桌面已锁定，等待解锁后重试。' }
        if (-not [GuardWindow]::IsWindow($script:Hwnd) -or [GuardWindow]::Pid($script:Hwnd) -ne $script:TargetPid) { Fail 'app_changed' 'Clash Verge 已退出或重新启动。' }
        if ($null -ne $script:PreparedInput -and [GuardWindow]::GetLastInputTick() -ne $script:PreparedInput) {
            Fail 'user_takeover' '准备更新后检测到新的桌面输入，停止界面操作。'
        }
        if (-not $Passive -and [GuardWindow]::Pid([GuardWindow]::GetForegroundWindow()) -ne $script:TargetPid) {
            Fail 'user_takeover' '前台窗口已切换，停止界面操作。'
        }
    }

    function Find-Named($Element, [string]$Name, $Type) {
        $conditions = @((New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty, $Name)))
        if ($null -ne $Type) { $conditions += New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, $Type) }
        if ($conditions.Count -eq 1) { $condition = $conditions[0] }
        else { $condition = New-Object System.Windows.Automation.AndCondition([System.Windows.Automation.Condition[]]$conditions) }
        $found = $Element.FindAll([System.Windows.Automation.TreeScope]::Descendants, $condition)
        return @($found | ForEach-Object { $_ })
    }

    function Profile-Titles {
        $matches = @(Find-Named (Root) $ProfileName $null)
        foreach ($candidate in $matches) {
            $parent = [System.Windows.Automation.TreeWalker]::ControlViewWalker.GetParent($candidate)
            $nested = $false
            for ($level = 0; $null -ne $parent -and $level -lt 16; $level++) {
                if ($parent.Current.ControlType -eq [System.Windows.Automation.ControlType]::Window) { break }
                if ($parent.Current.Name -eq $ProfileName) { $nested = $true; break }
                $parent = [System.Windows.Automation.TreeWalker]::ControlViewWalker.GetParent($parent)
            }
            if (-not $nested) { $candidate }
        }
    }

    function Route {
        try {
        $docs = @(Find-Named (Root) 'Clash Verge' ([System.Windows.Automation.ControlType]::Document))
        $values = @()
        foreach ($doc in $docs) {
            $value = $null
            $pattern = $null
            if ($doc.TryGetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern, [ref]$pattern)) { $value = $pattern.Current.Value }
            if ($value) { $values += $value }
        }
        foreach ($value in $values) {
            $uri = $null
            if ([Uri]::TryCreate([string]$value, [UriKind]::Absolute, [ref]$uri) -and $uri.Host -eq 'tauri.localhost') {
                switch ($uri.AbsolutePath.TrimEnd('/')) {
                    '/profile' { return 'profile' }
                    '/proxies' { return 'proxies' }
                    '/settings' { return 'settings' }
                    '' { return 'home' }
                    '/home' { return 'home' }
                }
            }
        }
        if (@(Profile-Titles).Count -eq 1) { return 'profile' }
        if (@(Find-Named (Root) '代理组' $null).Count -gt 0 -and @(Find-Named (Root) '全局' ([System.Windows.Automation.ControlType]::Button)).Count -gt 0) { return 'proxies' }
        } catch { }
        return 'unknown'
    }

    function Invoke-Element($Element, [switch]$Passive) {
        Check-Interactive -Passive:$Passive
        if ($Passive -and (-not $script:MenuOpened -or $script:UpdateInvoked -or $Element.Current.Name -ne '更新（代理）' -or $Element.Current.ControlType -ne [System.Windows.Automation.ControlType]::MenuItem)) {
            Fail 'control_unavailable' '当前控件不允许后台调用。'
        }
        if (-not $Element.Current.IsEnabled -or $Element.Current.IsOffscreen) { Fail 'control_unavailable' '目标控件当前不可操作。' }
        $pattern = $null
        if ($Element.TryGetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern, [ref]$pattern)) { $pattern.Invoke(); return }
        if ($Element.TryGetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern, [ref]$pattern)) { $pattern.Select(); return }
        Fail 'invoke_unsupported' '目标控件不支持安全调用。'
    }

    function Wake-Taskbar([IntPtr]$ExpectedForeground) {
        if (Check-WakeState $ExpectedForeground) { return $true }
        $taskbar = [GuardWindow]::Taskbar()
        if ($taskbar -eq [IntPtr]::Zero) { return $false }
        $element = [System.Windows.Automation.AutomationElement]::FromHandle($taskbar)
        $condition = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Button)
        $buttons = @($element.FindAll([System.Windows.Automation.TreeScope]::Descendants, $condition) | Where-Object {
            $_.Current.Name -eq 'Clash Verge' -or $_.Current.Name -match '^Clash Verge\s*[,，-]\s*1(?:\s|$)'
        })
        if ($buttons.Count -ne 1 -or -not $buttons[0].Current.IsEnabled -or $buttons[0].Current.IsOffscreen) { return $false }
        $pattern = $null
        if (Check-WakeState $ExpectedForeground) { return $true }
        if ($buttons[0].TryGetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern, [ref]$pattern)) {
            $pattern.Invoke()
            return $true
        }
        $rectangle = $buttons[0].Current.BoundingRectangle
        if ($rectangle.IsEmpty -or -not [GuardWindow]::LeftClick($taskbar, [int]($rectangle.X + $rectangle.Width / 2), [int]($rectangle.Y + $rectangle.Height / 2))) { return $false }
        [GuardWindow]::RestorePointer()
        Start-Sleep -Milliseconds 250
        return [GuardWindow]::Pid([GuardWindow]::GetForegroundWindow()) -eq $script:TargetPid
    }

    function Check-WakeState([IntPtr]$ExpectedForeground) {
        Check-Interactive -Passive
        $foreground = [GuardWindow]::GetForegroundWindow()
        if ([GuardWindow]::Pid($foreground) -eq $script:TargetPid) { return $true }
        if ($foreground -ne $ExpectedForeground -and -not [GuardWindow]::IsShellWindow($foreground)) {
            Fail 'user_takeover' '前台窗口已切换，停止界面操作。'
        }
        return $false
    }

    function Navigate([string]$Target) {
        $navigation = @{ profile = '订 阅'; proxies = '代 理'; home = '首 页'; settings = '设 置' }
        if (-not $navigation.ContainsKey($Target)) { return }
        if ((Route) -eq $Target) { return }
        $deadline = [DateTime]::UtcNow.AddSeconds(10)
        while ([DateTime]::UtcNow -lt $deadline) {
            Check-Interactive
            $buttons = @(Find-Named (Root) $navigation[$Target] ([System.Windows.Automation.ControlType]::Button))
            if ($buttons.Count -gt 1) { Fail 'ambiguous_navigation' '无法唯一确认导航按钮。' }
            if ($buttons.Count -eq 1) { Invoke-Element $buttons[0]; break }
            Start-Sleep -Milliseconds 100
        }
        while ([DateTime]::UtcNow -lt $deadline) {
            Check-Interactive
            if ((Route) -eq $Target) { return }
            Start-Sleep -Milliseconds 100
        }
        Fail 'navigation_timeout' '等待订阅页面超时。'
    }

    function Card {
        $headers = @(Profile-Titles)
        if ($headers.Count -gt 1) { Fail 'ambiguous_profile' '存在同名订阅，停止自动操作。' }
        if ($headers.Count -eq 0) { return $null }
        $parent = $headers[0]
        for ($level = 0; $null -ne $parent -and $level -lt 8; $level++) {
            if ($parent.Current.ControlType -eq [System.Windows.Automation.ControlType]::Window) { break }
            $refresh = @(Find-Named $parent '刷新' ([System.Windows.Automation.ControlType]::Button))
            if ($refresh.Count -eq 1) {
                return @{ header = $headers[0]; refresh = $refresh[0] }
            }
            $parent = [System.Windows.Automation.TreeWalker]::ControlViewWalker.GetParent($parent)
        }
        return $null
    }

    function Wait-Card {
        $deadline = [DateTime]::UtcNow.AddSeconds(10)
        while ([DateTime]::UtcNow -lt $deadline) {
            Check-Interactive
            $card = Card
            if ($null -ne $card) { return $card }
            Start-Sleep -Milliseconds 100
        }
        Fail 'profile_not_found' '无法找到指定订阅卡片及刷新控件。'
    }

    function Prepare-Window([IntPtr]$InitialForeground = ([GuardWindow]::GetForegroundWindow())) {
        if (-not [GuardWindow]::Unlocked()) { Fail 'desktop_locked' '桌面已锁定，等待解锁后重试。' }
        [void](Check-WakeState $initialForeground)
        $root = Root
        $windowPattern = $null
        try {
            if ($root.TryGetCurrentPattern([System.Windows.Automation.WindowPattern]::Pattern, [ref]$windowPattern)) {
                $windowPattern.SetWindowVisualState([System.Windows.Automation.WindowVisualState]::Normal)
            }
            else { [void][GuardWindow]::ShowWindow($script:Hwnd, 9) }
        } catch { [void][GuardWindow]::ShowWindow($script:Hwnd, 9) }
        [void](Check-WakeState $initialForeground)
        try { $root.SetFocus() } catch { }
        for ($attempt = 0; $attempt -lt 3; $attempt++) {
            if (Check-WakeState $initialForeground) { Check-Interactive; return }
            switch ($attempt) {
                0 { [void][GuardWindow]::SetForegroundWindow($script:Hwnd) }
                1 {
                    if ($null -eq $script:PreparedInput) {
                        try { [void](Wake-Taskbar $initialForeground) }
                        catch { if ($_.Exception.Data.Contains('guard_code')) { throw } }
                    }
                }
                2 { [void][GuardWindow]::TryForeground($script:Hwnd, $script:TargetPid, $initialForeground) }
            }
            for ($poll = 0; $poll -lt 10; $poll++) {
                if (Check-WakeState $initialForeground) { Check-Interactive; return }
                Start-Sleep -Milliseconds 100
            }
        }
        if (Check-WakeState $initialForeground) { Check-Interactive; return }
        Fail 'foreground_unavailable' '系统未允许 Clash Verge 切到前台，稍后重试。'
    }

    function Resume-PreparedWindow([string]$Receipt) {
        if (-not $Receipt) { Check-Interactive; return }
        try {
            $expected = $Receipt | ConvertFrom-Json
            if ([string]$expected.hwnd -ne $script:Hwnd.ToInt64().ToString() -or
                [int]$expected.pid -ne $script:TargetPid -or
                $null -eq $expected.last_input -or [long]$expected.last_input -lt 0 -or
                $null -eq $expected.previous -or $null -eq $expected.previous_pid) {
                throw 'invalid_handoff'
            }
            $previous = [IntPtr]([long]$expected.previous)
            $previousPid = [int]$expected.previous_pid
            $script:PreparedInput = [long]$expected.last_input
        } catch {
            Fail 'user_takeover' '无法确认准备更新时的窗口状态，停止界面操作。'
        }
        Check-Interactive -Passive
        $foreground = [GuardWindow]::GetForegroundWindow()
        if ([GuardWindow]::Pid($foreground) -ne $script:TargetPid) {
            # 仅处理焦点自动退回原窗口或桌面的情况，保留真实用户切换。
            if (-not [GuardWindow]::IsShellWindow($foreground) -and
                ($foreground -ne $previous -or [GuardWindow]::Pid($foreground) -ne $previousPid)) {
                Fail 'user_takeover' '前台窗口已切换，停止界面操作。'
            }
            Prepare-Window $foreground
        }
        Check-Interactive
    }

    function Find-NetworkSwitch([string]$Name) {
        $deadline = [DateTime]::UtcNow.AddSeconds(10)
        do {
            Check-Interactive
            # 2.5.9 将开关名称改为标题；路由改变后页面控件还可能尚未加载。
            $labels = @(Find-Named (Root) $Name $null | Where-Object { @(Find-Named $_ $Name $null).Count -eq 0 })
            $visible = @($labels | Where-Object { -not $_.Current.IsOffscreen })
            if ($visible.Count -gt 0) { $labels = $visible }
            if ($labels.Count -eq 0) { Start-Sleep -Milliseconds 100; continue }
            if ($labels.Count -ne 1) { Fail 'network_switch_unavailable' '无法唯一确认网络开关标签。' }
            $label = $labels[0]
            if ($label.Current.IsOffscreen) {
                $ancestor = $label
                $pattern = $null
                while ($null -ne $ancestor) {
                    Check-Interactive
                    if ($ancestor.TryGetCurrentPattern([System.Windows.Automation.ScrollItemPattern]::Pattern, [ref]$pattern)) {
                        $pattern.ScrollIntoView()
                        break
                    }
                    if ($ancestor.TryGetCurrentPattern([System.Windows.Automation.ScrollPattern]::Pattern, [ref]$pattern) -and $pattern.Current.VerticallyScrollable) {
                        $pattern.SetScrollPercent(-1, 0)
                        for ($step = 0; $step -lt 24 -and $label.Current.IsOffscreen; $step++) {
                            Check-Interactive
                            $pattern.Scroll([System.Windows.Automation.ScrollAmount]::NoAmount, [System.Windows.Automation.ScrollAmount]::LargeIncrement)
                            Start-Sleep -Milliseconds 100
                        }
                        break
                    }
                    $ancestor = [System.Windows.Automation.TreeWalker]::ControlViewWalker.GetParent($ancestor)
                }
                Start-Sleep -Milliseconds 100
                $labels = @(Find-Named (Root) $Name $null | Where-Object { -not $_.Current.IsOffscreen -and @(Find-Named $_ $Name $null).Count -eq 0 })
                if ($labels.Count -ne 1) { Fail 'network_switch_unavailable' '网络开关不在可见区域，停止操作。' }
            }
            $labelRectangle = $labels[0].Current.BoundingRectangle
            if ($labelRectangle.IsEmpty) { Fail 'network_switch_unavailable' '网络开关标签没有可确认的位置。' }
            $parent = $labels[0]
            $condition = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::IsTogglePatternAvailableProperty, $true)
            for ($level = 0; $level -lt 6; $level++) {
                Check-Interactive
                $parent = [System.Windows.Automation.TreeWalker]::ControlViewWalker.GetParent($parent)
                if ($null -eq $parent -or $parent.Current.ControlType -eq [System.Windows.Automation.ControlType]::Window) { break }
                $controls = @($parent.FindAll([System.Windows.Automation.TreeScope]::Descendants, $condition) | Where-Object {
                    $rectangle = $_.Current.BoundingRectangle
                    -not $_.Current.IsOffscreen -and -not $rectangle.IsEmpty -and
                        $rectangle.Left -ge $labelRectangle.Left -and
                        $rectangle.Top -lt $labelRectangle.Bottom -and $rectangle.Bottom -gt $labelRectangle.Top
                })
                if ($controls.Count -gt 1) { Fail 'network_switch_ambiguous' '网络开关定位不唯一，停止操作。' }
                if ($controls.Count -eq 1) {
                    $pattern = $null
                    if ($controls[0].TryGetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern, [ref]$pattern)) {
                        return @{ element = $controls[0]; pattern = $pattern }
                    }
                }
            }
            Start-Sleep -Milliseconds 100
        } while ([DateTime]::UtcNow -lt $deadline)
        Fail 'network_switch_unavailable' '找不到可安全操作的网络开关。'
    }

    function Enable-NetworkSwitch([string]$Name) {
        Check-Interactive
        $controlInfo = Find-NetworkSwitch $Name
        if ($controlInfo.pattern.Current.ToggleState -eq [System.Windows.Automation.ToggleState]::On) { return }
        if (-not $controlInfo.element.Current.IsEnabled -or $controlInfo.pattern.Current.ToggleState -ne [System.Windows.Automation.ToggleState]::Off) {
            Fail 'network_switch_unavailable' '网络开关当前不可操作，停止本次恢复。'
        }
        Check-Interactive
        $controlInfo.pattern.Toggle()
        $deadline = [DateTime]::UtcNow.AddSeconds(15)
        while ([DateTime]::UtcNow -lt $deadline) {
            Check-Interactive
            $controlInfo = Find-NetworkSwitch $Name
            if ($controlInfo.pattern.Current.ToggleState -eq [System.Windows.Automation.ToggleState]::On) { return }
            Start-Sleep -Milliseconds 100
        }
        Fail 'network_protection_lost' '等待网络开关开启超时，停止本次恢复。'
    }

    function Error-Names {
        $texts = (Root).FindAll([System.Windows.Automation.TreeScope]::Descendants, (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Text)))
        foreach ($text in $texts) {
            $name = $text.Current.Name
            if (-not $text.Current.IsOffscreen -and $name -match '失败|错误|超时|未能确认已应用到内核|\berror\b|\bfailed\b|\btimeout\b|unable') { $name }
        }
    }

    $result = @{ ok = $true }
    switch ($Action) {
        'snapshot' {
            $result.unlocked = [GuardWindow]::Unlocked()
            $route = 'unknown'
            if ($result.unlocked) { $route = Route }
            $result.window = @{
                pid = $script:TargetPid
                hwnd = $script:Hwnd.ToInt64().ToString()
                visible = [GuardWindow]::IsWindowVisible($script:Hwnd)
                minimized = [GuardWindow]::IsIconic($script:Hwnd)
                foreground = [GuardWindow]::GetForegroundWindow().ToInt64().ToString()
                route = $route
            }
        }
        'prepare' {
            $previous = [GuardWindow]::GetForegroundWindow()
            $previousPid = [GuardWindow]::Pid($previous)
            Prepare-Window
            Navigate 'profile'
            $card = Wait-Card
            if (-not $card.refresh.Current.IsEnabled) { Fail 'update_busy' '该订阅正在更新，稍后重试。' }
            $result.handoff = @{
                hwnd = $script:Hwnd.ToInt64().ToString()
                pid = $script:TargetPid
                previous = $previous.ToInt64().ToString()
                previous_pid = $previousPid
                last_input = [GuardWindow]::GetLastInputTick()
            }
        }
        'protect' {
            Prepare-Window
            Navigate 'settings'
            Enable-NetworkSwitch '虚拟网卡模式'
            Enable-NetworkSwitch '系统代理'
            $result.tun_enabled = $true
            $result.system_proxy_enabled = $true
        }
        'update' {
            Resume-PreparedWindow $SnapshotJson
            $card = Wait-Card
            if (-not $card.refresh.Current.IsEnabled) { Fail 'update_busy' '该订阅正在更新，稍后重试。' }
            $beforeErrors = @(Error-Names)
            $rectangle = $card.header.Current.BoundingRectangle
            if ($rectangle.IsEmpty -or $card.header.Current.IsOffscreen) { Fail 'profile_offscreen' '指定订阅不在当前可见区域。' }
            Check-Interactive
            $script:PreparedInput = $null # 鼠标点击本身会更新输入时间；之后只观察这次更新。
            if (-not [GuardWindow]::RightClick($script:Hwnd, [int]($rectangle.X + $rectangle.Width / 2), [int]($rectangle.Y + $rectangle.Height / 2))) {
                Fail 'context_menu_failed' '无法安全打开指定订阅菜单。'
            }
            $script:MenuOpened = $true
            $menuDeadline = [DateTime]::UtcNow.AddSeconds(10)
            $invoked = $false
            while ([DateTime]::UtcNow -lt $menuDeadline) {
                Check-Interactive -Passive
                $menus = @(Find-Named (Root) '更新（代理）' ([System.Windows.Automation.ControlType]::MenuItem))
                if ($menus.Count -gt 1) { Fail 'ambiguous_menu' '无法唯一确认代理更新菜单。' }
                if ($menus.Count -eq 1) {
                    Invoke-Element $menus[0] -Passive
                    $invoked = $true
                    $script:UpdateInvoked = $true
                    [GuardWindow]::RestorePointer()
                    break
                }
                Start-Sleep -Milliseconds 100
            }
            if (-not $invoked) { Fail 'menu_not_found' '找不到更新（代理）菜单。' }
            $updateDeadline = [DateTime]::UtcNow.AddSeconds(150)
            $sawLoading = $false
            $stableSince = $null
            $unobservableSince = $null
            while ([DateTime]::UtcNow -lt $updateDeadline -and $script:Started.Elapsed.TotalSeconds -lt 165) {
                Check-Interactive -Passive
                $observable = $false
                try {
                    $route = Route
                    if ($route -in @('home', 'proxies')) { Fail 'ui_changed' '用户已离开订阅页面，停止自动操作。' }
                    foreach ($errorName in @(Error-Names)) {
                        if ($beforeErrors -notcontains $errorName) { Fail 'update_error' 'Clash Verge 报告订阅更新失败或未确认应用到内核。' }
                    }
                    if ($route -eq 'profile') {
                        $card = Card
                        if ($null -ne $card) { $enabled = $card.refresh.Current.IsEnabled; $observable = $true }
                    }
                }
                catch {
                    $exception = $_.Exception
                    $stale = $false
                    while ($null -ne $exception) {
                        if ($exception -is [System.Windows.Automation.ElementNotAvailableException] -or $exception.HResult -eq -2147220991) { $stale = $true; break }
                        $exception = $exception.InnerException
                    }
                    if (-not $stale) { throw }
                }
                if (-not $observable) {
                    $stableSince = $null
                    if ($null -eq $unobservableSince) { $unobservableSince = [DateTime]::UtcNow }
                    elseif (([DateTime]::UtcNow - $unobservableSince).TotalSeconds -ge 10) { Fail 'ui_unavailable' '订阅更新界面持续不可观测，停止并等待下次重试。' }
                    Start-Sleep -Milliseconds 100
                    continue
                }
                $unobservableSince = $null
                if (-not $enabled) { $sawLoading = $true; $stableSince = $null }
                elseif ($null -eq $stableSince) { $stableSince = [DateTime]::UtcNow }
                elseif (([DateTime]::UtcNow - $stableSince).TotalSeconds -ge 2) {
                    $result.invoked = $true
                    $result.finished = $true
                    $result.loading_seen = $sawLoading
                    break
                }
                Start-Sleep -Milliseconds 100
            }
            if (-not $result.finished) { Fail 'update_timeout' '等待订阅更新结束超时。' }
        }
        'restore' {
            if (-not $SnapshotJson) { Fail 'snapshot_required' '缺少窗口恢复记录。' }
            $snapshot = $SnapshotJson | ConvertFrom-Json
            $window = $snapshot.window
            if ($null -eq $window -or [string]$window.hwnd -ne $script:Hwnd.ToInt64().ToString() -or [int]$window.pid -ne $script:TargetPid) {
                Fail 'snapshot_mismatch' '窗口已变化，不能恢复旧窗口记录。'
            }
            if (-not [GuardWindow]::Unlocked()) { Fail 'desktop_locked' '桌面已锁定，保留当前窗口状态。' }
            if ([GuardWindow]::Pid([GuardWindow]::GetForegroundWindow()) -ne $script:TargetPid) {
                $result.skipped = 'user_takeover'
                break
            }
            $result.route_restored = $false
            if (@('profile', 'proxies', 'home', 'settings') -contains [string]$window.route) {
                try { Navigate ([string]$window.route); $result.route_restored = $true }
                catch {
                    if ($_.Exception.Data['guard_code'] -in @('user_takeover', 'desktop_locked', 'app_changed')) { throw }
                }
            }
            Check-Interactive
            $foreground = [IntPtr]([long]$window.foreground)
            if ($foreground -ne $script:Hwnd -and [GuardWindow]::IsWindow($foreground)) {
                [void][GuardWindow]::SetForegroundWindow($foreground)
            }
            if (-not [bool]$window.visible) { [void][GuardWindow]::ShowWindow($script:Hwnd, 0) }
            elseif ([bool]$window.minimized) { [void][GuardWindow]::ShowWindow($script:Hwnd, 7) }
        }
    }
    [Console]::WriteLine(($result | ConvertTo-Json -Compress -Depth 5))
    exit 0
}
catch {
    $code = 'ui_unavailable'
    $message = '界面操作失败，已停止；请检查 Clash Verge 窗口。'
    if ($_.Exception.Data.Contains('guard_code')) { $code = $_.Exception.Data['guard_code']; $message = $_.Exception.Message }
    $diagnostic = @{ menu_opened = $script:MenuOpened; update_invoked = $script:UpdateInvoked; foreground_same_process = $false; foreground_owned_window = $false; foreground_process = 'none' }
    $failure = @{ ok = $false; code = $code; error = $message; diagnostic = $diagnostic }
    try {
        $foreground = [GuardWindow]::GetForegroundWindow()
        $foregroundPid = [GuardWindow]::Pid($foreground)
        $diagnostic.foreground_same_process = ($foregroundPid -eq $script:TargetPid)
        $diagnostic.foreground_owned_window = ([GuardWindow]::GetAncestor($foreground, 3) -eq $script:Hwnd)
        if ($foregroundPid -ne 0) {
            $processName = [Diagnostics.Process]::GetProcessById($foregroundPid).ProcessName
            $diagnostic.foreground_process = 'other'
            foreach ($category in @('clash-verge', 'msedgewebview2', 'Codex', 'explorer')) {
                if ($processName -ieq $category) { $diagnostic.foreground_process = $category; break }
            }
        }
    } catch { }
    if ($script:MenuOpened -and -not $script:UpdateInvoked) {
        try {
            if ([GuardWindow]::Unlocked() -and [GuardWindow]::Pid([GuardWindow]::GetForegroundWindow()) -eq $script:TargetPid) {
                $menus = @(Find-Named (Root) '更新（代理）' ([System.Windows.Automation.ControlType]::MenuItem))
                if ($menus.Count -eq 1 -and -not $menus[0].Current.IsOffscreen) { [GuardWindow]::DismissOwnMenu($script:Hwnd) }
            }
        } catch { }
    }
    try { [GuardWindow]::RestorePointer() } catch { }
    [Console]::WriteLine(($failure | ConvertTo-Json -Compress))
    exit 1
}
