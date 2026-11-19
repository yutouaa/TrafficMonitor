# TMVPNPlugin - TrafficMonitor VPN 监控插件

通过 mihomo 的命名管道（Clash Verge 内核 IPC，不需要打开 external-controller）
读取当前节点和延迟，并显示 Mihomo 虚拟网卡的速度与连接状态。

## 提供的显示项目

- 节点延迟 (ItemId: vpn_node_delay)：显示「节点名 · 延迟」，默认每 10 秒测速一次；
  未连接时显示「未连接」，测速超时显示「超时」。完整节点名在鼠标悬停提示里。
- VPN 网速 (ItemId: vpn_net_speed)：Mihomo 虚拟网卡上下行速度。
- VPN 状态 (ItemId: vpn_conn_status)：已连接 / 未连接。

## 自动恢复订阅

在 TrafficMonitor 的任务栏右击任一 VPN 显示项，选择「VPN 监控 → 自动恢复订阅」。
勾选后按设定间隔检查；取消勾选后暂停发起新恢复，三个显示项继续刷新。
开关沿用此前的暂停状态，退出或重启 TrafficMonitor 后仍保留。

在同一菜单的「插件选项」可以设置：

- **选择订阅**：列出 Clash Verge 已导入的远程订阅，并标出当前启用的一份。先在 Clash Verge 启用要用的订阅，再选择恢复目标。保存不会替你切换订阅；同名订阅请先在 Clash Verge 中改成不同的名字。
- **恢复目标节点**：默认 `PRO | 日本家宽S VL03 | 2倍`。保存后仅在下一次恢复时使用，不会切换当前节点。Clash 离线或已保存的节点暂时消失时，保留原选择。
- **刷新间隔**：可选 5、10、15、30、60 秒，默认 10 秒。设置同时影响任务栏延迟测速和助手恢复检测；网速和连接状态照常刷新。

选项保存在 `%LOCALAPPDATA%\ClashSubscriptionGuard\plugin-settings.json`，订阅按 ID 保存，保存后无需重启。旧版 `profile-binding.json` 中的绑定仍可识别。若设置文件损坏，请在「插件选项」重新保存；在此之前助手不会发起新恢复。

符合恢复条件时，助手先退出 Claude Desktop，检查 TUN 和系统代理，再切换到
订阅专用节点 AN，对当前订阅执行「更新（代理）」，最后切换到本次恢复开始时的目标并确认连通。
助手随 TrafficMonitor 启动；退出 TrafficMonitor 后不发起新恢复，进行中的恢复会完成或安全回退。
恢复状态和日志仍位于 `%LOCALAPPDATA%\ClashSubscriptionGuard`。

自动恢复要求 Clash Verge 正在使用所选订阅、处于全局模式，且订阅中有 `PRO | 订阅专用节点AN | 0倍`。不满足这些条件时仍可使用任务栏监控。

## 构建

    build.bat build

在 `build` 目录生成 `TMVPNPlugin.dll`（x64）和 `test_host.exe`。
在插件目录运行 `C:\Python314\python.exe -B -m unittest discover -s recovery` 可执行离线回归。

## 安装包

运行 Windows x64 安装 EXE，在开始菜单打开「TrafficMonitor VPN」。安装包包含 TrafficMonitor、插件、恢复助手和 Python，不包含 Clash Verge 或任何订阅。已有 TrafficMonitor 正在运行时，先退出旧进程，再打开此版本。只看节点和网速时无需选择订阅。

从源码制作安装包需准备 MSVC x64 Build Tools、Inno Setup 和脚本要求的 Microsoft VC++ x64 运行库安装程序。提交代码后运行 `./package.ps1 -Commit HEAD`；可用 `-InnoCompiler` 和 `-VSRedist` 指定本机工具路径。打包使用指定 Git 提交中的源码。

## 源码部署 / 升级旧安装

1. 构建 x64 插件后，在已登录桌面的管理员 PowerShell 中运行部署脚本。首次迁移运行 `.\deploy.ps1`；已在使用带恢复助手的插件时，运行 `.\deploy.ps1 -Upgrade`。升级会备份 DLL 和恢复脚本，等待当前恢复结束并重启 TrafficMonitor，旧守护任务保持停用。可用 `.\deploy.ps1 -Rollback <备份目录>` 恢复上一版。
2. 在任务栏窗口右键 ->「显示设置」勾选要显示的项目，
   或在 config.ini 的 [task_bar] 段写：
   plugin_display_item = vpn_node_delay（多个用逗号分隔）。

旧安装通过本机 `C:\Python314\pythonw.exe` 运行恢复助手。源码部署前用 `C:\Python314\python.exe -m pip install PyYAML==6.0.3` 准备依赖；安装 EXE 已包含 Python 和 PyYAML。两种方式均使用系统自带的 PowerShell。
部署沿用 TrafficMonitor 的登录自启，助手不创建独立托盘或新的登录任务。

## 实现说明

- 节点/延迟：枚举 \\.\pipe\verge-mihomo* 命名管道，直接发 HTTP：
  - GET /proxies 取 proxies.GLOBAL.now（当前全局节点）和可选恢复目标
  - GET /proxies/{节点}/delay?timeout=3000&url=http://www.gstatic.com/generate_204 取延迟
  - 后台按设定间隔刷新缓存，选项窗口直接使用缓存
- 网卡速度：GetIfTable2 按 Alias=Mihomo / Description=Meta Tunnel 匹配计数。
- 节点名会去掉首尾的标签段（"PRO | 日本家宽S VL03 | 2倍" -> "日本家宽S VL03"），
  改显示规则见 ShortNodeName()。

## 注意

- x64 插件，必须用 MSVC 编译（插件接口是 C++ 虚表 ABI）。
- TrafficMonitor 1.86 的可执行文件清单要求管理员权限，正常启动会弹 UAC；
  必须在正常启动的进程里运行才能访问 mihomo 管道。
