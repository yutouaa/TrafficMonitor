"""Clash Verge 当前订阅自动恢复；仅使用 Python 标准库。"""

from __future__ import annotations

import argparse
import base64
from contextlib import ExitStack
from contextvars import ContextVar
import ctypes
from ctypes import wintypes
import http.client
import json
import logging
from logging.handlers import RotatingFileHandler
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import types
from urllib.parse import quote, urlencode


TARGET = "PRO | 日本家宽S VL03 | 2倍"
BOOTSTRAP = "PRO | 订阅专用节点AN | 0倍"
PROFILE_ROOT = Path(os.environ.get("APPDATA", "")) / "io.github.clash-verge-rev.clash-verge-rev"
INSTALL_DIR = Path(os.environ.get("LOCALAPPDATA", "")) / "ClashSubscriptionGuard"
STATE_PATH = INSTALL_DIR / "state.json"
SCRIPT_DIR = Path(__file__).resolve().parent
PYTHON = Path(sys.executable).with_name("python.exe")
PYTHONW = Path(sys.executable).with_name("pythonw.exe")
POWERSHELL = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
CHECK_INTERVAL = 10
REFRESH_INTERVALS = (5, 10, 15, 30, 60)
PLUGIN_NODE_TYPES = {
    "shadowsocks", "shadowsocksr", "snell", "socks5", "http", "vmess", "vless", "trojan",
    "hysteria", "hysteria2", "wireguard", "tuic", "ssh", "mieru", "anytls", "sudoku",
    "masque", "trusttunnel", "shadowquic", "openvpn", "tailscale", "zerotier", "easytier", "gostrelay",
}
COOLDOWN = 15 * 60
DEFERRED_ERRORS = ("desktop_locked", "app_changed", "profile_reloading")
RECOVERY_TIMEOUT = 180
HEALTH_URLS = ("https://www.gstatic.com/generate_204", "https://cp.cloudflare.com/generate_204")
DIRECT_URLS = ("https://www.baidu.com",)
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
REQUEST_DEADLINE = ContextVar("request_deadline", default=None)
AUTO_ACTION_ALLOWED = ContextVar("auto_action_allowed", default=None)
PLUGIN_TARGET = ContextVar("plugin_target", default=None)
REPORT_PATH: Path | None = None


def load_profile_binding() -> tuple[str, str]:
    try:
        with (INSTALL_DIR / "profile-binding.json").open("rb") as stream:
            raw = stream.read(4097)
        if len(raw) <= 4096:
            data = json.loads(raw.decode("utf-8-sig"))
            if isinstance(data, dict):
                uid, name = data.get("profile_uid"), data.get("profile_name")
                if (isinstance(uid, str) and re.fullmatch(r"[A-Za-z0-9_-]+", uid)
                        and isinstance(name, str) and name.strip() and "\0" not in name):
                    return uid, name
    except (OSError, ValueError, RecursionError):
        pass
    return "", ""


PROFILE_UID, PROFILE_NAME = load_profile_binding()


class GuardError(Exception):
    def __init__(self, code: str, message: str, context: dict | None = None):
        super().__init__(message)
        self.code = code
        self.context = context


def remaining_timeout(maximum: float) -> float:
    deadline = REQUEST_DEADLINE.get()
    remaining = maximum if deadline is None else min(maximum, deadline - time.monotonic())
    if remaining <= 0:
        raise GuardError("recovery_timeout", "恢复等待超过 180 秒，停止并还原节点")
    return remaining


def log_event(code: str, message: str) -> None:
    logging.getLogger("guard").info("%s %s", code, message)


def setup_logging() -> None:
    INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("guard")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = RotatingFileHandler(INSTALL_DIR / "guard.log", maxBytes=1_000_000, backupCount=2, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
        logger.addHandler(handler)


def emit(data: dict) -> None:
    if REPORT_PATH is not None:
        temporary = REPORT_PATH.with_suffix(".tmp")
        temporary.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        os.replace(temporary, REPORT_PATH)
    if sys.stdout is not None:
        print(json.dumps(data, ensure_ascii=False))


def load_plugin_settings() -> tuple[str, int]:
    try:
        with (INSTALL_DIR / "plugin-settings.json").open("rb") as stream:
            raw = stream.read(4097)
        if len(raw) > 4096:
            raise ValueError()
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict) or data.keys() != {"target_node", "refresh_seconds"}:
            raise ValueError()
        target, seconds = data["target_node"], data["refresh_seconds"]
        if (not isinstance(target, str) or not 1 <= len(target.encode("utf-8")) <= 512
                or target != target.strip() or any(ord(ch) < 32 or ord(ch) == 127 for ch in target)
                or target.upper() in (BOOTSTRAP.upper(), "DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL")
                or type(seconds) is not int or seconds not in REFRESH_INTERVALS):
            raise ValueError()
        return target, seconds
    except FileNotFoundError:
        return TARGET, CHECK_INTERVAL
    except (OSError, ValueError):
        raise GuardError("plugin_settings_invalid", "恢复设置无法读取或内容无效，暂停自动恢复") from None


def supported_plugin_node(context: dict, target: str) -> bool:
    node = context["proxies"].get(target)
    protocol = node.get("type") if isinstance(node, dict) else None
    return isinstance(protocol, str) and protocol.lower() in PLUGIN_NODE_TYPES


def global_members(group: dict | None) -> list:
    members = group.get("all") if isinstance(group, dict) and group.get("type") == "Selector" else None
    if not isinstance(members, list):
        raise GuardError("global_unavailable", "未能确认内核全局组的可选节点，已停止自动恢复")
    return members


def target_available(context: dict, target: str) -> bool:
    proxies = context["proxies"]
    if PLUGIN_TARGET.get() is None:
        return target in proxies
    members = global_members(proxies.get("GLOBAL"))
    if target in proxies and not supported_plugin_node(context, target):
        raise GuardError("invalid_target_type", "恢复目标不再是受支持的代理节点，已停止自动恢复")
    return target in proxies and target in members


def default_state() -> dict:
    return {"failures": 0, "cooldown_until": 0, "transaction": None,
            "last_selected": None, "owned_reject": False, "last_status": "未运行"}


def load_state() -> dict:
    state = default_state()
    try:
        saved = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        if not isinstance(saved, dict):
            raise ValueError()
        failures = saved.get("failures", 0)
        cooldown = saved.get("cooldown_until", 0)
        transaction = saved.get("transaction")
        if type(failures) is not int or failures < 0:
            raise ValueError()
        if type(cooldown) not in (int, float) or not math.isfinite(cooldown) or cooldown < 0:
            raise ValueError()
        if transaction is not None and (not isinstance(transaction, dict) or
                any(not isinstance(transaction.get(k), str) or not transaction[k] for k in ("original", "expected"))):
            raise ValueError()
        if transaction and any(transaction.get(k) is not None and not isinstance(transaction[k], str)
                               for k in ("pending_selection", "before_selection", "plugin_target")):
            raise ValueError()
        if saved.get("last_selected") is not None and not isinstance(saved["last_selected"], str):
            raise ValueError()
        if "plugin_target" in saved and not isinstance(saved["plugin_target"], str):
            raise ValueError()
        if type(saved.get("owned_reject", False)) is not bool:
            raise ValueError()
        stamp = saved.get("last_profile_stamp")
        if stamp is not None and (not isinstance(stamp, list) or len(stamp) != 2 or any(type(n) is not int or n < 0 for n in stamp)):
            raise ValueError()
        pending = saved.get("pending_reload")
        if pending is not None:
            if (not isinstance(pending, dict) or not isinstance(pending.get("selected"), str)
                    or not pending["selected"] or type(pending.get("until")) not in (int, float)
                    or not math.isfinite(pending["until"]) or pending["until"] < 0):
                raise ValueError()
            stamp = pending.get("profile_stamp")
            if not isinstance(stamp, list) or len(stamp) != 2 or any(type(n) is not int or n < 0 for n in stamp):
                raise ValueError()
        state.update(saved)
    except FileNotFoundError:
        pass
    except (OSError, ValueError, TypeError, OverflowError):
        state["corrupt"] = True
    return state


def save_state(state: dict) -> None:
    INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    state["saved_at"] = time.time()
    temporary = STATE_PATH.with_suffix(".tmp")
    temporary.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temporary, STATE_PATH)


class InstanceLock:
    def __enter__(self):
        import msvcrt
        INSTALL_DIR.mkdir(parents=True, exist_ok=True)
        self.file = (INSTALL_DIR / "guard.lock").open("a+b")
        if self.file.tell() == 0:
            self.file.write(b"0")
            self.file.flush()
        self.file.seek(0)
        try:
            msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            self.file.close()
            raise GuardError("already_running", "守护程序或一次恢复正在运行") from None
        return self

    def __exit__(self, *args):
        import msvcrt
        self.file.seek(0)
        msvcrt.locking(self.file.fileno(), msvcrt.LK_UNLCK, 1)
        self.file.close()


class PluginHost:
    def __init__(self, stack: ExitStack, pid: int, created: int, image: Path):
        api = ctypes.WinDLL("kernel32", use_last_error=True)
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        handle = wintypes.HANDLE
        dword = wintypes.DWORD
        boolean = wintypes.BOOL
        filetime = ctypes.POINTER(wintypes.FILETIME)
        functions = (
            (api.OpenProcess, handle, dword, boolean, dword),
            (api.GetCurrentProcess, handle),
            (api.GetProcessTimes, boolean, handle, filetime, filetime, filetime, filetime),
            (api.QueryFullProcessImageNameW, boolean, handle, dword, wintypes.LPWSTR, ctypes.POINTER(dword)),
            (api.WaitForSingleObject, dword, handle, dword),
            (api.CreateMutexW, handle, wintypes.LPVOID, boolean, wintypes.LPCWSTR),
            (api.CreateEventW, handle, wintypes.LPVOID, boolean, boolean, wintypes.LPCWSTR),
            (api.SetEvent, boolean, handle),
            (api.ResetEvent, boolean, handle),
            (api.CloseHandle, boolean, handle),
            (advapi.OpenProcessToken, boolean, handle, dword, ctypes.POINTER(handle)),
            (advapi.GetTokenInformation, boolean, handle, ctypes.c_int, wintypes.LPVOID, dword, ctypes.POINTER(dword)),
        )
        for function, result, *arguments in functions:
            function.restype = result
            function.argtypes = arguments
        self.api = api
        self.pid = pid
        token = handle()
        elevated = dword()
        length = dword()
        if not advapi.OpenProcessToken(api.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
            raise GuardError("plugin_token", "无法验证恢复助手的用户权限")
        try:
            if (not advapi.GetTokenInformation(token, 20, ctypes.byref(elevated),
                    ctypes.sizeof(elevated), ctypes.byref(length)) or elevated.value):
                raise GuardError("plugin_token", "恢复助手必须以普通用户权限运行")
        finally:
            api.CloseHandle(token)
        if not 0 < pid <= 0xFFFFFFFF or created <= 0 or not image.is_absolute() or image.name.lower() != "trafficmonitor.exe":
            raise GuardError("plugin_host", "TrafficMonitor 进程身份无效")
        self.process = api.OpenProcess(0x101000, False, pid)  # SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION
        if not self.process:
            raise GuardError("plugin_host", "无法打开 TrafficMonitor 进程")
        stack.callback(api.CloseHandle, self.process)
        image_name = ctypes.create_unicode_buffer(32768)
        size = dword(len(image_name))
        times = [wintypes.FILETIME() for _ in range(4)]
        if (not api.QueryFullProcessImageNameW(self.process, 0, image_name, ctypes.byref(size))
                or not api.GetProcessTimes(self.process, *map(ctypes.byref, times))):
            raise GuardError("plugin_host", "无法验证 TrafficMonitor 的路径和启动时间")
        actual_created = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
        if (os.path.normcase(os.path.normpath(image_name.value)) != os.path.normcase(os.path.normpath(image))
                or actual_created != created or not self.alive()):
            raise GuardError("plugin_host", "TrafficMonitor 进程已退出或身份不匹配")

        suffix = f"{pid}.{created}"
        ctypes.set_last_error(0)
        mutex = api.CreateMutexW(None, False, "Local\\TMVPNPlugin.Guard." + suffix)
        error = ctypes.get_last_error()
        if not mutex:
            raise GuardError("plugin_mutex", "无法取得恢复助手的进程标记")
        stack.callback(api.CloseHandle, mutex)
        if error == 183:  # ERROR_ALREADY_EXISTS
            raise GuardError("already_running", "当前 TrafficMonitor 已有恢复助手")
        self.ready_event = api.CreateEventW(None, True, False, "Local\\TMVPNPlugin.GuardReady." + suffix)
        if not self.ready_event:
            raise GuardError("plugin_event", "无法创建恢复助手的就绪标记")
        stack.callback(api.CloseHandle, self.ready_event)
        if not api.ResetEvent(self.ready_event):
            raise GuardError("plugin_event", "无法初始化恢复助手的就绪标记")

    def alive(self, timeout_ms=0) -> bool:
        return self.api.WaitForSingleObject(self.process, timeout_ms) == 258  # WAIT_TIMEOUT

    def ready(self):
        if not self.api.SetEvent(self.ready_event):
            raise GuardError("plugin_event", "无法发布恢复助手的就绪标记")

    def not_ready(self):
        self.api.ResetEvent(self.ready_event)


def require_auto_action_allowed() -> None:
    allowed = AUTO_ACTION_ALLOWED.get()
    if allowed is not None and not allowed():
        raise GuardError("monitor_stopped", "自动恢复已暂停或 TrafficMonitor 已退出")


def root_scalar(text: str, key: str) -> str:
    """只读取应用生成的根级单行标量，不解析或改写订阅 YAML。"""
    match = re.search(r"^" + re.escape(key) + r":[ \t]*(.*)$", text, re.M)
    if not match:
        return ""
    value = match.group(1).strip()
    if value.startswith('"'):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, str) else ""
        except ValueError:
            raise GuardError("config_format", "配置标量格式不兼容，需要重新检查") from None
    if value.startswith("'") and value.endswith("'"):
        return value[1:-1].replace("''", "'")
    return "" if value in ("null", "~") else value


def current_profile_uid() -> str:
    try:
        text = (PROFILE_ROOT / "profiles.yaml").read_text(encoding="utf-8-sig")
        uid = root_scalar(text, "current")
        if not re.fullmatch(r"[A-Za-z0-9_-]+", uid):
            raise GuardError("profile_format", "无法识别当前订阅")
        return uid
    except OSError:
        raise GuardError("profile_unavailable", "无法读取 Clash Verge 当前订阅") from None


def profile_stamp() -> tuple[int, int]:
    try:
        info = (PROFILE_ROOT / "profiles" / (PROFILE_UID + ".yaml")).stat()
        return info.st_mtime_ns, info.st_size
    except OSError:
        raise GuardError("profile_unavailable", "当前绑定的订阅文件不存在") from None


def core_worker() -> None:
    """由有超时的独立子进程执行管道 I/O，避免失效管道永久阻塞守护。"""
    try:
        request = json.loads(sys.stdin.read())
        method, path = request["method"], request["path"]
        if method not in ("GET", "PUT") or not path.startswith(("/configs", "/proxies", "/version")) or "\r" in path or "\n" in path:
            raise GuardError("invalid_request", "不支持的内核请求")
        text = (PROFILE_ROOT / "clash-verge.yaml").read_text(encoding="utf-8-sig")
        configured = root_scalar(text, "external-controller-pipe")
        suffix = re.search(r"([a-f0-9]{64})$", configured)
        if not suffix:
            raise GuardError("core_identity", "无法确定当前用户的内核管道")
        names = [n for n in os.listdir(r"\\.\pipe")
                 if n.startswith(("verge-mihomo-production-", "verge-mihomo-sidecar-")) and n.endswith("-" + suffix.group(1))]
        if len(names) != 1:
            raise GuardError("core_offline", "Clash 内核未运行或存在多个匹配管道")
        body = json.dumps(request["body"], ensure_ascii=False).encode("utf-8") if request.get("body") is not None else b""
        secret = root_scalar(text, "secret")
        if "\r" in secret or "\n" in secret:
            raise GuardError("config_format", "内核认证配置不兼容")
        auth = ("Authorization: Bearer " + secret + "\r\n") if secret else ""
        headers = (method + " " + path + " HTTP/1.1\r\nHost: localhost\r\n" + auth
                   + "Content-Type: application/json\r\nContent-Length: " + str(len(body)) + "\r\nConnection: close\r\n\r\n")
        with open("\\\\.\\pipe\\" + names[0], "r+b", buffering=0) as pipe:
            pipe.write(headers.encode("utf-8") + body)
            response = http.client.HTTPResponse(types.SimpleNamespace(makefile=lambda *a, **k: pipe))
            response.begin()
            data = response.read(6_000_001)
            if len(data) > 6_000_000:
                raise GuardError("core_response", "内核响应超过限制")
            if response.status not in (200, 204):
                raise GuardError("core_http_" + str(response.status), "内核请求失败（HTTP " + str(response.status) + "）")
            emit({"ok": True, "data": json.loads(data) if data else {}})
    except GuardError as error:
        emit({"ok": False, "code": error.code, "error": str(error)})
    except Exception:
        emit({"ok": False, "code": "core_offline", "error": "无法访问 Clash 本地内核"})


def core_request(method: str, path: str, body=None, timeout: float = 12):
    timeout = remaining_timeout(timeout)
    try:
        completed = subprocess.run([str(PYTHON), str(Path(__file__).resolve()), "--core-worker"],
                                   input=json.dumps({"method": method, "path": path, "body": body}, ensure_ascii=False),
                                   capture_output=True, text=True, encoding="utf-8", timeout=max(0.1, timeout), creationflags=NO_WINDOW)
        result = json.loads(completed.stdout)
        if not result.get("ok"):
            raise GuardError(result.get("code", "core_error"), result.get("error", "内核请求失败"))
        return result["data"]
    except subprocess.TimeoutExpired:
        raise GuardError("core_timeout", "内核请求超时") from None
    except (OSError, ValueError, KeyError):
        raise GuardError("core_unavailable", "内核请求未返回有效结果") from None


def node_healthy(name: str, urls=HEALTH_URLS, timeout: float = 12) -> bool:
    for url in urls:
        effective = remaining_timeout(timeout)
        if effective < 0.6:
            return False
        query = urlencode({"url": url, "timeout": min(7000, int(effective * 1000) - 500)})
        try:
            result = core_request("GET", "/proxies/" + quote(name, safe="") + "/delay?" + query, timeout=effective)
            if isinstance(result.get("delay"), (int, float)) and result["delay"] >= 0:
                return True
        except GuardError as error:
            if error.code == "recovery_timeout":
                raise
    return False


def ui_action(action: str, snapshot=None, timeout: float | None = None) -> dict:
    timeout = remaining_timeout(timeout or (172 if action == "update" else 35))
    arguments = [str(POWERSHELL), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
                 str(SCRIPT_DIR / "verge_ui.ps1"), "-Action", action, "-ProfileName", PROFILE_NAME]
    if snapshot is not None:
        arguments += ["-SnapshotJson", json.dumps(snapshot, ensure_ascii=False)]
    try:
        done = subprocess.run(arguments, capture_output=True, encoding="utf-8-sig", errors="replace",
                              timeout=timeout, creationflags=NO_WINDOW)
        data = json.loads(done.stdout.strip().lstrip("\ufeff"))
        if not data.get("ok"):
            diagnostic = data.get("diagnostic", data)
            if isinstance(diagnostic, dict) and "menu_opened" in diagnostic and action == "update":
                foreground = diagnostic.get("foreground_process")
                foreground = foreground if foreground in ("clash-verge", "msedgewebview2", "Codex", "explorer", "none") else "other"
                log_event("update_ui_stopped", "菜单已打开=%s，更新已调用=%s，前台属于本应用=%s，前台属于本应用的窗口=%s，前台类别=%s" % (
                    diagnostic.get("menu_opened") is True, diagnostic.get("update_invoked") is True,
                    diagnostic.get("foreground_same_process") is True, diagnostic.get("foreground_owned_window") is True, foreground))
            raise GuardError(data.get("code", "ui_error"), data.get("error", "无法操作 Clash Verge 订阅界面"))
        return data
    except subprocess.TimeoutExpired:
        raise GuardError("ui_timeout", "订阅界面操作超时") from None
    except (OSError, ValueError, TypeError):
        raise GuardError("ui_unavailable", "订阅界面未返回有效结果") from None


def network_protection_status(config: dict) -> dict:
    import winreg
    verge = ""
    try:
        verge = (PROFILE_ROOT / "verge.yaml").read_text(encoding="utf-8-sig")
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings") as key:
            enabled = winreg.QueryValueEx(key, "ProxyEnable")[0] == 1
            server = winreg.QueryValueEx(key, "ProxyServer")[0]
    except FileNotFoundError:
        enabled, server = False, ""
    except OSError:
        raise GuardError("network_settings_unavailable", "无法读取虚拟网卡或系统代理状态") from None
    port = config.get("mixed-port")
    matches = False
    if type(port) is int and 0 < port < 65536 and isinstance(server, str):
        expected = {host + ":" + str(port) for host in ("127.0.0.1", "localhost", "[::1]")}
        parts = [part.strip().lower() for part in server.split(";") if part.strip()]
        if len(parts) == 1 and "=" not in parts[0]:
            matches = parts[0] in expected
        elif parts and all("=" in part for part in parts):
            mapping = dict(part.split("=", 1) for part in parts)
            matches = mapping.get("http") in expected and mapping.get("https") in expected
    tun = config.get("tun")
    return {"tun_enabled": isinstance(tun, dict) and tun.get("enable") is True
                and root_scalar(verge, "enable_tun_mode").lower() == "true",
            "system_proxy_enabled": enabled and matches
                and root_scalar(verge, "enable_system_proxy").lower() == "true"}


def network_ready(context: dict) -> bool:
    return context.get("tun_enabled") is True and context.get("system_proxy_enabled") is True


def inspect_context() -> dict:
    uid = current_profile_uid()
    config = core_request("GET", "/configs")
    proxies = core_request("GET", "/proxies").get("proxies", {})
    if current_profile_uid() != uid:
        raise GuardError("user_takeover", "当前订阅已切换，暂停自动操作")
    return {"profile_uid": uid, "mode": config.get("mode"), "selected": proxies.get("GLOBAL", {}).get("now"),
            "proxies": proxies, "profile_stamp": list(profile_stamp()) if uid == PROFILE_UID else None,
            **network_protection_status(config)}


def same_scope(context: dict) -> bool:
    return context["profile_uid"] == PROFILE_UID and context["mode"] == "global"


def check_recovery_context(before: dict, after: dict) -> None:
    if not same_scope(after):
        raise GuardError("user_takeover", "订阅或模式已切换，保留用户当前设置")
    changed = (before.get("profile_stamp") is not None and after.get("profile_stamp") is not None
               and before["profile_stamp"] != after["profile_stamp"])
    if after["selected"] != before["selected"]:
        # 文件变化本身不能证明自动回退，还必须确认旧节点已被删除。
        previous, proxies = before["selected"], after.get("proxies", {})
        removed = previous not in proxies
        if not removed and previous is not None and previous == PLUGIN_TARGET.get():
            removed = previous not in global_members(proxies.get("GLOBAL"))
        fallback = removed and after["selected"] in (BOOTSTRAP, "DIRECT", "REJECT")
        observed = (before.get("reload_stamp") is not None
                    and before["reload_stamp"] != after.get("profile_stamp"))
        if not fallback or not (changed or observed):
            raise GuardError("user_takeover", "检测到用户切换，保留当前选择")
        raise GuardError("profile_reloading", "订阅正在重载，下个检测周期重新确认", after)
    if changed:
        raise GuardError("profile_reloading", "订阅正在重载，下个检测周期重新确认", after)


def eligible(context: dict, state: dict, allow_unhealthy_selection: bool = False) -> bool:
    if not same_scope(context) or state.get("corrupt"):
        return False
    selected = context["selected"]
    pending = state.get("pending_reload")
    if pending and selected == pending["selected"]:
        return True
    target = PLUGIN_TARGET.get() or TARGET
    available = target_available(context, target)
    if selected == target:
        return True
    if (allow_unhealthy_selection and available and selected not in (BOOTSTRAP, "DIRECT", "REJECT")
            and selected in context["proxies"] and state.get("last_selected") == selected):
        return True
    if state.get("owned_reject") and selected == "REJECT":
        return True
    missing = not available and state.get("last_selected") == target
    if missing and selected == BOOTSTRAP:
        return True
    # 只有订阅文件刚变更才能把 DIRECT/REJECT 视为节点删除后的内核回退。
    return (missing and selected in ("DIRECT", "REJECT") and context.get("profile_stamp") is not None
            and state.get("last_profile_stamp") is not None
            and context["profile_stamp"] != state["last_profile_stamp"])


def set_selection(name: str) -> None:
    if current_profile_uid() != PROFILE_UID or core_request("GET", "/configs").get("mode") != "global":
        raise GuardError("user_takeover", "订阅或模式已切换，保留用户当前设置")
    before = {"selected": core_request("GET", "/proxies/GLOBAL").get("now"),
              "profile_stamp": list(profile_stamp())}
    close_claude_desktop()
    if current_profile_uid() != PROFILE_UID:
        raise GuardError("user_takeover", "订阅已切换，保留用户当前设置")
    mode = core_request("GET", "/configs").get("mode")
    group = core_request("GET", "/proxies/GLOBAL")
    after = {"profile_uid": PROFILE_UID, "mode": mode, "selected": group.get("now"),
             "profile_stamp": list(profile_stamp())}
    if after["selected"] != before["selected"] and after["profile_stamp"] != before["profile_stamp"]:
        after["proxies"] = core_request("GET", "/proxies").get("proxies", {})
    check_recovery_context(before, after)
    if name == PLUGIN_TARGET.get() and name not in global_members(group):
        raise GuardError("target_missing", "切换前目标节点已不在全局组的可选列表")
    core_request("PUT", "/proxies/GLOBAL", {"name": name})
    selected = core_request("GET", "/proxies/GLOBAL").get("now")
    if selected != name:
        raise GuardError("selection_failed", "未能确认 GLOBAL 节点选择")


def rollback(state: dict) -> str:
    transaction = state.get("transaction")
    if not transaction:
        return "nothing_to_restore"
    context = inspect_context()
    owned = {transaction["expected"], transaction["original"], transaction.get("pending_selection"), transaction.get("before_selection")}
    if not same_scope(context) or context["selected"] not in owned:
        log_event("user_takeover", "检测到用户切换，保留用户当前选择")
        state["transaction"] = None
        return "user_takeover"
    original = transaction["original"]
    restored = original if original in context["proxies"] and original != BOOTSTRAP else "REJECT"
    if original == transaction.get("plugin_target") and (not supported_plugin_node(context, original)
            or original not in global_members(context["proxies"].get("GLOBAL"))):
        restored = "REJECT"
    if context["selected"] != restored and not ui_action("snapshot").get("unlocked"):
        raise GuardError("desktop_locked", "桌面已锁定，解锁后再处理未完成的节点切换")
    set_selection(restored)
    state["owned_reject"] = restored == "REJECT"
    state["last_selected"] = restored
    state["transaction"] = None
    log_event("rolled_back", "已还原原节点" if restored != "REJECT" else "原节点无法还原，已选择 REJECT")
    return "rolled_back"


def repair_interrupted(state: dict) -> None:
    if state.get("transaction"):
        log_event("interrupted", "发现上次未完成的恢复，先尝试还原节点")
        rollback(state)
        deferred = state.get("last_error_code") in DEFERRED_ERRORS
        state["cooldown_until"] = 0 if deferred else time.time() + COOLDOWN
        state["last_status"] = "界面中断已回退，继续检测" if deferred else "上次恢复已中断，等待冷却"
        save_state(state)


def close_claude_desktop() -> None:
    """只强制退出当前用户会话中的 Claude Desktop 及其子进程，不重启应用。"""
    # shortcut: 识别本机 Microsoft Store 版桌面路径；换用其他发行版时重新核对路径。
    script = r'''
if(@(Get-Process -Name Claude -ErrorAction SilentlyContinue).Count -eq 0){
    @{ok=$true;remaining=0;stopped=0}|ConvertTo-Json -Compress;exit
};
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
public static class GuardProcessOwner {
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr handle);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    public static bool IsCurrentUser(int pid, string sid) {
        IntPtr process=OpenProcess(0x1000, false, pid);
        if(process==IntPtr.Zero) {
            int error=Marshal.GetLastWin32Error();
            if(error==87) return false;
            throw new Win32Exception(error);
        }
        IntPtr token=IntPtr.Zero;
        try {
            if(!OpenProcessToken(process, 8, out token)) throw new Win32Exception();
            using(var identity=new WindowsIdentity(token)) return identity.User.Value==sid;
        } finally {
            if(token!=IntPtr.Zero) CloseHandle(token);
            CloseHandle(process);
        }
    }
}
'@;
$session=[System.Diagnostics.Process]::GetCurrentProcess().SessionId;
$sid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value;
$pattern='^'+[regex]::Escape($env:ProgramFiles+'\WindowsApps\')+'Claude_[^\\]+\\app\\Claude\.exe$';
function Get-DesktopRoots {
    foreach($process in @(Get-Process -Name Claude -ErrorAction SilentlyContinue)){
        if($process.HasExited -or $process.SessionId -ne $session){continue};
        if([GuardProcessOwner]::IsCurrentUser($process.Id,$sid)){
            if($process.HasExited){continue};
            if(-not $process.Path){throw 'Cannot verify Claude path'};
            if($process.Path -match $pattern){$process}
        }
    }
}
$roots=@(Get-DesktopRoots);
$ids=@{};
$rootStarts=@{};
foreach($item in $roots){$ids[[int]$item.Id]=$true;$rootStarts[[int]$item.Id]=$item.StartTime.ToUniversalTime().Ticks};
if($roots.Count -eq 0){@{ok=$true;remaining=0;stopped=0}|ConvertTo-Json -Compress;exit};
$all=@(Get-CimInstance Win32_Process -Filter "SessionId=$session");
do {
    $added=$false;
    foreach($item in $all){
        if($ids.ContainsKey([int]$item.ParentProcessId) -and -not $ids.ContainsKey([int]$item.ProcessId)){
            $ids[[int]$item.ProcessId]=$true; $added=$true
        }
    }
} while($added);
$tracked=@(foreach($item in $all){
    if($ids.ContainsKey([int]$item.ProcessId)){
        $process=Get-Process -Id $item.ProcessId -ErrorAction SilentlyContinue;
        if(-not $process -or $process.HasExited){continue};
        if(-not [GuardProcessOwner]::IsCurrentUser($process.Id,$sid)){
            if($process.HasExited){continue};
            throw 'Cannot verify Claude child owner'
        };
        if([Math]::Abs(($process.StartTime-$item.CreationDate).TotalSeconds) -gt 0.01){throw 'Claude process identity changed'};
        if($rootStarts.ContainsKey([int]$process.Id) -and $rootStarts[[int]$process.Id] -ne $process.StartTime.ToUniversalTime().Ticks){throw 'Claude root identity changed'};
        $process
    }
});
foreach($root in $roots){
    $process=@($tracked | Where-Object {$_.Id -eq $root.Id}) | Select-Object -First 1;
    if($process -and -not $process.HasExited){
        $current=Get-Process -Id $process.Id -ErrorAction SilentlyContinue;
        if(-not $current -or $current.HasExited){continue};
        if($current.StartTime.ToUniversalTime().Ticks -ne $rootStarts[[int]$process.Id]){throw 'Claude root identity changed'};
        $start=New-Object System.Diagnostics.ProcessStartInfo;
        $start.FileName="$env:WINDIR\System32\taskkill.exe";
        $start.Arguments='/PID '+$process.Id+' /T /F';
        $start.UseShellExecute=$false; $start.CreateNoWindow=$true;
        $start.RedirectStandardOutput=$true; $start.RedirectStandardError=$true;
        $kill=[System.Diagnostics.Process]::Start($start);
        $kill.BeginOutputReadLine(); $kill.BeginErrorReadLine();
        if(-not $kill.WaitForExit(4000)){$kill.Kill();throw 'Claude termination timed out'};
        if($kill.ExitCode -ne 0 -and -not $process.HasExited){throw 'Claude termination failed'};
        $kill.Dispose()
    }
};
foreach($process in $tracked){
    if(-not $process.HasExited){try{$process.Kill()}catch{if(-not $process.HasExited){throw}}}
};
$deadline=[DateTime]::UtcNow.AddSeconds(5);
while(@($tracked | Where-Object {-not $_.HasExited}).Count -gt 0 -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 100};
$remaining=@(Get-DesktopRoots).Count+@($tracked | Where-Object {-not $_.HasExited}).Count;
@{ok=($remaining -eq 0);remaining=$remaining;stopped=$tracked.Count}|ConvertTo-Json -Compress
'''
    try:
        result = run_powershell(script, timeout=remaining_timeout(15))
        if (result.get("ok") is not True or type(result.get("remaining")) is not int or result["remaining"] != 0
                or type(result.get("stopped")) is not int or result["stopped"] < 0):
            raise ValueError()
    except (GuardError, ValueError, TypeError, AttributeError):
        raise GuardError("claude_exit_failed", "无法确认 Claude Desktop 已完全退出，停止节点切换及订阅更新") from None
    if result["stopped"]:
        log_event("claude_desktop_closed", "已强制退出 Claude Desktop 及其子进程，不会自动重启")


def recover(state: dict, manual: bool = False, unhealthy_selection: bool = False) -> str:
    target = PLUGIN_TARGET.get() or TARGET
    snapshot = None
    started = False
    switched = False
    ui_touched = False
    deadline_token = REQUEST_DEADLINE.set(time.monotonic() + RECOVERY_TIMEOUT)
    try:
        context = inspect_context()
        if not same_scope(context):
            return "paused_scope"
        if not manual and not eligible(context, state, allow_unhealthy_selection=unhealthy_selection):
            return "paused_selection"
        available = target_available(context, target)
        if (not state.get("pending_reload") and state.get("last_selected") == context["selected"]
                and state.get("last_profile_stamp") is not None
                and state["last_profile_stamp"] != context.get("profile_stamp")):
            context["reload_stamp"] = state["last_profile_stamp"]
        session = ui_action("probe")
        if not session.get("unlocked"):
            return "deferred_locked"
        fresh = inspect_context()
        check_recovery_context(context, fresh)
        fresh_available = target_available(fresh, target)
        require_auto_action_allowed()
        close_claude_desktop()
        snapshot = ui_action("snapshot")
        if not snapshot.get("unlocked"):
            return "deferred_locked"
        fresh = inspect_context()
        check_recovery_context(context, fresh)
        if context.get("reload_stamp") is not None:
            raise GuardError("profile_reloading", "订阅文件已更新，等待内核应用后重新检查", fresh)
        pending = state.get("pending_reload")
        reuse_profile = (pending is not None and pending["selected"] == context["selected"]
                         and fresh_available and network_ready(fresh) and node_healthy(target))
        original = context["selected"]
        if pending or (not manual and not available and state.get("last_selected") == target):
            original = target
        if not reuse_profile:
            if BOOTSTRAP not in fresh["proxies"]:
                raise GuardError("bootstrap_missing", "当前订阅中没有 AN 订阅专用节点")
            if not node_healthy("DIRECT", DIRECT_URLS):
                return "deferred_offline"
            stamp = profile_stamp()
            require_auto_action_allowed()
            ui_touched = True
            if not network_ready(fresh):
                ui_action("protect")
                protection_deadline = time.monotonic() + remaining_timeout(20)
                while True:
                    try:
                        fresh = inspect_context()
                    except GuardError as error:
                        if error.code not in ("core_offline", "core_timeout", "core_unavailable"):
                            raise
                        fresh = None
                    if fresh is not None:
                        check_recovery_context(context, fresh)
                        if network_ready(fresh):
                            break
                    if time.monotonic() >= protection_deadline:
                        raise GuardError("network_protection_lost", "未能确认虚拟网卡和系统代理生效，停止本次恢复")
                    time.sleep(0.25)
                log_event("network_protection_enabled", "已确认虚拟网卡和 Clash 系统代理均已开启并生效")
            prepared = ui_action("prepare")
            fresh = inspect_context()
            check_recovery_context(context, fresh)
            if not network_ready(fresh):
                raise GuardError("network_protection_lost", "虚拟网卡或系统代理已关闭，停止本次恢复")
            require_auto_action_allowed()
            state.pop("last_error_code", None)
            state["transaction"] = {"original": original, "before_selection": context["selected"], "expected": BOOTSTRAP,
                                    "phase": "switching", "started_at": time.time(), "window": snapshot,
                                    "plugin_target": PLUGIN_TARGET.get()}
            save_state(state)
            started = True
            set_selection(BOOTSTRAP)
            switched = True
            state["transaction"]["phase"] = "updating"
            current = inspect_context()
            if not same_scope(current) or current["selected"] != BOOTSTRAP:
                raise GuardError("user_takeover", "检测到用户切换，停止订阅更新")
            if not network_ready(current):
                raise GuardError("network_protection_lost", "更新前虚拟网卡或系统代理已关闭，停止本次恢复")
            update_context = current
            log_event("subscription_update", "已切换 AN 节点，开始更新当前订阅")
            update_budget = remaining_timeout(172) - 20
            if update_budget < 1:
                raise GuardError("recovery_timeout", "恢复等待超过 180 秒，停止并还原节点")
            update_started = time.monotonic()
            result = ui_action("update", prepared.get("handoff"), timeout=update_budget)
            if not result.get("invoked") or not result.get("finished"):
                raise GuardError("update_unconfirmed", "未能确认原生订阅更新操作结束")
            if profile_stamp() == stamp:
                raise GuardError("subscription_unchanged", "未检测到当前订阅文件更新")
            log_event("subscription_saved", "当前订阅已保存且原生更新结束，耗时 %.2f 秒" % (time.monotonic() - update_started))
            reload_deadline = time.monotonic() + remaining_timeout(12)
            while True:
                try:
                    current = inspect_context()
                except GuardError as error:
                    if error.code not in ("core_offline", "core_timeout", "core_unavailable"):
                        raise
                    if time.monotonic() >= reload_deadline:
                        raise
                    time.sleep(0.25)
                    continue
                if not same_scope(current):
                    raise GuardError("user_takeover", "检测到用户切换，保留当前选择")
                if current["selected"] != BOOTSTRAP:
                    try:
                        check_recovery_context(update_context, current)
                    except GuardError as error:
                        if error.code == "profile_reloading":
                            state["transaction"]["expected"] = current["selected"]
                            save_state(state)
                        raise
                if not network_ready(current):
                    raise GuardError("network_protection_lost", "订阅更新期间虚拟网卡或系统代理已关闭，停止本次恢复")
                if target_available(current, target):
                    break
                if time.monotonic() >= reload_deadline:
                    raise GuardError("target_missing", "等待内核重载后仍没有恢复目标节点")
                time.sleep(0.25)
        else:
            fresh = inspect_context()
            check_recovery_context(context, fresh)
            if not target_available(fresh, target):
                raise GuardError("target_missing", "切换前目标节点已无法选择")
            if not network_ready(fresh):
                raise GuardError("network_protection_lost", "订阅重载后的网络保护未通过确认")
            require_auto_action_allowed()
            state.pop("last_error_code", None)
            state["transaction"] = {"original": original, "before_selection": context["selected"],
                                    "expected": context["selected"], "phase": "selecting_target",
                                    "started_at": time.time(), "plugin_target": PLUGIN_TARGET.get()}
            save_state(state)
            started = True
            log_event("subscription_reloaded", "外部订阅重载后目标节点已连通，直接切换，不重复更新")
        switch_started = time.monotonic()
        state["transaction"]["pending_selection"] = target
        state["transaction"]["phase"] = "selecting_target"
        save_state(state)
        set_selection(target)
        log_event("target_selected", "已切换至目标节点，耗时 %.2f 秒，开始确认连通" % (time.monotonic() - switch_started))
        verify_started = time.monotonic()
        remaining = remaining_timeout(20)
        if remaining < 2 or not node_healthy(target, timeout=min(10, remaining / 2)):
            raise GuardError("target_unhealthy", "更新后目标节点仍无法连接")
        log_event("target_verified", "目标节点连通验证通过，耗时 %.2f 秒" % (time.monotonic() - verify_started))
        remaining_timeout(12)
        final = inspect_context()
        if not network_ready(final):
            raise GuardError("network_protection_lost", "最终网络保护状态未通过确认，停止本次恢复")
        if not same_scope(final) or final["selected"] != target or not target_available(final, target):
            raise GuardError("selection_failed", "最终节点选择未通过确认")
        remaining_timeout(1)
        state.update(transaction=None, failures=0, cooldown_until=0, last_selected=target,
                     last_profile_stamp=final.get("profile_stamp"), owned_reject=False,
                     last_status="网络恢复成功", last_recovery=time.time())
        state.pop("last_error_code", None)
        state.pop("pending_reload", None)
        save_state(state)
        log_event("network_restored", "已选择目标节点并实测连通，网络恢复成功")
        return "network_restored"
    except (Exception, KeyboardInterrupt) as caught:
        error = caught if isinstance(caught, GuardError) else GuardError(
            "state_io" if isinstance(caught, OSError) else "recovery_error", "恢复过程异常，已停止并尝试还原节点")
        if error.code == "monitor_stopped":
            return error.code
        REQUEST_DEADLINE.reset(deadline_token)
        deadline_token = REQUEST_DEADLINE.set(time.monotonic() + 30)
        if started and error.code == "profile_reloading" and not switched:
            # 此错误只在 PUT 前产生；不能把尚未执行的切换回退成 REJECT。
            state["transaction"] = None
        elif started:
            try:
                restored = rollback(state)
                if error.code == "profile_reloading":
                    current = inspect_context()
                    if (restored == "rolled_back" and same_scope(current)
                            and current["selected"] == state.get("last_selected")):
                        error.context = current
                    else:
                        error = GuardError("user_takeover", "重载回退期间检测到用户切换，保留当前选择")
            except Exception:
                log_event("rollback_pending", "暂时无法还原节点，已保留中断记录，下次运行继续处理")
        if error.code == "profile_reloading" and error.context is not None:
            state["pending_reload"] = {"selected": error.context["selected"],
                                       "profile_stamp": error.context["profile_stamp"],
                                       "until": time.time() + 30}
        elif error.code == "user_takeover":
            state.pop("pending_reload", None)
        state["failures"] = max(2, state.get("failures", 0)) if error.code == "claude_exit_failed" and not started else 0
        deferred = error.code in DEFERRED_ERRORS
        state["cooldown_until"] = time.time() + COOLDOWN if (started or ui_touched) and not deferred else 0
        state["last_status"] = str(error)
        state["last_error_code"] = error.code
        try:
            save_state(state)
        except OSError:
            log_event("state_io", "无法保存恢复状态；保留已有磁盘记录供下次检查")
        log_event(error.code, str(error))
        if state["cooldown_until"]:
            log_event("recovery_cooldown", "界面准备或恢复失败，15 分钟内继续检测，不再自动打开 Clash")
        if started and deferred:
            log_event("recovery_deferred", "界面操作中断，下个检测周期重新检测；保留用户选择，不进入15分钟冷却")
        return error.code
    finally:
        REQUEST_DEADLINE.reset(deadline_token)
        if snapshot is not None and ui_touched:
            try:
                ui_action("restore", snapshot)
            except GuardError:
                log_event("window_restore_skipped", "未能恢复原窗口状态，节点处理结果不受影响")


def watch_tick(state: dict) -> str:
    target = PLUGIN_TARGET.get() or TARGET
    state["last_check"] = time.time()
    try:
        repair_interrupted(state)
        context = inspect_context()
        if state.get("corrupt"):
            return "paused_selection"
        available = same_scope(context) and target_available(context, target)
        cooling_down = time.time() < state.get("cooldown_until", 0)
        pending_ready = False
        pending = state.get("pending_reload")
        if pending:
            if (same_scope(context) and context["selected"] != pending["selected"]
                    and time.time() < pending["until"]
                    and (pending["selected"] not in context["proxies"]
                         or (pending["selected"] == target and not available))
                    and context["selected"] in (BOOTSTRAP, "DIRECT", "REJECT")):
                pending["selected"] = context["selected"]
            if not same_scope(context) or context["selected"] != pending["selected"]:
                state.pop("pending_reload", None)
            else:
                if not ui_action("probe").get("unlocked"):
                    return "deferred_locked"
                if not cooling_down and (not available or context["selected"] != target):
                    require_auto_action_allowed()
                    close_claude_desktop()
                if context.get("profile_stamp") != pending["profile_stamp"]:
                    pending["profile_stamp"] = context.get("profile_stamp")
                    if time.time() < pending["until"]:
                        return "profile_reloading"
                pending_ready = available and network_ready(context) and node_healthy(target)
                if pending_ready and context["selected"] != target:
                    return "cooldown" if cooling_down else recover(state)
                if not pending_ready:
                    if available and context["selected"] == target:
                        state["failures"] = state.get("failures", 0) + 1
                        if state["failures"] >= 2 and not cooling_down:
                            require_auto_action_allowed()
                            close_claude_desktop()
                    if time.time() < pending["until"]:
                        return "profile_reloading"
                    return "cooldown" if cooling_down else recover(state)
        if not eligible(context, state):
            selected = context["selected"]
            if (available and selected not in (target, BOOTSTRAP, "DIRECT", "REJECT")
                    and selected in context["proxies"]):
                if state.get("last_selected") != selected:
                    state["failures"] = 0
                    state["owned_reject"] = False
                    state["last_selected"] = selected
                    state["last_profile_stamp"] = context.get("profile_stamp")
                    return "paused_selection"
                cooling_down = time.time() < state.get("cooldown_until", 0)
                session = ui_action("probe")
                if not session.get("unlocked"):
                    return "deferred_locked"
                if node_healthy(selected) and network_ready(context):
                    state["failures"] = 0
                    state["owned_reject"] = False
                    state["last_selected"] = selected
                    state["last_profile_stamp"] = context.get("profile_stamp")
                    return "paused_selection"
                if cooling_down:
                    return "cooldown"
                state["failures"] = state.get("failures", 0) + 1
                state["last_selected"] = selected
                state["last_profile_stamp"] = context.get("profile_stamp")
                if state["failures"] < 2:
                    return "first_failure"
                return recover(state, unhealthy_selection=True)
            state["failures"] = 0
            state["owned_reject"] = False
            state["last_selected"] = context["selected"]
            state["last_profile_stamp"] = context.get("profile_stamp")
            return "paused_scope" if not same_scope(context) else "paused_selection"
        cooling_down = time.time() < state.get("cooldown_until", 0)
        session = ui_action("probe")
        if not session.get("unlocked"):
            return "deferred_locked"
        if available and (pending_ready or node_healthy(target)) and network_ready(context):
            if context["selected"] != target:
                return "cooldown" if cooling_down else recover(state)
            state["failures"] = 0
            state["owned_reject"] = False
            state.pop("last_error_code", None)
            if (not pending and state.get("last_profile_stamp") is not None
                    and context.get("profile_stamp") != state["last_profile_stamp"]):
                state["pending_reload"] = {"selected": context["selected"],
                                           "profile_stamp": context["profile_stamp"],
                                           "until": time.time() + 30}
            elif pending and time.time() >= pending["until"]:
                state.pop("pending_reload", None)
            state["last_selected"] = context["selected"]
            state["last_profile_stamp"] = context.get("profile_stamp")
            return "healthy"
        if cooling_down:
            return "cooldown"
        state["failures"] = state.get("failures", 0) + 1
        if available and state["failures"] < 2:
            state["last_selected"] = context["selected"]
            state["last_profile_stamp"] = context.get("profile_stamp")
            return "first_failure"
        return recover(state)
    except GuardError as error:
        state["failures"] = 0
        state["last_error_code"] = error.code
        state["last_status"] = str(error) + "（下个检测周期重试）"
        return error.code


def run_powershell(script: str, timeout=30) -> dict:
    prefix = '$ErrorActionPreference="Stop"; $env:PSModulePath="$env:WINDIR\\System32\\WindowsPowerShell\\v1.0\\Modules;$env:ProgramFiles\\WindowsPowerShell\\Modules"; [Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false); '
    encoded = base64.b64encode((prefix + script).encode("utf-16le")).decode("ascii")
    try:
        result = subprocess.run([str(POWERSHELL), "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                                capture_output=True, encoding="utf-8-sig", errors="replace", timeout=timeout, creationflags=NO_WINDOW)
        if result.returncode != 0:
            raise GuardError("task_error", "Windows 计划任务操作失败，请检查当前用户的任务权限")
        return json.loads(result.stdout.strip() or "{}")
    except (OSError, ValueError, subprocess.TimeoutExpired):
        raise GuardError("task_error", "Windows 计划任务未返回有效结果") from None


def ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def redirected_storage() -> Path | None:
    """MSIX 子进程可能无包标识却继承 AppData 写入重定向，用实际文件句柄路径判断。"""
    INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    probe = INSTALL_DIR / (".storage-probe-" + str(os.getpid()))
    try:
        probe.write_bytes(b"")
        physical = probe.resolve().parent
    finally:
        probe.unlink(missing_ok=True)
    if re.search(r"\\Packages\\[^\\]+\\LocalCache\\Local\\ClashSubscriptionGuard$", str(physical), re.I):
        return physical
    return None


def monitor_enabled() -> bool:
    return not (INSTALL_DIR / "monitor.pause").exists()


def start_tray() -> None:
    try:
        subprocess.Popen([str(POWERSHELL), "-NoProfile", "-NonInteractive", "-STA", "-WindowStyle", "Hidden",
                          "-ExecutionPolicy", "Bypass", "-File", str(SCRIPT_DIR / "tray.ps1"),
                          "-PythonExecutable", str(PYTHONW), "-GuardScript", str(Path(__file__).resolve()),
                          "-StorageDirectory", str(INSTALL_DIR),
                          "-OwnerPid", str(os.getpid())], creationflags=NO_WINDOW,
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError:
        log_event("tray_unavailable", "托盘未能启动，后台守护继续运行")


def tray_status() -> dict:
    """托盘只读测速；不调用界面、不切节点、不更改恢复状态。"""
    state = load_state()
    result = {"ok": True, "monitor_enabled": monitor_enabled(), "last_status": state.get("last_status"),
              "recovering": bool(state.get("transaction")), "latency_ms": None}
    config = core_request("GET", "/configs", timeout=3)
    proxies = core_request("GET", "/proxies", timeout=3).get("proxies", {})
    mode = config.get("mode")
    selected = proxies.get("GLOBAL", {}).get("now") if mode == "global" else None
    result.update(mode=mode, selected=selected)
    result["latency_status"] = "当前模式没有单一全局节点"
    if mode == "global":
        if not selected or selected not in proxies:
            result["latency_status"] = "节点不存在"
        elif selected in (BOOTSTRAP, "REJECT", "DIRECT"):
            result["latency_status"] = "订阅专用节点，不测速" if selected == BOOTSTRAP else "拒绝连接" if selected == "REJECT" else "直连模式"
        else:
            result["latency_status"] = "测速超时或不可达"
            for url in HEALTH_URLS:
                query = urlencode({"url": url, "timeout": 3500})
                try:
                    delay = core_request("GET", "/proxies/" + quote(selected, safe="") + "/delay?" + query, timeout=4).get("delay")
                    if type(delay) in (int, float) and math.isfinite(delay) and delay >= 0:
                        result.update(latency_ms=round(delay), latency_status="测试地址连通延迟")
                        break
                except GuardError:
                    continue
    final_mode = core_request("GET", "/configs", timeout=3).get("mode")
    final_selected = core_request("GET", "/proxies", timeout=3).get("proxies", {}).get("GLOBAL", {}).get("now")
    if final_mode != mode or (mode == "global" and final_selected != selected):
        result.update(mode=final_mode, selected=final_selected if final_mode == "global" else None,
                      latency_ms=None, latency_status="节点或模式已切换，等待刷新")
    result["sampled_at"] = time.time()
    return result


def watch() -> None:
    with InstanceLock():
        (INSTALL_DIR / "stop.request").unlink(missing_ok=True)
        state = load_state()
        start_tray()
        log_event("watch_started", "后台检测已启动：每 10 秒检查节点、虚拟网卡和系统代理，只恢复日本家宽 VL03")
        watch_loop(state)
        log_event("watch_stopped", "后台检测已停止")


def plugin_watch(pid: int, created: int, image: Path) -> None:
    with ExitStack() as stack:
        host = PluginHost(stack, pid, created, image)
        if redirected_storage() is not None:
            raise GuardError("storage_identity", "恢复助手无法访问原有状态目录")
        while host.alive():
            try:
                stack.enter_context(InstanceLock())
            except GuardError as error:
                if error.code != "already_running":
                    raise
                if not host.alive(1000):
                    return
            else:
                break
        else:
            return
        if not host.alive():
            return
        setup_logging()
        state = load_state()
        if not host.alive():
            return
        host.ready()
        stack.callback(host.not_ready)
        log_event("plugin_ready", f"TrafficMonitor 恢复助手已就绪，宿主 PID={pid}")
        action_token = AUTO_ACTION_ALLOWED.set(lambda: host.alive() and monitor_enabled())
        try:
            watch_loop(state, host)
        finally:
            AUTO_ACTION_ALLOWED.reset(action_token)
            log_event("plugin_stopped", f"TrafficMonitor 恢复助手已停止，宿主 PID={pid}")


def watch_loop(state: dict, host: PluginHost | None = None) -> None:
    last_started = None
    previous_status = None
    previous_paused = None
    pause_status = "自动恢复已暂停，延迟显示仍刷新" if host else "自动检查已暂停，托盘仍刷新延迟"
    while (host.alive() if host else not (INSTALL_DIR / "stop.request").exists()):
        paused = not monitor_enabled()
        if paused != previous_paused:
            state["failures"] = 0
            if paused:
                state.update(last_result="paused_manual", last_status=pause_status)
                save_state(state)
            last_started = None
            previous_paused = paused
            previous_status = None
        manual_file = INSTALL_DIR / "recover.request"
        manual = host is None and manual_file.exists()
        if manual:
            manual_file.unlink(missing_ok=True)
        settings_error = None
        target, interval = TARGET, CHECK_INTERVAL
        if host:
            try:
                target, interval = load_plugin_settings()
            except GuardError as error:
                settings_error = error
        due = last_started is None or time.monotonic() >= last_started + interval
        if manual or (due and (not paused or state.get("transaction"))):
            last_started = time.monotonic()
            try:
                if host and not host.alive():
                    break
                if paused and not manual:
                    repair_interrupted(state)
                    status = "paused_manual"
                elif host and state.get("transaction"):
                    try:
                        repair_interrupted(state)
                        status = "interrupted_repaired"
                    except GuardError as error:
                        status = error.code
                        state.update(last_error_code=error.code, last_status=str(error))
                elif settings_error:
                    status = settings_error.code
                    state.update(failures=0, last_error_code=status, last_status=str(settings_error))
                else:
                    if host:
                        if state.get("plugin_target", TARGET) != target:
                            state.update(failures=0, owned_reject=False, last_selected=None)
                            state.pop("pending_reload", None)
                            state.pop("last_profile_stamp", None)
                        state["plugin_target"] = target
                        if state.get("last_error_code") == "plugin_settings_invalid":
                            state.pop("last_error_code", None)
                    token = PLUGIN_TARGET.set(target if host else None)
                    try:
                        status = recover(state, manual=True) if manual else watch_tick(state)
                    finally:
                        PLUGIN_TARGET.reset(token)
                state["last_result"] = status
                messages = {
                    "healthy": "恢复目标节点正常，继续监控",
                    "first_failure": "首次检测到节点或网络保护异常，等待下一次确认",
                    "cooldown": "恢复冷却中，稍后重试",
                    "deferred_locked": "桌面锁定，解锁后继续",
                    "deferred_offline": "基础网络不可用，稍后重试",
                    "paused_scope": "当前订阅或模式已改变，暂停接管",
                    "paused_selection": "保留用户选择，暂停接管",
                    "paused_manual": pause_status,
                    "profile_reloading": "订阅正在重载，短暂等待后重新检查目标节点",
                }
                if status in messages:
                    state["last_status"] = messages[status]
                if status != previous_status:
                    log_event("watch_status", status)
                previous_status = status
                state["last_check_finished"] = time.time()
                save_state(state)
            except Exception:
                log_event("unexpected_error", "本次检查异常，保留恢复记录并稍后重试")
        if host:
            if not host.alive(1000):
                break
        else:
            time.sleep(1)


def check_status() -> dict:
    context = inspect_context()
    snapshot = ui_action("snapshot")
    state = load_state()
    return {"ok": True, "monitor_enabled": monitor_enabled(), "profile_matches": context["profile_uid"] == PROFILE_UID,
            "mode": context["mode"], "selected": context["selected"],
            "target_present": TARGET in context["proxies"], "bootstrap_present": BOOTSTRAP in context["proxies"],
            "desktop_unlocked": snapshot.get("unlocked"),
            "tun_enabled": context.get("tun_enabled"), "system_proxy_enabled": context.get("system_proxy_enabled"),
            "target_healthy": node_healthy(TARGET) if TARGET in context["proxies"] else False,
            "last_result": state.get("last_result"), "last_status": state.get("last_status"),
            "last_check": state.get("last_check"), "last_check_finished": state.get("last_check_finished"),
            "last_error_code": state.get("last_error_code"),
            "last_recovery": state.get("last_recovery"), "cooldown_until": state.get("cooldown_until"),
            "install_directory": str(INSTALL_DIR)}


def main() -> int:
    global REPORT_PATH
    if sys.stdout is not None:
        sys.stdout.reconfigure(encoding="utf-8")
    if sys.stdin is not None:
        sys.stdin.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    for action in ("check", "core-worker", "plugin-watch"):
        group.add_argument("--" + action, action="store_true")
    parser.add_argument("--report", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--host-pid", type=int)
    parser.add_argument("--host-created", type=int)
    parser.add_argument("--host-image", type=Path)
    args = parser.parse_args()
    REPORT_PATH = args.report
    if args.core_worker:
        core_worker()
        return 0
    if not PROFILE_UID:
        emit({"ok": False, "code": "profile_binding_invalid", "error": "请配置本机订阅绑定 profile-binding.json"})
        return 1
    if args.check:
        try:
            emit(check_status())
            return 0
        except GuardError as error:
            emit({"ok": False, "code": error.code, "error": str(error)})
            return 1
        except Exception:
            emit({"ok": False, "code": "status_unavailable", "error": "暂时无法读取当前节点状态"})
            return 1
    if args.host_pid is None or args.host_created is None or args.host_image is None:
        parser.error("--plugin-watch requires --host-pid, --host-created, and --host-image")
    try:
        plugin_watch(args.host_pid, args.host_created, args.host_image)
        return 0
    except GuardError as error:
        log_event(error.code, str(error))
        emit({"ok": False, "code": error.code, "error": str(error)})
        return 1
    except Exception:
        log_event("unexpected_error", "程序异常退出，已保留恢复记录；下次运行先尝试还原节点")
        emit({"ok": False, "code": "unexpected_error", "error": "程序异常，请查看本地日志"})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
