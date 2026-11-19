"""纯模拟回归：不访问内核、桌面或计划任务；原生 PowerShell 只执行桩函数，文件锁使用临时目录。"""

from contextlib import ExitStack, nullcontext
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import guard


def run_ui_selfcheck(script):
    # Windows limits the length of the UTF-16 encoded command line.
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "selfcheck.ps1"
        path.write_text(script, encoding="utf-8")
        return guard.run_powershell(f"& ([ScriptBlock]::Create([IO.File]::ReadAllText({guard.ps_quote(str(path))})))")


class World:
    def __init__(self, case):
        self.case = case
        self.state = guard.default_state()
        self.state["last_selected"] = guard.TARGET
        self.context = {
            "profile_uid": guard.PROFILE_UID,
            "mode": "global",
            "tun_enabled": True, "system_proxy_enabled": True,
            "selected": guard.TARGET,
            "proxies": {
                "GLOBAL": {}, guard.TARGET: {}, guard.BOOTSTRAP: {},
                "DIRECT": {}, "REJECT": {}, "用户手选节点": {},
            },
            "profile_stamp": [100, 10],
        }
        self.stamp = (100, 10)
        self.unlocked = True
        self.health = {guard.TARGET: True, "DIRECT": True, "用户手选节点": True}
        self.now = 0.0
        self.update_hook = None
        self.protect_hook = None
        self.select_hook = None
        self.close_hook = None
        self.events = []
        self.real_selection = guard.set_selection
        stack = case.enterContext(ExitStack())
        self.inspect = stack.enter_context(patch.object(guard, "inspect_context", side_effect=lambda *a, **k: deepcopy(self.context)))
        self.ui = stack.enter_context(patch.object(guard, "ui_action", side_effect=self.ui_action))
        self.check_health = stack.enter_context(patch.object(guard, "node_healthy", side_effect=lambda name, *a, **k: self.health[name]))
        stack.enter_context(patch.object(guard, "profile_stamp", side_effect=lambda: self.stamp))
        self.select = stack.enter_context(patch.object(guard, "set_selection", side_effect=self.set_selection))
        self.close_claude = stack.enter_context(patch.object(guard, "close_claude_desktop", side_effect=self.close_claude_desktop, create=True))
        self.saved = []
        self.save = stack.enter_context(patch.object(guard, "save_state", side_effect=lambda state: self.saved.append(deepcopy(state))))
        self.log = stack.enter_context(patch.object(guard, "log_event"))
        stack.enter_context(patch.object(guard.time, "time", return_value=1000.0))
        stack.enter_context(patch.object(guard.time, "monotonic", side_effect=lambda: self.now))

    def ui_action(self, action, snapshot=None, **kwargs):
        self.events.append(action)
        if action in ("probe", "snapshot"):
            return {"ok": True, "unlocked": self.unlocked, "window": {"visible": False}}
        if action == "protect":
            if self.protect_hook:
                return self.protect_hook()
            self.context.update(tun_enabled=True, system_proxy_enabled=True)
            return {"ok": True, "tun_enabled": True, "system_proxy_enabled": True}
        if action == "update":
            if self.update_hook:
                return self.update_hook()
            self.stamp = (200, 10)
            return {"ok": True, "invoked": True, "finished": True}
        return {"ok": True}

    def set_selection(self, name, **kwargs):
        self.events.append(name)
        self.context["selected"] = name
        if self.select_hook:
            self.select_hook(name)

    def close_claude_desktop(self):
        self.events.append("close_claude")
        if self.close_hook:
            return self.close_hook()

    def assert_not_changed(self):
        self.select.assert_not_called()
        self.close_claude.assert_not_called()
        self.case.assertFalse(any(call.args[0] in ("protect", "prepare", "update") for call in self.ui.call_args_list))

    def fail_update(self, code="update_error"):
        def fail():
            raise guard.GuardError(code, "模拟更新失败")
        self.update_hook = fail


class GuardTests(unittest.TestCase):
    def test_healthy_tick_never_switches_or_opens_window(self):
        world = World(self)
        self.assertEqual(guard.watch_tick(world.state), "healthy")
        world.assert_not_changed()
        self.assertEqual(world.state["failures"], 0)

    def test_healthy_tick_clears_obsolete_error_code(self):
        world = World(self)
        world.state["last_error_code"] = "claude_exit_failed"
        self.assertEqual(guard.watch_tick(world.state), "healthy")
        self.assertNotIn("last_error_code", world.state)
        world.assert_not_changed()

    def test_detection_does_not_require_subscription_window(self):
        world = World(self)
        original_ui = world.ui_action
        def without_window(action, *args, **kwargs):
            if action == "snapshot":
                raise guard.GuardError("window_unavailable", "未找到可操作的 Clash Verge 窗口。")
            return original_ui(action, *args, **kwargs)
        world.ui.side_effect = without_window
        self.assertEqual(guard.watch_tick(world.state), "healthy")
        world.health[guard.TARGET] = False
        self.assertEqual(guard.watch_tick(world.state), "first_failure")
        self.assertEqual(guard.watch_tick(world.state), "window_unavailable")
        self.assertEqual(world.state["last_error_code"], "window_unavailable")
        self.assertNotIn("正常", world.state["last_status"])
        self.assertEqual(world.state["cooldown_until"], 0)
        world.close_claude.assert_called_once_with()
        world.select.assert_not_called()
        self.assertFalse(any(call.args[0] in ("protect", "prepare", "update") for call in world.ui.call_args_list))

    def test_detection_error_replaces_obsolete_healthy_message_and_retries(self):
        world = World(self)
        world.state["last_status"] = "日本家宽 VL03 正常，继续监控"
        world.ui.side_effect = guard.GuardError("app_not_running", "Clash Verge 未运行。")
        self.assertEqual(guard.watch_tick(world.state), "app_not_running")
        self.assertEqual(world.state["last_error_code"], "app_not_running")
        self.assertIn("下个检测周期重试", world.state["last_status"])
        self.assertNotIn("正常", world.state["last_status"])
        world.ui.side_effect = world.ui_action
        self.assertEqual(guard.watch_tick(world.state), "healthy")
        self.assertNotIn("last_error_code", world.state)
        world.assert_not_changed()

    def test_update_ui_diagnostic_logs_only_booleans_and_known_foreground_category(self):
        sensitive = r"C:\private\session-token\Claude.exe PID 123456 --secret"
        for foreground in (sensitive, "unrecognized-foreground-category"):
            payload = {"ok": False, "code": "ui_error", "diagnostic": {
                "menu_opened": sensitive, "update_invoked": 1,
                "foreground_same_process": sensitive, "foreground_owned_window": True,
                "foreground_process": foreground, "pid": 123456,
                "path": sensitive, "command_line": sensitive, "error": sensitive,
            }}
            with self.subTest(foreground=foreground), \
                    patch.object(guard.subprocess, "run", return_value=Mock(stdout=guard.json.dumps(payload))), \
                    patch.object(guard, "log_event") as log:
                with self.assertRaises(guard.GuardError) as caught:
                    guard.ui_action("update")
                self.assertEqual(caught.exception.code, "ui_error")
                self.assertEqual(str(caught.exception), "无法操作 Clash Verge 订阅界面")
                log.assert_called_once_with("update_ui_stopped", "菜单已打开=False，更新已调用=False，前台属于本应用=False，前台属于本应用的窗口=True，前台类别=other")
                self.assertNotIn(sensitive, str(log.call_args))

    def test_existing_target_needs_two_consecutive_failures(self):
        world = World(self)
        world.health[guard.TARGET] = False
        with patch.object(guard, "recover", return_value="requested") as recover:
            self.assertEqual(guard.watch_tick(world.state), "first_failure")
            recover.assert_not_called()
            world.close_claude.assert_not_called()
            self.assertEqual(guard.watch_tick(world.state), "requested")
            recover.assert_called_once_with(world.state)

    def test_unhealthy_manual_selection_needs_two_failures_then_recovers(self):
        world = World(self)
        world.context["selected"] = "用户手选节点"
        world.health["用户手选节点"] = False
        with patch.object(guard, "recover", return_value="requested") as recover:
            self.assertEqual(guard.watch_tick(world.state), "paused_selection")
            self.assertEqual(guard.watch_tick(world.state), "first_failure")
            self.assertEqual(world.state["failures"], 1)
            self.assertEqual(guard.watch_tick(world.state), "requested")
            recover.assert_called_once_with(world.state, unhealthy_selection=True)

    def test_successful_tick_resets_consecutive_failures(self):
        world = World(self)
        world.state["failures"] = 1
        self.assertEqual(guard.watch_tick(world.state), "healthy")
        self.assertEqual(world.state["failures"], 0)

    def test_owned_reject_recovers_even_when_target_is_healthy_again(self):
        world = World(self)
        world.context["selected"] = "REJECT"
        world.state["owned_reject"] = True
        with patch.object(guard, "recover", return_value="requested") as recover:
            self.assertEqual(guard.watch_tick(world.state), "requested")
            recover.assert_called_once_with(world.state)

    def test_missing_target_requests_recovery_without_second_failure(self):
        world = World(self)
        del world.context["proxies"][guard.TARGET]
        with patch.object(guard, "recover", return_value="requested") as recover:
            self.assertEqual(guard.watch_tick(world.state), "requested")
            recover.assert_called_once_with(world.state)

    def test_user_profile_mode_or_selection_pauses(self):
        world = World(self)
        for key, value in (("profile_uid", "another_profile"), ("mode", "rule"), ("selected", "用户手选节点")):
            with self.subTest(key=key):
                original = world.context[key]
                world.context[key] = value
                self.assertTrue(guard.watch_tick(world.state).startswith("paused_"))
                world.assert_not_changed()
                world.context[key] = original
                world.state["last_selected"] = guard.TARGET

    def test_missing_target_does_not_override_explicit_other_selection(self):
        world = World(self)
        del world.context["proxies"][guard.TARGET]
        world.context["selected"] = "用户手选节点"
        self.assertEqual(guard.watch_tick(world.state), "paused_selection")
        world.assert_not_changed()

    def test_missing_target_with_changed_profile_can_recover_core_fallback(self):
        world = World(self)
        del world.context["proxies"][guard.TARGET]
        world.context["selected"] = "DIRECT"
        world.state["last_profile_stamp"] = [99, 10]
        with patch.object(guard, "recover", return_value="requested") as recover:
            self.assertEqual(guard.watch_tick(world.state), "requested")
            recover.assert_called_once_with(world.state)

    def test_missing_target_without_profile_change_preserves_direct_choice(self):
        world = World(self)
        del world.context["proxies"][guard.TARGET]
        world.context["selected"] = "DIRECT"
        world.state["last_profile_stamp"] = [100, 10]
        self.assertEqual(guard.watch_tick(world.state), "paused_selection")
        world.assert_not_changed()

    def test_failed_recovery_after_core_direct_fallback_fails_closed(self):
        world = World(self)
        del world.context["proxies"][guard.TARGET]
        world.context["selected"] = "DIRECT"
        world.state["last_profile_stamp"] = [99, 10]
        world.fail_update()
        self.assertEqual(guard.recover(world.state), "update_error")
        self.assertEqual(world.context["selected"], "REJECT")
        self.assertEqual([call.args[0] for call in world.select.call_args_list], [guard.BOOTSTRAP, "REJECT"])

    def test_locked_and_core_offline_never_switch(self):
        world = World(self)
        world.unlocked = False
        self.assertEqual(guard.watch_tick(world.state), "deferred_locked")
        world.assert_not_changed()
        world.inspect.side_effect = guard.GuardError("core_offline", "模拟离线")
        self.assertEqual(guard.watch_tick(world.state), "core_offline")
        world.assert_not_changed()

    def test_recover_success_requires_saved_profile_healthy_target_and_global(self):
        world = World(self)
        world.state["last_error_code"] = "claude_exit_failed"
        self.assertEqual(guard.recover(world.state), "network_restored")
        self.assertEqual([call.args[0] for call in world.select.call_args_list], [guard.BOOTSTRAP, guard.TARGET])
        self.assertTrue(world.saved[0]["transaction"])
        self.assertIsNone(world.state["transaction"])
        self.assertEqual(world.context["selected"], guard.TARGET)
        self.assertEqual(world.state["last_status"], "网络恢复成功")
        self.assertNotIn("last_error_code", world.state)

    def test_updated_target_is_selected_before_health_verification(self):
        world = World(self)
        def health(name, *args, **kwargs):
            if name == guard.TARGET:
                self.assertEqual(world.context["selected"], guard.TARGET)
                self.assertEqual(world.stamp, (200, 10))
                self.assertEqual(world.saved[-1]["transaction"]["pending_selection"], guard.TARGET)
                self.assertEqual(world.saved[-1]["transaction"]["phase"], "selecting_target")
                world.events.append("target_health")
            return True
        world.check_health.side_effect = health
        self.assertEqual(guard.recover(world.state), "network_restored")
        self.assertLess(world.events.index("update"), world.events.index(guard.TARGET))
        self.assertLess(world.events.index(guard.TARGET), world.events.index("target_health"))

    def test_early_target_selection_rolls_back_if_health_fails_without_success(self):
        world = World(self)
        world.context["selected"] = "REJECT"
        world.state.update(last_selected="REJECT", owned_reject=True)
        world.health[guard.TARGET] = False
        self.assertEqual(guard.recover(world.state), "target_unhealthy")
        self.assertEqual([call.args[0] for call in world.select.call_args_list], [guard.BOOTSTRAP, guard.TARGET, "REJECT"])
        self.assertEqual(world.context["selected"], "REJECT")
        self.assertIsNone(world.state["transaction"])
        self.assertTrue(world.state["owned_reject"])
        self.assertEqual(world.state["cooldown_until"], 1000 + guard.COOLDOWN)
        self.assertNotIn("network_restored", [call.args[0] for call in world.log.call_args_list])

    def test_user_switch_during_selected_target_health_is_preserved(self):
        world = World(self)
        def health(name, *args, **kwargs):
            if name == guard.TARGET:
                self.assertEqual(world.context["selected"], guard.TARGET)
                world.context["selected"] = "用户手选节点"
            return True
        world.check_health.side_effect = health
        self.assertNotEqual(guard.recover(world.state), "network_restored")
        self.assertEqual(world.context["selected"], "用户手选节点")
        self.assertEqual([call.args[0] for call in world.select.call_args_list], [guard.BOOTSTRAP, guard.TARGET])
        self.assertIsNone(world.state["transaction"])
        self.assertNotIn("network_restored", [call.args[0] for call in world.log.call_args_list])

    def test_confirmed_failure_closes_claude_before_window_and_an(self):
        world = World(self)
        world.health[guard.TARGET] = False
        world.state["failures"] = 1
        def update():
            world.health[guard.TARGET] = True
            world.stamp = (200, 10)
            return {"ok": True, "invoked": True, "finished": True}
        world.update_hook = update
        self.assertEqual(guard.watch_tick(world.state), "network_restored")
        self.assertLess(world.events.index("close_claude"), world.events.index("prepare"))
        self.assertLess(world.events.index("prepare"), world.events.index(guard.BOOTSTRAP))
        self.assertLess(world.events.index(guard.BOOTSTRAP), world.events.index("update"))

    def test_missing_target_closes_claude_before_subscription_recovery(self):
        world = World(self)
        del world.context["proxies"][guard.TARGET]
        world.fail_update()
        self.assertEqual(guard.watch_tick(world.state), "update_error")
        world.close_claude.assert_called_once_with()
        self.assertLess(world.events.index("close_claude"), world.events.index(guard.BOOTSTRAP))

    def test_claude_exit_failure_cannot_prepare_update_or_switch(self):
        world = World(self)
        world.close_claude.side_effect = guard.GuardError("claude_exit_failed", "模拟 Claude 无法退出")
        self.assertEqual(guard.recover(world.state), "claude_exit_failed")
        world.select.assert_not_called()
        self.assertFalse(any(call.args[0] in ("prepare", "update") for call in world.ui.call_args_list))
        self.assertIsNone(world.state["transaction"])

    def test_claude_preflight_failure_retries_on_next_failed_tick_without_cooldown(self):
        world = World(self)
        world.health[guard.TARGET] = False
        world.state["failures"] = 1
        world.close_claude.side_effect = guard.GuardError("claude_exit_failed", "模拟 Claude 无法退出")
        self.assertEqual(guard.watch_tick(world.state), "claude_exit_failed")
        self.assertEqual(world.state["cooldown_until"], 0)
        self.assertGreaterEqual(world.state["failures"], 2)
        self.assertEqual(guard.watch_tick(world.state), "claude_exit_failed")
        self.assertEqual(world.close_claude.call_count, 2)
        self.assertEqual(world.state["last_error_code"], "claude_exit_failed")
        self.assertEqual(world.state["last_check"], 1000.0)
        world.select.assert_not_called()
        self.assertFalse(any(call.args[0] in ("prepare", "update") for call in world.ui.call_args_list))

    def test_cooldown_still_checks_target_and_reports_recovered_health(self):
        world = World(self)
        world.state.update(cooldown_until=1900.0, failures=2)
        with patch.object(guard, "recover") as recover:
            self.assertEqual(guard.watch_tick(world.state), "healthy")
        world.check_health.assert_called_once_with(guard.TARGET)
        recover.assert_not_called()
        self.assertEqual(world.state["failures"], 0)
        world.assert_not_changed()

    def test_unhealthy_target_during_cooldown_is_checked_without_new_recovery(self):
        world = World(self)
        world.state.update(cooldown_until=1900.0, failures=2)
        world.health[guard.TARGET] = False
        with patch.object(guard, "recover") as recover:
            self.assertEqual(guard.watch_tick(world.state), "cooldown")
        world.check_health.assert_called_once_with(guard.TARGET)
        recover.assert_not_called()
        world.assert_not_changed()

    def test_preparation_failures_cool_down_without_reopening_clash(self):
        world = World(self)
        for action, code in (("protect", "network_switch_unavailable"),
                             ("prepare", "profile_not_found"),
                             ("prepare", "ui_timeout"),
                             ("prepare", "foreground_unavailable"),
                             ("prepare", "user_takeover")):
            with self.subTest(action=action, code=code):
                world.state = guard.default_state()
                world.state["last_selected"] = guard.TARGET
                world.context.update(selected=guard.TARGET, tun_enabled=action != "protect",
                                     system_proxy_enabled=True)
                world.health[guard.TARGET] = False
                world.events.clear()
                world.ui.reset_mock()
                world.select.reset_mock()
                world.close_claude.reset_mock()
                def fail_preparation(requested, *args, **kwargs):
                    if requested == action:
                        world.events.append(requested)
                        raise guard.GuardError(code, "模拟界面准备失败")
                    return world.ui_action(requested, *args, **kwargs)
                world.ui.side_effect = fail_preparation

                self.assertEqual(guard.watch_tick(world.state), "first_failure")
                self.assertEqual(guard.watch_tick(world.state), code)
                self.assertEqual(world.state["cooldown_until"], 1000 + guard.COOLDOWN)
                self.assertIsNone(world.state["transaction"])
                world.select.assert_not_called()
                self.assertNotIn("update", world.events)
                self.assertEqual(world.context["selected"], guard.TARGET)
                attempts = world.events.count(action)
                closed = world.close_claude.call_count
                for _ in range(4):
                    self.assertEqual(guard.watch_tick(world.state), "cooldown")
                self.assertEqual(world.events.count(action), attempts)
                self.assertEqual(world.close_claude.call_count, closed)
                with patch.object(guard.time, "time", return_value=1000 + guard.COOLDOWN):
                    self.assertEqual(guard.watch_tick(world.state), "first_failure")
                    self.assertEqual(guard.watch_tick(world.state), code)
                self.assertEqual(world.events.count(action), attempts + 1)

    def test_locked_or_offline_before_ui_does_not_delay_next_check(self):
        world = World(self)
        world.unlocked = False
        self.assertEqual(guard.recover(world.state), "deferred_locked")
        self.assertEqual(world.state["cooldown_until"], 0)
        world.assert_not_changed()

        world.unlocked = True
        world.health["DIRECT"] = False
        self.assertEqual(guard.recover(world.state), "deferred_offline")
        self.assertEqual(world.state["cooldown_until"], 0)
        self.assertFalse(any(call.args[0] in ("protect", "prepare", "update")
                             for call in world.ui.call_args_list))
        world.select.assert_not_called()
        world.health["DIRECT"] = True
        self.assertEqual(guard.watch_tick(world.state), "healthy")

    def test_watch_uses_check_start_for_ten_second_cadence(self):
        world = World(self)
        starts = []
        def tick(state):
            starts.append(world.now)
            world.now += 4
            return "healthy"
        def exists(path):
            return path.name == "stop.request" and len(starts) >= 2
        def sleep(seconds):
            world.now += seconds
        with patch.object(guard, "InstanceLock"), patch.object(guard, "load_state", return_value=world.state), \
                patch.object(guard, "start_tray"), \
                patch.object(guard, "watch_tick", side_effect=tick), patch.object(Path, "unlink"), \
                patch.object(Path, "exists", autospec=True, side_effect=exists), patch.object(guard.time, "sleep", side_effect=sleep):
            guard.watch()
        self.assertEqual(starts, [0, 10])

    def test_pause_blocks_automatic_checks_and_resume_starts_fresh_confirmation(self):
        world = World(self)
        world.state["failures"] = 1
        checks = []
        def tick(state):
            checks.append((world.now, state["failures"]))
            return "healthy"
        with patch.object(guard, "InstanceLock"), patch.object(guard, "start_tray"), \
                patch.object(guard, "load_state", return_value=world.state), \
                patch.object(guard, "monitor_enabled", side_effect=lambda: world.now >= 3), \
                patch.object(guard, "watch_tick", side_effect=tick), patch.object(Path, "unlink"), \
                patch.object(Path, "exists", autospec=True, side_effect=lambda path: path.name == "stop.request" and bool(checks)), \
                patch.object(guard.time, "sleep", side_effect=lambda seconds: setattr(world, "now", world.now + seconds)):
            guard.watch()
        self.assertEqual(checks, [(3, 0)])
        self.assertEqual(world.saved[0]["last_result"], "paused_manual")
        world.assert_not_changed()

    def test_paused_restart_repairs_interrupted_switch_without_new_recovery(self):
        world = World(self)
        world.state["transaction"] = {"original": guard.TARGET, "expected": guard.BOOTSTRAP}
        def repair(state):
            state["transaction"] = None
        with patch.object(guard, "InstanceLock"), patch.object(guard, "start_tray"), \
                patch.object(guard, "load_state", return_value=world.state), patch.object(guard, "monitor_enabled", return_value=False), \
                patch.object(guard, "repair_interrupted", side_effect=repair) as rollback, \
                patch.object(guard, "watch_tick") as tick, patch.object(guard, "recover") as recover, patch.object(Path, "unlink"), \
                patch.object(Path, "exists", autospec=True, side_effect=lambda path: path.name == "stop.request" and world.now >= 1), \
                patch.object(guard.time, "sleep", side_effect=lambda seconds: setattr(world, "now", world.now + seconds)):
            guard.watch()
        rollback.assert_called_once_with(world.state)
        tick.assert_not_called()
        recover.assert_not_called()

    def test_pause_marker_persists_independently_of_state(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(guard, "INSTALL_DIR", Path(directory)):
            self.assertTrue(guard.monitor_enabled())
            (Path(directory) / "monitor.pause").write_text("paused", encoding="ascii")
            self.assertFalse(guard.monitor_enabled())
            (Path(directory) / "monitor.pause").unlink()
            self.assertTrue(guard.monitor_enabled())

    def test_tray_reads_current_user_node_without_ui_or_recovery(self):
        world = World(self)
        selected = "用户手选节点"
        responses = [{"mode": "global"}, {"proxies": {"GLOBAL": {"now": selected}, selected: {}}},
                     {"delay": 123}, {"mode": "global"}, {"proxies": {"GLOBAL": {"now": selected}}}]
        with patch.object(guard, "load_state", return_value=world.state), \
                patch.object(guard, "core_request", side_effect=responses) as core:
            status = guard.tray_status()
        self.assertEqual(status["selected"], selected)
        self.assertEqual(status["latency_ms"], 123)
        self.assertIn(guard.quote(selected, safe=""), core.call_args_list[2].args[1])
        self.assertTrue(all(call.args[0] == "GET" for call in core.call_args_list))
        world.ui.assert_not_called()
        world.assert_not_changed()
        world.save.assert_not_called()

    def test_tray_discards_delay_after_user_switch(self):
        responses = [{"mode": "global"}, {"proxies": {"GLOBAL": {"now": guard.TARGET}, guard.TARGET: {}}},
                     {"delay": 98}, {"mode": "global"}, {"proxies": {"GLOBAL": {"now": "其他节点"}}}]
        with patch.object(guard, "load_state", return_value=guard.default_state()), \
                patch.object(guard, "core_request", side_effect=responses):
            status = guard.tray_status()
        self.assertEqual(status["selected"], "其他节点")
        self.assertIsNone(status["latency_ms"])
        self.assertIn("已切换", status["latency_status"])

    def test_tray_fallback_and_invalid_delay_never_shows_false_success(self):
        for first in (guard.GuardError("core_timeout", "超时"), {"delay": True}, {"delay": float("nan")}, {"delay": -1}):
            with self.subTest(first=first):
                responses = [{"mode": "global"}, {"proxies": {"GLOBAL": {"now": guard.TARGET}, guard.TARGET: {}}},
                             first, {"delay": 207}, {"mode": "global"}, {"proxies": {"GLOBAL": {"now": guard.TARGET}}}]
                with patch.object(guard, "load_state", return_value=guard.default_state()), \
                        patch.object(guard, "core_request", side_effect=responses):
                    status = guard.tray_status()
                self.assertEqual(status["latency_ms"], 207)

    def test_tray_special_nodes_and_rule_mode_are_not_probed(self):
        for mode, selected in (("rule", guard.TARGET), ("direct", "DIRECT"), ("global", guard.BOOTSTRAP), ("global", "REJECT")):
            with self.subTest(mode=mode, selected=selected):
                responses = [{"mode": mode}, {"proxies": {"GLOBAL": {"now": selected}, selected: {}}},
                             {"mode": mode}, {"proxies": {"GLOBAL": {"now": selected}}}]
                with patch.object(guard, "load_state", return_value=guard.default_state()), \
                        patch.object(guard, "core_request", side_effect=responses) as core:
                    status = guard.tray_status()
                self.assertIsNone(status["latency_ms"])
                self.assertEqual(core.call_count, 4)

    def test_tray_launch_is_hidden_and_failure_does_not_stop_guard(self):
        with patch.object(guard.subprocess, "Popen") as launch:
            guard.start_tray()
        args = launch.call_args.args[0]
        self.assertIn("-STA", args)
        self.assertIn("Hidden", args)
        self.assertIn(str(guard.SCRIPT_DIR / "tray.ps1"), args)
        with patch.object(guard.subprocess, "Popen", side_effect=OSError), patch.object(guard, "log_event") as log:
            guard.start_tray()
        self.assertEqual(log.call_args.args[0], "tray_unavailable")

    @unittest.skipUnless(guard.os.name == "nt", "Windows 窗口识别离线自检")
    def test_native_window_selection_and_process_probe_without_real_desktop(self):
        source = (guard.SCRIPT_DIR / "verge_ui.ps1").read_text(encoding="utf-8-sig")
        native = source.split("Add-Type -TypeDefinition @'\n", 1)[1].split("\n'@", 1)[0]
        method = native[native.index("    public static IntPtr[] Windows() {"):native.index("    public static bool Unlocked() {")]
        method = method.replace('Process.GetProcessById(Pid(hwnd)).ProcessName', 'Names[Pid(hwnd) - 1]')
        stub = r'''
using System;
using System.Text;
using System.Collections.Generic;
public static class GuardWindowSelectionStub {
    static string[] Titles, Names;
    static bool[] Visible;
    public static bool IsUnlocked = true;
    public static bool Unlocked() { return IsUnlocked; }
    public delegate bool EnumProc(IntPtr hwnd, IntPtr ignored);
    public static void Set(string[] titles, string[] names, bool[] visible) { Titles=titles; Names=names; Visible=visible; }
    static bool EnumWindows(EnumProc callback, IntPtr ignored) {
        for (int i=0; i<Titles.Length; i++) callback(new IntPtr(i+1), ignored);
        return true;
    }
    static int Pid(IntPtr hwnd) { return hwnd.ToInt32(); }
    static bool IsWindowVisible(IntPtr hwnd) { return Visible[Pid(hwnd)-1]; }
    static int GetWindowText(IntPtr hwnd, StringBuilder text, int count) { text.Append(Titles[Pid(hwnd)-1]); return text.Length; }
METHOD
}
'''.replace("METHOD", method)
        probe = source[source.index("    if ($Action -eq 'probe') {"):source.index("    $candidates =")]
        probe = probe.replace("[GuardWindow]", "[GuardWindowSelectionStub]").replace("exit 0", "return")
        script = r'''
Add-Type -TypeDefinition NATIVE
Add-Type -TypeDefinition STUB
[GuardWindowSelectionStub]::Set(@('Clash Verge',''), @('clash-verge','clash-verge'), @($false,$true))
if(@([GuardWindowSelectionStub]::Windows()).Count -ne 1 -or [GuardWindowSelectionStub]::Windows()[0].ToInt32() -ne 1){throw 'exact_title_priority'}
[GuardWindowSelectionStub]::Set(@('',''), @('clash-verge','other'), @($true,$true))
if(@([GuardWindowSelectionStub]::Windows()).Count -ne 1){throw 'empty_title_fallback'}
[GuardWindowSelectionStub]::Set(@('',''), @('clash-verge','clash-verge'), @($true,$true))
if(@([GuardWindowSelectionStub]::Windows()).Count -ne 2){throw 'ambiguous_candidates_preserved'}
[GuardWindowSelectionStub]::Set(@('','Clash Verge'), @('clash-verge','other'), @($false,$true))
if(@([GuardWindowSelectionStub]::Windows()).Count -ne 0){throw 'hidden_or_wrong_process_ignored'}
function Fail($code,$message){throw $code}
function Get-Process { param($Name,$ErrorAction)
    if($Name -ne 'clash-verge'){throw 'wrong_process_name'}
    $session=[Diagnostics.Process]::GetCurrentProcess().SessionId
    if($script:sameSession){[pscustomobject]@{SessionId=$session}}else{[pscustomobject]@{SessionId=$session+1}}
}
function Invoke-Probe {
PROBE
}
$Action='probe'; $script:sameSession=$true
$result=Invoke-Probe | ConvertFrom-Json
if(-not $result.ok -or -not $result.unlocked){throw 'probe_without_window'}
[GuardWindowSelectionStub]::IsUnlocked=$false
if((Invoke-Probe | ConvertFrom-Json).unlocked){throw 'probe_locked'}
$script:sameSession=$false
$caught=$false
try{Invoke-Probe}catch{if($_.Exception.Message -ne 'app_not_running'){throw};$caught=$true}
if(-not $caught){throw 'other_session_accepted'}
@{passed=7}|ConvertTo-Json -Compress
'''.replace("NATIVE", guard.ps_quote(native)).replace("STUB", guard.ps_quote(stub)).replace("PROBE", probe)
        self.assertEqual(run_ui_selfcheck(script)["passed"], 7)

    @unittest.skipUnless(guard.os.name == "nt", "Windows 网络开关定位离线自检")
    def test_native_network_switch_heading_row_and_loading_without_desktop(self):
        script = r'''
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes, WindowsBase
Add-Type -TypeDefinition @'
public class GuardSwitchRect {
    public double Left, Top, Right, Bottom;
    public bool IsEmpty;
    public GuardSwitchRect(double left, double top, double width, double height) { Left=left; Top=top; Right=left+width; Bottom=top+height; }
}
public class GuardSwitchInfo {
    public string Name;
    public bool IsOffscreen;
    public object ControlType;
    public GuardSwitchRect BoundingRectangle;
}
public class GuardSwitchNode {
    public GuardSwitchInfo Current = new GuardSwitchInfo();
    public GuardSwitchNode Parent;
    public GuardSwitchNode[] Children = new GuardSwitchNode[0];
    public object Pattern;
    public GuardSwitchNode[] FindAll(object scope, object condition) { return Children; }
    public bool TryGetCurrentPattern(object id, out object pattern) { pattern=Pattern; return pattern!=null; }
}
'@
$path = SOURCE
$source = [IO.File]::ReadAllText($path)
$start = $source.IndexOf('    function Find-NetworkSwitch(')
$finish = $source.IndexOf('    function Enable-NetworkSwitch(', $start)
$function = $source.Substring($start, $finish-$start).Replace('[System.Windows.Automation.TreeWalker]::ControlViewWalker.GetParent($parent)', '(Get-StubParent $parent)').Replace('[System.Windows.Automation.TreeWalker]::ControlViewWalker.GetParent($ancestor)', '(Get-StubParent $ancestor)')
Invoke-Expression $function
function Fail([string]$Code, [string]$Message) {
    $error = New-Object InvalidOperationException($Message)
    $error.Data['guard_code'] = $Code
    throw $error
}
function Check-Interactive { $script:Checks++ }
function Get-StubParent($element) { return $element.Parent }
function Root { return $script:Root }
function Find-Named($element, [string]$Name, $Type) {
    if ($null -ne $Type) { throw 'heading_rejected_by_type' }
    return @($element.Children | Where-Object { $_.Current.Name -eq $Name })
}
function Start-Sleep {
    param($Milliseconds)
    $script:Sleeps++
    if ($script:Pending -and $script:Sleeps -ge 2) {
        $script:Root.Children = @($script:Label)
        $script:Parent.Children = @($script:Toggle)
    }
    if ($script:Sleeps -gt 4) { throw 'unexpected_retry_loop' }
}
function New-Node([string]$Name, [double]$Y, [double]$Left=20, [double]$Width=100) {
    $node = New-Object GuardSwitchNode
    $node.Current.Name = $Name
    $node.Current.ControlType = [System.Windows.Automation.ControlType]::Header
    $node.Current.BoundingRectangle = New-Object GuardSwitchRect($Left, $Y, $Width, 20)
    return $node
}
function Reset-Case {
    $script:Checks=0; $script:Sleeps=0; $script:Pending=$false
    $script:Root=New-Node 'root' 0
    $script:Parent=New-Node '系统设置' 0
    $script:Label=New-Node '虚拟网卡模式' 100
    $script:Label.Parent=$script:Parent
    $script:Toggle=New-Node '' 100 200 40
    $script:Toggle.Pattern='target'
    $script:Parent.Children=@($script:Toggle)
    $script:Root.Children=@($script:Label)
}
function Assert-Fails([string]$Code) {
    try { Find-NetworkSwitch '虚拟网卡模式' | Out-Null; throw 'expected_failure' }
    catch { if ($_.Exception.Data['guard_code'] -ne $Code) { throw } }
}
$passed=0
Reset-Case
$other=New-Node '' 140 200 40; $other.Pattern='other'
$script:Parent.Children=@($other,$script:Toggle)
if ((Find-NetworkSwitch '虚拟网卡模式').pattern -ne 'target') { throw 'heading_row_match' }; $passed++
Reset-Case
$script:Label.Current.BoundingRectangle=New-Object GuardSwitchRect(20,100,260,20)
if ((Find-NetworkSwitch '虚拟网卡模式').pattern -ne 'target') { throw 'full_width_heading' }; $passed++
Reset-Case
$script:Label.Current.ControlType=[System.Windows.Automation.ControlType]::Text
if ((Find-NetworkSwitch '虚拟网卡模式').pattern -ne 'target') { throw 'legacy_text' }; $passed++
Reset-Case
$container=New-Node '虚拟网卡模式' 100
$container.Children=@($script:Label)
$script:Root.Children=@($container,$script:Label)
if ((Find-NetworkSwitch '虚拟网卡模式').pattern -ne 'target') { throw 'nested_name' }; $passed++
Reset-Case
$duplicate=New-Node '虚拟网卡模式' 100
$script:Root.Children=@($script:Label,$duplicate)
Assert-Fails 'network_switch_unavailable'; $passed++
Reset-Case
$duplicate=New-Node '' 100 260 40; $duplicate.Pattern='wrong'
$script:Parent.Children=@($script:Toggle,$duplicate)
Assert-Fails 'network_switch_ambiguous'; $passed++
Reset-Case
$script:Root.Children=@(); $script:Pending=$true
if ((Find-NetworkSwitch '虚拟网卡模式').pattern -ne 'target' -or $script:Sleeps -ne 2) { throw 'delayed_label' }; $passed++
Reset-Case
$other=New-Node '' 140 200 40; $other.Pattern='wrong'
$script:Parent.Children=@($other); $script:Pending=$true
if ((Find-NetworkSwitch '虚拟网卡模式').pattern -ne 'target' -or $script:Sleeps -ne 2) { throw 'stale_content_retry' }; $passed++
@{ ok=$true; passed=$passed } | ConvertTo-Json -Compress

'''.replace("SOURCE", guard.ps_quote(str(guard.SCRIPT_DIR / "verge_ui.ps1")))
        self.assertEqual(guard.run_powershell(script)["passed"], 8)

    @unittest.skipUnless(guard.os.name == "nt", "Windows 前台唤醒离线自检")
    def test_native_foreground_wakeup_helpers_compile(self):
        source = (guard.SCRIPT_DIR / "verge_ui.ps1").read_text(encoding="utf-8-sig")
        native = source.split("Add-Type -TypeDefinition @'\n", 1)[1].split("\n'@", 1)[0]
        self.assertIn("LeftClick", source)
        self.assertIn("BoundingRectangle", source)
        script = r'''Add-Type -TypeDefinition NATIVE
if(-not [GuardWindow]::IsShellWindow([IntPtr]::Zero)){throw 'zero_is_not_shell'}
@{ok=$true}|ConvertTo-Json -Compress'''.replace("NATIVE", guard.ps_quote(native))
        self.assertEqual(guard.run_powershell(script), {"ok": True})

    @unittest.skipUnless(guard.os.name == "nt", "Windows 原生托盘离线自检")
    def test_native_tray_menu_toggle_and_display_without_visible_icon(self):
        script = r'''
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$native=[regex]::Match([IO.File]::ReadAllText(SOURCE),"(?s)Add-Type -TypeDefinition @'\r?\n(.*?)\r?\n'@ -ReferencedAssemblies").Groups[1].Value
Add-Type -TypeDefinition $native -ReferencedAssemblies System.Windows.Forms,System.Drawing
$badgeTest=New-Object ClashTaskbarBadge
if($badgeTest.ShowInTaskbar -or -not $badgeTest.TransparencyKey.IsEmpty -or $badgeTest.FormBorderStyle -ne 'None'){throw 'badge_transparency'}
if($badgeTest.Font.Name -ne 'Segoe UI' -or $badgeTest.Font.SizeInPoints -ne 10){throw 'badge_requested_font'}
$badgeTest.ClientSize=New-Object Drawing.Size(192,44)
$badgeTest.BadgeText='日本家宽VL03 · 75 ms'
$bitmap=[ClashTaskbarBadge]::RenderText($badgeTest.BadgeText,$badgeTest.Font,$badgeTest.ClientSize,96)
try{
    $whitePixels=0; $smoothPixels=0; $transparentPixels=0
    for($y=0;$y -lt $bitmap.Height;$y++){for($x=0;$x -lt $bitmap.Width;$x++){
        $color=$bitmap.GetPixel($x,$y)
        if($color.A -eq 0){$transparentPixels++;continue}
        if($color.R -ne $color.G -or $color.G -ne $color.B){throw 'badge_color_fringe'}
        if($color.A -eq 255){$whitePixels++}else{$smoothPixels++}
    }}
    if($whitePixels -eq 0 -or $smoothPixels -eq 0 -or $transparentPixels -eq 0){throw 'badge_alpha_text_missing'}
    $badgeTest.RefreshSurface()
    $badgeTest.RefreshSurface()
    if($badgeTest.Visible -or $badgeTest.Text -ne 'Clash 节点延迟'){throw 'badge_hidden_surface'}
}finally{$bitmap.Dispose()}
$badgeTest.Dispose()
$errors=$null; $tokens=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile(SOURCE, [ref]$tokens, [ref]$errors)
if($errors.Count){throw 'tray_syntax'}
$update=$ast.Find({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Update-Tray'},$true)
Invoke-Expression $update.Extent.Text
$click=$ast.Find({param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and $n.Expression.Extent.Text -eq '$toggleItem' -and $n.Member.Value -eq 'add_Click'},$true)
$directory=Join-Path ([IO.Path]::GetTempPath()) ('tray-test-'+[Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($directory)|Out-Null
$pauseFile=Join-Path $directory 'monitor.pause'
$stateFile=Join-Path $directory 'state.json'
[IO.File]::WriteAllText($stateFile,'{"transaction":null,"last_status":"正常"}')
$toggleItem=New-Object System.Windows.Forms.ToolStripMenuItem
$toggleItem.add_Click($click.Arguments[0].ScriptBlock.GetScriptBlock())
$statusItem=[pscustomobject]@{Text='';ToolTipText=''}
$nodeItem=[pscustomobject]@{Text=''}
$delayItem=[pscustomobject]@{Text='';ToolTipText=''}
$timeItem=[pscustomobject]@{Text=''}
$icon=[pscustomobject]@{Text='';Icon=$null}
$badge=[pscustomobject]@{BadgeText=''}
$badgeTip=New-Object PSObject
$badgeTip | Add-Member ScriptMethod SetToolTip {param($label,$text)}
$script:sample=[pscustomobject]@{mode='global';selected='PRO | 日本家宽S VL03 | 2倍';latency_ms=123;sampled_at=1792762368;latency_status='';recovering=$false}
$script:lastError=$null
try{
    Update-Tray
    if(-not $toggleItem.Checked -or $delayItem.Text -ne '节点延迟：123 ms' -or $badge.BadgeText -ne '日本家宽VL03 · 123 ms'){throw 'active_display'}
    $toggleItem.PerformClick()
    if(-not [IO.File]::Exists($pauseFile) -or $toggleItem.Checked -or $badge.BadgeText -notlike '暂停*'){throw 'pause_click'}
    [IO.File]::WriteAllText($stateFile,'{"transaction":{"expected":"AN"}}')
    Update-Tray
    if($statusItem.Text -notlike '*完成后暂停*'){throw 'in_flight_pause'}
    $toggleItem.PerformClick()
    if([IO.File]::Exists($pauseFile) -or -not $toggleItem.Checked){throw 'resume_click'}
    $script:sample.selected='X'*200; $script:sample.latency_ms=0
    Update-Tray
    if($icon.Text.Length -gt 63 -or $delayItem.Text -ne '节点延迟：0 ms'){throw 'zero_delay'}
    $script:sample=$null; $script:lastError='测速超时'
    Update-Tray
    if($delayItem.Text -ne '节点延迟：测速超时' -or $nodeItem.Text -ne '当前节点：未获取'){throw 'stale_delay'}
    @{passed=9}|ConvertTo-Json -Compress
}finally{
    $toggleItem.Dispose()
    Remove-Item -LiteralPath $pauseFile,$stateFile -Force -ErrorAction SilentlyContinue
    [IO.Directory]::Delete($directory)
}
'''.replace("SOURCE", guard.ps_quote(str(guard.SCRIPT_DIR / "tray.ps1")))
        self.assertEqual(guard.run_powershell(script)["passed"], 9)

    def test_status_exposes_last_check_and_safe_error_code(self):
        world = World(self)
        world.state.update(last_check=1000.0, last_check_finished=1004.0, last_error_code="claude_exit_failed")
        with patch.object(guard, "load_state", return_value=world.state):
            result = guard.check_status()
        self.assertEqual(result["last_check"], 1000.0)
        self.assertEqual(result["last_check_finished"], 1004.0)
        self.assertEqual(result["last_error_code"], "claude_exit_failed")
        self.assertTrue(result["tun_enabled"])
        self.assertTrue(result["system_proxy_enabled"])

    def test_user_takeover_before_claude_close_preserves_application(self):
        world = World(self)
        changed = deepcopy(world.context)
        changed["selected"] = "用户手选节点"
        world.inspect.side_effect = [deepcopy(world.context), changed]
        self.assertEqual(guard.recover(world.state), "user_takeover")
        self.assertEqual(world.state["cooldown_until"], 0)
        world.assert_not_changed()

    def test_user_takeover_during_claude_close_preserves_selection(self):
        world = World(self)
        world.close_hook = lambda: world.context.update(selected="用户手选节点")
        self.assertEqual(guard.recover(world.state), "user_takeover")
        self.assertEqual(world.context["selected"], "用户手选节点")
        self.assertEqual(world.state["cooldown_until"], 0)
        world.select.assert_not_called()
        self.assertFalse(any(call.args[0] == "update" for call in world.ui.call_args_list))

    def test_locked_manual_recovery_does_not_close_claude(self):
        world = World(self)
        world.unlocked = False
        self.assertEqual(guard.recover(world.state, manual=True), "deferred_locked")
        world.assert_not_changed()

    def test_interrupted_recovery_keeps_transaction_if_claude_will_not_exit(self):
        world = World(self)
        world.context["selected"] = guard.BOOTSTRAP
        transaction = {"original": guard.TARGET, "expected": guard.BOOTSTRAP, "phase": "switching"}
        world.state["transaction"] = deepcopy(transaction)
        world.select.side_effect = world.real_selection
        world.close_claude.side_effect = guard.GuardError("claude_exit_failed", "模拟 Claude 无法退出")
        with patch.object(guard, "current_profile_uid", return_value=guard.PROFILE_UID), \
                patch.object(guard, "core_request", return_value={"mode": "global"}) as core:
            with self.assertRaises(guard.GuardError) as caught:
                guard.repair_interrupted(world.state)
        self.assertEqual(caught.exception.code, "claude_exit_failed")
        self.assertEqual(world.state["transaction"], transaction)
        self.assertEqual(world.context["selected"], guard.BOOTSTRAP)
        self.assertFalse(any(call.args[0] == "PUT" for call in core.call_args_list))

    def test_locked_interrupted_recovery_defers_without_claude_exit(self):
        world = World(self)
        world.unlocked = False
        world.context["selected"] = guard.BOOTSTRAP
        transaction = {"original": guard.TARGET, "expected": guard.BOOTSTRAP, "phase": "switching"}
        world.state["transaction"] = deepcopy(transaction)
        with self.assertRaises(guard.GuardError) as caught:
            guard.repair_interrupted(world.state)
        self.assertEqual(caught.exception.code, "desktop_locked")
        self.assertEqual(world.state["transaction"], transaction)
        world.assert_not_changed()

    def test_interrupted_recovery_respects_user_takeover_without_claude_exit(self):
        world = World(self)
        world.context["selected"] = "用户手选节点"
        world.state["transaction"] = {"original": guard.TARGET, "expected": guard.BOOTSTRAP, "phase": "switching"}
        guard.repair_interrupted(world.state)
        self.assertEqual(world.context["selected"], "用户手选节点")
        self.assertIsNone(world.state["transaction"])
        world.assert_not_changed()

    def test_selection_rechecks_claude_before_every_core_put(self):
        world = World(self)
        def core_request(method, path, body=None):
            if method == "PUT":
                world.events.append("put")
                world.context["selected"] = body["name"]
                return {}
            return {"mode": "global"} if path == "/configs" else {"now": world.context["selected"]}
        with patch.object(guard, "current_profile_uid", return_value=guard.PROFILE_UID), \
                patch.object(guard, "core_request", side_effect=core_request):
            world.real_selection(guard.BOOTSTRAP)
            world.real_selection(guard.TARGET)
        self.assertEqual(world.events, ["close_claude", "put", "close_claude", "put"])

    def test_selection_cannot_put_if_claude_exit_fails(self):
        world = World(self)
        world.close_claude.side_effect = guard.GuardError("claude_exit_failed", "模拟 Claude 无法退出")
        with patch.object(guard, "current_profile_uid", return_value=guard.PROFILE_UID), \
                patch.object(guard, "core_request", return_value={"mode": "global"}) as core:
            with self.assertRaises(guard.GuardError) as caught:
                world.real_selection(guard.BOOTSTRAP)
        self.assertEqual(caught.exception.code, "claude_exit_failed")
        self.assertFalse(any(call.args[0] == "PUT" for call in core.call_args_list))

    def test_selection_scope_change_does_not_close_claude(self):
        world = World(self)
        with patch.object(guard, "current_profile_uid", return_value="另一份订阅"), \
                patch.object(guard, "core_request") as core:
            with self.assertRaises(guard.GuardError) as caught:
                world.real_selection(guard.BOOTSTRAP)
        self.assertEqual(caught.exception.code, "user_takeover")
        world.close_claude.assert_not_called()
        core.assert_not_called()

    def test_selection_preserves_user_changes_during_claude_exit(self):
        world = World(self)
        baseline = deepcopy(world.context)
        def core_request(method, path, body=None):
            return {"mode": world.context["mode"]} if path == "/configs" else {"now": world.context["selected"]}
        for key, value in (("profile_uid", "另一份订阅"), ("mode", "rule"), ("selected", "用户手选节点")):
            with self.subTest(key=key):
                world.context = deepcopy(baseline)
                world.close_hook = lambda key=key, value=value: world.context.update({key: value})
                with patch.object(guard, "current_profile_uid", side_effect=lambda: world.context["profile_uid"]), \
                        patch.object(guard, "core_request", side_effect=core_request) as core:
                    with self.assertRaises(guard.GuardError) as caught:
                        world.real_selection(guard.BOOTSTRAP)
                self.assertEqual(caught.exception.code, "user_takeover")
                self.assertEqual(world.context[key], value)
                self.assertFalse(any(call.args[0] == "PUT" for call in core.call_args_list))

    def test_claude_helper_rejects_remaining_processes_and_malformed_results(self):
        invalid_results = (
            {"ok": True, "remaining": 1, "stopped": 2},
            {"ok": False, "remaining": 0, "stopped": 0},
            {"ok": True, "remaining": False, "stopped": 0},
            {"ok": True, "remaining": 0, "stopped": True},
            {"ok": True, "remaining": 0, "stopped": -1},
            {"ok": True, "remaining": "0", "stopped": 0},
            {"ok": True, "remaining": 0}, {}, None, [], "bad JSON structure",
        )
        for result in invalid_results:
            with self.subTest(result=result), patch.object(guard, "run_powershell", return_value=result), \
                    patch.object(guard, "log_event") as log:
                with self.assertRaises(guard.GuardError) as caught:
                    guard.close_claude_desktop()
                self.assertEqual(caught.exception.code, "claude_exit_failed")
                log.assert_not_called()

    def test_claude_helper_native_failures_return_fixed_safe_error(self):
        sensitive = r"C:\sensitive\Claude.exe PID 123456"
        native_failures = (OSError(sensitive), guard.subprocess.TimeoutExpired(sensitive, 15),
                           Mock(returncode=1, stdout=sensitive), Mock(returncode=0, stdout="invalid JSON"))
        for failure in native_failures:
            options = {"side_effect": failure} if isinstance(failure, Exception) else {"return_value": failure}
            with self.subTest(failure=type(failure).__name__), patch.object(guard.subprocess, "run", **options), \
                    patch.object(guard, "log_event") as log:
                with self.assertRaises(guard.GuardError) as caught:
                    guard.close_claude_desktop()
                self.assertEqual(caught.exception.code, "claude_exit_failed")
                self.assertNotIn(sensitive, str(caught.exception))
                log.assert_not_called()

    def test_claude_helper_success_logs_no_process_details(self):
        with patch.object(guard, "run_powershell", return_value={"ok": True, "remaining": 0, "stopped": 3}), \
                patch.object(guard, "log_event") as log:
            guard.close_claude_desktop()
        log.assert_called_once_with("claude_desktop_closed", "已强制退出 Claude Desktop 及其子进程，不会自动重启")
        with patch.object(guard, "run_powershell", return_value={"ok": True, "remaining": 0, "stopped": 0}), \
                patch.object(guard, "log_event") as log:
            guard.close_claude_desktop()
        log.assert_not_called()

    def claude_native_branch(self, candidate_present):
        with patch.object(guard, "run_powershell", return_value={"ok": True, "remaining": 0, "stopped": 0}) as runner, \
                patch.object(guard, "log_event"):
            guard.close_claude_desktop()
        script = runner.call_args.args[0]
        stubs = r'''
function Get-Process {
    [CmdletBinding()]param([string]$Name)
    RETURN_CANDIDATE
}
function Add-Type {
    [CmdletBinding()]param([string]$TypeDefinition)
    throw 'test_add_type_reached'
}
function Get-CimInstance {
    [CmdletBinding()]param([string]$ClassName,[string]$Filter)
    throw 'test_forbidden_cim'
}
'''.replace("RETURN_CANDIDATE", "[pscustomobject]@{Id=-1}" if candidate_present else "return")
        harness = stubs + "try { & {\n" + script + "\n} } catch { @{ok=$false;test_stage=$_.Exception.Message}|ConvertTo-Json -Compress }"
        return guard.run_powershell(harness, timeout=15)

    @unittest.skipUnless(guard.os.name == "nt", "Windows PowerShell 纯桩分支验证")
    def test_no_claude_native_fast_path_skips_csharp_compilation(self):
        result = self.claude_native_branch(candidate_present=False)
        self.assertEqual(result, {"ok": True, "remaining": 0, "stopped": 0})

    @unittest.skipUnless(guard.os.name == "nt", "Windows PowerShell 纯桩分支验证")
    def test_claude_candidate_native_path_still_enters_strict_validation(self):
        result = self.claude_native_branch(candidate_present=True)
        self.assertEqual(result, {"ok": False, "test_stage": "test_add_type_reached"})

    def test_manual_selection_with_disabled_switches_still_pauses_takeover(self):
        world = World(self)
        world.context.update(selected="用户手选节点", tun_enabled=False, system_proxy_enabled=False)
        self.assertEqual(guard.watch_tick(world.state), "paused_selection")
        world.assert_not_changed()

    def test_disabled_network_switches_need_two_checks_and_claude_exit_first(self):
        world = World(self)
        for tun, proxy in ((False, True), (True, False), (False, False)):
            with self.subTest(tun=tun, proxy=proxy):
                world.state = guard.default_state()
                world.state["last_selected"] = guard.TARGET
                world.context.update(tun_enabled=tun, system_proxy_enabled=proxy)
                world.stamp = (100, 10)
                world.events.clear()
                world.close_claude.reset_mock()
                self.assertEqual(guard.watch_tick(world.state), "first_failure")
                world.close_claude.assert_not_called()
                self.assertEqual(guard.watch_tick(world.state), "network_restored")
                self.assertLess(world.events.index("close_claude"), world.events.index("protect"))
                self.assertLess(world.events.index("protect"), world.events.index(guard.BOOTSTRAP))
                self.assertTrue(guard.network_ready(world.context))
                self.assertEqual(world.context["selected"], guard.TARGET)

    def test_network_switch_enable_failure_never_selects_an_or_updates(self):
        world = World(self)
        world.context["tun_enabled"] = False
        def fail():
            raise guard.GuardError("network_switch_unavailable", "模拟开关不可操作")
        world.protect_hook = fail
        self.assertEqual(guard.recover(world.state), "network_switch_unavailable")
        world.select.assert_not_called()
        self.assertNotIn("update", world.events)
        self.assertEqual(world.state["cooldown_until"], 1000 + guard.COOLDOWN)
        self.assertEqual(world.context["selected"], guard.TARGET)

    def test_network_protection_must_be_confirmed_by_actual_state(self):
        world = World(self)
        world.context["system_proxy_enabled"] = False
        world.protect_hook = lambda: {"ok": True, "tun_enabled": True, "system_proxy_enabled": True}
        def advance(seconds):
            world.now += seconds
        with patch.object(guard.time, "sleep", side_effect=advance):
            self.assertEqual(guard.recover(world.state), "network_protection_lost")
        world.select.assert_not_called()
        self.assertNotIn("update", world.events)
        self.assertEqual(world.state["cooldown_until"], 1000 + guard.COOLDOWN)

    def test_user_switch_during_network_protection_is_preserved(self):
        world = World(self)
        world.context["tun_enabled"] = False
        def takeover():
            world.context.update(tun_enabled=True, system_proxy_enabled=True, selected="用户手选节点")
            return {"ok": True}
        world.protect_hook = takeover
        self.assertEqual(guard.recover(world.state), "user_takeover")
        self.assertEqual(world.context["selected"], "用户手选节点")
        self.assertEqual(world.state["cooldown_until"], 1000 + guard.COOLDOWN)
        world.select.assert_not_called()
        self.assertNotIn("update", world.events)
        attempts = world.close_claude.call_count
        for _ in range(3):
            self.assertEqual(guard.watch_tick(world.state), "paused_selection")
        self.assertEqual(world.close_claude.call_count, attempts)
        self.assertEqual(world.context["selected"], "用户手选节点")

    def test_core_restart_while_enabling_tun_is_waited_for(self):
        world = World(self)
        world.context["tun_enabled"] = False
        calls = 0
        def inspect():
            nonlocal calls
            calls += 1
            if calls == 1:
                raise guard.GuardError("core_offline", "模拟开启虚拟网卡后内核重启")
            return deepcopy(world.context)
        def enable():
            world.context.update(tun_enabled=True, system_proxy_enabled=True)
            world.inspect.side_effect = inspect
            return {"ok": True}
        world.protect_hook = enable
        def advance(seconds):
            world.now += seconds
        with patch.object(guard.time, "sleep", side_effect=advance):
            self.assertEqual(guard.recover(world.state), "network_restored")
        self.assertTrue(guard.network_ready(world.context))

    def test_switch_disabled_during_update_cannot_report_success(self):
        world = World(self)
        def update():
            world.context["system_proxy_enabled"] = False
            world.stamp = (200, 10)
            return {"ok": True, "invoked": True, "finished": True}
        world.update_hook = update
        self.assertEqual(guard.recover(world.state), "network_protection_lost")
        self.assertEqual(world.context["selected"], guard.TARGET)
        self.assertEqual(world.state["cooldown_until"], 1000 + guard.COOLDOWN)
        self.assertNotIn("network_restored", [call.args[0] for call in world.log.call_args_list])

    def test_final_network_protection_must_remain_enabled(self):
        world = World(self)
        def health(name, *args, **kwargs):
            if name == guard.TARGET:
                world.context["tun_enabled"] = False
            return True
        world.check_health.side_effect = health
        self.assertEqual(guard.recover(world.state), "network_protection_lost")
        self.assertNotIn("network_restored", [call.args[0] for call in world.log.call_args_list])

    def test_network_status_requires_verge_core_and_correct_windows_proxy(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            registry = Mock()
            registry.OpenKey.side_effect = lambda *args: nullcontext("key")
            cases = (
                (True, True, True, 1, "127.0.0.1:7897", 7897, True, True),
                (True, True, True, 1, "http=localhost:7897;https=[::1]:7897", 7897, True, True),
                (False, True, True, 1, "127.0.0.1:7897", 7897, False, True),
                (True, False, True, 1, "127.0.0.1:7897", 7897, False, True),
                (True, True, False, 1, "127.0.0.1:7897", 7897, True, False),
                (True, True, True, 0, "127.0.0.1:7897", 7897, True, False),
                (True, True, True, 1, "127.0.0.1:7890", 7897, True, False),
                (True, True, True, 1, "127.0.0.1.evil:7897", 7897, True, False),
                (True, True, True, 1, "http=127.0.0.1:7897;https=remote:7897", 7897, True, False),
                (True, True, True, 1, "127.0.0.1:7897", "7897", True, False),
            )
            for core_tun, verge_tun, verge_proxy, enabled, server, port, want_tun, want_proxy in cases:
                with self.subTest(core_tun=core_tun, verge_tun=verge_tun, verge_proxy=verge_proxy, enabled=enabled, server=server, port=port):
                    (root / "verge.yaml").write_text("enable_tun_mode: " + str(verge_tun).lower() + "\nenable_system_proxy: " + str(verge_proxy).lower() + "\n", encoding="utf-8")
                    registry.QueryValueEx.side_effect = lambda key, name: (enabled if name == "ProxyEnable" else server, 1)
                    with patch.object(guard, "PROFILE_ROOT", root), patch.dict(guard.sys.modules, {"winreg": registry}):
                        status = guard.network_protection_status({"tun": {"enable": core_tun}, "mixed-port": port})
                    self.assertEqual(status, {"tun_enabled": want_tun, "system_proxy_enabled": want_proxy})

    def test_native_network_toggle_only_enables_off_controls(self):
        source = (guard.SCRIPT_DIR / "verge_ui.ps1").read_text(encoding="utf-8-sig")
        start = source.index("    function Enable-NetworkSwitch(")
        end = source.index("    function Error-Names {", start)
        function = source[start:end]
        harness = r'''Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
$ErrorActionPreference = 'Stop'
function Fail([string]$Code, [string]$Message) {
    $failure = New-Object System.InvalidOperationException($Message)
    $failure.Data['guard_code'] = $Code
    throw $failure
}
function Check-Interactive {
    if ($script:StopInput) { Fail 'user_takeover' '模拟前台切换' }
}
function Find-NetworkSwitch([string]$Name) { return $script:Control }
function New-TestControl($State, [bool]$Enabled) {
    $script:Calls = 0
    $script:StopInput = $false
    $pattern = New-Object PSObject -Property @{ Current = [pscustomobject]@{ ToggleState = $State } }
    $pattern | Add-Member -MemberType ScriptMethod -Name Toggle -Value {
        $script:Calls++
        $this.Current.ToggleState = [System.Windows.Automation.ToggleState]::On
    }
    $script:Control = @{ pattern = $pattern; element = [pscustomobject]@{ Current = [pscustomobject]@{ IsEnabled = $Enabled } } }
}
function Expect-Failure([string]$Code) {
    try { Enable-NetworkSwitch '系统代理'; throw 'expected_failure' }
    catch { if ($_.Exception.Data['guard_code'] -ne $Code) { throw } }
}
'''
        harness += function
        harness += r'''
New-TestControl ([System.Windows.Automation.ToggleState]::On) $true
Enable-NetworkSwitch '虚拟网卡模式'
if ($script:Calls -ne 0) { throw 'already_on_was_toggled' }
New-TestControl ([System.Windows.Automation.ToggleState]::Off) $true
Enable-NetworkSwitch '系统代理'
if ($script:Calls -ne 1) { throw 'off_was_not_enabled_once' }
New-TestControl ([System.Windows.Automation.ToggleState]::Off) $false
Expect-Failure 'network_switch_unavailable'
if ($script:Calls -ne 0) { throw 'disabled_control_was_toggled' }
New-TestControl ([System.Windows.Automation.ToggleState]::Indeterminate) $true
Expect-Failure 'network_switch_unavailable'
if ($script:Calls -ne 0) { throw 'indeterminate_control_was_toggled' }
New-TestControl ([System.Windows.Automation.ToggleState]::Off) $true
$script:StopInput = $true
Expect-Failure 'user_takeover'
if ($script:Calls -ne 0) { throw 'foreground_change_was_ignored' }
@{ok=$true;checks=5}|ConvertTo-Json -Compress
'''
        done = guard.subprocess.run([str(guard.POWERSHELL), "-NoProfile", "-NonInteractive", "-Command", harness],
                                    capture_output=True, encoding="utf-8-sig", timeout=10, creationflags=guard.NO_WINDOW)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(guard.json.loads(done.stdout), {"ok": True, "checks": 5})

    def test_update_error_or_timeout_rolls_back_and_cools_down(self):
        world = World(self)
        for code in ("update_error", "ui_timeout"):
            with self.subTest(code=code):
                world.state = guard.default_state()
                world.state["last_selected"] = guard.TARGET
                world.select.reset_mock()
                world.fail_update(code)
                self.assertEqual(guard.recover(world.state), code)
                self.assertEqual(world.context["selected"], guard.TARGET)
                self.assertIsNone(world.state["transaction"])
                self.assertEqual(world.state["cooldown_until"], 1000 + guard.COOLDOWN)
                self.assertEqual([call.args[0] for call in world.select.call_args_list], [guard.BOOTSTRAP, guard.TARGET])

    def test_ui_interruption_cools_down_except_locked_or_changed_application(self):
        world = World(self)
        for code in ("user_takeover", "desktop_locked", "app_changed"):
            with self.subTest(code=code):
                world.state = guard.default_state()
                world.state["last_selected"] = guard.TARGET
                world.fail_update(code)
                self.assertEqual(guard.recover(world.state), code)
                self.assertEqual(world.context["selected"], guard.TARGET)
                self.assertIsNone(world.state["transaction"])
                self.assertEqual(world.state["cooldown_until"],
                                 0 if code in ("desktop_locked", "app_changed") else 1000 + guard.COOLDOWN)
                self.assertNotIn("network_restored", [call.args[0] for call in world.log.call_args_list])

    def test_foreground_interruption_with_missing_target_retries_after_cooldown(self):
        world = World(self)
        del world.context["proxies"][guard.TARGET]
        world.fail_update("user_takeover")
        self.assertEqual(guard.watch_tick(world.state), "user_takeover")
        self.assertEqual(world.context["selected"], "REJECT")
        self.assertTrue(world.state["owned_reject"])
        self.assertEqual(world.state["cooldown_until"], 1000 + guard.COOLDOWN)

        def update():
            world.context["proxies"][guard.TARGET] = {}
            world.stamp = (200, 10)
            return {"ok": True, "invoked": True, "finished": True}
        world.update_hook = update
        calls = world.close_claude.call_count
        self.assertEqual(guard.watch_tick(world.state), "cooldown")
        self.assertEqual(guard.watch_tick(world.state), "cooldown")
        self.assertEqual(world.close_claude.call_count, calls)
        with patch.object(guard.time, "time", return_value=1000 + guard.COOLDOWN):
            self.assertEqual(guard.watch_tick(world.state), "network_restored")
        self.assertEqual(world.context["selected"], guard.TARGET)
        self.assertEqual(world.state["cooldown_until"], 0)
        self.assertFalse(world.state["owned_reject"])

    def test_locked_interruption_retries_after_unlock_and_pending_rollback(self):
        world = World(self)
        del world.context["proxies"][guard.TARGET]
        def lock_during_update():
            world.unlocked = False
            raise guard.GuardError("desktop_locked", "模拟更新前锁屏")
        world.update_hook = lock_during_update
        self.assertEqual(guard.watch_tick(world.state), "desktop_locked")
        self.assertIsNotNone(world.state["transaction"])
        self.assertEqual(world.state["cooldown_until"], 0)
        self.assertEqual(guard.watch_tick(world.state), "desktop_locked")
        self.assertEqual(world.context["selected"], guard.BOOTSTRAP)

        world.unlocked = True
        def update():
            world.context["proxies"][guard.TARGET] = {}
            world.stamp = (200, 10)
            return {"ok": True, "invoked": True, "finished": True}
        world.update_hook = update
        self.assertEqual(guard.watch_tick(world.state), "network_restored")
        self.assertEqual(world.context["selected"], guard.TARGET)
        self.assertIsNone(world.state["transaction"])
        self.assertEqual(world.state["cooldown_until"], 0)

    def test_missing_original_rolls_back_to_reject_only(self):
        world = World(self)
        del world.context["proxies"][guard.TARGET]
        world.fail_update()
        self.assertEqual(guard.recover(world.state), "update_error")
        self.assertEqual(world.context["selected"], "REJECT")
        self.assertTrue(world.state["owned_reject"])
        self.assertEqual([call.args[0] for call in world.select.call_args_list], [guard.BOOTSTRAP, "REJECT"])

    def test_mtime_change_alone_never_reports_success(self):
        world = World(self)
        world.health[guard.TARGET] = False
        self.assertEqual(guard.recover(world.state), "target_unhealthy")
        self.assertNotIn("network_restored", [call.args[0] for call in world.log.call_args_list])
        self.assertEqual(world.context["selected"], guard.TARGET)

    def test_unchanged_subscription_never_reports_success(self):
        world = World(self)
        world.update_hook = lambda: {"ok": True, "invoked": True, "finished": True}
        self.assertEqual(guard.recover(world.state), "subscription_unchanged")
        self.assertEqual(world.context["selected"], guard.TARGET)

    def test_user_takeover_during_update_is_preserved(self):
        world = World(self)
        def takeover():
            world.context["selected"] = "用户手选节点"
            world.stamp = (200, 10)
            return {"ok": True, "invoked": True, "finished": True}
        world.update_hook = takeover
        self.assertEqual(guard.recover(world.state), "user_takeover")
        self.assertEqual(world.context["selected"], "用户手选节点")
        self.assertEqual([call.args[0] for call in world.select.call_args_list], [guard.BOOTSTRAP])
        self.assertIsNone(world.state["transaction"])
        self.assertEqual(world.state["cooldown_until"], 1000 + guard.COOLDOWN)
        self.assertEqual(guard.watch_tick(world.state), "paused_selection")
        self.assertEqual(world.context["selected"], "用户手选节点")

    def test_user_switch_when_target_is_selected_cannot_be_reported_as_success(self):
        world = World(self)
        def takeover(name):
            if name == guard.TARGET:
                world.context["selected"] = "用户手选节点"
        world.select_hook = takeover
        self.assertNotEqual(guard.recover(world.state), "network_restored")
        self.assertEqual(world.context["selected"], "用户手选节点")

    def test_new_attempt_clears_old_ui_error_before_crash_recovery(self):
        world = World(self)
        world.state["last_error_code"] = "user_takeover"
        def crash(name):
            if name == guard.BOOTSTRAP:
                raise SystemExit("模拟进程终止")
        world.select_hook = crash
        with self.assertRaises(SystemExit):
            guard.recover(world.state)
        self.assertIsNotNone(world.state["transaction"])
        self.assertNotIn("last_error_code", world.state)
        world.select_hook = None
        guard.repair_interrupted(world.state)
        self.assertEqual(world.context["selected"], guard.TARGET)
        self.assertEqual(world.state["cooldown_until"], 1000 + guard.COOLDOWN)

    def test_interrupted_switching_transaction_restores_original(self):
        world = World(self)
        world.context["selected"] = guard.BOOTSTRAP
        world.state["transaction"] = {"original": guard.TARGET, "expected": guard.BOOTSTRAP, "phase": "switching"}
        guard.repair_interrupted(world.state)
        self.assertEqual(world.context["selected"], guard.TARGET)
        self.assertIsNone(world.state["transaction"])

    def test_crash_between_target_save_and_switch_still_restores_bootstrap(self):
        world = World(self)
        world.context["selected"] = guard.BOOTSTRAP
        world.state["transaction"] = {"original": guard.TARGET, "expected": guard.BOOTSTRAP,
                                      "pending_selection": guard.TARGET, "phase": "selecting_target"}
        guard.repair_interrupted(world.state)
        self.assertEqual(world.context["selected"], guard.TARGET)
        self.assertIsNone(world.state["transaction"])

    def test_timeout_after_update_never_selects_target_for_success(self):
        world = World(self)
        def exceed_deadline():
            world.now = guard.RECOVERY_TIMEOUT + 1
            world.stamp = (200, 10)
            return {"ok": True, "invoked": True, "finished": True}
        world.update_hook = exceed_deadline
        self.assertNotEqual(guard.recover(world.state), "network_restored")
        self.assertEqual(world.context["selected"], guard.TARGET)

    def test_deadline_is_rechecked_after_slow_health(self):
        world = World(self)
        def slow_health(name, *args, **kwargs):
            if name == guard.TARGET:
                self.assertEqual(world.context["selected"], guard.TARGET)
                world.now = guard.RECOVERY_TIMEOUT + 1
            return True
        world.check_health.side_effect = slow_health
        self.assertEqual(guard.recover(world.state), "recovery_timeout")
        self.assertEqual(world.context["selected"], guard.TARGET)
        self.assertIsNone(world.state["transaction"])
        self.assertEqual(world.state["cooldown_until"], 1000 + guard.COOLDOWN)
        self.assertNotIn("network_restored", [call.args[0] for call in world.log.call_args_list])

    def test_disk_error_before_switch_never_changes_selection(self):
        world = World(self)
        world.save.side_effect = OSError("模拟磁盘写入失败")
        try:
            guard.recover(world.state)
        except (OSError, guard.GuardError):
            pass
        world.select.assert_not_called()

    def test_disk_error_before_target_switch_recovers_on_next_tick(self):
        world = World(self)
        failed = False
        def save(state):
            nonlocal failed
            transaction = state.get("transaction")
            if transaction and transaction.get("phase") == "selecting_target" and not failed:
                failed = True
                raise OSError("模拟磁盘写入失败")
            world.saved.append(deepcopy(state))
        world.save.side_effect = save
        try:
            guard.recover(world.state)
        except (OSError, guard.GuardError):
            pass
        guard.repair_interrupted(world.state)
        self.assertEqual(world.context["selected"], guard.TARGET)
        self.assertIsNone(world.state["transaction"])

    def test_two_health_endpoints_allow_single_site_outage(self):
        with patch.object(guard, "core_request", side_effect=[guard.GuardError("core_http_503", "模拟网站故障"), {"delay": 60}]) as core:
            self.assertTrue(guard.node_healthy(guard.TARGET))
            self.assertEqual(core.call_count, 2)

    def test_two_health_endpoints_both_failing_is_unhealthy(self):
        with patch.object(guard, "core_request", side_effect=guard.GuardError("core_timeout", "模拟超时")) as core:
            self.assertFalse(guard.node_healthy(guard.TARGET))
            self.assertEqual(core.call_count, 2)

    def test_malformed_saved_state_is_disabled(self):
        context = {"profile_uid": guard.PROFILE_UID, "mode": "global", "selected": guard.TARGET, "proxies": {guard.TARGET: {}}}
        for saved in ('{"failures": "2"}', '{"cooldown_until": -1}', '{"transaction": "bad"}', '{"transaction": {}}'):
            with self.subTest(saved=saved), patch.object(Path, "read_text", return_value=saved):
                state = guard.load_state()
                self.assertTrue(state.get("corrupt"))
                self.assertFalse(guard.eligible(context, state))

    def test_redirected_storage_only_recognizes_own_msix_cache(self):
        shadow = Path(r"C:\Users\tester\AppData\Local\Packages\OpenAI.Codex_test\LocalCache\Local\ClashSubscriptionGuard")
        candidates = ((shadow, shadow), (Path(r"C:\Users\tester\AppData\Local\ClashSubscriptionGuard"), None),
                      (shadow.with_name("OtherProgram"), None))
        for physical, expected in candidates:
            with self.subTest(physical=physical), patch.object(Path, "mkdir"), patch.object(Path, "write_bytes"), \
                    patch.object(Path, "resolve", return_value=physical / ".storage-probe-123"), patch.object(Path, "unlink") as unlink:
                self.assertEqual(guard.redirected_storage(), expected)
                unlink.assert_called_once_with(missing_ok=True)

    def test_native_report_is_written_atomically_without_console(self):
        destination = Path(r"C:\guard-mock\result.json")
        with patch.object(guard, "REPORT_PATH", destination), patch.object(guard.sys, "stdout", None), \
                patch.object(Path, "write_text") as write, patch.object(guard.os, "replace") as replace:
            guard.emit({"ok": True, "result": "queued"})
            self.assertEqual(guard.json.loads(write.call_args.args[0]), {"ok": True, "result": "queued"})
            replace.assert_called_once_with(destination.with_suffix(".tmp"), destination)

    @unittest.skipUnless(guard.os.name == "nt", "Windows 文件锁")
    def test_single_instance_rejects_duplicate(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(guard, "INSTALL_DIR", Path(directory)):
            with guard.InstanceLock():
                with self.assertRaises(guard.GuardError) as caught:
                    with guard.InstanceLock():
                        self.fail("重复锁不应成功")
                self.assertEqual(caught.exception.code, "already_running")
            with guard.InstanceLock():
                pass


class ProfileReloadTests(unittest.TestCase):
    @unittest.skipUnless(guard.os.name == "nt", "Windows 前台唤醒离线自检")
    def test_native_foreground_wakeup_retries_and_races_without_desktop_input(self):
        script = r'''
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
$source = [IO.File]::ReadAllText(SOURCE_PATH)
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw 'verge_ui_syntax' }

# Run the production method against in-memory Win32 substitutes; no desktop input is sent.
$method = [regex]::Match($source, '(?s)    public static bool TryForeground\(.*?(?=\r?\n    public static IntPtr\[\] Windows\()').Value
if (-not $method) { throw 'foreground_method_missing' }
$stub = @'
using System;
public static class GuardWindow {
    public static IntPtr Target = (IntPtr)10, Foreground = (IntPtr)20;
    public static bool Locked, InvalidWindow, ChangedPid, DirectSuccess, AttachedSuccess, ThrowAttached, SameThread;
    public static bool AttachSuccess = true, Attached;
    public static int ForegroundCalls, AttachCalls, DetachCalls, ShowCalls, Sleeps, AttachEffect, FocusEffect, AllowOnCall;
    public static int LastInput, PreviousPid;
    public static void Reset() {
        Foreground = (IntPtr)20;
        Locked = InvalidWindow = ChangedPid = DirectSuccess = AttachedSuccess = ThrowAttached = SameThread = Attached = false;
        AttachSuccess = true;
        ForegroundCalls = AttachCalls = DetachCalls = ShowCalls = Sleeps = AttachEffect = FocusEffect = AllowOnCall = 0;
        LastInput = 1000;
        PreviousPid = 200;
    }
    public static bool Unlocked() { return !Locked; }
    public static bool IsWindow(IntPtr hwnd) { return hwnd == Target && !InvalidWindow; }
    public static int Pid(IntPtr hwnd) {
        if (hwnd == Target) return ChangedPid ? 101 : 100;
        if (hwnd == (IntPtr)20) return PreviousPid;
        return hwnd == IntPtr.Zero ? 0 : (int)hwnd * 10;
    }
    public static long GetLastInputTick() { return LastInput; }
    public static bool IsShellWindow(IntPtr hwnd) { return hwnd == IntPtr.Zero || hwnd == (IntPtr)30; }
    public static IntPtr GetForegroundWindow() { return Foreground; }
    public static uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid) {
        pid = (uint)Pid(hwnd);
        return SameThread ? 1U : (hwnd == IntPtr.Zero ? 0U : pid + 1);
    }
    public static uint GetCurrentThreadId() { return 1; }
    public static bool ShowWindow(IntPtr hwnd, int mode) { ShowCalls++; return true; }
    public static bool SetForegroundWindow(IntPtr hwnd) {
        ForegroundCalls++;
        if (Attached && ThrowAttached) throw new InvalidOperationException("activation_exception");
        if (DirectSuccess || (Attached && AttachedSuccess) || ForegroundCalls == AllowOnCall) Foreground = hwnd;
        return Foreground == hwnd;
    }
    public static bool AttachThreadInput(uint source, uint target, bool attach) {
        if (!attach) { DetachCalls++; Attached = false; return true; }
        AttachCalls++;
        if (!AttachSuccess) return false;
        Attached = true;
        if (AttachEffect == 1) Foreground = (IntPtr)40;
        if (AttachEffect == 2) Locked = true;
        if (AttachEffect == 3) InvalidWindow = true;
        if (AttachEffect == 4) ChangedPid = true;
        return true;
    }
__TRY_FOREGROUND__
}
public sealed class GuardWakeRoot {
    public bool TryGetCurrentPattern(object pattern, ref object value) { return false; }
    public void SetFocus() { if (GuardWindow.FocusEffect == 1) GuardWindow.Foreground = (IntPtr)40; }
}
'@
Add-Type -TypeDefinition ($stub.Replace('__TRY_FOREGROUND__', $method))
foreach ($name in @('Fail', 'Check-Interactive', 'Check-WakeState', 'Prepare-Window', 'Resume-PreparedWindow')) {
    $function = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true)
    if ($null -eq $function) { throw "missing_function_$name" }
    Invoke-Expression $function.Extent.Text
}
function Root { return New-Object GuardWakeRoot }
function Start-Sleep([int]$Milliseconds) {
    [GuardWindow]::Sleeps++
    if ([GuardWindow]::Sleeps -eq $script:EffectAtSleep) {
        switch ($script:SleepEffect) {
            'target' { [GuardWindow]::Foreground = [GuardWindow]::Target }
            'other' { [GuardWindow]::Foreground = [IntPtr]40 }
            'shell' { [GuardWindow]::Foreground = [IntPtr]30 }
            'locked' { [GuardWindow]::Locked = $true }
            'input' { [GuardWindow]::LastInput++ }
        }
    }
}
function Wake-Taskbar([IntPtr]$ExpectedForeground) {
    [void](Check-WakeState $ExpectedForeground)
    $script:WakeCalls++
    if ($script:TaskbarFailure) { Fail $script:TaskbarFailure 'simulated_taskbar_guard' }
    if ($script:TaskbarThrows) { throw 'simulated_taskbar_unavailable' }
    if ($script:TaskbarSuccess) { [GuardWindow]::Foreground = $script:Hwnd; return $true }
    return $false
}
function Reset-Case {
    [GuardWindow]::Reset()
    $script:Hwnd = [GuardWindow]::Target
    $script:TargetPid = 100
    $script:PreparedInput = $null
    $script:EffectAtSleep = 0
    $script:SleepEffect = ''
    $script:WakeCalls = 0
    $script:TaskbarSuccess = $false
    $script:TaskbarThrows = $false
    $script:TaskbarFailure = ''
}
function Assert([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}
function Assert-Failure([string]$Code) {
    $caught = $null
    try { Prepare-Window } catch { $caught = $_ }
    Assert ($null -ne $caught) "missing_failure_$Code"
    Assert ($caught.Exception.Data['guard_code'] -eq $Code) "wrong_failure_$Code"
}
$passed = 0

Reset-Case
[GuardWindow]::Foreground = $script:Hwnd
Prepare-Window
Assert ([GuardWindow]::ForegroundCalls -eq 0 -and $script:WakeCalls -eq 0) 'already_foreground_mutated'
$passed++

Reset-Case
[GuardWindow]::DirectSuccess = $true
Prepare-Window
Assert ([GuardWindow]::ForegroundCalls -eq 1 -and $script:WakeCalls -eq 0) 'direct_activation'
$passed++

Reset-Case
$script:EffectAtSleep = 2; $script:SleepEffect = 'target'
Prepare-Window
Assert ([GuardWindow]::Sleeps -eq 2 -and $script:WakeCalls -eq 0) 'delayed_direct_activation'
$passed++

Reset-Case
$script:TaskbarSuccess = $true
Prepare-Window
Assert ($script:WakeCalls -eq 1 -and [GuardWindow]::AttachCalls -eq 0) 'taskbar_activation'
$passed++

Reset-Case
$script:EffectAtSleep = 12; $script:SleepEffect = 'target'
Prepare-Window
Assert ($script:WakeCalls -eq 1 -and [GuardWindow]::AttachCalls -eq 0) 'delayed_taskbar_activation'
$passed++

Reset-Case
[GuardWindow]::AttachedSuccess = $true
Prepare-Window
Assert ($script:WakeCalls -eq 1 -and [GuardWindow]::ForegroundCalls -eq 2) 'attached_fallback_activation'
Assert ([GuardWindow]::AttachCalls -eq 1 -and [GuardWindow]::DetachCalls -eq 1 -and -not [GuardWindow]::Attached) 'attached_fallback_cleanup'
$passed++

Reset-Case
$script:TaskbarThrows = $true
[GuardWindow]::AttachedSuccess = $true
Prepare-Window
Assert ([GuardWindow]::AttachCalls -eq 1 -and [GuardWindow]::DetachCalls -eq 1) 'taskbar_error_fallback'
$passed++

Reset-Case
Assert-Failure 'foreground_unavailable'
Assert ([GuardWindow]::Sleeps -eq 30 -and $script:WakeCalls -eq 1 -and [GuardWindow]::ForegroundCalls -eq 2) 'unbounded_activation_retry'
Assert ([GuardWindow]::AttachCalls -eq 1 -and [GuardWindow]::DetachCalls -eq 1) 'failed_activation_cleanup'
$passed++

Reset-Case
$script:EffectAtSleep = 1; $script:SleepEffect = 'other'
Assert-Failure 'user_takeover'
Assert ([GuardWindow]::ForegroundCalls -eq 1 -and $script:WakeCalls -eq 0 -and [GuardWindow]::AttachCalls -eq 0) 'user_takeover_kept_retrying'
$passed++

Reset-Case
$script:TaskbarFailure = 'user_takeover'
Assert-Failure 'user_takeover'
Assert ([GuardWindow]::AttachCalls -eq 0) 'taskbar_takeover_swallowed'
$passed++

Reset-Case
[GuardWindow]::Locked = $true
Assert-Failure 'desktop_locked'
Assert ([GuardWindow]::ShowCalls -eq 0 -and [GuardWindow]::ForegroundCalls -eq 0) 'locked_desktop_activated'
$passed++

Reset-Case
$script:EffectAtSleep = 1; $script:SleepEffect = 'locked'
Assert-Failure 'desktop_locked'
Assert ($script:WakeCalls -eq 0 -and [GuardWindow]::AttachCalls -eq 0) 'lock_during_wait_kept_retrying'
$passed++

foreach ($change in @('InvalidWindow', 'ChangedPid')) {
    Reset-Case
    if ($change -eq 'InvalidWindow') { [GuardWindow]::InvalidWindow = $true } else { [GuardWindow]::ChangedPid = $true }
    Assert-Failure 'app_changed'
    Assert ([GuardWindow]::ShowCalls -eq 0 -and [GuardWindow]::ForegroundCalls -eq 0) "changed_app_activated_$change"
    $passed++
}

foreach ($effect in @(1, 2, 3, 4)) {
    Reset-Case
    [GuardWindow]::AttachEffect = $effect
    $code = if ($effect -eq 1) { 'user_takeover' } elseif ($effect -eq 2) { 'desktop_locked' } else { 'app_changed' }
    Assert-Failure $code
    Assert ([GuardWindow]::ForegroundCalls -eq 1 -and [GuardWindow]::DetachCalls -eq 1 -and -not [GuardWindow]::Attached) "attach_race_not_stopped_$effect"
    $passed++
}

Reset-Case
[GuardWindow]::ThrowAttached = $true
$caught = $null
try { Prepare-Window } catch { $caught = $_ }
Assert ($null -ne $caught -and [GuardWindow]::DetachCalls -eq 1 -and -not [GuardWindow]::Attached) 'activation_exception_left_attached'
$passed++

Reset-Case
[GuardWindow]::AttachSuccess = $false
Assert-Failure 'foreground_unavailable'
Assert ([GuardWindow]::AttachCalls -eq 1 -and [GuardWindow]::DetachCalls -eq 0 -and [GuardWindow]::ForegroundCalls -eq 1) 'failed_attach_used_foreground'
$passed++

Reset-Case
$script:EffectAtSleep = 1; $script:SleepEffect = 'shell'
[GuardWindow]::AttachedSuccess = $true
Prepare-Window
Assert ([GuardWindow]::Foreground -eq $script:Hwnd -and [GuardWindow]::DetachCalls -eq 1) 'shell_transition_rejected'
$passed++

Reset-Case
[GuardWindow]::FocusEffect = 1
Assert-Failure 'user_takeover'
Assert ([GuardWindow]::ForegroundCalls -eq 0 -and $script:WakeCalls -eq 0) 'focus_takeover_kept_retrying'
$passed++

foreach ($foreground in @([IntPtr]::Zero, [IntPtr]20)) {
    Reset-Case
    [GuardWindow]::Foreground = $foreground
    [GuardWindow]::SameThread = ($foreground -ne [IntPtr]::Zero)
    [GuardWindow]::AllowOnCall = 2
    Prepare-Window
    Assert ([GuardWindow]::AttachCalls -eq 0 -and [GuardWindow]::Foreground -eq $script:Hwnd) 'unnecessary_thread_attach'
    $passed++
}

$receipt = '{"hwnd":"10","pid":100,"previous":"20","previous_pid":200,"last_input":1000}'
foreach ($foreground in @(0, 10, 20, 30)) {
    Reset-Case
    [GuardWindow]::Foreground = [IntPtr]$foreground
    [GuardWindow]::DirectSuccess = $true
    Resume-PreparedWindow $receipt
    $calls = if ($foreground -eq 10) { 0 } else { 1 }
    Assert ([GuardWindow]::Foreground -eq $script:Hwnd -and [GuardWindow]::ForegroundCalls -eq $calls -and $script:WakeCalls -eq 0) "handoff_failed_$foreground"
    $passed++
}

foreach ($case in @('missing', 'invalid', 'wrong_hwnd', 'wrong_pid', 'reused_hwnd', 'input', 'unrelated', 'app_changed', 'desktop_locked')) {
    Reset-Case
    [GuardWindow]::DirectSuccess = $true
    $inputReceipt = $receipt
    switch ($case) {
        'missing' { $inputReceipt = '' }
        'invalid' { $inputReceipt = '{' }
        'wrong_hwnd' { $inputReceipt = $receipt.Replace('"10"', '"11"') }
        'wrong_pid' { $inputReceipt = $receipt.Replace('100,', '101,') }
        'reused_hwnd' { [GuardWindow]::PreviousPid = 201 }
        'input' { [GuardWindow]::LastInput++ }
        'unrelated' { [GuardWindow]::Foreground = [IntPtr]40 }
        'app_changed' { [GuardWindow]::ChangedPid = $true }
        'desktop_locked' { [GuardWindow]::Locked = $true }
    }
    $code = if ($case -in @('app_changed', 'desktop_locked')) { $case } else { 'user_takeover' }
    $caught = $null
    try { Resume-PreparedWindow $inputReceipt } catch { $caught = $_ }
    Assert ($null -ne $caught -and $caught.Exception.Data['guard_code'] -eq $code) "handoff_wrong_error_$case"
    Assert ([GuardWindow]::ShowCalls -eq 0 -and [GuardWindow]::ForegroundCalls -eq 0 -and $script:WakeCalls -eq 0) "handoff_activated_$case"
    $passed++
}

Reset-Case
$script:EffectAtSleep = 1; $script:SleepEffect = 'input'
$caught = $null
try { Resume-PreparedWindow $receipt } catch { $caught = $_ }
Assert ($null -ne $caught -and $caught.Exception.Data['guard_code'] -eq 'user_takeover') 'handoff_missed_new_input'
Assert ([GuardWindow]::ForegroundCalls -eq 1 -and $script:WakeCalls -eq 0 -and [GuardWindow]::AttachCalls -eq 0) 'handoff_retried_after_input'
$passed++

@{ ok = $true; passed = $passed; real_ui_actions = 0 } | ConvertTo-Json -Compress
'''.replace("SOURCE_PATH", guard.ps_quote(str(guard.SCRIPT_DIR / "verge_ui.ps1")))
        self.assertEqual(run_ui_selfcheck(script), {"ok": True, "passed": 38, "real_ui_actions": 0})

    def external_reload(self, world, selected=guard.BOOTSTRAP, remove_target=True):
        world.stamp = (200, 10)
        world.context["profile_stamp"] = list(world.stamp)
        world.context["selected"] = selected
        if remove_target:
            world.context["proxies"].pop(guard.TARGET, None)

    def mock_core(self, world):
        def request(method, path, body=None):
            if method == "PUT":
                world.events.append("put")
                world.context["selected"] = body["name"]
                return {}
            if path == "/configs":
                return {"mode": world.context["mode"]}
            if path == "/proxies":
                proxies = deepcopy(world.context["proxies"])
                proxies["GLOBAL"] = {"now": world.context["selected"]}
                return {"proxies": proxies}
            if path == "/proxies/GLOBAL":
                return {"now": world.context["selected"]}
            self.fail("未预期的内核请求：" + path)
        self.enterContext(patch.object(guard, "current_profile_uid", side_effect=lambda: world.context["profile_uid"]))
        return self.enterContext(patch.object(guard, "core_request", side_effect=request))

    def defer_during_prepare(self, world, selected=guard.BOOTSTRAP, remove_target=True):
        def ui(action, *args, **kwargs):
            if action == "prepare":
                self.external_reload(world, selected, remove_target)
            return world.ui_action(action, *args, **kwargs)
        world.ui.side_effect = ui
        self.assertEqual(guard.recover(world.state), "profile_reloading")
        world.ui.side_effect = world.ui_action
        return world.state["pending_reload"]["until"]

    def test_same_scope_reload_is_deferred_but_real_selection_changes_are_preserved(self):
        world = World(self)
        baseline = deepcopy(world.context)
        cases = (
            (guard.BOOTSTRAP, True, True, None, "profile_reloading"),
            ("DIRECT", True, True, None, "profile_reloading"),
            ("REJECT", True, True, None, "profile_reloading"),
            (guard.TARGET, False, True, None, "profile_reloading"),
            ("用户手选节点", True, True, None, "user_takeover"),
            (guard.BOOTSTRAP, False, True, None, "user_takeover"),
            (guard.BOOTSTRAP, True, False, None, "user_takeover"),
            (guard.BOOTSTRAP, True, True, ("profile_uid", "另一份订阅"), "user_takeover"),
            (guard.BOOTSTRAP, True, True, ("mode", "rule"), "user_takeover"),
        )
        for selected, remove_target, change_stamp, scope, code in cases:
            with self.subTest(selected=selected, remove_target=remove_target, change_stamp=change_stamp, scope=scope):
                after = deepcopy(baseline)
                after["selected"] = selected
                if remove_target:
                    after["proxies"].pop(guard.TARGET)
                if change_stamp:
                    after["profile_stamp"] = [200, 10]
                if scope:
                    after[scope[0]] = scope[1]
                with self.assertRaises(guard.GuardError) as caught:
                    guard.check_recovery_context(baseline, after)
                self.assertEqual(caught.exception.code, code)
                if code == "profile_reloading":
                    self.assertEqual(caught.exception.context, after)

    def test_selection_detects_external_reload_before_put(self):
        world = World(self)
        baseline = deepcopy(world.context)
        core = self.mock_core(world)
        for fallback in (guard.BOOTSTRAP, "DIRECT", "REJECT"):
            with self.subTest(fallback=fallback):
                world.context = deepcopy(baseline)
                world.stamp = (100, 10)
                world.close_hook = lambda fallback=fallback: self.external_reload(world, fallback)
                core.reset_mock()
                with self.assertRaises(guard.GuardError) as caught:
                    world.real_selection(guard.BOOTSTRAP)
                self.assertEqual(caught.exception.code, "profile_reloading")
                self.assertEqual(world.context["selected"], fallback)
                self.assertFalse(any(call.args[0] == "PUT" for call in core.call_args_list))

    def test_selection_keeps_manual_choice_or_scope_change_even_with_new_stamp(self):
        world = World(self)
        baseline = deepcopy(world.context)
        core = self.mock_core(world)
        for key, value in (("profile_uid", "另一份订阅"), ("mode", "rule"), ("selected", "用户手选节点")):
            with self.subTest(key=key):
                world.context = deepcopy(baseline)
                world.stamp = (100, 10)
                def change(key=key, value=value):
                    self.external_reload(world)
                    world.context[key] = value
                world.close_hook = change
                core.reset_mock()
                with self.assertRaises(guard.GuardError) as caught:
                    world.real_selection(guard.BOOTSTRAP)
                self.assertEqual(caught.exception.code, "user_takeover")
                self.assertEqual(world.context[key], value)
                self.assertFalse(any(call.args[0] == "PUT" for call in core.call_args_list))

    def test_reload_during_prepare_does_not_switch_update_or_cool_down(self):
        world = World(self)
        self.defer_during_prepare(world)
        world.select.assert_not_called()
        self.assertNotIn("update", world.events)
        self.assertEqual(world.context["selected"], guard.BOOTSTRAP)
        self.assertIsNone(world.state["transaction"])
        self.assertEqual(world.state["cooldown_until"], 0)
        self.assertEqual(world.state["pending_reload"]["selected"], guard.BOOTSTRAP)

    def test_reload_while_closing_claude_before_an_put_does_not_roll_back_to_reject(self):
        world = World(self)
        world.select.side_effect = world.real_selection
        core = self.mock_core(world)
        def close():
            if world.close_claude.call_count == 2:
                self.external_reload(world, "DIRECT")
        world.close_hook = close
        self.assertEqual(guard.recover(world.state), "profile_reloading")
        self.assertEqual(world.context["selected"], "DIRECT")
        self.assertFalse(any(call.args[0] == "PUT" for call in core.call_args_list))
        self.assertNotIn("update", world.events)
        self.assertIsNone(world.state["transaction"])
        self.assertEqual(world.state["cooldown_until"], 0)
        self.assertEqual(world.state["pending_reload"]["selected"], "DIRECT")
        self.assertNotIn("rolled_back", [call.args[0] for call in world.log.call_args_list])

    def test_reloaded_healthy_target_is_selected_without_duplicate_subscription_update(self):
        world = World(self)
        self.defer_during_prepare(world)
        world.context["proxies"][guard.TARGET] = {}
        world.health[guard.TARGET] = True
        world.events.clear()
        world.ui.reset_mock()
        world.select.reset_mock()
        guard.watch_tick(world.state)
        self.assertEqual(world.context["selected"], guard.TARGET)
        self.assertEqual([call.args[0] for call in world.select.call_args_list], [guard.TARGET])
        self.assertFalse(any(call.args[0] in ("prepare", "update") for call in world.ui.call_args_list))
        self.assertFalse(world.state.get("pending_reload"))
        self.assertIsNone(world.state["transaction"])
        self.assertEqual(world.state["cooldown_until"], 0)

    def test_stamp_only_reload_already_healthy_does_not_update_again(self):
        world = World(self)
        self.defer_during_prepare(world, guard.TARGET, remove_target=False)
        world.events.clear()
        world.ui.reset_mock()
        world.select.reset_mock()
        self.assertEqual(guard.watch_tick(world.state), "healthy")
        world.select.assert_not_called()
        self.assertNotIn("update", world.events)
        self.assertFalse(any(call.args[0] in ("prepare", "update") for call in world.ui.call_args_list))

    def test_pending_reload_waits_without_reopening_clash_or_extending_deadline(self):
        world = World(self)
        until = self.defer_during_prepare(world)
        world.events.clear()
        world.ui.reset_mock()
        for offset in (1, 10, 20):
            with patch.object(guard.time, "time", return_value=1000 + offset):
                if offset == 10:
                    world.stamp = (300, 10)
                    world.context["profile_stamp"] = list(world.stamp)
                self.assertEqual(guard.watch_tick(world.state), "profile_reloading")
                self.assertEqual(world.state["pending_reload"]["until"], until)
        world.select.assert_not_called()
        self.assertFalse(any(call.args[0] in ("protect", "prepare", "update") for call in world.ui.call_args_list))
        self.assertEqual(world.state["cooldown_until"], 0)

    def test_changing_reload_stamp_cannot_extend_wait_past_deadline(self):
        world = World(self)
        until = self.defer_during_prepare(world)
        world.stamp = (300, 10)
        world.context["profile_stamp"] = list(world.stamp)
        def update():
            world.stamp = (400, 10)
            world.context["profile_stamp"] = list(world.stamp)
            world.context["proxies"][guard.TARGET] = {}
            return {"ok": True, "invoked": True, "finished": True}
        world.update_hook = update
        world.events.clear()
        with patch.object(guard.time, "time", return_value=until + 1):
            self.assertEqual(guard.watch_tick(world.state), "network_restored")
        self.assertEqual(world.events.count("update"), 1)
        self.assertEqual(world.context["selected"], guard.TARGET)

    def test_expired_pending_reload_can_update_again(self):
        world = World(self)
        until = self.defer_during_prepare(world)
        def update():
            world.stamp = (300, 10)
            world.context["profile_stamp"] = list(world.stamp)
            world.context["proxies"][guard.TARGET] = {}
            return {"ok": True, "invoked": True, "finished": True}
        world.update_hook = update
        world.events.clear()
        with patch.object(guard.time, "time", return_value=until + 1):
            self.assertEqual(guard.watch_tick(world.state), "network_restored")
        self.assertIn("update", world.events)
        self.assertEqual(world.context["selected"], guard.TARGET)
        self.assertFalse(world.state.get("pending_reload"))

    def test_expired_pending_reload_can_retry_unhealthy_returned_target(self):
        world = World(self)
        until = self.defer_during_prepare(world)
        world.context["proxies"][guard.TARGET] = {}
        world.health[guard.TARGET] = False
        def update():
            world.stamp = (300, 10)
            world.context["profile_stamp"] = list(world.stamp)
            world.health[guard.TARGET] = True
            return {"ok": True, "invoked": True, "finished": True}
        world.update_hook = update
        world.events.clear()
        with patch.object(guard.time, "time", return_value=until + 1):
            self.assertEqual(guard.watch_tick(world.state), "network_restored")
        self.assertIn("update", world.events)
        self.assertEqual(world.context["selected"], guard.TARGET)
        self.assertFalse(world.state.get("pending_reload"))

    def test_failed_pending_reload_still_obeys_cooldown_when_reject_matches_marker(self):
        world = World(self)
        until = self.defer_during_prepare(world, "REJECT")
        world.fail_update()
        with patch.object(guard.time, "time", return_value=until + 1):
            self.assertEqual(guard.watch_tick(world.state), "update_error")
        self.assertEqual(world.context["selected"], "REJECT")
        self.assertEqual(world.state["cooldown_until"], until + 1 + guard.COOLDOWN)
        self.assertIsNone(world.state["transaction"])
        attempts = world.events.count("prepare")
        updates = world.events.count("update")
        exits = world.close_claude.call_count
        selections = world.select.call_count
        for offset in (2, 10, 20):
            with patch.object(guard.time, "time", return_value=until + offset):
                self.assertEqual(guard.watch_tick(world.state), "cooldown")
        self.assertEqual(world.events.count("prepare"), attempts)
        self.assertEqual(world.events.count("update"), updates)
        self.assertEqual(world.close_claude.call_count, exits)
        self.assertEqual(world.select.call_count, selections)

    def test_pending_reload_saved_state_rejects_malformed_markers(self):
        valid = {"selected": guard.BOOTSTRAP, "profile_stamp": [200, 10], "until": 1030.0}
        with patch.object(Path, "read_text", return_value=guard.json.dumps({"pending_reload": valid})):
            self.assertEqual(guard.load_state()["pending_reload"], valid)
        malformed = (
            [], {}, {**valid, "selected": ""}, {**valid, "profile_stamp": [200]},
            {**valid, "profile_stamp": [True, 10]}, {**valid, "until": True},
            {**valid, "until": float("inf")}, {**valid, "until": -1},
        )
        for marker in malformed:
            with self.subTest(marker=marker), \
                    patch.object(Path, "read_text", return_value=guard.json.dumps({"pending_reload": marker})):
                self.assertTrue(guard.load_state().get("corrupt"))

    def test_corrupt_state_cannot_use_valid_pending_marker_to_operate(self):
        world = World(self)
        world.state.update(corrupt=True, pending_reload={
            "selected": guard.TARGET, "profile_stamp": [100, 10], "until": 1030.0,
        })
        self.assertEqual(guard.watch_tick(world.state), "paused_selection")
        world.assert_not_changed()
        world.ui.assert_not_called()

    def test_pending_reload_respects_new_manual_selection_mode_or_profile(self):
        world = World(self)
        self.defer_during_prepare(world)
        deferred_state = deepcopy(world.state)
        baseline = deepcopy(world.context)
        for key, value in (("selected", "用户手选节点"), ("mode", "rule"), ("profile_uid", "另一份订阅")):
            with self.subTest(key=key):
                world.state = deepcopy(deferred_state)
                world.context = deepcopy(baseline)
                world.context[key] = value
                world.select.reset_mock()
                world.ui.reset_mock()
                self.assertTrue(guard.watch_tick(world.state).startswith("paused_"))
                self.assertEqual(world.context[key], value)
                self.assertFalse(world.state.get("pending_reload"))
                world.select.assert_not_called()
                self.assertFalse(any(call.args[0] in ("prepare", "update") for call in world.ui.call_args_list))

    def test_own_update_waits_for_core_target_list_before_selecting_vl03(self):
        world = World(self)
        def update():
            world.stamp = (200, 10)
            world.context["profile_stamp"] = list(world.stamp)
            world.context["proxies"].pop(guard.TARGET)
            def inspect():
                if world.now >= 0.5:
                    world.context["proxies"][guard.TARGET] = {}
                return deepcopy(world.context)
            world.inspect.side_effect = inspect
            return {"ok": True, "invoked": True, "finished": True}
        world.update_hook = update
        with patch.object(guard.time, "sleep", side_effect=lambda seconds: setattr(world, "now", world.now + seconds)):
            self.assertEqual(guard.recover(world.state), "network_restored")
        self.assertGreaterEqual(world.now, 0.5)
        self.assertEqual(world.events.count("update"), 1)
        self.assertEqual(world.context["selected"], guard.TARGET)
        self.assertEqual([call.args[0] for call in world.select.call_args_list], [guard.BOOTSTRAP, guard.TARGET])

    def test_own_update_core_target_wait_is_bounded_and_fails_closed(self):
        world = World(self)
        def update():
            world.stamp = (200, 10)
            world.context["profile_stamp"] = list(world.stamp)
            world.context["proxies"].pop(guard.TARGET)
            return {"ok": True, "invoked": True, "finished": True}
        world.update_hook = update
        with patch.object(guard.time, "sleep", side_effect=lambda seconds: setattr(world, "now", world.now + seconds)):
            result = guard.recover(world.state)
        self.assertIn(result, ("target_missing", "recovery_timeout"))
        self.assertGreater(world.now, 0)
        self.assertLessEqual(world.now, guard.RECOVERY_TIMEOUT + 30)
        self.assertEqual(world.context["selected"], "REJECT")
        self.assertIsNone(world.state["transaction"])
        self.assertEqual(world.state["cooldown_until"], 1000 + guard.COOLDOWN)
        self.assertNotIn("network_restored", [call.args[0] for call in world.log.call_args_list])

    def test_own_update_deleted_an_fallback_rolls_back_safely_and_reuses_returned_target(self):
        world = World(self)
        baseline = deepcopy(world.context)
        for fallback in ("DIRECT", "REJECT"):
            with self.subTest(fallback=fallback):
                world.context = deepcopy(baseline)
                world.state = guard.default_state()
                world.state["last_selected"] = guard.TARGET
                world.stamp = (100, 10)
                world.select.reset_mock()
                world.events.clear()
                world.saved.clear()
                def update(fallback=fallback):
                    self.external_reload(world, fallback)
                    world.context["proxies"].pop(guard.BOOTSTRAP)
                    return {"ok": True, "invoked": True, "finished": True}
                world.update_hook = update
                self.assertEqual(guard.recover(world.state), "profile_reloading")
                self.assertEqual(world.context["selected"], "REJECT")
                self.assertIsNone(world.state["transaction"])
                self.assertEqual(world.state["cooldown_until"], 0)
                self.assertEqual(world.state["pending_reload"]["selected"], "REJECT")
                self.assertEqual(world.state["pending_reload"]["profile_stamp"], [200, 10])
                self.assertEqual([call.args[0] for call in world.select.call_args_list], [guard.BOOTSTRAP, "REJECT"])
                self.assertTrue(any(saved.get("transaction", {}).get("expected") == fallback
                                    for saved in world.saved if saved.get("transaction")))
                world.context["proxies"][guard.TARGET] = {}
                world.select.reset_mock()
                world.ui.reset_mock()
                self.assertEqual(guard.watch_tick(world.state), "network_restored")
                self.assertEqual(world.context["selected"], guard.TARGET)
                self.assertEqual([call.args[0] for call in world.select.call_args_list], [guard.TARGET])
                self.assertEqual(world.events.count("update"), 1)
                self.assertFalse(any(call.args[0] in ("prepare", "update") for call in world.ui.call_args_list))
                self.assertFalse(world.state.get("pending_reload"))

    def test_saved_file_observed_healthy_before_core_fallback_remains_recoverable(self):
        world = World(self)
        baseline = deepcopy(world.context)
        for fallback in (guard.BOOTSTRAP, "DIRECT", "REJECT"):
            with self.subTest(fallback=fallback):
                world.context = deepcopy(baseline)
                world.state = guard.default_state()
                world.state.update(last_selected=guard.TARGET, last_profile_stamp=[100, 10])
                world.stamp = (200, 10)
                world.context["profile_stamp"] = list(world.stamp)
                world.events.clear()
                world.select.reset_mock()
                world.close_claude.reset_mock()
                self.assertEqual(guard.watch_tick(world.state), "healthy")
                self.assertEqual(world.state["pending_reload"]["selected"], guard.TARGET)
                self.assertEqual(world.state["pending_reload"]["until"], 1030)
                world.close_claude.assert_not_called()
                world.context["proxies"].pop(guard.TARGET)
                world.context["selected"] = fallback
                self.assertEqual(guard.watch_tick(world.state), "profile_reloading")
                self.assertEqual(world.state["pending_reload"]["selected"], fallback)
                self.assertEqual(world.state["pending_reload"]["until"], 1030)
                world.close_claude.assert_called_once_with()
                world.select.assert_not_called()
                self.assertNotIn("prepare", world.events)
                self.assertNotIn("update", world.events)
                world.context["proxies"][guard.TARGET] = {}
                self.assertEqual(guard.watch_tick(world.state), "network_restored")
                self.assertEqual(world.context["selected"], guard.TARGET)
                self.assertEqual([call.args[0] for call in world.select.call_args_list], [guard.TARGET])
                self.assertNotIn("prepare", world.events)
                self.assertNotIn("update", world.events)

    def test_saved_file_pending_keeps_manual_node_or_scope_change(self):
        world = World(self)
        baseline = deepcopy(world.context)
        for key, value in (("selected", "用户手选节点"), ("mode", "rule"), ("profile_uid", "另一份订阅")):
            with self.subTest(key=key):
                world.context = deepcopy(baseline)
                world.state = guard.default_state()
                world.state.update(last_selected=guard.TARGET, last_profile_stamp=[100, 10])
                world.context["profile_stamp"] = [200, 10]
                self.assertEqual(guard.watch_tick(world.state), "healthy")
                self.assertTrue(world.state.get("pending_reload"))
                world.context["proxies"].pop(guard.TARGET)
                world.context[key] = value
                world.select.reset_mock()
                world.ui.reset_mock()
                world.close_claude.reset_mock()
                self.assertTrue(guard.watch_tick(world.state).startswith("paused_"))
                self.assertEqual(world.context[key], value)
                self.assertFalse(world.state.get("pending_reload"))
                world.assert_not_changed()

    def test_recovery_notices_saved_file_before_core_applies_same_stamp_fallback(self):
        world = World(self)
        baseline = deepcopy(world.context)
        for fallback in (None, guard.BOOTSTRAP, "DIRECT", "REJECT"):
            with self.subTest(fallback=fallback):
                world.context = deepcopy(baseline)
                world.state = guard.default_state()
                world.state.update(last_selected=guard.TARGET, last_profile_stamp=[100, 10])
                world.stamp = (200, 10)
                world.context["profile_stamp"] = list(world.stamp)
                world.select.reset_mock()
                world.close_claude.reset_mock()
                world.events.clear()
                world.close_hook = None if fallback is None else lambda fallback=fallback: self.external_reload(world, fallback)
                self.assertEqual(guard.recover(world.state), "profile_reloading")
                self.assertEqual(world.context["selected"], guard.TARGET if fallback is None else fallback)
                self.assertEqual(world.state["pending_reload"]["selected"], world.context["selected"])
                self.assertEqual(world.state["cooldown_until"], 0)
                self.assertIsNone(world.state["transaction"])
                world.close_claude.assert_called_once_with()
                world.select.assert_not_called()
                self.assertNotIn("prepare", world.events)
                self.assertNotIn("update", world.events)

    def test_observed_prior_stamp_does_not_capture_manual_node_or_scope_change(self):
        world = World(self)
        before = deepcopy(world.context)
        before.update(profile_stamp=[200, 10], reload_stamp=[100, 10])
        for key, value in (("selected", "用户手选节点"), ("mode", "rule"), ("profile_uid", "另一份订阅")):
            with self.subTest(key=key):
                after = deepcopy(before)
                after["proxies"].pop(guard.TARGET)
                after["selected"] = "DIRECT"
                after[key] = value
                with self.assertRaises(guard.GuardError) as caught:
                    guard.check_recovery_context(before, after)
                self.assertEqual(caught.exception.code, "user_takeover")

    def test_real_manual_choice_during_reload_rollback_is_not_saved_as_pending(self):
        world = World(self)
        baseline = deepcopy(world.context)
        for takeover_at in ("before_rollback", "after_rollback"):
            with self.subTest(takeover_at=takeover_at):
                world.context = deepcopy(baseline)
                world.state = guard.default_state()
                world.state["last_selected"] = guard.TARGET
                world.stamp = (100, 10)
                world.events.clear()
                world.select.reset_mock()
                world.inspect.side_effect = lambda: deepcopy(world.context)
                def update(takeover_at=takeover_at):
                    self.external_reload(world, "DIRECT")
                    world.context["proxies"].pop(guard.BOOTSTRAP)
                    calls = 0
                    def inspect():
                        nonlocal calls
                        calls += 1
                        if calls == (2 if takeover_at == "before_rollback" else 3):
                            world.context["selected"] = "用户手选节点"
                        return deepcopy(world.context)
                    world.inspect.side_effect = inspect
                    return {"ok": True, "invoked": True, "finished": True}
                world.update_hook = update
                self.assertEqual(guard.recover(world.state), "user_takeover")
                self.assertEqual(world.context["selected"], "用户手选节点")
                self.assertFalse(world.state.get("pending_reload"))
                self.assertIsNone(world.state["transaction"])
                expected = [guard.BOOTSTRAP] if takeover_at == "before_rollback" else [guard.BOOTSTRAP, "REJECT"]
                self.assertEqual([call.args[0] for call in world.select.call_args_list], expected)


if __name__ == "__main__":
    unittest.main(verbosity=2)
