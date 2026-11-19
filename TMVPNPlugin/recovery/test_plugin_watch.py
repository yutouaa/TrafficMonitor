from contextlib import ExitStack, contextmanager
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import guard
from test_guard import World


class PluginSettingsTest(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(patch.object(guard, "INSTALL_DIR", self.directory))
        self.enterContext(patch.object(guard, "PROFILE_ROOT", self.directory))
        self.enterContext(patch.object(guard, "STATE_PATH", self.directory / "state.json"))
        self.settings_path = self.directory / "plugin-settings.json"
        self.profiles_path = self.directory / "profiles.yaml"
        self.profiles()

    def settings(self, target, interval, **extra):
        self.settings_path.write_text(json.dumps({"target_node": target, "refresh_seconds": interval, **extra}), encoding="utf-8")

    def profiles(self, current="fixture_primary", secondary_name="Second: Team", primary_name="测试订阅"):
        # Use actual block-style YAML, including quoting, Unicode and a private field.
        self.profiles_path.write_text(f"""current: '{current}'
items:
- uid: fixture_primary
  type: remote
  name: {json.dumps(primary_name, ensure_ascii=False)}
  url: https://example.invalid/?private-test-token
- uid: second
  type: remote
  name: {json.dumps(secondary_name, ensure_ascii=False)}
- uid: local
  type: local
  name: '本地配置'
- uid: merge
  type: merge
""", encoding="utf-8-sig")

    def world(self):
        world = World(self)
        self.add_proxy(world, guard.BOOTSTRAP, "Vless")
        return world

    @staticmethod
    def add_proxy(world, name, protocol, *, member=True):
        group = world.context["proxies"]["GLOBAL"]
        group.setdefault("type", "Selector")
        members = group.setdefault("all", [])
        if member and name not in members:
            members.append(name)
        world.context["proxies"][name] = {"type": protocol}

    @staticmethod
    def host_until(world, seconds, on_wait=lambda: None):
        class Host:
            def alive(self, timeout_ms=0):
                if timeout_ms:
                    world.now += timeout_ms / 1000
                    on_wait()
                return world.now < seconds
        return Host()

    def test_settings_defaults_and_validation(self):
        self.assertEqual(guard.load_plugin_settings(), (guard.TARGET, 10, None))
        for interval in guard.REFRESH_INTERVALS:
            self.settings("日本备用节点", interval)
            self.assertEqual(guard.load_plugin_settings(), ("日本备用节点", interval, None))
        for uid in ("second", ""):
            self.settings(guard.TARGET, 10, profile_uid=uid)
            self.assertEqual(guard.load_plugin_settings(), (guard.TARGET, 10, uid))
        for uid in (None, 42, "订阅", "../second", "a" * 129):
            self.settings(guard.TARGET, 10, profile_uid=uid)
            with self.assertRaisesRegex(guard.GuardError, "恢复设置"):
                guard.load_plugin_settings()
        for target, interval in ((guard.BOOTSTRAP, 10), ("direct", 10), ("GLOBAL", 10),
                                 ("节点\n", 10), ("节点\u3000", 10), ("节" * 171, 10),
                                 ("节点", 2), ("节点", 10.0), ("节点", True)):
            with self.subTest(target=target, interval=interval):
                self.settings(target, interval)
                with self.assertRaises(guard.GuardError) as error:
                    guard.load_plugin_settings()
                self.assertEqual(error.exception.code, "plugin_settings_invalid")
        self.settings_path.write_text("{}", encoding="utf-8")
        with self.assertRaises(guard.GuardError):
            guard.load_plugin_settings()

    def test_profile_binding_uses_only_valid_local_settings(self):
        path = self.directory / "profile-binding.json"
        self.assertEqual(guard.load_profile_binding(), ("", ""))
        path.write_text('{"profile_uid":"../other","profile_name":"示例订阅"}', encoding="utf-8")
        self.assertEqual(guard.load_profile_binding(), ("", ""))
        path.write_text('{"profile_uid":"fixture_123","profile_name":"示例订阅"}', encoding="utf-8-sig")
        self.assertEqual(guard.load_profile_binding(), ("fixture_123", "示例订阅"))

    def test_interval_change_reschedules_from_last_start(self):
        world = self.world()
        self.settings(guard.TARGET, 30)
        starts = []
        def tick(_state):
            starts.append(world.now)
            return "healthy"
        def change():
            if world.now == 3:
                self.settings(guard.TARGET, 5)
            if world.now == 6:
                self.settings(guard.TARGET, 15)
        with patch.object(guard, "watch_tick", side_effect=tick):
            guard.watch_loop(world.state, self.host_until(world, 21, change))
        self.assertEqual(starts, [0, 5, 20])

    def test_config_change_keeps_running_recovery_snapshot_and_healthy_selection(self):
        world = self.world()
        alternate = "配置的日本节点"
        next_target = "下一轮目标"
        self.add_proxy(world, alternate, "Vless")
        self.add_proxy(world, next_target, "Trojan")
        world.context["selected"] = alternate
        world.health[alternate] = False
        self.settings(alternate, 5)
        def update():
            self.settings(next_target, 5)
            world.stamp = (200, 10)
            world.health[alternate] = True
            return {"ok": True, "invoked": True, "finished": True}
        world.update_hook = update
        guard.watch_loop(world.state, self.host_until(world, 16))
        self.assertEqual([call.args[0] for call in world.select.call_args_list], [guard.BOOTSTRAP, alternate])
        self.assertEqual(world.context["selected"], alternate)
        self.assertEqual(world.state["plugin_target"], next_target)
        self.assertEqual(world.state["last_result"], "paused_selection")

    def test_settings_change_waits_for_interrupted_rollback_and_preserves_cooldown(self):
        world = self.world()
        alternate = "新目标"
        self.settings(alternate, 5)
        world.context["selected"] = guard.BOOTSTRAP
        self.add_proxy(world, alternate, "Socks5")
        world.state.update(
            plugin_target=guard.TARGET, failures=2, owned_reject=True, last_profile_stamp=[100, 10],
            transaction={"original": guard.TARGET, "expected": guard.BOOTSTRAP},
            pending_reload={"selected": guard.TARGET, "profile_stamp": [100, 10], "until": 1030},
        )
        guard.watch_loop(world.state, self.host_until(world, 6))
        world.select.assert_called_once_with(guard.TARGET)
        self.assertEqual(world.state["plugin_target"], alternate)
        self.assertIsNone(world.state["transaction"])
        self.assertNotIn("pending_reload", world.state)
        self.assertFalse(world.state["owned_reject"])
        self.assertEqual(world.state["failures"], 0)
        self.assertEqual(world.state["cooldown_until"], 1000 + guard.COOLDOWN)
        self.assertEqual(world.state["last_result"], "paused_selection")

    def test_invalid_settings_pause_new_checks_but_not_interrupted_rollback(self):
        world = self.world()
        self.settings_path.write_text("{", encoding="utf-8")
        world.context["selected"] = guard.BOOTSTRAP
        world.state["transaction"] = {"original": guard.TARGET, "expected": guard.BOOTSTRAP}
        with patch.object(guard, "watch_tick") as tick:
            guard.watch_loop(world.state, self.host_until(world, 11))
        world.select.assert_called_once_with(guard.TARGET)
        tick.assert_not_called()
        self.assertIsNone(world.state["transaction"])
        self.assertEqual(world.state["last_result"], "plugin_settings_invalid")

    def test_configured_group_cannot_be_recovered(self):
        world = self.world()
        self.settings("新目标", 5)
        world.context["selected"] = "新目标"
        self.add_proxy(world, "新目标", "Selector")
        guard.watch_loop(world.state, self.host_until(world, 1))
        self.assertEqual(world.state["last_result"], "invalid_target_type")
        world.assert_not_changed()

    def test_target_replaced_by_group_is_not_restored_on_rollback(self):
        world = self.world()
        alternate = "原代理节点"
        self.settings(alternate, 5)
        world.context["selected"] = alternate
        self.add_proxy(world, alternate, "Hysteria2")
        world.health[alternate] = False
        def update():
            world.stamp = (200, 10)
            world.context["proxies"][alternate] = {"type": "Selector"}
            return {"ok": True, "invoked": True, "finished": True}
        world.update_hook = update
        guard.watch_loop(world.state, self.host_until(world, 6))
        self.assertEqual([call.args[0] for call in world.select.call_args_list], [guard.BOOTSTRAP, "REJECT"])
        self.assertEqual(world.state["last_result"], "invalid_target_type")
        self.assertIsNone(world.state["transaction"])

    def test_target_outside_global_waits_for_reload_before_switching(self):
        world = self.world()
        alternate = "恢复目标"
        self.settings(alternate, 5)
        world.context["selected"] = alternate
        self.add_proxy(world, alternate, "Vless", member=False)
        def update():
            world.stamp = (200, 10)
            return {"ok": True, "invoked": True, "finished": True}
        world.update_hook = update
        def apply_reload(seconds):
            world.now += seconds
            self.assertEqual(world.context["selected"], guard.BOOTSTRAP)
            self.add_proxy(world, alternate, "Vless")
            world.health[alternate] = True
        with patch.object(guard.time, "sleep", side_effect=apply_reload) as waited:
            guard.watch_loop(world.state, self.host_until(world, 1))
        waited.assert_called_once()
        self.assertEqual([call.args[0] for call in world.select.call_args_list], [guard.BOOTSTRAP, alternate])
        self.assertEqual(world.state["last_result"], "network_restored")

    def test_invalid_global_group_is_not_treated_as_a_missing_target(self):
        world = self.world()
        self.settings(guard.TARGET, 5)
        self.add_proxy(world, guard.TARGET, "Vless")
        world.context["proxies"]["GLOBAL"]["type"] = "URLTest"
        guard.watch_loop(world.state, self.host_until(world, 1))
        self.assertEqual(world.state["last_result"], "global_unavailable")
        world.assert_not_changed()

    def test_unlisted_original_plugin_target_rolls_back_to_reject_after_restart(self):
        world = self.world()
        alternate = "原代理节点"
        self.settings(guard.TARGET, 5)
        world.context["selected"] = guard.BOOTSTRAP
        self.add_proxy(world, alternate, "Vless", member=False)
        world.state["transaction"] = {"original": alternate, "expected": guard.BOOTSTRAP,
                                      "plugin_target": alternate}
        guard.watch_loop(world.state, self.host_until(world, 1))
        world.select.assert_called_once_with("REJECT")
        self.assertIsNone(world.state["transaction"])

    def test_paused_catalog_uses_actual_yaml_and_omits_private_fields(self):
        world = self.world()
        (self.directory / "monitor.pause").touch()
        self.profiles(primary_name="本地配置")
        with patch.object(guard, "publish_profile_catalog", wraps=guard.publish_profile_catalog) as publish:
            guard.watch_loop(world.state, self.host_until(world, 3))
        publish.assert_called_once()
        data = (self.directory / "profile-catalog.json").read_text(encoding="utf-8")
        self.assertNotIn("private-test-token", data)
        self.assertEqual(json.loads(data), {"available": True, "current": "fixture_primary", "selected": "fixture_primary",
            "items": [{"uid": "fixture_primary", "name": "本地配置", "ambiguous": True},
                      {"uid": "second", "name": "Second: Team", "ambiguous": False}]})
        world.assert_not_changed()

    def test_explicit_unbound_ambiguous_and_missing_profiles_do_not_recover(self):
        world = self.world()
        for uid, name, result in (("", "second name", "profile_unbound"),
                                  ("fixture_primary", "测试订阅", "ambiguous_profile"),
                                  ("unknown", "second name", "profile_not_found")):
            self.settings(guard.TARGET, 5, profile_uid=uid)
            self.profiles(secondary_name=name)
            guard.watch_loop(world.state, self.host_until(world, world.now + 1))
            self.assertEqual(world.state["last_result"], result)
        world.assert_not_changed()

    def test_inactive_subscription_remains_untouched_until_applied(self):
        world = self.world()
        self.settings(guard.TARGET, 5, profile_uid="second")
        world.state.update(failures=2, owned_reject=True)
        world.state["pending_reload"] = {"selected": guard.TARGET, "profile_stamp": [90, 10], "until": 1030}
        guard.watch_loop(world.state, self.host_until(world, 1))
        self.assertEqual(world.state["last_result"], "paused_scope")
        self.assertEqual(world.state["failures"], 0)
        self.assertNotIn("pending_reload", world.state)
        world.assert_not_changed()
        self.profiles(current="second")
        world.context["profile_uid"] = "second"
        self.add_proxy(world, guard.TARGET, "Vless")
        guard.watch_loop(world.state, self.host_until(world, 2))
        self.assertEqual(world.state["last_result"], "healthy")

    def test_subscription_update_uses_frozen_uid_and_new_name_after_rename(self):
        world = self.world()
        self.profiles(current="second", secondary_name='-团队 "订阅"')
        self.settings(guard.TARGET, 5, profile_uid="second")
        world.context["profile_uid"] = "second"
        self.add_proxy(world, guard.TARGET, "Vless")
        world.health[guard.TARGET] = False
        def update():
            self.assertEqual(guard.bound_profile(), ("second", '-团队 "订阅"'))
            self.assertEqual(world.state["transaction"]["profile_uid"], "second")
            self.settings(guard.TARGET, 5, profile_uid="fixture_primary")
            world.stamp = (200, 10)
            world.health[guard.TARGET] = True
            return {"invoked": True, "finished": True}
        world.update_hook = update
        guard.watch_loop(world.state, self.host_until(world, 11))
        self.assertEqual([call.args[0] for call in world.select.call_args_list], [guard.BOOTSTRAP, guard.TARGET])
        self.assertEqual(world.state["last_result"], "paused_scope")

    def test_interruption_cannot_rollback_to_different_subscription_even_if_node_matches(self):
        world = self.world()
        self.profiles(current="second")
        self.settings(guard.TARGET, 5, profile_uid="second")
        world.context.update(profile_uid="second", selected=guard.BOOTSTRAP)
        world.state["transaction"] = {"original": guard.TARGET, "expected": guard.BOOTSTRAP,
                                      "profile_uid": "fixture_primary"}
        guard.watch_loop(world.state, self.host_until(world, 1))
        world.assert_not_changed()
        self.assertIsNone(world.state["transaction"])

    def test_no_usable_an_does_not_close_claude_in_reloading_branch(self):
        world = self.world()
        self.settings(guard.TARGET, 5)
        self.add_proxy(world, guard.TARGET, "Vless")
        world.context["proxies"]["GLOBAL"]["all"].remove(guard.BOOTSTRAP)
        world.health[guard.TARGET] = False
        world.state["pending_reload"] = {"selected": guard.TARGET, "profile_stamp": [100, 10], "until": 1000}
        guard.watch_loop(world.state, self.host_until(world, 1))
        self.assertEqual(world.state["last_result"], "bootstrap_missing")
        world.assert_not_changed()

    def test_fresh_metadata_check_blocks_stale_scope_before_closing_claude(self):
        world = self.world()
        self.settings(guard.TARGET, 5)
        self.add_proxy(world, guard.TARGET, "Vless")
        world.context["proxies"].pop(guard.TARGET)
        def changed_after_inspect(action, *args, **kwargs):
            if action == "probe":
                self.profiles(secondary_name="测试订阅")
            return world.ui_action(action, *args, **kwargs)
        world.ui.side_effect = changed_after_inspect
        guard.watch_loop(world.state, self.host_until(world, 1))
        self.assertEqual(world.state["last_result"], "ambiguous_profile")
        world.assert_not_changed()


class PluginWatchTest(unittest.TestCase):
    def test_legacy_stop_and_manual_request_are_ignored(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for marker in ("stop.request", "recover.request", "monitor.pause"):
                (directory / marker).touch()
            state = guard.default_state()
            class Host:
                def alive(self, timeout_ms=0):
                    if timeout_ms:
                        (directory / "monitor.pause").unlink()
                    return True
            host = Host()
            def tick(current):
                self.assertEqual(current["failures"], 0)
                host.alive = lambda timeout_ms=0: False
                return "healthy"
            with patch.object(guard, "INSTALL_DIR", directory), \
                    patch.object(guard, "save_state"), \
                    patch.object(guard, "profile_catalog_view", return_value=({"available": True}, ("fixture_primary", "Fixture"))), \
                    patch.object(guard, "watch_tick", side_effect=tick) as automatic, \
                    patch.object(guard, "recover") as manual:
                guard.watch_loop(state, host)
            automatic.assert_called_once_with(state)
            manual.assert_not_called()
            self.assertTrue((directory / "stop.request").exists())
            self.assertTrue((directory / "recover.request").exists())

    def test_paused_helper_can_repair_existing_transaction(self):
        world = World(self)
        state = world.state
        state["transaction"] = {"original": guard.TARGET, "expected": guard.BOOTSTRAP}
        class Host:
            def alive(self, timeout_ms=0):
                return not timeout_ms
        with patch.object(guard, "monitor_enabled", return_value=False), \
                patch.object(guard, "repair_interrupted") as repair, \
                patch.object(guard, "watch_tick") as tick, \
                patch.object(guard, "recover") as recover:
            guard.watch_loop(state, Host())
        repair.assert_called_once_with(state)
        tick.assert_not_called()
        recover.assert_not_called()

    def test_host_exit_or_pause_before_mutations_blocks_trigger(self):
        world = World(self)
        state = world.state
        with ExitStack() as stack:
            token = guard.AUTO_ACTION_ALLOWED.set(lambda: False)
            stack.callback(guard.AUTO_ACTION_ALLOWED.reset, token)
            self.assertEqual(guard.recover(state), "monitor_stopped")
            self.assertFalse(state["transaction"])

            state["pending_reload"] = {
                "selected": world.context["selected"], "profile_stamp": world.context["profile_stamp"],
                "until": world.now + 30,
            }
            world.health[guard.TARGET] = False
            state["failures"] = 1
            self.assertEqual(guard.watch_tick(state), "monitor_stopped")

            world.context["proxies"].pop(guard.TARGET)
            self.assertEqual(guard.watch_tick(state), "monitor_stopped")
        world.close_claude.assert_not_called()
        world.assert_not_changed()

    def test_host_exit_during_recovery_preflight_leaves_clash_untouched(self):
        world = World(self)
        token = guard.AUTO_ACTION_ALLOWED.set(lambda: not world.close_claude.called)
        try:
            self.assertEqual(guard.recover(world.state), "monitor_stopped")
        finally:
            guard.AUTO_ACTION_ALLOWED.reset(token)
        self.assertIsNone(world.state["transaction"])
        world.select.assert_not_called()
        self.assertFalse(any(call.args[0] in ("protect", "prepare", "update") for call in world.ui.call_args_list))

    def test_running_recovery_can_finish_after_pause(self):
        world = World(self)
        token = guard.AUTO_ACTION_ALLOWED.set(lambda: not world.select.called)
        try:
            self.assertEqual(guard.recover(world.state), "network_restored")
        finally:
            guard.AUTO_ACTION_ALLOWED.reset(token)
        world.select.assert_called()
        self.assertEqual(world.context["selected"], guard.TARGET)
        self.assertIsNone(world.state["transaction"])

    def test_pause_during_ui_preparation_restores_window_without_switch(self):
        world = World(self)
        token = guard.AUTO_ACTION_ALLOWED.set(lambda: "prepare" not in world.events)
        try:
            self.assertEqual(guard.recover(world.state), "monitor_stopped")
        finally:
            guard.AUTO_ACTION_ALLOWED.reset(token)
        self.assertEqual(world.events[-2:], ["prepare", "restore"])
        self.assertIsNone(world.state["transaction"])
        world.select.assert_not_called()

    def test_lock_wait_can_end_when_host_exits(self):
        class Host:
            def __init__(self, stack, pid, created, image):
                pass
            def alive(self, timeout_ms=0):
                return not timeout_ms
        @contextmanager
        def locked():
            raise guard.GuardError("already_running", "previous helper still owns lock")
            yield
        with patch.object(guard, "PluginHost", Host), patch.object(guard, "InstanceLock", locked), \
                patch.object(guard, "redirected_storage", return_value=None), \
                patch.object(guard, "setup_logging") as logging, patch.object(guard, "watch_loop") as loop:
            guard.plugin_watch(123, 456, Path("TrafficMonitor.exe"))
        logging.assert_not_called()
        loop.assert_not_called()

    @unittest.skipUnless(os.name == "nt", "Windows kernel objects")
    def test_real_host_identity_duplicate_and_event_lifetime(self):
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.GetProcessTimes.argtypes = (wintypes.HANDLE, *[ctypes.POINTER(wintypes.FILETIME)] * 4)
        k32.GetProcessTimes.restype = wintypes.BOOL
        k32.OpenEventW.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR)
        k32.OpenEventW.restype = wintypes.HANDLE
        k32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        k32.CloseHandle.argtypes = (wintypes.HANDLE,)
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "TrafficMonitor.exe"
            shutil.copyfile(Path(os.environ["SystemRoot"]) / "System32" / "findstr.exe", image)
            with subprocess.Popen([str(image), "/L", "fixture"], stdin=subprocess.PIPE,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  creationflags=guard.NO_WINDOW) as process:
                try:
                    times = [wintypes.FILETIME() for _ in range(4)]
                    self.assertTrue(k32.GetProcessTimes(int(process._handle), *map(ctypes.byref, times)))
                    created = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
                    with ExitStack() as stack:
                        try:
                            host = guard.PluginHost(stack, process.pid, created, image)
                        except guard.GuardError as error:
                            if error.code == "plugin_token":
                                self.skipTest("The test runner needs an ordinary user token")
                            raise
                        with self.assertRaisesRegex(guard.GuardError, "身份不匹配"), ExitStack() as other:
                            guard.PluginHost(other, process.pid, created + 1, image)
                        with self.assertRaisesRegex(guard.GuardError, "已有恢复助手"), ExitStack() as other:
                            guard.PluginHost(other, process.pid, created, image)
                        name = f"Local\\TMVPNPlugin.GuardReady.{process.pid}.{created}"
                        event = k32.OpenEventW(0x100000, False, name)
                        self.assertTrue(event)
                        stack.callback(k32.CloseHandle, event)
                        self.assertEqual(k32.WaitForSingleObject(event, 0), 258)
                        host.ready()
                        self.assertEqual(k32.WaitForSingleObject(event, 0), 0)
                        process.stdin.close()
                        process.wait(timeout=5)
                        self.assertFalse(host.alive())
                        host.not_ready()
                        self.assertEqual(k32.WaitForSingleObject(event, 0), 258)
                    self.assertFalse(k32.OpenEventW(0x100000, False, name))
                finally:
                    if process.poll() is None:
                        process.terminate()
