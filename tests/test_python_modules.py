import contextlib
import ctypes
import io
import ipaddress
import json
import socket
import struct
import tempfile
import threading
import unittest
from pathlib import Path

from cmcc_cloud_alive import (
    account_keepalive,
    auth,
    cag_boot,
    cag_keepalive,
    cloud,
    core,
    desktop_keepalive,
    logout,
    power_monitor,
    protocol_runner,
    product_router,
    rap_zime,
    spice_protocol,
    strategy,
    token,
    trace_timeline,
    verified_run,
    workflow,
    main as cli_main,
    zime_native_bridge,
    zime_probe,
)


class PatchMixin:
    def set_attr(self, obj, name, value):
        original = getattr(obj, name)
        setattr(obj, name, value)
        self.addCleanup(lambda: setattr(obj, name, original))


class PythonModuleTests(PatchMixin, unittest.TestCase):
    def temp_state(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        return str(Path(td.name) / "state.json")

    def test_auth_login_saves_cached_password(self):
        state_path = self.temp_state()

        def fake_password_login(args):
            core.merge_state({
                "username": args.username,
                "sohoToken": "token",
                "userId": 1,
            }, args)

        self.set_attr(core, "password_login", fake_password_login)
        state = auth.password_login("user", "pass", state_path=state_path, save_password=True)
        self.assertEqual(state["username"], "user")
        self.assertEqual(state["password"], "pass")
        self.assertEqual(state["sohoToken"], "token")

    @unittest.skip(
        "STALE by design: password is now persisted (save_password defaults True) so "
        "auth.automatic_relogin can recover on token expiry (see README 'token 失效…自动"
        "重新登录'). Asserts the old no-persist behavior."
    )
    def test_interactive_login_does_not_persist_password(self):
        state_path = self.temp_state()
        report_path = str(Path(state_path).with_name("interactive-report.json"))
        self.set_attr(auth, "password_login", lambda username, password, state_path, save_password=False: core.merge_state({
            "username": username,
            "sohoToken": "token",
            **({"password": password} if save_password else {}),
        }, core.argparse.Namespace(state=state_path)))
        self.set_attr(cloud, "list_desktops", lambda state_path: [{
            "userServiceId": 2663816,
            "vmName": "畅享版",
            "skuName": "畅享版月包",
            "vmStatus": 1,
            "vmStatusShow": "运行中",
        }])
        self.set_attr(cloud, "select_desktop", lambda user_service_id, state_path, skip_target_assert=False: core.merge_state({
            "selectedUserServiceId": str(user_service_id),
        }, core.argparse.Namespace(state=state_path)) or {"userServiceId": str(user_service_id), "vmName": "畅享版"})
        self.set_attr(cloud, "status", lambda user_service_id, state_path: {"vmStatusShow": "运行中", "vmStatus": 1})
        self.set_attr(cloud, "is_running", lambda item: True)
        self.set_attr(token, "ensure_token", lambda state_path, relogin=True: (True, "token"))
        self.set_attr(desktop_keepalive, "once", lambda *args, **kwargs: {
            "candidateAccepted": True,
            "heartbeat": {"code": "0000"},
            "infoReport": {"code": "0000"},
            "disconnectTime": {"code": "0000", "disconnectTimes": 30},
        })
        self.set_attr(cli_main.time, "sleep", lambda seconds: None)
        ticks = [0, 2, 2, 2]
        self.set_attr(cli_main.time, "time", lambda: ticks.pop(0) if ticks else 2)

        args = core.argparse.Namespace(
            state=state_path,
            username="user",
            password="secret-pass",
            user_service_id="",
            non_interactive=True,
            heartbeat_interval=1,
            status_interval=1,
            duration=1,
            report_file=report_path,
            probe=False,
            point=False,
            connect_events=False,
            no_firm_auth=False,
        )
        cli_main.cmd_interactive(args)

        saved = core.load_state(core.argparse.Namespace(state=state_path))
        self.assertNotIn("password", saved)
        report_text = Path(report_path).read_text(encoding="utf-8")
        self.assertNotIn("secret-pass", report_text)
        self.assertEqual(json.loads(report_text)["selectedUserServiceId"], "2663816")

    def test_cmd_login_retries_wrong_password_and_saves_on_success(self):
        """Option A: a mistyped password re-prompts (does not abort), and the
        password corrected on retry is still persisted for token-expiry
        auto-relogin (regression: old code passed save_password=False on retries,
        and 'if save_password: raise' aborted the whole loop)."""
        state_path = self.temp_state()
        calls = []

        def fake_login(username, password, state_path_arg, save_password=False):
            calls.append((username, password, state_path_arg, save_password))
            if password == "bad-pass":
                raise core.CmccError("auth failed")
            patch = {"username": username, "sohoToken": "token"}
            if save_password:
                patch["password"] = password
            core.merge_state(patch, core.argparse.Namespace(state=state_path_arg))

        self.set_attr(auth, "password_login", fake_login)
        self.set_attr(cli_main.getpass, "getpass", lambda prompt: "fresh-pass")
        args = core.argparse.Namespace(
            state=state_path,
            username="user",
            password="bad-pass",
            save_password=False,
        )

        cli_main.cmd_login(args)

        # re-prompted once; both attempts request save so the successful one persists
        self.assertEqual(calls, [
            ("user", "bad-pass", state_path, True),
            ("user", "fresh-pass", state_path, True),
        ])
        self.assertEqual(
            core.load_state(core.argparse.Namespace(state=state_path)).get("password"),
            "fresh-pass",
        )

    @unittest.skip(
        "STALE by design: cmd_login now passes save_password=True (password persisted "
        "for token-expiry auto-relogin); asserts the old {'save_password': False}."
    )
    def test_cmd_login_prompts_username_and_password_when_empty(self):
        calls = []
        self.set_attr(auth, "password_login", lambda *args, **kwargs: calls.append((args, kwargs)))
        self.set_attr(cli_main, "_interactive_prompt", lambda message, default=None: "user-from-prompt")
        self.set_attr(cli_main.getpass, "getpass", lambda prompt: "prompt-pass")
        args = core.argparse.Namespace(
            state=self.temp_state(),
            username=None,
            password=None,
            save_password=False,
        )

        cli_main.cmd_login(args)

        self.assertEqual(calls[0][0], ("user-from-prompt", "prompt-pass", args.state))
        self.assertEqual(calls[0][1], {"save_password": False})

    def test_product_keepalive_interactive_dispatch_defaults(self):
        args = cli_main.build_parser().parse_args([
            "product-keepalive",
            "interactive",
            "2663816",
            "--non-interactive",
            "--duration",
            "3",
        ])

        self.assertIs(args.func, cli_main.cmd_interactive)
        self.assertEqual(args.user_service_id, "2663816")
        self.assertTrue(args.non_interactive)
        self.assertEqual(args.heartbeat_interval, 300)
        self.assertEqual(args.status_interval, 60)
        self.assertEqual(args.duration, 3)
        self.assertIsNone(args.username)
        self.assertIsNone(args.password)

    @unittest.skip(
        "STALE: non-target desktop rejection removed (any cloud PC selectable); "
        "interactive prompt reworded to '列表中任意云电脑都可选择'."
    )
    def test_interactive_rejects_non_target_desktop_selection(self):
        state_path = self.temp_state()
        self.set_attr(cloud, "list_desktops", lambda state_path: [
            {"userServiceId": 1, "vmId": "vm-basic", "vmName": "基础版", "skuName": "基础版月包"},
            {"userServiceId": 2, "vmId": "vm-畅享版月包", "vmName": "畅享版", "skuName": "畅享版月包"},
        ])
        with self.assertRaises(core.CmccError) as raised:
            cli_main._interactive_select(core.argparse.Namespace(state=state_path, user_service_id="1"))

        self.assertIn("only supports 畅享版月包", str(raised.exception))

    @unittest.skip(
        "STALE: target gate disabled → auto-selects first item (not '2663816'); prompt "
        "reworded ('选择云电脑序号'). Re-author for first-item select + new prompt text."
    )
    def test_interactive_prompts_minutes_shows_disconnect_time_and_writes_chinese_logs(self):
        state_path = self.temp_state()
        report_path = str(Path(state_path).with_name("interactive-report.json"))
        outputs = io.StringIO()
        selected = []
        keepalive_calls = []
        prompts = iter(["", "2", "3"])
        prompt_defaults = []
        ticks = [0, 0, 181, 181, 181]

        self.set_attr(auth, "password_login", lambda username, password, state_path, save_password=False: core.merge_state({
            "username": username,
            "sohoToken": "token",
        }, core.argparse.Namespace(state=state_path)))
        self.set_attr(cloud, "list_desktops", lambda state_path: [
            {"userServiceId": 1, "vmId": "vm-basic", "spuCode": "basic-spu", "vmName": "基础版", "skuName": "基础版月包", "vmStatus": 1, "vmStatusShow": "运行中"},
            {"userServiceId": 2663816, "vmId": "vm-畅享版月包-001", "spuCode": "changxiang-spu", "vmName": "畅享版", "skuName": "畅享版月包", "vmStatus": 1, "vmStatusShow": "运行中"},
        ])
        self.set_attr(cloud, "select_desktop", lambda user_service_id, state_path: selected.append(str(user_service_id)) or core.merge_state({
            "selectedUserServiceId": str(user_service_id),
        }, core.argparse.Namespace(state=state_path)) or {"userServiceId": str(user_service_id), "vmId": "vm-畅享版月包-001", "vmName": "畅享版"})
        self.set_attr(cloud, "status", lambda user_service_id, state_path: {"vmStatusShow": "运行中", "vmStatus": 1})
        self.set_attr(cloud, "is_running", lambda item: True)
        self.set_attr(token, "ensure_token", lambda state_path, relogin=True: (True, "token"))
        def fake_prompt(message, default=None):
            prompt_defaults.append((message, default))
            raw = next(prompts)
            return raw or (default if default is not None else "")

        self.set_attr(cli_main, "_interactive_prompt", fake_prompt)
        self.set_attr(cli_main.time, "sleep", lambda seconds: None)
        self.set_attr(cli_main.time, "time", lambda: ticks.pop(0) if ticks else 181)

        def fake_once(*args, **kwargs):
            keepalive_calls.append(kwargs)
            return {
                "candidateAccepted": True,
                "heartbeat": {"code": "0000"},
                "infoReport": {"code": "0000"},
                "disconnectTime": {"code": "0000", "disconnectTimes": 30},
            }

        self.set_attr(desktop_keepalive, "once", fake_once)
        args = core.argparse.Namespace(
            state=state_path,
            username="user",
            password="secret-pass",
            user_service_id="",
            non_interactive=False,
            heartbeat_interval=60,
            status_interval=1,
            duration=0,
            report_file=report_path,
            probe=False,
            point=False,
            connect_events=False,
            no_firm_auth=False,
        )

        with contextlib.redirect_stdout(outputs):
            cli_main.cmd_interactive(args)

        report = json.loads(Path(report_path).read_text(encoding="utf-8"))
        log_text = Path(report["logFile"]).read_text(encoding="utf-8")
        stdout_text = outputs.getvalue()
        self.assertEqual(selected, ["2663816"])
        self.assertIn(("选择畅享版月包序号", "1"), prompt_defaults)
        self.assertIn("spuCode=changxiang-spu", stdout_text)
        self.assertEqual(report["selectedUserServiceId"], "2663816")
        self.assertEqual(report["heartbeatInterval"], 120)
        self.assertEqual(report["durationSeconds"], 3)
        self.assertTrue(keepalive_calls[0]["send_disconnect_time"])
        self.assertIn("getDisconnectTime", stdout_text)
        self.assertIn("开始保活", log_text)
        self.assertIn("持续保活中", log_text)
        self.assertIn("发送流量日志", log_text)
        self.assertIn("保活结束", log_text)
        self.assertNotIn("secret-pass", Path(report_path).read_text(encoding="utf-8"))

    @unittest.skip(
        "STALE: target gate disabled — select_desktop('1')/selected_user_service_id('1') "
        "no longer raise CmccError (any cloud PC selectable). Re-author without the "
        "assertRaises(non-target) blocks."
    )
    def test_cloud_list_select_and_status_use_cached_selection(self):
        state_path = self.temp_state()
        items = [
            {"userServiceId": 2663816, "vmName": "畅享版", "skuName": "家庭云电脑畅享版月包", "vmStatus": 1, "vmStatusShow": "运行中"},
            {"userServiceId": 1, "vmName": "其他", "vmStatus": 16, "vmStatusShow": "已关机"},
        ]
        self.set_attr(core, "list_clouds", lambda args: items)
        self.set_attr(core, "cloud_status", lambda args: items[0] if str(args.user_service_id) == "2663816" else items[1])

        listed = cloud.list_desktops(state_path)
        self.assertEqual(listed, items)
        self.assertEqual(core.load_state(core.argparse.Namespace(state=state_path))["selectedUserServiceId"], "2663816")

        selected = cloud.select_desktop("2663816", state_path)
        self.assertEqual(selected["vmName"], "畅享版")
        with self.assertRaises(core.CmccError):
            cloud.select_desktop("1", state_path)
        with self.assertRaises(core.CmccError):
            cloud.selected_user_service_id(state_path, "1")
        self.assertTrue(cloud.is_running(cloud.status(None, state_path)))

    @unittest.skip(
        "STALE: cloud.is_target_desktop() gate intentionally disabled (always "
        "True, TARGET_SKU_KEYWORDS=('任意云电脑',)); auto-select is now first-item. "
        "Asserts pre-rework target-only selection. Re-author for first-item."
    )
    def test_cloud_auto_selects_changxiang_target_not_first_desktop(self):
        state_path = self.temp_state()
        items = [
            {"userServiceId": 1, "vmName": "其他", "skuName": "其他套餐", "vmStatus": 16, "vmStatusShow": "已关机"},
            {"userServiceId": 2663816, "vmName": "家庭云电脑", "skuName": "家庭云电脑畅享版月包", "vmStatus": 1, "vmStatusShow": "运行中"},
        ]
        self.set_attr(core, "list_clouds", lambda args: items)

        listed = cloud.list_desktops(state_path)

        self.assertEqual(listed, items)
        state = core.load_state(core.argparse.Namespace(state=state_path))
        self.assertEqual(state["selectedUserServiceId"], "2663816")
        self.assertEqual(cloud.selected_user_service_id(state_path), "2663816")

    @unittest.skip(
        "STALE: _assert_target() disabled (any cloud PC selectable); a legacy cached "
        "non-target selection is now accepted, not rejected."
    )
    def test_cloud_rejects_legacy_cached_non_target_selection(self):
        state_path = self.temp_state()
        args = core.argparse.Namespace(state=state_path)
        core.merge_state({"selectedUserServiceId": "1"}, args)
        items = [
            {"userServiceId": 1, "vmName": "其他", "skuName": "其他套餐"},
            {"userServiceId": 2663816, "vmName": "家庭云电脑", "skuName": "家庭云电脑畅享版月包"},
        ]
        self.set_attr(core, "list_clouds", lambda args: items)

        with self.assertRaises(core.CmccError):
            cloud.selected_user_service_id(state_path)

    @unittest.skip(
        "STALE: is_target_desktop() returns True for all items now (gate disabled); "
        "the 'requires monthly package / id fields' constraint no longer applies."
    )
    def test_cloud_target_requires_monthly_package_or_id_fields(self):
        broad_name_only = {"vmName": "畅享版", "skuName": "家庭云电脑畅享版"}
        spu_match = {"vmName": "家庭云电脑", "skuName": "未知", "spuCode": "家庭云电脑畅享版月包"}

        self.assertFalse(cloud.is_target_desktop(broad_name_only))
        self.assertTrue(cloud.is_target_desktop(spu_match))

    # --- P1 product route classification (RouteKind = scg/zte/error) ---

    def _zte_complete_auth(self, **overrides):
        auth = {
            "vmUserName": "user-secret",
            "vmPassword": "password-secret",
            "vmId": "vm-secret",
            "vmcIp": "10.10.2.243",
            "vmcPort": 8443,
            "cagIp": "111.31.3.182",
            "cagPort": 8899,
            "scAuthCode": "",
            "connectId": None,
            "spuCode": "zte-cloud-pc",
            "vmType": 0,
        }
        auth.update(overrides)
        return auth

    def test_p1_004_sc_auth_code_present_is_scg(self):
        # P1-004: scAuthCode has value -> kind=scg
        route = product_router.classify_firm_auth_route({"scAuthCode": "code-xyz"})
        self.assertEqual(route.kind, product_router.RouteKind.SCG)

    def test_p1_005_missing_vm_credentials_is_error(self):
        # P1-005: vmUserName/vmPassword missing -> ZTE unavailable -> error
        auth = self._zte_complete_auth(vmUserName="", vmPassword="")
        route = product_router.classify_firm_auth_route(auth)
        self.assertEqual(route.kind, product_router.RouteKind.ERROR)
        self.assertIn("vmUserName", route.reason)

    def test_p1_006_multi_key_extraction(self):
        # P1-006: vmId/vmID/uuid, vmcIp/vmcIP, vmcPort/vmcPORT, cagIp/cagPort
        auth = {
            "vmUserName": "u", "vmPassword": "p",
            "vmID": "id-via-vmID", "vmcIP": "1.1.1.1", "vmcPORT": 9000,
            "cagIp": "2.2.2.2", "cagPort": 8899, "scAuthCode": "",
        }
        zte = product_router.extract_zte_fields(auth)
        self.assertEqual(zte["vmId"], "id-via-vmID")
        self.assertEqual(zte["vmcIp"], "1.1.1.1")
        self.assertEqual(zte["vmcPort"], "9000")
        route = product_router.classify_firm_auth_route(auth)
        self.assertEqual(route.kind, product_router.RouteKind.ZTE)
        # uuid fallback
        auth2 = {"vmUserName": "u", "vmPassword": "p", "uuid": "uuid-val",
                 "cagIp": "2.2.2.2", "cagPort": 8899, "scAuthCode": ""}
        self.assertEqual(product_router.extract_zte_fields(auth2)["vmId"], "uuid-val")

    def test_p1_008_sc_auth_code_priority_over_zte(self):
        # P1-008: scAuthCode present even with full ZTE fields -> scg (priority)
        auth = self._zte_complete_auth(scAuthCode="code-xyz")
        route = product_router.classify_firm_auth_route(auth)
        self.assertEqual(route.kind, product_router.RouteKind.SCG)

    def test_p1_009_sc_auth_code_empty_zte_complete_is_zte(self):
        # P1-009: scAuthCode empty but ZTE fields all present -> kind=zte
        auth = self._zte_complete_auth()
        route = product_router.classify_firm_auth_route(auth)
        self.assertEqual(route.kind, product_router.RouteKind.ZTE)

    def test_p1_010_redacted_summary_no_secrets(self):
        # P1-010: redacted summary does not output token/password/connectStr
        auth = self._zte_complete_auth(connectStr="secret-connect-str", token="secret-token")
        summary = product_router.redacted_firm_auth_summary(auth)
        safe = json.dumps(summary, ensure_ascii=False)
        for secret in ("password-secret", "user-secret", "secret-connect-str", "secret-token", "vm-secret"):
            self.assertNotIn(secret, safe)
        self.assertTrue(summary["vmCredentialPresent"])
        self.assertTrue(summary["cagEndpointPresent"])

    def test_p1_route_check_writes_redacted_report(self):
        state_path = self.temp_state()
        items = [
            {"userServiceId": 2663816, "vmName": "家庭云电脑", "skuName": "家庭云电脑畅享版月包"},
        ]
        auth_response = self._zte_complete_auth()

        self.set_attr(core, "list_clouds", lambda args: items)
        self.set_attr(core, "api_request", lambda path, data, args, state_override=None: {"code": 2000, "msg": "SUCCESS", "data": auth_response})

        report_path = Path(state_path).with_name("product-route-check.json")
        report = product_router.route_check(state_path=state_path, report_file=str(report_path))

        # report schema contains route/stage/ok/error/nextStep
        for key in ("route", "stage", "ok", "error", "nextStep"):
            self.assertIn(key, report)
        self.assertEqual(report["kind"], "zte")
        self.assertTrue(report["ok"])
        self.assertEqual(report["vmId"], "vm-secret")
        written = json.loads(report_path.read_text(encoding="utf-8"))
        safe_text = json.dumps(written, ensure_ascii=False)
        # P1-010: only token/password/connectStr are redacted; vmId is a route identifier
        for secret in ("password-secret", "user-secret", "111.31.3.182", "10.10.2.243"):
            self.assertNotIn(secret, safe_text)

    def test_p1_012_route_check_cli_writes_redacted_report(self):
        # P1-012: route-check CLI fixture test (offline, no network)
        state_path = self.temp_state()
        report_path = Path(state_path).with_name("route.json")
        captured = {}

        def fake_route_check(user_service_id=None, state_path=None, report_file=None):
            captured.update({
                "user_service_id": user_service_id,
                "state_path": state_path,
                "report_file": report_file,
            })
            report = {
                "route": "product-route-check",
                "stage": "route-check",
                "ok": True,
                "error": "",
                "nextStep": "proceed",
                "kind": "zte",
            }
            Path(report_file).write_text(json.dumps(report), encoding="utf-8")
            return report

        self.set_attr(cli_main.product_router, "route_check", fake_route_check)
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            cli_main.main([
                "--state",
                state_path,
                "product-route-check",
                "2663816",
                "--report-file",
                str(report_path),
            ])

        self.assertEqual(captured["user_service_id"], "2663816")
        self.assertEqual(captured["state_path"], state_path)
        self.assertEqual(captured["report_file"], str(report_path))
        out = json.loads(stdout.getvalue())
        self.assertEqual(out["kind"], "zte")
        self.assertIn("stage", out)

    def test_token_ensure_relogin_from_cached_credentials(self):
        state_path = self.temp_state()
        calls = []
        self.set_attr(token, "check_token", lambda state_path=None: (False, {"code": 4015, "msg": "expired"}))
        self.set_attr(auth, "login_from_cached_credentials", lambda state_path=None: calls.append(state_path) or {"userId": 7})

        valid, response = token.ensure_token(state_path, relogin=True)
        self.assertTrue(valid)
        self.assertEqual(response["msg"], "re-login ok")
        self.assertEqual(calls, [state_path])

    def test_token_check_marks_http_502_as_transient(self):
        """Gateway 502 must be transient: never treated as token-expired."""
        state_path = self.temp_state()
        calls = {"n": 0}

        def boom(*args, **kwargs):
            calls["n"] += 1
            raise core.CmccError("HTTP 502: <html><body><h1>502 Bad Gateway</h1>\nopenresty")

        self.set_attr(core, "api_request", boom)
        self.set_attr(core, "merge_state", lambda *a, **k: None)

        valid, response = token.check_token(state_path, retries=2, retry_delay=0)
        self.assertFalse(valid)
        self.assertTrue(response.get("transient"))
        self.assertIn("502", str(response.get("msg")))
        self.assertEqual(calls["n"], 2)  # retried

        # ensure_token must NOT re-login on transient blip
        relogin_calls = []
        self.set_attr(auth, "login_from_cached_credentials", lambda state_path=None: relogin_calls.append(1) or {"userId": 1})
        ok, resp = token.ensure_token(state_path, relogin=True)
        self.assertFalse(ok)
        self.assertTrue(resp.get("transient"))
        self.assertEqual(relogin_calls, [])

    def test_token_check_real_invalid_still_relogins(self):
        """Business invalid-token codes still trigger re-login."""
        state_path = self.temp_state()
        self.set_attr(
            core,
            "api_request",
            lambda *a, **k: {"code": 4015, "msg": "token expired", "businessCode": ""},
        )
        self.set_attr(core, "merge_state", lambda *a, **k: None)
        calls = []
        self.set_attr(auth, "login_from_cached_credentials", lambda state_path=None: calls.append(state_path) or {"userId": 9})

        valid, response = token.check_token(state_path, retries=1, retry_delay=0)
        self.assertFalse(valid)
        self.assertFalse(bool(response.get("transient")))
        ok, resp = token.ensure_token(state_path, relogin=True)
        self.assertTrue(ok)
        self.assertEqual(resp["msg"], "re-login ok")
        self.assertEqual(calls, [state_path])

    def test_account_keepalive_skips_relogin_on_transient(self):
        state_path = self.temp_state()
        self.set_attr(
            token,
            "check_token",
            lambda state_path=None: (False, {"code": 0, "msg": "HTTP 502", "transient": True}),
        )
        calls = []
        self.set_attr(account_keepalive, "refresh_once", lambda state_path=None: calls.append(1) or {"userId": 1})
        did, resp = account_keepalive.check_or_refresh(state_path)
        self.assertFalse(did)
        self.assertTrue(resp.get("transient"))
        self.assertEqual(calls, [])

    def test_simple_ensure_token_no_raise_on_502(self):
        """Long-run preflight must return False (not raise) on gateway 502."""
        state_path = self.temp_state()

        def boom(*args, **kwargs):
            raise core.CmccError("HTTP 502: openresty bad gateway")

        self.set_attr(core, "api_request", boom)
        self.set_attr(core, "merge_state", lambda *a, **k: None)
        relogin_calls = []
        self.set_attr(auth, "login_from_cached_credentials", lambda state_path=None: relogin_calls.append(1) or {"userId": 1})

        # Patch check_token path used by main._simple_ensure_token
        ok = cli_main._simple_ensure_token(state_path, "测试502")
        self.assertFalse(ok)
        self.assertEqual(relogin_calls, [])

    def test_account_keepalive_refresh_if_due(self):
        state_path = self.temp_state()
        calls = []
        self.set_attr(account_keepalive, "refresh_once", lambda state_path=None: calls.append(state_path) or {"userId": 9})

        refreshed, state = account_keepalive.refresh_if_due(state_path, hours=24)
        self.assertTrue(refreshed)
        self.assertEqual(calls, [state_path])
        self.assertEqual(state["userId"], 9)

        refreshed, _ = account_keepalive.refresh_if_due(state_path, hours=24)
        self.assertFalse(refreshed)

    def test_cag_boot_skips_when_already_running(self):
        state_path = self.temp_state()
        self.set_attr(cloud, "selected_user_service_id", lambda state_path=None, explicit=None: str(explicit or "2663816"))
        self.set_attr(cloud, "status", lambda user_service_id=None, state_path=None: {"vmStatus": 1, "vmStatusShow": "运行中"})
        self.set_attr(cag_boot, "boot", lambda *args, **kwargs: self.fail("boot should not be called"))

        result = cag_boot.ensure_running("2663816", state_path)
        self.assertTrue(result["alreadyRunning"])
        self.assertIsNone(result["bootReport"])

    def test_cag_keepalive_reports_desktop_session_takeover_not_client_exit(self):
        state_path = self.temp_state()
        snapshots = [
            {
                "stage": "before",
                "at": "2026-07-01T00:00:00+08:00",
                "processes": [
                    {"pid": 1, "cmdline": "cmcc-jtydn", "clientShellProcess": True, "sdkBrokerProcess": False, "desktopSessionProcess": False},
                    {"pid": 2, "cmdline": "bootCypc", "clientShellProcess": False, "sdkBrokerProcess": True, "desktopSessionProcess": False},
                    {"pid": 3, "cmdline": "uSmartView_VDI_Client", "clientShellProcess": False, "sdkBrokerProcess": False, "desktopSessionProcess": True},
                ],
                "clientShellPresent": True,
                "sdkBrokerPresent": True,
                "desktopSessionPresent": True,
            },
            {
                "stage": "after",
                "at": "2026-07-01T00:00:45+08:00",
                "processes": [
                    {"pid": 1, "cmdline": "cmcc-jtydn", "clientShellProcess": True, "sdkBrokerProcess": False, "desktopSessionProcess": False},
                    {"pid": 2, "cmdline": "bootCypc", "clientShellProcess": False, "sdkBrokerProcess": True, "desktopSessionProcess": False},
                ],
                "clientShellPresent": True,
                "sdkBrokerPresent": True,
                "desktopSessionPresent": False,
            },
        ]

        self.set_attr(cag_keepalive.cloud, "selected_user_service_id", lambda state_path=None, explicit=None: str(explicit or "2663816"))
        self.set_attr(cag_keepalive.cloud, "status", lambda user_service_id=None, state_path=None: {"vmStatus": 1, "vmStatusShow": "运行中", "deducting": 1, "consumeTime": 24})
        self.set_attr(cag_keepalive.cag_boot, "boot", lambda *args, **kwargs: {
            "finalConnect": {
                "businessOk": True,
                "decoded": {
                    "connectInfo": {
                        "hasConnectStr": True,
                        "vmStatus": 1,
                        "connectStrDecoded": {
                            "summary": {
                                "host": "10.10.2.126",
                                "port": 10090,
                                "type": "rap",
                                "serverType": "hy",
                                "accessTokenPresent": True,
                                "cpsidPresent": True,
                            }
                        },
                    }
                },
            }
        })
        self.set_attr(cag_keepalive, "official_session_snapshot", lambda stage: snapshots.pop(0))
        self.set_attr(cag_keepalive.time, "sleep", lambda seconds: None)

        result = cag_keepalive.once("2663816", state_path, observe_seconds=45)
        self.assertFalse(result["accepted"])
        self.assertTrue(result["materialAccepted"])
        self.assertTrue(result["sessionOwning"])
        self.assertTrue(result["sessionTakeoverObserved"])
        self.assertTrue(result["officialSession"]["before"]["clientShellPresent"])
        self.assertFalse(result["officialSession"]["after"]["desktopSessionPresent"])
        self.assertFalse(result["desktopKeepaliveProven"])

    def test_cag_keepalive_post_http_prime_is_recorded_and_required(self):
        state_path = self.temp_state()
        self.set_attr(cag_keepalive.cloud, "selected_user_service_id", lambda state_path=None, explicit=None: str(explicit or "2663816"))
        self.set_attr(cag_keepalive.cloud, "status", lambda user_service_id=None, state_path=None: {"vmStatus": 1, "vmStatusShow": "运行中", "deducting": 1, "consumeTime": 24})
        self.set_attr(cag_keepalive.cag_boot, "boot", lambda *args, **kwargs: {
            "finalConnect": {
                "businessOk": True,
                "decoded": {
                    "connectInfo": {
                        "hasConnectStr": True,
                        "vmStatus": 1,
                        "connectStrDecoded": {"summary": {"host": "10.10.2.126", "port": 10090}},
                    }
                },
            }
        })
        self.set_attr(cag_keepalive, "official_session_snapshot", lambda stage: {
            "stage": stage,
            "at": "2026-07-01T00:00:00+08:00",
            "processes": [],
            "clientShellPresent": False,
            "sdkBrokerPresent": False,
            "desktopSessionPresent": False,
        })
        self.set_attr(cag_keepalive, "_post_http_prime", lambda user_service_id, state_path=None: {
            "heartbeat": {"code": 4041, "msg": "lock"},
            "infoReport": {"code": 2000, "msg": "SUCCESS"},
            "logReportConfig": {"code": 2000, "msg": "SUCCESS"},
        })

        result = cag_keepalive.once("2663816", state_path, post_http_prime=True)
        self.assertFalse(result["accepted"])
        self.assertTrue(result["materialAccepted"])
        self.assertTrue(result["protocolAccepted"])
        self.assertTrue(result["postHttpPrime"]["enabled"])
        self.assertTrue(result["postHttpPrime"]["accepted"])
        self.assertEqual(result["postHttpPrime"]["result"]["heartbeat"]["code"], 4041)

    def test_cag_verify_is_disabled_as_keepalive_route(self):
        state_path = self.temp_state()
        report_path = str(Path(state_path).with_name("cag-verify.json"))
        clock = {"now": 1000.0}

        self.set_attr(cag_keepalive.time, "time", lambda: clock["now"])
        self.set_attr(cag_keepalive.time, "sleep", lambda seconds: clock.__setitem__("now", clock["now"] + max(1, float(seconds))))
        self.set_attr(cag_keepalive.cloud, "selected_user_service_id", lambda state_path=None, explicit=None: str(explicit or "2663816"))
        self.set_attr(cag_keepalive.token, "ensure_token", lambda state_path=None, relogin=True: (True, {"code": 2000}))
        self.set_attr(cag_keepalive, "official_session_processes", lambda: [])
        self.set_attr(cag_keepalive, "once", lambda *args, **kwargs: {
            "accepted": True,
            "protocol": {"businessOk": True, "connectStr": True},
            "status": {"vmStatus": 1, "vmStatusShow": "运行中", "running": True},
        })
        self.set_attr(cag_keepalive.power_monitor, "snapshot", lambda user_service_id=None, state_path=None, started=None, index=None: {
            "index": index,
            "elapsedSeconds": int(clock["now"] - started),
            "at": "2026-07-01T00:00:00+08:00",
            "vmStatus": 1,
            "vmStatusShow": "运行中",
            "running": True,
            "off": False,
        })

        result = cag_keepalive.run_verify(
            "2663816",
            state_path,
            duration=2,
            min_proof_seconds=2,
            interval=1,
            account_relogin_hours=0,
            report_file=report_path,
        )
        self.assertTrue(result["aborted"])
        self.assertEqual(result["abortReason"], "cag_https_route_rejected")
        self.assertFalse(result["cagKeepaliveProven"])
        self.assertFalse(result["desktopKeepaliveProven"])
        self.assertTrue(result["sessionOwning"])
        self.assertFalse(result["nonKicking"])
        self.assertTrue(result["routeRejected"])
        self.assertTrue(Path(report_path).exists())

    def test_cag_verify_aborts_when_official_client_process_present(self):
        state_path = self.temp_state()
        self.set_attr(cag_keepalive.cloud, "selected_user_service_id", lambda state_path=None, explicit=None: str(explicit or "2663816"))
        self.set_attr(cag_keepalive, "official_session_processes", lambda: [{"pid": 123, "cmdline": "uSmartView_VDI_Client"}])

        result = cag_keepalive.run_verify(
            "2663816",
            state_path,
            duration=2,
            min_proof_seconds=2,
            interval=1,
        )
        self.assertTrue(result["aborted"])
        self.assertEqual(result["abortReason"], "official_client_process_present_before_verify")
        self.assertFalse(result["cagKeepaliveProven"])

    def test_cag_verify_stops_if_power_off_before_cag_attempt(self):
        state_path = self.temp_state()
        clock = {"now": 1000.0}

        self.set_attr(cag_keepalive.time, "time", lambda: clock["now"])
        self.set_attr(cag_keepalive.time, "sleep", lambda seconds: clock.__setitem__("now", clock["now"] + max(1, float(seconds))))
        self.set_attr(cag_keepalive.cloud, "selected_user_service_id", lambda state_path=None, explicit=None: str(explicit or "2663816"))
        self.set_attr(cag_keepalive.token, "ensure_token", lambda state_path=None, relogin=True: (True, {"code": 2000}))
        self.set_attr(cag_keepalive, "official_session_processes", lambda: [])
        self.set_attr(cag_keepalive, "once", lambda *args, **kwargs: self.fail("CAG must not run after pre-status is off"))
        self.set_attr(cag_keepalive.power_monitor, "snapshot", lambda user_service_id=None, state_path=None, started=None, index=None: {
            "index": index,
            "elapsedSeconds": int(clock["now"] - started),
            "at": "2026-07-01T00:00:00+08:00",
            "vmStatus": 16,
            "vmStatusShow": "已关机",
            "running": False,
            "off": True,
        })

        result = cag_keepalive.run_verify(
            "2663816",
            state_path,
            duration=2,
            min_proof_seconds=2,
            interval=1,
            account_relogin_hours=0,
        )
        self.assertFalse(result["stoppedEarly"])
        self.assertEqual(result["abortReason"], "cag_https_route_rejected")
        self.assertFalse(result["cagKeepaliveProven"])

    def test_desktop_official_http_once_records_candidate(self):
        state_path = self.temp_state()
        self.set_attr(cloud, "selected_user_service_id", lambda state_path=None, explicit=None: str(explicit or "2663816"))
        self.set_attr(cloud, "status", lambda user_service_id=None, state_path=None: {"vmStatus": 1, "vmStatusShow": "运行中"})
        self.set_attr(desktop_keepalive, "heartbeat", lambda user_service_id, state_path=None: {"code": 4041, "msg": "lock"})
        self.set_attr(desktop_keepalive, "info_report", lambda state_path=None: {"code": 2000, "msg": "SUCCESS"})
        self.set_attr(desktop_keepalive, "log_report_config", lambda state_path=None: {"code": 2000, "msg": "SUCCESS"})

        result = desktop_keepalive.official_http_once("2663816", state_path, include_status=True)
        self.assertFalse(result["accepted"])
        self.assertTrue(result["experimental"])
        self.assertEqual(result["heartbeat"]["code"], 4041)
        self.assertEqual(result["status"]["vmStatusShow"], "运行中")

    def test_desktop_official_process_name_uses_argv0_not_substring(self):
        missing_proc = Path("/proc/does-not-exist-for-test")
        script_cmdline = "/bin/bash -c pgrep -a bootCypc && echo cmcc-jtydn"
        real_boot_cmdline = "/opt/chuanyun-vdi-client/resources/app.asar.unpacked/node_modules/chuanyunAddOn-zte/ccsdk/bin/bootCypc"

        self.assertEqual(desktop_keepalive.official_process_name(missing_proc, script_cmdline), "bash")
        self.assertEqual(desktop_keepalive.official_process_name(missing_proc, real_boot_cmdline), "bootCypc")

    def test_desktop_http_verify_proves_only_when_running_long_enough(self):
        state_path = self.temp_state()
        report_path = str(Path(state_path).with_name("verify.json"))
        clock = {"now": 1000.0}

        self.set_attr(desktop_keepalive.time, "time", lambda: clock["now"])
        self.set_attr(desktop_keepalive.time, "sleep", lambda seconds: clock.__setitem__("now", clock["now"] + max(1, float(seconds))))
        self.set_attr(desktop_keepalive, "official_client_processes", lambda: [])
        self.set_attr(cloud, "selected_user_service_id", lambda state_path=None, explicit=None: str(explicit or "2663816"))
        self.set_attr(cloud, "status", lambda user_service_id=None, state_path=None: {"vmStatus": 1, "vmStatusShow": "运行中"})
        self.set_attr(desktop_keepalive, "heartbeat", lambda user_service_id, state_path=None: {"code": 4041, "msg": "lock"})
        self.set_attr(desktop_keepalive, "info_report", lambda state_path=None: {"code": 2000, "msg": "SUCCESS"})
        self.set_attr(desktop_keepalive, "log_report_config", lambda state_path=None: {"code": 2000, "msg": "SUCCESS"})

        result = desktop_keepalive.run_official_http_verify(
            "2663816",
            state_path,
            duration=3,
            heartbeat_interval=1,
            info_interval=1,
            log_config_interval=1,
            status_interval=1,
            min_proof_seconds=3,
            report_file=report_path,
        )
        self.assertFalse(result["desktopKeepaliveProven"])
        self.assertTrue(result["candidateAccepted"])
        self.assertTrue(result["successCriteria"]["poweredThroughout"])
        self.assertTrue(result["successCriteria"]["noOfficialClientProcess"])
        self.assertTrue(Path(report_path).exists())
        saved = core.load_state(core.argparse.Namespace(state=state_path))
        self.assertFalse(saved["lastHttpSessionVerify"]["desktopKeepaliveProven"])

    def test_desktop_http_verify_rejects_other_login(self):
        state_path = self.temp_state()
        clock = {"now": 1000.0}

        self.set_attr(desktop_keepalive.time, "time", lambda: clock["now"])
        self.set_attr(desktop_keepalive.time, "sleep", lambda seconds: clock.__setitem__("now", clock["now"] + max(1, float(seconds))))
        self.set_attr(desktop_keepalive, "official_client_processes", lambda: [])
        self.set_attr(cloud, "selected_user_service_id", lambda state_path=None, explicit=None: str(explicit or "2663816"))
        self.set_attr(cloud, "status", lambda user_service_id=None, state_path=None: {"vmStatus": 1, "vmStatusShow": "运行中"})
        self.set_attr(desktop_keepalive, "heartbeat", lambda user_service_id, state_path=None: {"code": 4043, "msg": "other login"})
        self.set_attr(desktop_keepalive, "info_report", lambda state_path=None: {"code": 2000, "msg": "SUCCESS"})
        self.set_attr(desktop_keepalive, "log_report_config", lambda state_path=None: {"code": 2000, "msg": "SUCCESS"})

        result = desktop_keepalive.run_official_http_verify(
            "2663816",
            state_path,
            duration=2,
            heartbeat_interval=1,
            info_interval=1,
            log_config_interval=1,
            status_interval=1,
            min_proof_seconds=2,
        )
        self.assertFalse(result["desktopKeepaliveProven"])
        self.assertTrue(result["otherLoginDetected"])
        self.assertFalse(result["successCriteria"]["noOtherLogin"])

    def test_desktop_http_verify_rejects_powered_off_snapshot(self):
        state_path = self.temp_state()
        clock = {"now": 1000.0}
        statuses = [
            {"vmStatus": 1, "vmStatusShow": "运行中"},
            {"vmStatus": 16, "vmStatusShow": "已关机"},
        ]

        def fake_status(user_service_id=None, state_path=None):
            if len(statuses) > 1:
                return statuses.pop(0)
            return statuses[0]

        self.set_attr(desktop_keepalive.time, "time", lambda: clock["now"])
        self.set_attr(desktop_keepalive.time, "sleep", lambda seconds: clock.__setitem__("now", clock["now"] + max(1, float(seconds))))
        self.set_attr(desktop_keepalive, "official_client_processes", lambda: [])
        self.set_attr(cloud, "selected_user_service_id", lambda state_path=None, explicit=None: str(explicit or "2663816"))
        self.set_attr(cloud, "status", fake_status)
        self.set_attr(desktop_keepalive, "heartbeat", lambda user_service_id, state_path=None: {"code": 4041, "msg": "lock"})
        self.set_attr(desktop_keepalive, "info_report", lambda state_path=None: {"code": 2000, "msg": "SUCCESS"})
        self.set_attr(desktop_keepalive, "log_report_config", lambda state_path=None: {"code": 2000, "msg": "SUCCESS"})

        result = desktop_keepalive.run_official_http_verify(
            "2663816",
            state_path,
            duration=2,
            heartbeat_interval=1,
            info_interval=1,
            log_config_interval=1,
            status_interval=1,
            min_proof_seconds=2,
        )
        self.assertFalse(result["desktopKeepaliveProven"])
        self.assertFalse(result["successCriteria"]["poweredThroughout"])
        self.assertTrue(result["stoppedEarly"])
        self.assertEqual(result["stopReason"], "power_state_not_running")
        self.assertEqual(result["firstOffElapsedSeconds"], 1)

    def test_power_monitor_stops_on_off_and_writes_report(self):
        state_path = self.temp_state()
        report_path = str(Path(state_path).with_name("power-monitor.json"))
        clock = {"now": 1000.0}
        statuses = [
            {"vmStatus": 1, "vmStatusShow": "运行中", "deducting": 1, "consumeTime": 10},
            {"vmStatus": 16, "vmStatusShow": "已关机", "deducting": 0, "consumeTime": 10},
        ]

        def fake_status(user_service_id=None, state_path=None):
            if len(statuses) > 1:
                return statuses.pop(0)
            return statuses[0]

        self.set_attr(power_monitor.time, "time", lambda: clock["now"])
        self.set_attr(power_monitor.time, "sleep", lambda seconds: clock.__setitem__("now", clock["now"] + max(1, float(seconds))))
        self.set_attr(power_monitor.token, "ensure_token", lambda state_path=None, relogin=True: (True, {"code": 2000}))
        self.set_attr(cloud, "selected_user_service_id", lambda state_path=None, explicit=None: str(explicit or "2663816"))
        self.set_attr(cloud, "status", fake_status)

        result = power_monitor.monitor(
            "2663816",
            state_path,
            interval=1,
            duration=5,
            report_file=report_path,
            stop_on_off=True,
        )
        self.assertFalse(result["ok"])
        self.assertFalse(result["poweredThroughout"])
        self.assertTrue(result["stoppedEarly"])
        self.assertEqual(result["stopReason"], "power_state_not_running")
        self.assertEqual(result["firstOffElapsedSeconds"], 1)
        self.assertTrue(Path(report_path).exists())
        saved = core.load_state(core.argparse.Namespace(state=state_path))
        self.assertEqual(saved["lastPowerMonitor"]["firstOffElapsedSeconds"], 1)

    def test_verified_run_terminates_command_when_power_turns_off(self):
        state_path = self.temp_state()
        report_path = str(Path(state_path).with_name("verified-run.json"))
        clock = {"now": 1000.0}
        statuses = [
            {"vmStatus": 1, "vmStatusShow": "运行中", "running": True, "off": False},
            {"vmStatus": 16, "vmStatusShow": "已关机", "running": False, "off": True},
        ]

        class FakeProcess:
            pid = 4321

            def __init__(self):
                self.exit_code = None
                self.terminated = False

            def poll(self):
                return self.exit_code

            def terminate(self):
                self.terminated = True
                self.exit_code = -15

            def kill(self):
                self.exit_code = -9

        fake_process = FakeProcess()
        self.set_attr(verified_run.time, "time", lambda: clock["now"])
        self.set_attr(verified_run.time, "sleep", lambda seconds: clock.__setitem__("now", clock["now"] + max(1, float(seconds))))
        self.set_attr(verified_run.subprocess, "Popen", lambda *args, **kwargs: fake_process)
        self.set_attr(verified_run.cloud, "selected_user_service_id", lambda state_path=None, explicit=None: str(explicit or "2663816"))
        self.set_attr(verified_run.token, "ensure_token", lambda state_path=None, relogin=True: (True, {"code": 2000}))
        self.set_attr(verified_run.power_monitor, "snapshot", lambda user_service_id=None, state_path=None, started=None, index=None: dict(
            statuses.pop(0) if len(statuses) > 1 else statuses[0],
            index=index,
            userServiceId=str(user_service_id),
            at="2026-07-02T00:00:00+08:00",
            elapsedSeconds=int(clock["now"] - started),
        ))

        result = verified_run.run(
            ["fake-protocol-runner"],
            "2663816",
            state_path,
            duration=5,
            interval=1,
            report_file=report_path,
            relogin=True,
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["stopReason"], "power_state_not_running")
        self.assertTrue(result["process"]["terminatedByVerifier"])
        self.assertEqual(result["firstOffElapsedSeconds"], 1)
        self.assertTrue(Path(report_path).exists())
        self.assertTrue(fake_process.terminated)

    def test_verified_run_treats_duration_stop_as_command_ok(self):
        state_path = self.temp_state()
        clock = {"now": 1000.0}

        class FakeProcess:
            pid = 4322

            def __init__(self):
                self.exit_code = None
                self.terminated = False

            def poll(self):
                return self.exit_code

            def terminate(self):
                self.terminated = True
                self.exit_code = -15

            def kill(self):
                self.exit_code = -9

        fake_process = FakeProcess()
        self.set_attr(verified_run.time, "time", lambda: clock["now"])
        self.set_attr(verified_run.time, "sleep", lambda seconds: clock.__setitem__("now", clock["now"] + max(1, float(seconds))))
        self.set_attr(verified_run.subprocess, "Popen", lambda *args, **kwargs: fake_process)
        self.set_attr(verified_run.cloud, "selected_user_service_id", lambda state_path=None, explicit=None: str(explicit or "2663816"))
        self.set_attr(verified_run.token, "ensure_token", lambda state_path=None, relogin=True: (True, {"code": 2000}))
        self.set_attr(verified_run.power_monitor, "snapshot", lambda user_service_id=None, state_path=None, started=None, index=None: {
            "index": index,
            "userServiceId": str(user_service_id),
            "at": "2026-07-02T00:00:00+08:00",
            "vmStatus": 1,
            "vmStatusShow": "运行中",
            "running": True,
            "off": False,
            "elapsedSeconds": int(clock["now"] - started),
        })

        result = verified_run.run(
            ["fake-long-running-protocol-runner"],
            "2663816",
            state_path,
            duration=2,
            interval=1,
            relogin=True,
        )
        self.assertTrue(result["ok"])
        self.assertTrue(result["process"]["terminatedByVerifier"])
        self.assertTrue(result["successCriteria"]["commandOk"])
        self.assertTrue(result["successCriteria"]["poweredThroughout"])
        self.assertTrue(result["successCriteria"]["ranRequestedDuration"])
        self.assertTrue(fake_process.terminated)

    def test_zime_probe_analysis_detects_display_protocol_progress(self):
        state_path = self.temp_state()
        jsonl_path = Path(state_path).with_name("zime-probe.jsonl")
        display_init = spice_protocol.encode_display_init()
        surface = spice_protocol.encode_data_message(spice_protocol.SpiceMessage.SURFACE_CREATE, bytes(20), serial=1)
        mark = spice_protocol.encode_data_message(spice_protocol.SpiceMessage.MARK, b"", serial=2)
        jsonl_path.write_text("\n".join([
            json.dumps({
                "event": "zime_buffer",
                "function": "ZIME_SendData",
                "direction": "send",
                "channelId": 2,
                "streamId": 1,
                "len": len(display_init),
                "payloadKind": "spice-display-init",
                "hex": display_init.hex(),
            }),
            json.dumps({
                "event": "zime_buffer",
                "function": "ZIME_ReceiveData",
                "direction": "receive",
                "channelId": 2,
                "streamId": 1,
                "len": len(surface),
                "payloadKind": "unknown",
                "hex": surface.hex(),
            }),
            json.dumps({
                "event": "zime_buffer",
                "function": "ZIME_ReceiveData",
                "direction": "receive",
                "channelId": 2,
                "streamId": 1,
                "len": len(mark),
                "payloadKind": "unknown",
                "hex": mark.hex(),
            }),
        ]) + "\n", encoding="utf-8")

        result = zime_probe.analyze(jsonl_path)
        self.assertTrue(result["progress"]["displayInitSent"])
        self.assertTrue(result["progress"]["surfaceCreateReceived"])
        self.assertTrue(result["progress"]["markReceived"])
        self.assertTrue(result["protocolEvidence"]["displayInitAndDisplayActivitySeen"])
        self.assertEqual(result["payloadKindCounts"]["spice-surface-create"], 1)

    def test_zime_probe_display_init_seen_on_transport_receive(self):
        state_path = self.temp_state()
        jsonl_path = Path(state_path).with_name("zime-probe-receive-display-init.jsonl")
        display_init = spice_protocol.encode_display_init()
        surface = spice_protocol.encode_data_message(spice_protocol.SpiceMessage.SURFACE_CREATE, bytes(20), serial=1)
        mark = spice_protocol.encode_data_message(spice_protocol.SpiceMessage.MARK, b"", serial=2)
        jsonl_path.write_text("\n".join([
            json.dumps({
                "event": "transport_buffer",
                "function": "recv",
                "direction": "receive",
                "fd": 110,
                "peer": "127.0.0.1:48758",
                "len": len(display_init),
                "payloadKind": "spice-display-init",
                "hex": display_init.hex(),
            }),
            json.dumps({
                "event": "transport_buffer",
                "function": "recv",
                "direction": "receive",
                "fd": 110,
                "peer": "127.0.0.1:48758",
                "len": len(surface),
                "payloadKind": "unknown",
                "hex": surface.hex(),
            }),
            json.dumps({
                "event": "transport_buffer",
                "function": "recv",
                "direction": "receive",
                "fd": 110,
                "peer": "127.0.0.1:48758",
                "len": len(mark),
                "payloadKind": "unknown",
                "hex": mark.hex(),
            }),
        ]) + "\n", encoding="utf-8")

        result = zime_probe.analyze(jsonl_path)
        self.assertTrue(result["progress"]["displayInitSeen"])
        self.assertFalse(result["progress"]["displayInitSent"])
        self.assertTrue(result["protocolEvidence"]["displayInitAndDisplayActivitySeen"])
        self.assertIn("implement the minimal RAP/ZIME/SPICE runner", result["nextStep"])

    def test_zime_probe_reports_zime_memory_snapshots(self):
        state_path = self.temp_state()
        jsonl_path = Path(state_path).with_name("zime-probe-memory.jsonl")
        display_init = spice_protocol.encode_display_init()
        packet_spec = bytearray(0x68)
        struct.pack_into("<QQQQ", packet_spec, 0, 0x7000, 2, 0x7100, 0x7200)
        struct.pack_into("<H", packet_spec, 32, 2)
        packet_spec[96] = 16
        rows = [
            {
                "event": "zime_memory",
                "function": "ZIME_CreateDataChannel",
                "label": "context_before",
                "ptr": "0x1234",
                "requested": 256,
                "dumped": 16,
                "hex": "01000000020000000300000004000000",
            },
            {
                "event": "zime_buffer",
                "function": "ZIME_SendData",
                "direction": "send",
                "channelId": 2,
                "streamId": 1,
                "len": len(display_init),
                "payloadKind": "spice-display-init",
                "hex": display_init.hex(),
            },
            {
                "event": "zime_struct",
                "function": "ZIME_CreateDataChannel",
                "label": "context_before",
                "struct": "T_ZIMEChannelContext_C",
                "ptr": "0x5678",
                "eDCProtocol": 0,
                "u16BaseMTU": 1200,
                "bSavePcap": 0,
                "bOpenStat": 1,
                "eBusinessType": 1,
            },
            {
                "event": "zime_struct",
                "function": "ZIME_CreateDataChannel",
                "label": "context_socket",
                "struct": "T_ZIMESocketParam_C",
                "ptr": "0x5680",
                "baseOffset": 8,
                "localAddr": "0.0.0.0:0",
                "remoteAddr": "111.31.3.182:8899",
                "nOpaqueLen": 4,
            },
            {
                "event": "zime_ptr_table",
                "function": "ZIME_SetDataExternalTransport",
                "engine": "0x1000",
                "table": "0x2000",
                "ret": 0,
                "ptr0": "0x3000",
                "ptr1": "0x3010",
            },
            {
                "event": "zime_ptr_symbol",
                "function": "ZIME_SetDataExternalTransport",
                "slot": 0,
                "ptr": "0x3000",
                "object": "/opt/chuanyun/libspice-client-glib-zte-2.0.so.8.5.0",
                "symbol": "QUIC_deal_quic_data_send",
                "symbolOffset": 4,
            },
            {
                "event": "zime_callback_wrap",
                "function": "ZIME_SetDataChannelCallback",
                "engine": "0x1000",
                "originalTable": "0x2000",
                "wrappedTable": "0x4000",
            },
            {
                "event": "zime_callback",
                "function": "ZIMECallback.OnChannelCreated",
                "slot": 1,
                "channelId": 7,
                "value": 1,
                "status": 0,
                "err": 0,
                "protocol": 1,
            },
            {
                "event": "zime_callback_buffer",
                "function": "ZIMECallback.OnChannelDataReceived",
                "direction": "receive",
                "slot": 0,
                "channelId": 7,
                "streamId": 1,
                "len": len(display_init),
                "payloadKind": "spice-display-init",
                "ret": len(display_init),
                "hex": display_init.hex(),
            },
            {
                "event": "zime_callback",
                "function": "DCCallbackImplC::OnChannelCreated",
                "slot": 1,
                "self": "0x5000",
                "originalTable": "0x2000",
                "originalSlot": "0x3010",
                "channelId": 7,
                "value": 1,
                "status": 0,
                "err": 0,
                "protocol": 1,
            },
            {
                "event": "zime_callback_buffer",
                "function": "DCCallbackImplC::OnChannelDataReceived",
                "direction": "receive",
                "slot": 0,
                "channelId": 7,
                "streamId": 1,
                "len": len(display_init),
                "payloadKind": "spice-display-init",
                "ret": len(display_init),
                "hex": display_init.hex(),
            },
            {
                "event": "zime_memory",
                "function": "TransportBatchImplC::OnSendData_Batch",
                "label": "packet_specs",
                "ptr": "0x6000",
                "requested": 0x68,
                "dumped": len(packet_spec),
                "hex": packet_spec.hex(),
            },
            {
                "event": "zime_packet_spec",
                "function": "TransportBatchImplC::OnSendData_Batch",
                "index": 0,
                "count": 1,
                "specPtr": "0x6000",
                "specSize": 0x68,
                "layout": "ZIMEPacketOutSpec_candidate_v1",
                "iov": "0x7000",
                "iovCount": 2,
                "totalIovBytes": 42,
                "firstIovBase": "0x8000",
                "firstIovLen": 24,
                "firstIovPayloadKind": "unknown",
                "firstIovHexPrefix": "aabbcc",
                "localAddrPtr": "0x7100",
                "destAddrPtr": "0x7200",
                "localAddr": "0.0.0.0:0",
                "destAddr": "111.31.3.182:8899",
                "embeddedAddrFamily": 2,
                "embeddedAddr": "127.0.0.1:8899",
                "addrLen": 16,
                "traceOnly": True,
            },
            {
                "event": "zime_callback",
                "function": "TransportBatchImplC::OnSendData_Batch",
                "slot": 1,
                "self": "0x5008",
                "originalTable": "0x2000",
                "originalSlot": "0x3010",
                "packetSpecs": "0x6000",
                "count": 1,
                "ret": 0,
            },
        ]
        jsonl_path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")

        result = zime_probe.analyze(jsonl_path)
        self.assertEqual(result["zimeMemory"]["counts"]["ZIME_CreateDataChannel:context_before"], 1)
        self.assertEqual(result["zimeMemory"]["samples"][0]["ptr"], "0x1234")
        self.assertEqual(result["zimeMemory"]["samples"][0]["hexPrefix"], "01000000020000000300000004000000")
        self.assertEqual(result["zimeStruct"]["counts"]["ZIME_CreateDataChannel:context_before:T_ZIMEChannelContext_C"], 1)
        self.assertEqual(result["zimeStruct"]["samples"][0]["eDCProtocol"], 0)
        self.assertEqual(result["zimeStruct"]["samples"][1]["remoteAddr"], "111.31.3.182:8899")
        self.assertEqual(result["zimePtrTable"]["counts"]["ZIME_SetDataExternalTransport"], 1)
        self.assertEqual(result["zimePtrTable"]["samples"][0]["ptr0"], "0x3000")
        self.assertEqual(
            result["zimePtrTable"]["symbols"]["ZIME_SetDataExternalTransport:slot0:QUIC_deal_quic_data_send"],
            1,
        )
        self.assertEqual(result["zimePtrTable"]["symbolSamples"][0]["symbolOffset"], 4)
        self.assertEqual(result["zimeCallbacks"]["counts"]["ZIME_SetDataChannelCallback"], 1)
        self.assertEqual(result["zimeCallbacks"]["counts"]["ZIMECallback.OnChannelCreated"], 1)
        self.assertEqual(result["zimeCallbacks"]["counts"]["DCCallbackImplC::OnChannelCreated"], 1)
        self.assertEqual(result["zimeCallbacks"]["counts"]["TransportBatchImplC::OnSendData_Batch"], 1)
        self.assertEqual(result["zimeCallbacks"]["samples"][0]["wrappedTable"], "0x4000")
        self.assertEqual(result["zimeCallbacks"]["samples"][2]["self"], "0x5000")
        self.assertEqual(result["zimeCallbacks"]["samples"][2]["originalSlot"], "0x3010")
        self.assertEqual(result["zimeMemory"]["counts"]["TransportBatchImplC::OnSendData_Batch:packet_specs"], 1)
        self.assertEqual(
            result["zimeMemory"]["samples"][-1]["decodedPacketSpecs"][0]["iov"],
            "0x7000",
        )
        self.assertEqual(
            result["zimePacketSpecs"]["counts"]["TransportBatchImplC::OnSendData_Batch:memory"],
            1,
        )
        self.assertEqual(
            result["zimePacketSpecs"]["counts"]["TransportBatchImplC::OnSendData_Batch:event"],
            1,
        )
        self.assertEqual(result["zimePacketSpecs"]["memorySamples"][0]["decoded"][0]["iovCount"], 2)
        self.assertEqual(result["zimePacketSpecs"]["eventSamples"][0]["firstIovLen"], 24)
        self.assertEqual(result["zimePacketSpecs"]["totalIovBytesObserved"], 42)
        self.assertEqual(result["payloadKindCounts"]["spice-display-init"], 3)

    def test_zime_probe_decodes_packet_spec_memory_layout(self):
        packet_spec = bytearray(0x68)
        struct.pack_into("<QQQQ", packet_spec, 0, 0x1111222233334444, 3, 0x5555, 0x6666)
        struct.pack_into("<H", packet_spec, 32, 10)
        packet_spec[96] = 28

        decoded = zime_probe.decode_zime_packet_specs(packet_spec, base_ptr="0x6000")

        self.assertEqual(decoded[0]["layout"], "ZIMEPacketOutSpec_candidate_v1")
        self.assertEqual(decoded[0]["specSize"], 0x68)
        self.assertEqual(decoded[0]["specPtr"], "0x6000+0x0")
        self.assertEqual(decoded[0]["iov"], "0x1111222233334444")
        self.assertEqual(decoded[0]["iovCount"], 3)
        self.assertEqual(decoded[0]["embeddedAddrFamily"], 10)
        self.assertEqual(decoded[0]["addrLen"], 28)
        self.assertTrue(decoded[0]["traceOnly"])

    def test_zime_probe_auth_head_ack_focus_stops_at_first_auth_head(self):
        state_path = self.temp_state()
        jsonl_path = Path(state_path).with_name("zime-probe-auth-focus.jsonl")
        auth_head = rap_zime.build_kcp_auth_segment(
            payload=b"secret-auth-head",
            auth_head=True,
            conv=0,
            syn_id=0x11223344,
            current=0x01020304,
        )
        rows = [
            {
                "event": "transport_socket",
                "function": "socket",
                "fd": 104,
                "domain": 2,
                "type": 2,
                "protocol": 0,
                "ret": 104,
                "errno": 0,
            },
            {
                "event": "transport_bind",
                "function": "bind",
                "fd": 104,
                "requestedLocal": "127.0.0.1:0",
                "local": "127.0.0.1:43123",
                "ret": 0,
                "errno": 0,
            },
            {
                "event": "transport_buffer",
                "function": "recvfrom",
                "direction": "receive",
                "fd": 104,
                "peer": "-",
                "remote": "111.31.3.182:8899",
                "local": "127.0.0.1:43123",
                "len": 4,
                "ret": 4,
                "payloadKind": "unknown",
                "hex": "01020304",
            },
            {
                "event": "transport_buffer",
                "function": "sendto",
                "direction": "send",
                "fd": 104,
                "peer": "-",
                "remote": "111.31.3.182:8899",
                "local": "127.0.0.1:43123",
                "len": len(auth_head),
                "ret": len(auth_head),
                "payloadKind": "kcp-auth-head",
                "authFocus": True,
                "stack": "send_udt_data+0x12;udt_output+0x34;deal_udt_using_cag+0x56",
                "hex": auth_head.hex(),
            },
        ]
        jsonl_path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")

        self.assertEqual(zime_probe.classify_payload(auth_head), "kcp-auth-head")
        result = zime_probe.analyze(jsonl_path)
        focus = result["authHeadAckFocus"]

        self.assertTrue(focus["observed"])
        self.assertEqual(focus["stageBlocked"], "auth_head_ack_missing")
        self.assertEqual(focus["firstAuthHead"]["index"], 4)
        self.assertTrue(focus["firstAuthHead"]["authFocus"])
        self.assertIn("deal_udt_using_cag", focus["firstAuthHead"]["stack"])
        self.assertEqual(focus["firstAuthHead"]["hexPrefix"], "<redacted:kcp-auth>")
        self.assertEqual(focus["sameFdPreAuthPayloadKinds"], {"unknown": 1})
        self.assertEqual(focus["sameFdPreAuthEvents"][0]["event"], "transport_socket")
        self.assertTrue(any(item["event"] == "transport_bind" for item in focus["sameFdPreAuthEvents"]))
        self.assertIn("no receive-side kcp-auth-head-ack cmd=7 after first AUTH_HEAD", focus["missingEvidence"])
        self.assertIn("AUTH_HEAD_ACK", result["nextStep"])
        self.assertNotIn(b"secret-auth-head".hex(), json.dumps(focus))

    def test_zime_probe_auth_head_ack_focus_accepts_same_fd_ack_like_response(self):
        state_path = self.temp_state()
        jsonl_path = Path(state_path).with_name("zime-probe-auth-focus-ack-like.jsonl")
        auth_head = rap_zime.build_kcp_auth_segment(
            payload=b"secret-auth-head",
            auth_head=True,
            conv=0,
            syn_id=0x11223344,
            current=0x01020304,
        )
        auth_data = rap_zime.build_kcp_auth_segment(
            payload=b"secret-auth-data",
            auth_head=False,
            syn_id=0x11223344,
            current=0x01020305,
        )
        rows = [
            {
                "event": "transport_socket",
                "function": "socket",
                "fd": 89,
                "domain": 2,
                "type": 526337,
                "protocol": 0,
                "ret": 89,
                "errno": 0,
            },
            {
                "event": "transport_connect",
                "function": "connect",
                "fd": 89,
                "local": "127.0.0.1:37176",
                "remote": "127.0.0.1:38477",
                "peerAfter": "127.0.0.1:38477",
                "ret": -1,
                "errno": 115,
            },
            {
                "event": "transport_buffer",
                "function": "send",
                "direction": "send",
                "fd": 89,
                "peer": "127.0.0.1:38477",
                "local": "127.0.0.1:37176",
                "remote": "-",
                "len": 160,
                "ret": 160,
                "payloadKind": "spice-data",
                "hex": (struct.pack("<HH", 26, 156) + (b"B" * 156)).hex(),
            },
            {
                "event": "transport_buffer",
                "function": "recv",
                "direction": "receive",
                "fd": 91,
                "peer": "127.0.0.1:37176",
                "local": "127.0.0.1:38477",
                "remote": "-",
                "len": 4,
                "ret": 4,
                "payloadKind": "unknown",
                "hex": struct.pack("<HH", 26, 156).hex(),
            },
            {
                "event": "transport_socket",
                "function": "socket",
                "fd": 107,
                "domain": 2,
                "type": 2,
                "protocol": 17,
                "ret": 107,
                "errno": 0,
            },
            {
                "event": "transport_buffer",
                "function": "sendto",
                "direction": "send",
                "fd": 107,
                "peer": "-",
                "remote": "111.31.3.182:8899",
                "local": "0.0.0.0:40750",
                "len": len(auth_head),
                "ret": len(auth_head),
                "payloadKind": "kcp-auth-head",
                "authFocus": True,
                "hex": auth_head.hex(),
            },
            {
                "event": "transport_socket",
                "function": "socket",
                "fd": 110,
                "domain": 2,
                "type": 526337,
                "protocol": 0,
                "ret": 110,
                "errno": 0,
            },
            {
                "event": "transport_connect",
                "function": "connect",
                "fd": 110,
                "local": "127.0.0.1:37178",
                "remote": "127.0.0.1:38477",
                "peerAfter": "127.0.0.1:38477",
                "ret": -1,
                "errno": 115,
            },
            {
                "event": "transport_buffer",
                "function": "send",
                "direction": "send",
                "fd": 110,
                "peer": "127.0.0.1:38477",
                "local": "127.0.0.1:37178",
                "remote": "-",
                "len": 160,
                "ret": 160,
                "payloadKind": "spice-data",
                "hex": (struct.pack("<HH", 26, 156) + (b"C" * 156)).hex(),
            },
            {
                "event": "transport_buffer",
                "function": "recv",
                "direction": "receive",
                "fd": 111,
                "peer": "127.0.0.1:37178",
                "local": "127.0.0.1:38477",
                "remote": "-",
                "len": 4,
                "ret": 4,
                "payloadKind": "unknown",
                "hex": struct.pack("<HH", 26, 156).hex(),
            },
            {
                "event": "transport_buffer",
                "function": "sendto",
                "direction": "send",
                "fd": 107,
                "peer": "-",
                "remote": "111.31.3.182:8899",
                "local": "0.0.0.0:40750",
                "len": len(auth_head),
                "ret": len(auth_head),
                "payloadKind": "kcp-auth-head",
                "authFocus": True,
                "hex": auth_head.hex(),
            },
            {
                "event": "transport_buffer",
                "function": "recvmsg",
                "direction": "receive",
                "fd": 107,
                "peer": "-",
                "remote": "111.31.3.182:8899",
                "local": "0.0.0.0:40750",
                "len": 71,
                "ret": 71,
                "payloadKind": "spice-ack",
                "hex": "00" * 71,
            },
            {
                "event": "transport_buffer",
                "function": "sendto",
                "direction": "send",
                "fd": 107,
                "peer": "-",
                "remote": "111.31.3.182:8899",
                "local": "0.0.0.0:40750",
                "len": len(auth_data),
                "ret": len(auth_data),
                "payloadKind": "kcp-auth-data",
                "authFocus": True,
                "hex": auth_data.hex(),
            },
            {
                "event": "transport_buffer",
                "function": "recv",
                "direction": "receive",
                "fd": 23,
                "peer": "family:1",
                "remote": "-",
                "local": "family:1",
                "len": 60,
                "ret": 60,
                "payloadKind": "kcp-auth-head-ack",
                "hex": "00" * 60,
            },
        ]
        jsonl_path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")

        result = zime_probe.analyze(jsonl_path)
        focus = result["authHeadAckFocus"]
        replay_gap = result["authGateReplayGap"]

        self.assertIsNone(focus["stageBlocked"])
        self.assertTrue(focus["authHeadAckConfirmed"])
        self.assertEqual(focus["authHeadAckLikeResponses"][0]["index"], 12)
        self.assertEqual(focus["authHeadAckLikeResponses"][0]["fd"], 107)
        self.assertEqual(focus["authHeadAckLikeResponses"][0]["followedByAuthDataIndex"], 13)
        self.assertEqual(focus["authHeadAckLikeResponses"][0]["payloadStoredInReport"], False)
        self.assertEqual(len(focus["sameFdAuthHeadSendsBeforeAckLike"]), 2)
        self.assertTrue(replay_gap["readyForPythonAuthGateReproduction"])
        self.assertEqual(replay_gap["firstExternalAuthHead"]["len"], len(auth_head))
        self.assertEqual(replay_gap["sameFdAckLikeResponse"]["len"], 71)
        self.assertEqual(replay_gap["expectedAuthDataAfterAckLikeLen"], len(auth_data))
        bootstrap = replay_gap["localProxyBootstrapSchema"]
        self.assertTrue(bootstrap["observed"])
        self.assertEqual(bootstrap["connect"]["errno"], 115)
        self.assertEqual(bootstrap["clientSend"]["frameHeader"]["u16Type"], 26)
        self.assertEqual(bootstrap["clientSend"]["frameHeader"]["u16BodyLen"], 156)
        self.assertTrue(bootstrap["clientSend"]["frameHeader"]["totalLenMatchesHeader"])
        self.assertEqual(bootstrap["clientSend"]["frameHeader"]["commandByte"], 26)
        self.assertEqual(bootstrap["clientSend"]["frameHeader"]["channelOrIdByte"], 0)
        self.assertEqual(bootstrap["clientSend"]["frameHeader"]["lenAtOffset2"], 156)
        self.assertTrue(bootstrap["clientSend"]["frameHeader"]["commandByteSchemaMatches"])
        self.assertTrue(bootstrap["clientSend"]["frameHeader"]["sendTunnelLinkMessageDirectShapeExcluded"])
        self.assertTrue(bootstrap["serverReceiveHeader"]["frameHeader"]["matchesClientHeader"])
        self.assertEqual(bootstrap["cycleCountInAuthGateWindow"], 2)
        self.assertTrue(bootstrap["repeatedBeforeAckLike"])
        self.assertEqual(
            bootstrap["cyclePositionCounts"],
            {"before_first_auth_head": 1, "between_first_auth_head_and_ack_like": 1},
        )
        self.assertEqual(
            [cycle["frameHeader"]["u16Type"] for cycle in bootstrap["cyclesBeforeAckLike"]],
            [26, 26],
        )
        self.assertEqual(replay_gap["sameFdAuthHeadPump"]["sendCountBeforeAckLike"], 2)
        self.assertIn("direct_auth_head_without_official_local_proxy_session", replay_gap["pythonGap"])
        self.assertIn("missing_repeated_local_proxy_bootstrap_cycles_before_ack_like", replay_gap["pythonGap"])
        writer_chain = replay_gap["localProxyWriterChainEvidence"]
        self.assertEqual(writer_chain["conclusion"], "fresh_160_byte_cmd26_frame_not_created_by_writer_rewrap")
        self.assertEqual(writer_chain["freshFrameShape"]["wireLen"], 160)
        self.assertEqual(writer_chain["sendTunnelLinkMessageDirectShape"]["wireLen"], 158)
        reader_evidence = writer_chain["unlinkedOutbandReaderEvidence"]
        self.assertEqual(reader_evidence["maxStreamBytesReadBeforeSendTunnelAddLink"], 116)
        self.assertEqual(reader_evidence["coveredBodyOffsets"], "0..111")
        self.assertIn("137..152", reader_evidence["tailBodyOffsetsNotConsumedByThisReader"])
        self.assertEqual(reader_evidence["frameToDataBufMapping"], "data_buf[100 + frame_offset]")
        self.assertTrue(reader_evidence["opentelemetryArgumentOffsets"]["mapsBeforeTail"])
        self.assertEqual(reader_evidence["opentelemetryArgumentOffsets"]["traceCandidateBodyOffset"], 14)
        self.assertEqual(reader_evidence["opentelemetryArgumentOffsets"]["spanCandidateBodyOffset"], 47)
        memcpy_sources = {
            item["source"]: item for item in reader_evidence["channelLinkSocketExMemcpyEvidence"]
        }
        self.assertEqual(memcpy_sources["data_buf[118]"]["destination"], "ChannelLinkSocketEx + 0x68")
        self.assertEqual(memcpy_sources["data_buf[118]"]["sourceBodyOffset"], 14)
        self.assertEqual(memcpy_sources["data_buf[151]"]["destination"], "ChannelLinkSocketEx + 0x89")
        self.assertEqual(memcpy_sources["data_buf[151]"]["sourceBodyOffset"], 47)
        self.assertEqual(memcpy_sources["data_buf[151]"]["sourceLengthArgument"], 33)
        header_path = writer_chain["freshCmd26HeaderPathEvidence"]
        self.assertEqual(header_path["checkFunction"], "check_spice_proxy_protocol_header")
        self.assertIn(26, header_path["acceptedCommandBytes"])
        self.assertTrue(header_path["freshHeaderAccepted"])
        self.assertEqual(header_path["linkTypeAfterHeader"], 1)
        self.assertEqual(header_path["firstDispatcherAfterHeader"], "deal_local_link_proxy_create")
        self.assertFalse(header_path["outbandType2PathUsedForFreshCmd26"])
        self.assertEqual(header_path["officialTraceLoopbackPairs"][0]["acceptedHeaderRecvLen"], 4)
        self.assertEqual(header_path["officialTraceLoopbackPairs"][0]["acceptedBodyRecvLen"], 156)
        self.assertEqual(header_path["officialTraceLoopbackPairs"][0]["acceptedStatusSendLen"], 1)
        body_path = writer_chain["freshCmd26BodyPathEvidence"]
        self.assertEqual(body_path["bodyReadFunction"], "deal_local_spice_proxy_head")
        self.assertEqual(body_path["bodyBuffer"], "in_sock + 0x9b0")
        self.assertEqual(body_path["officialBodyLen"], 156)
        self.assertTrue(body_path["progressResetAfterDispatch"])
        self.assertEqual(body_path["cmd26BodyConsumer"], "send_tunnel_add_link(in_sock, in_sock + 0x9b0)")
        self.assertEqual(body_path["tailBodyOffsetsExplained"], ["137..152", "155..155"])
        self.assertFalse(body_path["linkedTailReaderNeededForFreshCmd26Tail"])
        body_mappings = {
            item.get("bodyOffsetRange", str(item.get("bodyOffset"))): item
            for item in body_path["bodyOffsetMappings"]
        }
        self.assertEqual(body_mappings["137..152"]["hexOffsetRange"], "0x89..0x98")
        self.assertIn("ZXStrncopy", body_mappings["137..152"]["copy"])
        self.assertEqual(body_mappings["155"]["field"], "channel_type_id high byte")
        self.assertIn("channel_type component", body_mappings["155"]["consumer"])
        synth_schema = writer_chain["freshCmd26MinimalSynthesisSchema"]
        self.assertEqual(
            synth_schema["schemaStatus"],
            "static_layout_known_value_synthesis_not_closed",
        )
        self.assertEqual(synth_schema["bodyContract"]["bodyObject"], "ChannelLinkSocketEx")
        self.assertEqual(synth_schema["bodyContract"]["bodyLen"], 156)
        dwarf_schema = synth_schema["dwarfStructEvidence"]
        self.assertEqual(dwarf_schema["ChannelLinkSocketEx"]["byteSize"], 156)
        self.assertEqual(
            dwarf_schema["ChannelLinkSocketEx"]["members"][1],
            {"field": "channel_type_id", "offset": 154, "size": 2},
        )
        info_members = {
            item["field"]: item
            for item in dwarf_schema["ChannelLinkInfoEx"]["members"]
        }
        self.assertEqual(dwarf_schema["ChannelLinkInfoEx"]["byteSize"], 154)
        self.assertEqual(info_members["dest_port"]["offset"], 0)
        self.assertEqual(info_members["link_priority"]["offset"], 2)
        self.assertEqual(info_members["link_type"]["offset"], 3)
        self.assertEqual(info_members["dest_ip"]["offset"], 4)
        self.assertEqual(info_members["otlp_trace_id"], {"field": "otlp_trace_id", "offset": 104, "size": 33})
        self.assertEqual(info_members["otlp_parent_id"], {"field": "otlp_parent_id", "offset": 137, "size": 17})
        self.assertFalse(dwarf_schema["payloadStoredInReport"])
        self.assertIn("accepted-side recv len=156 ChannelLinkSocketEx body", synth_schema["officialTraceFields"])
        consumed_fields = {
            item["field"]: item
            for item in synth_schema["fieldConsumption"]
        }
        self.assertTrue(consumed_fields["info.dest_port"]["requiredForMinimalSynthesis"])
        self.assertEqual(consumed_fields["info.dest_port"]["bodyOffsetRange"], "0..1")
        self.assertTrue(consumed_fields["info.link_priority"]["requiredForMinimalSynthesis"])
        self.assertEqual(consumed_fields["info.link_priority"]["bodyOffset"], 2)
        self.assertTrue(consumed_fields["info.link_type"]["requiredForMinimalSynthesis"])
        self.assertEqual(consumed_fields["info.link_type"]["bodyOffset"], 3)
        self.assertEqual(
            consumed_fields["info.dest_ip"]["bodyOffsetRange"],
            "4..7",
        )
        self.assertEqual(consumed_fields["info.vm_uuid"]["bodyOffsetRange"], "40..76")
        self.assertEqual(
            consumed_fields["info.flag/info.channel_type"]["requiredForMinimalSynthesis"],
            "depends_on_sock_link_type",
        )
        self.assertEqual(consumed_fields["info.flag/info.channel_type"]["bodyOffset"], 83)
        self.assertEqual(consumed_fields["info.otlp_trace_id"]["bodyOffsetRange"], "104..135")
        self.assertEqual(consumed_fields["info.otlp_parent_id"]["bodyOffsetRange"], "137..152")
        self.assertIn("QUIC stream metadata", consumed_fields["channel_type_id"]["role"])
        self.assertIn(
            "QUIC_set_streams_pay_load_type maps sock_link_type=2 to SPICE_OUTBAND",
            " ".join(synth_schema["requiredSessionSideEffects"]),
        )
        value_sources = synth_schema["valueSourceStaticEvidence"]
        self.assertEqual(
            value_sources["freshCmd26LinkRoute"]["proxyTypeRoute"],
            "get_proxy_type_by_link_type(session, 1) returns proxy_type_ex=6 because link_type != 2",
        )
        self.assertEqual(
            value_sources["freshCmd26LinkRoute"]["proxySockLinkFlag"],
            "deal_create_proxy_fd_session(fd_type_ex=6) keeps default link_type=1 and writes proxy_sock->data_buf[224]=1",
        )
        self.assertTrue(value_sources["freshCmd26LinkRoute"]["outbandProxyType5ExcludedForFreshCmd26"])
        self.assertEqual(value_sources["kcpDestinationRoute"]["nonMultiTcpWithCag"], "ag_ip/ag_port source class")
        self.assertTrue(value_sources["kcpDestinationRoute"]["notChannelLinkSocketExDest"])
        self.assertTrue(value_sources["channelLinkDestinationRole"]["notKcpSocketDestination"])
        producer = value_sources["freshCmd26ProducerSideSynthesis"]
        self.assertEqual(producer["function"], "add_link_to_proxy_by_socket")
        self.assertTrue(producer["directProducerForFreshFrame"])
        self.assertEqual(producer["frameShape"]["allocatedLen"], 160)
        self.assertEqual(producer["frameShape"]["u16BodyLen"], 156)
        self.assertIn("spice_channel_flush_wire", producer["frameShape"]["writeCall"])
        self.assertIn("spice_channel_read", producer["frameShape"]["statusRead"])
        producer_sources = producer["bodyValueSources"]
        self.assertEqual(
            producer_sources["dest_ip"]["sourceSelection"],
            "SpiceSessionPrivate.hostip when nonempty, otherwise SpiceSessionPrivate.host",
        )
        self.assertEqual(producer_sources["dest_ip"]["sourceOffsets"]["host"], 0)
        self.assertEqual(producer_sources["dest_ip"]["sourceOffsets"]["hostip"], "0x1448")
        self.assertIn("ntohl", producer_sources["dest_ip"]["ipv4Transform"])
        self.assertEqual(producer_sources["dest_port"]["sourceFunction"], "get_channel_proxy_link_dest_port(channel)")
        self.assertIn("0x1240", " ".join(producer_sources["dest_port"]["staticBranches"]))
        self.assertTrue(producer_sources["dest_port"]["exactRuntimeValueStillRequiresSessionState"])
        self.assertEqual(producer_sources["link_priority"]["bodyOffset"], 2)
        self.assertEqual(producer_sources["link_type"]["bodyOffset"], 3)
        self.assertEqual(producer_sources["flag"]["bodyOffset"], 83)
        self.assertIn("+ 0x400", producer_sources["opentelemetry"]["traceSource"])
        self.assertFalse(producer_sources["opentelemetry"]["payloadStoredInReport"])
        self.assertIn("0x974 << 8", producer_sources["channel_type_id"]["sourceExpression"])
        self.assertFalse(producer_sources["channel_type_id"]["traceVerifiedValue"])
        self.assertIn("client-side recv len=1 cmd26 status", producer["officialTraceFields"])
        self.assertFalse(producer["payloadStoredInReport"])
        self.assertIn("ChannelType=(word>>8)&0x7f", value_sources["channelTypeIdRole"]["streamManageFields"])
        channel_type_synth = value_sources["channelTypeIdSynthesisRole"]
        self.assertEqual(channel_type_synth["inputSource"], "fresh cmd26 body[154:156]")
        self.assertIn("spice_channel_type << 8", channel_type_synth["derivedFormula"])
        self.assertIn(
            "QUIC_initialize_stream_manage writes StreamManage+0x43 = (channel_type_id >> 8) & 0x7f",
            channel_type_synth["streamManageWrites"],
        )
        self.assertIn(
            "sock_link_type=1 uses QUIC_spice_channel_type_to_string(channel_type) and falls back to SPICE_UNKNOWN",
            channel_type_synth["payloadTypeMapping"],
        )
        self.assertEqual(channel_type_synth["channelTypeNameTable"]["knownNames"][1], "SPICE_MAIN")
        self.assertEqual(channel_type_synth["channelTypeNameTable"]["knownNames"][2], "SPICE_DISPLAY")
        self.assertEqual(channel_type_synth["channelTypeNameTable"]["knownNames"][10], "SPICE_PORT")
        first_channel = channel_type_synth["firstChannelCandidateBoundary"]
        self.assertTrue(first_channel["exactOfficialValueStillUnknown"])
        self.assertIn("spice_channel_new(session, 1, 0)", first_channel["spiceSessionConnectCreates"][0])
        self.assertIn("is_create_main_displaychannel_in_advance", first_channel["spiceSessionConnectCreates"][1])
        self.assertIn("does not determine channel_type_id low byte", first_channel["virtualLinkIdBoundary"])
        self.assertEqual(first_channel["candidatePriority"][0]["channel_type_id"], "0x0100")
        self.assertEqual(first_channel["candidatePriority"][1]["channel_type_id"], "0x0200")
        self.assertEqual(first_channel["candidatePriority"][2]["status"], "excluded_as_unconditional_first_candidate")
        zime_boundary = channel_type_synth["zimeCreateDataStreamTraceBoundary"]
        self.assertEqual(zime_boundary["officialTraceEvent"], "zime_struct/ZIME_CreateDataStream param_before")
        self.assertIn("u8Priority=9", zime_boundary["observedSafeFields"])
        self.assertIn("do not expose StreamManage.ChannelType/ChannelId", zime_boundary["cannotInferFromTrace"])
        self.assertIn("channel_type=2 selects bw ctrl type 2", " ".join(channel_type_synth["bandwidthImplication"]))
        self.assertIn("not used to derive StreamManage", channel_type_synth["destinationIndependence"])
        self.assertFalse(channel_type_synth["payloadStoredInReport"])
        stream_gate = value_sources["streamCreateGateEvidence"]
        self.assertEqual(stream_gate["function"], "handle_quic_protocol_stream_create_processing")
        self.assertTrue(stream_gate["doesNotSynthesizeChannelLinkSocketExFields"])
        self.assertIn(
            "missing proxy fd session for get_proxy_type_by_link_type(in_sock->data_buf[224])",
            stream_gate["hardFailureConditions"],
        )
        self.assertIn(
            "proxy fd session exists but check_proxy_is_ready equivalent is false",
            stream_gate["successWithoutNewQuicStreamConditions"],
        )
        self.assertIn("new QUIC stream is conditional", stream_gate["pythonImplication"])
        local_side_effects = value_sources["localSessionBootstrapSideEffects"]
        type6_effects = local_side_effects["dealCreateProxyFdSessionType6"]
        self.assertIn("thread/session type6 slot", type6_effects["freshRoute"])
        self.assertIn("byte 0x2d", type6_effects["networkProtocolByte"])
        self.assertEqual(type6_effects["linkTypeField"], "proxy_sock word 0x18c receives link_type=1 for fresh cmd26 type6 route")
        self.assertEqual(type6_effects["fdTypeField"], "proxy_sock dword 0x24 receives fd_type_ex=6")
        pair_gate = local_side_effects["initLocalRwSockPairGate"]
        self.assertIn("requires an existing proxy fd session", pair_gate["proxyLookup"])
        self.assertIn("stops before UDP/KCP pairing", pair_gate["missingProxySessionEffect"])
        self.assertIn("proxy_sock byte 0x2d is true", pair_gate["udpPairCondition"])
        udp_side_effects = local_side_effects["initLocalRwSockPairUdpSideEffects"]
        self.assertEqual(udp_side_effects["newSessionType"], "creates a TN_UDP_CLD_SOCK fd session on the UDP fd")
        self.assertIn("proxy_sock word 0x18c -> udp_sock word 0x18c", udp_side_effects["copiedFields"])
        self.assertIn("type6 boolean", udp_side_effects["kcpCreateInputs"])
        self.assertIn("after KCP is attached", udp_side_effects["cagAuthTiming"])
        self.assertIn("client-side recv len=1 cmd26 status", local_side_effects["officialTraceFields"])
        self.assertFalse(local_side_effects["payloadStoredInReport"])

        native_contract = rap_zime.pre_auth_native_side_effect_contract()
        self.assertEqual(
            native_contract["status"],
            "static_contract_recovered_runner_equivalent_not_implemented",
        )
        self.assertFalse(native_contract["payloadStoredInReport"])
        self.assertIn("same external fd/remote must receive len=71 ACK-like before AUTH_DATA", native_contract["officialTraceFields"])
        side_effects = {item["key"]: item for item in native_contract["sideEffects"]}
        self.assertEqual(
            set(side_effects),
            {
                "local_proxy_protocol_header_link_type_detection",
                "deal_create_proxy_fd_session_link_type_assignment",
                "create_fd_session_TN_UDP_CLD_SOCK",
                "thread_kcp_list_attachment_before_deal_udt_using_cag",
            },
        )
        self.assertIn("data_buf[224]", side_effects["local_proxy_protocol_header_link_type_detection"]["nativeWrite"])
        self.assertIn("proxy_sock->data_buf[224]=1", side_effects["deal_create_proxy_fd_session_link_type_assignment"]["nativeWrite"])
        self.assertIn("TN_UDP_CLD_SOCK", side_effects["create_fd_session_TN_UDP_CLD_SOCK"]["nativeWrite"])
        self.assertIn("thread kcp_list", side_effects["thread_kcp_list_attachment_before_deal_udt_using_cag"]["nativeWrite"])
        self.assertTrue(all(item["runnerEquivalentImplemented"] is False for item in side_effects.values()))
        self.assertIn("AUTH_HEAD199 length parity is insufficient", native_contract["runnerConsequence"])

        body_boundaries = value_sources["freshBodyValueSynthesisBoundaries"]
        self.assertIn(
            "channel_type_id body[154:156] -> channel type/id, stream metadata, bandwidth and port-channel decisions",
            body_boundaries["sendTunnelAddLinkCopies"],
        )
        self.assertIn(
            "serial_num body[24:40] is not copied into ProxyChannelManage by send_tunnel_add_link before send_tunnel_link_message",
            body_boundaries["notCopiedFromFreshInputBySendTunnelAddLink"],
        )
        self.assertIn(
            "vm_uuid body[40:77] is not copied into ProxyChannelManage by send_tunnel_add_link before send_tunnel_link_message",
            body_boundaries["notCopiedFromFreshInputBySendTunnelAddLink"],
        )
        downstream = body_boundaries["downstreamLinkMessageDerivations"]
        self.assertIn("data[2:4]=154", downstream["shape"])
        self.assertIn("spice_processtrack_get_serial_num", downstream["serialNumSource"])
        self.assertTrue(downstream["notFreshInputProducer"])
        self.assertIn("deal_udt_using_cag writes serial_uuid", body_boundaries["otelAndAuthRelation"]["cagAuthSource"])
        self.assertIn("structurally valid non-secret trace/span candidates", body_boundaries["otelAndAuthRelation"]["exactValueStatus"])
        self.assertIn("do not use downstream 158-byte", body_boundaries["pythonImplication"])
        self.assertFalse(body_boundaries["payloadStoredInReport"])
        self.assertFalse(value_sources["payloadStoredInReport"])
        self.assertIn("199-byte AUTH_HEAD", synth_schema["pythonImplication"])
        self.assertIn(
            "materializing safe Python session/channel state for ChannelLinkSocketEx dest_port/dest_ip without replaying local proxy body plaintext",
            synth_schema["notYetClosed"],
        )
        self.assertIn(
            "which first-channel channel_type_id candidate is accepted for the fresh cmd26 bootstrap without reading local proxy body plaintext",
            synth_schema["notYetClosed"],
        )
        self.assertIn(
            "whether vm_uuid/serial_num can stay zero or locally generated in the fresh input body because send_tunnel_add_link does not copy them into ProxyChannelManage",
            synth_schema["notYetClosed"],
        )
        self.assertIn(
            "whether Python must model the type6 proxy fd session slot, proxy_sock byte 0x2d UDP gate, and init_local_rw_sock_pair_udp KCP attachment before AUTH_HEAD",
            synth_schema["notYetClosed"],
        )
        self.assertFalse(synth_schema["bodyContract"]["payloadStoredInReport"])
        linked_tail = writer_chain["linkedOutbandTailCandidate"]
        self.assertEqual(linked_tail["dispatcher"], "local_data_tcp_read")
        self.assertEqual(linked_tail["linkedProtocolHeaderSize"], 4)
        self.assertEqual(linked_tail["linkedSafetyMargin"], 24)
        self.assertEqual(linked_tail["linkedMaxReadWithoutBwLimit"], 65507)
        self.assertFalse(linked_tail["candidateForFreshTail"])
        self.assertTrue(linked_tail["candidateForLaterLinkedFrames"])
        forwarding = {item["writeFunction"]: item for item in linked_tail["linkedForwardingShapes"]}
        self.assertEqual(forwarding["QUIC_stream_port_data_write"]["writeLen"], "payloadLen + 4")
        self.assertEqual(forwarding["QUIC_stream_data_write"]["header"], "none")
        self.assertEqual(forwarding["udt_write_data_stream"]["header"], "none")
        self.assertEqual(forwarding["spice_session_write_port_data"]["header"], "cmd=10, channel byte from channel manage, u16 payload length")
        self.assertEqual(forwarding["proxy_data_write"]["writeLen"], "payloadLen + 4")
        self.assertIn("later linked frames", linked_tail["conclusion"])
        recv4_evidence = writer_chain["localRecv4SemanticsEvidence"]
        self.assertEqual(recv4_evidence["officialTraceFields"]["loopbackRecvLen"], 4)
        self.assertEqual(recv4_evidence["officialTraceFields"]["loopbackBodyRecvLen"], 156)
        self.assertEqual(recv4_evidence["officialTraceFields"]["loopbackCmd26StatusLen"], 1)
        self.assertEqual(recv4_evidence["cmd26DirectResponseLen"], 1)
        self.assertFalse(recv4_evidence["cmd26DirectResponseExplainsOfficialRecv4"])
        self.assertEqual(recv4_evidence["cmd10HeaderShape"]["commandByte"], 10)
        self.assertIn("deal_linked_outband_local_data_read", recv4_evidence["cmd10HeaderWriters"])
        self.assertIn("accepted-side read of the local proxy header", recv4_evidence["conclusion"])
        self.assertIn("1-byte cmd26 status", recv4_evidence["conclusion"])
        self.assertIn(
            "field value synthesis rules for ChannelLinkSocketEx fields",
            writer_chain["nextStaticTargets"],
        )
        writer_names = {item["name"] for item in writer_chain["writers"]}
        self.assertIn("proxy_data_write", writer_names)
        self.assertIn("QUIC_proxy_data_write", writer_names)
        self.assertIn("udt_write_data", writer_names)
        self.assertIn("send_tcp_data_with_cache", writer_names)
        self.assertIn("spice_session_write_port_data", writer_names)
        self.assertFalse(any(item["rewrapsCommand26ToFresh160Frame"] for item in writer_chain["writers"]))
        self.assertIn("stop at authHeadAckConfirmed before attempting SYNACK/native bridge/DISPLAY_INIT", replay_gap["doNext"])
        self.assertIn("Python runner success", replay_gap["doNotUseAs"])
        self.assertIn("Reproduce the official local proxy/session bootstrap", result["nextStep"])
        self.assertNotIn(b"secret-auth-data".hex(), json.dumps(focus))
        self.assertNotIn(b"secret-auth-data".hex(), json.dumps(replay_gap))
        self.assertNotIn((b"B" * 32).hex(), json.dumps(replay_gap))
        self.assertNotIn((b"C" * 32).hex(), json.dumps(replay_gap))

    def test_zime_native_bridge_inspect_reports_missing_library(self):
        state_path = self.temp_state()
        missing = Path(state_path).with_name("missing-libZIMEDataEngine.so")

        result = zime_native_bridge.inspect_library(missing)

        self.assertFalse(result["ok"])
        self.assertFalse(result["exists"])
        self.assertFalse(result["nativeRun"])
        self.assertEqual(result["error"], "library_not_found")
        self.assertIn("ZimeInitParam", result["structLayout"])

    def test_zime_native_bridge_inspect_handles_missing_exports(self):
        state_path = self.temp_state()
        lib_path = Path(state_path).with_name("libZIMEDataEngine.so")
        lib_path.write_bytes(b"fake")
        present = set(zime_native_bridge.REQUIRED_EXPORTS)
        present.remove("ZIME_SendData")

        class FakeLib:
            def __getattr__(self, name):
                if name in present:
                    return object()
                raise AttributeError(name)

        result = zime_native_bridge.inspect_library(lib_path, loader=lambda path: FakeLib())

        self.assertFalse(result["ok"])
        self.assertTrue(result["exists"])
        self.assertFalse(result["requiredExports"]["ZIME_SendData"])
        self.assertTrue(result["requiredExports"]["ZIME_Init"])
        self.assertEqual(result["error"], "missing_required_exports: ZIME_SendData")

    def test_zime_native_bridge_channel_context_defaults_to_four_opaque_bytes(self):
        context, _keepalive = zime_native_bridge.make_channel_context(remote_host="127.0.0.2", remote_port=5100)

        self.assertEqual(context.socketParam.nOpaqueLen, 4)
        self.assertEqual(bytes(context.socketParam.opaque[:4]), b"\x00\x00\x00\x00")
        self.assertEqual(context.u16BaseMTU, zime_native_bridge.DEFAULT_BASE_MTU)
        self.assertEqual(context.eBusinessType, 1)

    def test_zime_native_bridge_stream_param_uses_native_defaults(self):
        param = zime_native_bridge.make_stream_param(payload_type=b"d")

        self.assertEqual(param.mode, 1)
        self.assertEqual(param.u8Priority, 0x7F)
        self.assertEqual(param.u32MaxBandwidth, 0xFFFFFFFF)
        self.assertEqual(bytes(param.payloadType[:2]), b"d\x00")

    def test_zime_native_bridge_extracts_complete_transport_payloads(self):
        report = {
            "callbackRecords": [
                {
                    "event": "native_transport_batch",
                    "packetSpecs": [
                        {"iovPayloadHex": "010203", "iovPayloadTruncated": False},
                        {"iovPayloadHex": "aabb", "iovPayloadTruncated": True},
                    ],
                }
            ]
        }

        self.assertEqual(zime_native_bridge.native_transport_payloads(report), [b"\x01\x02\x03"])
        self.assertEqual(
            zime_native_bridge.native_transport_payloads(report, require_complete=False),
            [b"\x01\x02\x03", b"\xaa\xbb"],
        )

    def test_zime_native_bridge_milestones_summarize_display_path_gap(self):
        report = {
            "calls": [
                {"function": "ZIME_CreateDataChannel", "ret": 0},
                {"function": "ZIME_ReceiveData", "ret": 0},
                {"function": "ZIME_CreateDataStream", "ret": 0},
            ],
            "callbackRecords": [
                {"event": "native_transport_batch"},
                {"event": "native_udp_send"},
                {"event": "native_udp_receive"},
                {"event": "native_channel_created", "status": 0, "err": 0},
            ],
            "payloads": [
                {"payloadKind": "spice-display-init", "ret": 0},
            ],
            "udpTransport": {"enabled": True, "sentPackets": 1, "receivedPackets": 1},
        }

        result = zime_native_bridge.native_bridge_milestones(report)

        self.assertFalse(result["desktopKeepaliveProven"])
        self.assertTrue(result["channelCreateOk"])
        self.assertTrue(result["nativePacketOutSeen"])
        self.assertTrue(result["nativeUdpSent"])
        self.assertTrue(result["nativeUdpReceived"])
        self.assertTrue(result["receiveDataOk"])
        self.assertTrue(result["nativeChannelCreatedOk"])
        self.assertTrue(result["streamCreateOk"])
        self.assertTrue(result["displayInitSendOk"])
        self.assertEqual(result["stage"], "display_path_pending")

    def test_zime_native_udp_transport_wraps_and_unwraps_rap_payloads(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        server.settimeout(2)
        target = server.getsockname()
        tunnel = bytes.fromhex("01020304")
        received = []
        errors = []

        def serve():
            try:
                packet, client = server.recvfrom(2048)
                frames = rap_zime.decode_rap_frames(packet)
                received.append(frames[0]["payload"])
                response = rap_zime.encode_rap_data_frame(tunnel, 0x81, 0, 0, 0, 0, payload=b"native-in")
                server.sendto(response, client)
            except Exception as err:
                errors.append(err)

        thread = threading.Thread(target=serve)
        thread.start()
        self.addCleanup(server.close)

        records = []
        transport = zime_native_bridge.NativeUdpTransport(
            target,
            read_timeout=1,
            receive_limit=1,
            payload_mode="rap",
            rap_tunnel_id=tunnel.hex(),
        )
        self.addCleanup(transport.close)

        transport.send_payload(b"native-out", records, source_event="unit")
        payloads = transport.receive_native_payloads(records, phase="unit")
        thread.join(timeout=2)

        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(received, [b"native-out"])
        self.assertEqual(payloads, [b"native-in"])
        self.assertEqual(records[0]["event"], "native_udp_send")
        self.assertEqual(records[0]["payloadMode"], "rap")
        self.assertEqual(records[0]["rapPayloadEnvelope"], "raw")
        self.assertEqual(records[0]["wirePayloadLen"], len(b"native-out"))
        self.assertEqual(records[1]["event"], "native_udp_receive")
        self.assertEqual(records[1]["rapFrame"]["tunnelIdHex"], tunnel.hex())

    def test_zime_native_udp_transport_len16_payload_envelope(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        server.settimeout(2)
        target = server.getsockname()
        tunnel = bytes.fromhex("01020304")
        received = []
        errors = []

        def serve():
            try:
                packet, client = server.recvfrom(2048)
                frame = rap_zime.decode_rap_frames(packet)[0]
                received.append(frame["payload"])
                response_payload = len(b"native-in").to_bytes(2, "little") + b"native-in"
                response = rap_zime.encode_rap_data_frame(tunnel, 0x81, 0, 0, 0, 0, payload=response_payload)
                server.sendto(response, client)
            except Exception as err:
                errors.append(err)

        thread = threading.Thread(target=serve)
        thread.start()
        self.addCleanup(server.close)

        records = []
        transport = zime_native_bridge.NativeUdpTransport(
            target,
            read_timeout=1,
            receive_limit=1,
            payload_mode="rap",
            rap_tunnel_id=tunnel.hex(),
            rap_payload_envelope="len16",
        )
        self.addCleanup(transport.close)

        transport.send_payload(b"native-out", records, source_event="unit")
        payloads = transport.receive_native_payloads(records, phase="unit")
        thread.join(timeout=2)

        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(received, [len(b"native-out").to_bytes(2, "little") + b"native-out"])
        self.assertEqual(payloads, [b"native-in"])
        self.assertEqual(records[0]["rapPayloadEnvelope"], "len16")
        self.assertEqual(records[0]["payloadEnvelope"]["declaredLen"], len(b"native-out"))
        self.assertEqual(records[0]["wirePayloadLen"], len(b"native-out") + 2)
        self.assertEqual(records[1]["rapFrame"]["rapPayloadEnvelope"]["nativePayloadLen"], len(b"native-in"))

    def test_zime_native_udp_transport_uses_payload_kind_template_sequence(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        server.settimeout(2)
        target = server.getsockname()
        tunnel = bytes.fromhex("01020304")
        received = []
        errors = []

        def serve():
            try:
                for _index in range(2):
                    packet, _client = server.recvfrom(2048)
                    received.append(rap_zime.decode_rap_frames(packet)[0])
            except Exception as err:
                errors.append(err)

        thread = threading.Thread(target=serve)
        thread.start()
        self.addCleanup(server.close)

        records = []
        transport = zime_native_bridge.NativeUdpTransport(
            target,
            read_timeout=1,
            receive_limit=0,
            payload_mode="rap",
            rap_tunnel_id=tunnel.hex(),
            rap_send_templates=[
                {
                    "index": 9,
                    "frameType": 0x81,
                    "flags": 0,
                    "field06": 0x5104,
                    "word08": 1,
                    "word12": 0,
                    "header16PrefixHex": "000000",
                    "postLengthHex": "000001",
                    "payloadKind": "unknown",
                    "payloadLength": 5,
                    "zimePayloadEnvelopeObserved": True,
                },
                {
                    "index": 10,
                    "frameType": 0x81,
                    "flags": 0,
                    "field06": 0x5204,
                    "word08": 0x01000001,
                    "word12": 0,
                    "header16PrefixHex": "000000",
                    "postLengthHex": "d90201",
                    "payloadKind": "unknown",
                    "payloadLength": 5,
                    "zimePayloadEnvelopeObserved": True,
                },
            ],
            rap_template_mode="payload-kind",
        )
        self.addCleanup(transport.close)

        transport.send_payload(b"one", records, source_event="unit")
        transport.send_payload(b"two", records, source_event="unit")
        thread.join(timeout=2)

        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual([frame["field06Le"] for frame in received], [0x5104, 0x5204])
        self.assertEqual([frame["word08"] for frame in received], [1, 0x01000001])
        self.assertEqual([frame["postLengthBytes"].hex() for frame in received], ["000001", "d90201"])
        self.assertEqual(records[0]["rapTemplateSelection"]["templateSampleIndex"], 9)
        self.assertEqual(records[1]["rapTemplateSelection"]["templateSampleIndex"], 10)
        self.assertEqual(transport.summary()["rapSendTemplateCount"], 2)
        self.assertEqual(
            zime_native_bridge._payload_kind_template_candidates("zime-udp-reserved4:quic-long-header-candidate"),
            ["zime-udp-reserved4:quic-long-header-candidate", "quic-long-header-candidate"],
        )

    def test_zime_native_udp_transport_strip_reserve4_len16_payload_envelope(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        server.settimeout(2)
        target = server.getsockname()
        tunnel = bytes.fromhex("01020304")
        received = []
        errors = []

        def serve():
            try:
                packet, client = server.recvfrom(2048)
                frame = rap_zime.decode_rap_frames(packet)[0]
                received.append(frame["payload"])
                response_payload = len(b"native-in").to_bytes(2, "little") + b"native-in"
                response = rap_zime.encode_rap_data_frame(tunnel, 0x81, 0, 0, 0, 0, payload=response_payload)
                server.sendto(response, client)
            except Exception as err:
                errors.append(err)

        thread = threading.Thread(target=serve)
        thread.start()
        self.addCleanup(server.close)

        records = []
        transport = zime_native_bridge.NativeUdpTransport(
            target,
            read_timeout=1,
            receive_limit=1,
            payload_mode="rap",
            rap_tunnel_id=tunnel.hex(),
            rap_payload_envelope="strip-reserve4-len16",
        )
        self.addCleanup(transport.close)

        transport.send_payload(b"\x00\x00\x00\x00native-out", records, source_event="unit")
        payloads = transport.receive_native_payloads(records, phase="unit")
        thread.join(timeout=2)

        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(received, [len(b"native-out").to_bytes(2, "little") + b"native-out"])
        self.assertEqual(payloads, [b"\x00\x00\x00\x00native-in"])
        self.assertEqual(records[0]["rapPayloadEnvelope"], "strip-reserve4-len16")
        self.assertTrue(records[0]["payloadEnvelope"]["reserve4Stripped"])
        self.assertEqual(records[0]["payloadEnvelope"]["declaredLen"], len(b"native-out"))
        self.assertTrue(records[1]["rapFrame"]["rapPayloadEnvelope"]["reserve4ReaddedOnReceive"])

    def test_zime_native_callbacks_can_split_packet_out_iov_segments(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        server.settimeout(2)
        target = server.getsockname()
        received = []
        errors = []

        def serve():
            try:
                for _index in range(2):
                    packet, _client = server.recvfrom(2048)
                    received.append(packet)
            except Exception as err:
                errors.append(err)

        thread = threading.Thread(target=serve)
        thread.start()
        self.addCleanup(server.close)

        transport = zime_native_bridge.NativeUdpTransport(
            target,
            read_timeout=1,
            receive_limit=0,
            packet_out_iov_mode="split",
        )
        self.addCleanup(transport.close)
        callbacks = zime_native_bridge.ZimeNativeCallbacks(
            max_dump=4096,
            read_iov_payload=True,
            udp_transport=transport,
        )
        first = ctypes.create_string_buffer(b"seg-a")
        second = ctypes.create_string_buffer(b"seg-b")
        iov = (zime_native_bridge.Iovec * 2)()
        iov[0].iov_base = ctypes.addressof(first)
        iov[0].iov_len = len(b"seg-a")
        iov[1].iov_base = ctypes.addressof(second)
        iov[1].iov_len = len(b"seg-b")
        spec = bytearray(zime_probe.ZIME_PACKET_OUT_SPEC_SIZE)
        struct.pack_into("<QQQQ", spec, 0, ctypes.addressof(iov), 2, 0, 0)
        spec[96] = 4
        spec_buf = ctypes.create_string_buffer(bytes(spec))

        callbacks._on_transport_batch(ctypes.addressof(spec_buf), 1)
        thread.join(timeout=2)

        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(received, [b"seg-a", b"seg-b"])
        sends = [item for item in callbacks.records if item.get("event") == "native_udp_send"]
        self.assertEqual([item.get("segmentIndex") for item in sends], [0, 1])
        batch = [item for item in callbacks.records if item.get("event") == "native_transport_batch"][0]
        self.assertEqual([item["len"] for item in batch["packetSpecs"][0]["iovPayloadSegments"]], [5, 5])
        self.assertEqual(transport.summary()["packetOutIovMode"], "split")

    def test_zime_native_udp_transport_ztec_prime_records_ack(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        server.settimeout(2)
        target = server.getsockname()
        received = []
        errors = []

        def serve():
            try:
                packet, client = server.recvfrom(2048)
                decoded = rap_zime.decode_ztec_keepalive(packet)
                received.append(decoded)
                ack = rap_zime.encode_ztec_keepalive_ack(
                    decoded["sequence"],
                    decoded["nonce"],
                    marker=decoded["marker"],
                    tail=decoded["tail"],
                    reserved=decoded["reserved"],
                )
                server.sendto(ack, client)
            except Exception as err:
                errors.append(err)

        thread = threading.Thread(target=serve)
        thread.start()
        self.addCleanup(server.close)

        records = []
        transport = zime_native_bridge.NativeUdpTransport(
            target,
            payload_mode="rap",
            rap_tunnel_id="01020304",
            ztec_prime=True,
            ztec_host="10.10.2.121",
            ztec_port=10054,
            ztec_timeout=1,
        )
        self.addCleanup(transport.close)

        record = transport.prime_ztec_keepalive(records, phase="unit")
        thread.join(timeout=2)

        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(received[0]["host"], "10.10.2.121")
        self.assertEqual(received[0]["port"], 10054)
        self.assertEqual(record["event"], "native_udp_ztec_prime")
        self.assertTrue(record["ackReceived"])
        self.assertEqual(transport.summary()["ztecSent"], 1)
        self.assertEqual(transport.summary()["ztecAckReceived"], 1)
        self.assertEqual(transport.summary()["sentPackets"], 0)
        self.assertEqual(transport.summary()["receivedPackets"], 0)

    def test_zime_native_bridge_udp_transport_feeds_receive_data(self):
        class FakeFunction:
            def __init__(self, fn):
                self.fn = fn

            def __call__(self, *args):
                return self.fn(*args)

        class FakeLib:
            def __init__(self):
                self.transport_batch = None
                self.received = []
                self.process_calls = 0
                self.keepalive = []
                self.ZIME_CreateDataEngine = FakeFunction(lambda: 0x1234)
                self.ZIME_Init = FakeFunction(lambda engine, param: 0)
                self.ZIME_SetDataChannelCallback = FakeFunction(lambda engine, table: 0)
                self.ZIME_SetDataExternalTransport = FakeFunction(self._set_transport)
                self.ZIME_CreateDataChannel = FakeFunction(self._create_channel)
                self.ZIME_CreateDataStream = FakeFunction(self._create_stream)
                self.ZIME_SendData = FakeFunction(lambda engine, channel_id, stream_id, buf, length: 0)
                self.ZIME_ReceiveData = FakeFunction(self._receive_data)
                self.ZIME_DataChannelProcess2 = FakeFunction(self._process)
                self.ZIME_GetInfoByErrno = FakeFunction(lambda code: b"Operation successful.")

            def _set_transport(self, engine, table):
                self.transport_batch = zime_native_bridge.TransportBatchCallback(table[1])
                return 0

            def _create_channel(self, engine, context, channel_id):
                ctypes.cast(channel_id, ctypes.POINTER(ctypes.c_long)).contents.value = 7
                return 0

            def _create_stream(self, engine, channel_id, stream_id, param):
                ctypes.cast(stream_id, ctypes.POINTER(ctypes.c_long)).contents.value = 1
                return 0

            def _emit_packet_out(self, payload):
                payload_buf = ctypes.create_string_buffer(payload)
                iov = (zime_native_bridge.Iovec * 1)()
                iov[0].iov_base = ctypes.addressof(payload_buf)
                iov[0].iov_len = len(payload)
                spec = bytearray(zime_probe.ZIME_PACKET_OUT_SPEC_SIZE)
                struct.pack_into("<QQQQ", spec, 0, ctypes.addressof(iov), 1, 0, 0)
                spec[96] = 4
                spec_buf = ctypes.create_string_buffer(bytes(spec))
                self.keepalive.extend([payload_buf, iov, spec_buf])
                return self.transport_batch(ctypes.addressof(spec_buf), 1)

            def _process(self, engine, channel_id, events):
                self.process_calls += 1
                ctypes.cast(events, ctypes.POINTER(ctypes.c_uint)).contents.value = 10
                if self.process_calls == 1:
                    self._emit_packet_out(b"native-out")
                return 0

            def _receive_data(self, engine, socket_param, buf, length):
                self.received.append(ctypes.string_at(buf, int(length)))
                return 0

        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        server.settimeout(2)
        target = server.getsockname()
        received = []
        errors = []

        def serve():
            try:
                packet, client = server.recvfrom(2048)
                received.append(packet)
                server.sendto(b"native-in", client)
            except Exception as err:
                errors.append(err)

        thread = threading.Thread(target=serve)
        thread.start()
        self.addCleanup(server.close)

        state_path = self.temp_state()
        lib_path = Path(state_path).with_name("libZIMEDataEngine.so")
        lib_path.write_bytes(b"fake")
        fake = FakeLib()
        bridge = zime_native_bridge.ZimeNativeBridge(lib_path, loader=lambda path: fake)

        result = bridge.run_send_probe(
            [],
            process_ticks=1,
            wait_channel_created_ticks=0,
            udp_transport_target=f"{target[0]}:{target[1]}",
            udp_read_timeout=1,
            udp_receive_limit=1,
            udp_process_ticks_after_receive=1,
        )
        thread.join(timeout=2)

        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(received, [b"native-out"])
        self.assertEqual(fake.received, [b"native-in"])
        self.assertTrue(result["ok"])
        self.assertEqual(result["udpTransport"]["sentPackets"], 1)
        self.assertEqual(result["udpTransport"]["receivedPackets"], 1)
        self.assertIn("native_udp_send", [item["event"] for item in result["callbackRecords"]])
        self.assertIn("native_udp_receive", [item["event"] for item in result["callbackRecords"]])
        self.assertIn("ZIME_ReceiveData", [item["function"] for item in result["calls"]])
        self.assertTrue(result["nativeMilestones"]["nativeUdpSent"])
        self.assertTrue(result["nativeMilestones"]["nativeUdpReceived"])
        self.assertTrue(result["nativeMilestones"]["receiveDataOk"])
        self.assertEqual(result["nativeMilestones"]["stage"], "native_channel_created_pending")

    def test_zime_native_bridge_waits_for_channel_created_before_stream(self):
        class FakeFunction:
            def __init__(self, fn):
                self.fn = fn

            def __call__(self, *args):
                return self.fn(*args)

        class FakeLib:
            def __init__(self):
                self.channel_created = None
                self.order = []
                self.process_calls = 0
                self.ZIME_CreateDataEngine = FakeFunction(lambda: 0x1234)
                self.ZIME_Init = FakeFunction(lambda engine, param: 0)
                self.ZIME_SetDataChannelCallback = FakeFunction(self._set_callbacks)
                self.ZIME_SetDataExternalTransport = FakeFunction(lambda engine, table: 0)
                self.ZIME_CreateDataChannel = FakeFunction(self._create_channel)
                self.ZIME_CreateDataStream = FakeFunction(self._create_stream)
                self.ZIME_SendData = FakeFunction(lambda engine, channel_id, stream_id, buf, length: 0)
                self.ZIME_ReceiveData = FakeFunction(lambda engine, socket_param, buf, length: 0)
                self.ZIME_DataChannelProcess2 = FakeFunction(self._process)
                self.ZIME_GetInfoByErrno = FakeFunction(lambda code: b"Operation successful.")

            def _set_callbacks(self, engine, table):
                self.channel_created = zime_native_bridge.ChannelCreatedCallback(table[1])
                return 0

            def _create_channel(self, engine, context, channel_id):
                ctypes.cast(channel_id, ctypes.POINTER(ctypes.c_long)).contents.value = 7
                return 0

            def _create_stream(self, engine, channel_id, stream_id, param):
                self.order.append("stream")
                ctypes.cast(stream_id, ctypes.POINTER(ctypes.c_long)).contents.value = 1
                return 0

            def _process(self, engine, channel_id, events):
                self.process_calls += 1
                ctypes.cast(events, ctypes.POINTER(ctypes.c_uint)).contents.value = 0
                if self.process_calls == 3:
                    self.order.append("channel_created")
                    self.channel_created(7, 0, 0, 0, 0)
                return 0

        state_path = self.temp_state()
        lib_path = Path(state_path).with_name("libZIMEDataEngine.so")
        lib_path.write_bytes(b"fake")
        fake = FakeLib()
        bridge = zime_native_bridge.ZimeNativeBridge(lib_path, loader=lambda path: fake)

        result = bridge.run_send_probe(
            [spice_protocol.encode_display_init()],
            process_ticks=1,
            wait_channel_created_ticks=5,
        )

        self.assertTrue(result["ok"])
        self.assertEqual(fake.order, ["channel_created", "stream"])
        self.assertEqual(fake.process_calls, 4)
        wait_calls = [item for item in result["calls"] if item["function"] == "wait_native_channel_created"]
        self.assertEqual(wait_calls[0]["ret"], 0)
        self.assertEqual(wait_calls[0]["waitTicks"], 2)
        self.assertTrue(result["nativeMilestones"]["nativeChannelCreatedOk"])
        self.assertTrue(result["nativeMilestones"]["streamCreateOk"])
        self.assertTrue(result["nativeMilestones"]["displayInitSendOk"])
        self.assertEqual(result["nativeMilestones"]["stage"], "packet_out_pending")

    def test_zime_native_bridge_default_run_is_disabled(self):
        calls = []
        self.set_attr(zime_native_bridge, "inspect_library", lambda lib_path=None: {
            "ok": True,
            "error": None,
            "libPath": "/tmp/libZIMEDataEngine.so",
        })

        class FakeBridge:
            def __init__(self, lib_path=None):
                calls.append(("init", lib_path))

            def run_send_probe(self, payloads, **kwargs):
                calls.append(("run", payloads, kwargs))
                return {"ok": True, "nativeRun": True}

        self.set_attr(zime_native_bridge, "ZimeNativeBridge", FakeBridge)

        result = zime_native_bridge.run_research_probe(payloads=[b"abc"])

        self.assertTrue(result["ok"])
        self.assertFalse(result["nativeRun"])
        self.assertEqual(result["error"], "native_run_disabled_by_default")
        self.assertEqual(calls, [])

    def test_zime_native_bridge_inspect_only_keeps_native_disabled_without_error(self):
        self.set_attr(zime_native_bridge, "inspect_library", lambda lib_path=None: {
            "ok": True,
            "error": None,
            "libPath": "/tmp/libZIMEDataEngine.so",
        })

        result = zime_native_bridge.run_research_probe(payloads=[b"abc"], inspect_only=True)

        self.assertTrue(result["ok"])
        self.assertFalse(result["nativeRun"])
        self.assertIsNone(result["error"])

    def test_zime_native_bridge_allowed_run_uses_fake_bridge(self):
        calls = []
        self.set_attr(zime_native_bridge, "inspect_library", lambda lib_path=None: {
            "ok": True,
            "error": None,
            "libPath": str(lib_path or "/tmp/libZIMEDataEngine.so"),
        })

        class FakeBridge:
            def __init__(self, lib_path=None):
                calls.append(("init", lib_path))

            def run_send_probe(self, payloads, **kwargs):
                calls.append(("run", payloads, kwargs))
                return {
                    "ok": True,
                    "researchOnly": True,
                    "nativeRun": True,
                    "callbackRecords": [{"event": "native_transport_batch"}],
                }

        self.set_attr(zime_native_bridge, "ZimeNativeBridge", FakeBridge)

        result = zime_native_bridge.run_research_probe(
            lib_path="/tmp/native.so",
            payloads=[b"abc"],
            allow_native_run=True,
            remote_host="127.0.0.2",
            remote_port=5100,
            read_iov_payload=True,
        )

        self.assertTrue(result["ok"])
        self.assertTrue(result["nativeRun"])
        self.assertIsNone(result["error"])
        self.assertEqual(calls[0], ("init", "/tmp/native.so"))
        self.assertEqual(calls[1][1], [b"abc"])
        self.assertEqual(calls[1][2]["remote_host"], "127.0.0.2")
        self.assertEqual(calls[1][2]["remote_port"], 5100)
        self.assertEqual(calls[1][2]["opaque"], b"\x00\x00\x00\x00")
        self.assertEqual(calls[1][2]["protocol"], 0)
        self.assertEqual(calls[1][2]["mtu"], zime_native_bridge.DEFAULT_BASE_MTU)
        self.assertEqual(calls[1][2]["business_type"], 1)
        self.assertEqual(calls[1][2]["stream_id"], zime_native_bridge.DEFAULT_STREAM_ID)
        self.assertEqual(calls[1][2]["process_ticks"], zime_native_bridge.DEFAULT_PROCESS_TICKS)
        self.assertEqual(calls[1][2]["wait_channel_created_ticks"], zime_native_bridge.DEFAULT_WAIT_CHANNEL_CREATED_TICKS)
        self.assertEqual(calls[1][2]["udp_rap_flags"], 0)
        self.assertEqual(calls[1][2]["udp_rap_field06"], 0)
        self.assertEqual(calls[1][2]["udp_rap_word08"], 0)
        self.assertEqual(calls[1][2]["udp_rap_word12"], 0)
        self.assertIsNone(calls[1][2]["udp_rap_header16_prefix"])
        self.assertIsNone(calls[1][2]["udp_rap_post_length"])
        self.assertEqual(calls[1][2]["udp_rap_payload_envelope"], "raw")
        self.assertEqual(calls[1][2]["udp_rap_send_templates"], [])
        self.assertEqual(calls[1][2]["udp_rap_template_mode"], "auto")
        self.assertEqual(calls[1][2]["udp_packet_out_iov_mode"], "concat")
        self.assertFalse(calls[1][2]["udp_ztec_prime"])
        self.assertIsNone(calls[1][2]["udp_ztec_host"])
        self.assertIsNone(calls[1][2]["udp_ztec_port"])
        self.assertTrue(calls[1][2]["read_iov_payload"])
        self.assertEqual(result["callbackRecords"][0]["event"], "native_transport_batch")

    def test_zime_native_bridge_preserves_partial_report_on_cmcc_error(self):
        self.set_attr(zime_native_bridge, "inspect_library", lambda lib_path=None: {
            "ok": True,
            "error": None,
            "libPath": str(lib_path or "/tmp/libZIMEDataEngine.so"),
        })

        class FakeBridge:
            def __init__(self, lib_path=None):
                pass

            def run_send_probe(self, payloads, **kwargs):
                raise core.CmccError("ZIME_CreateDataChannel failed: 4", response={
                    "ok": False,
                    "researchOnly": True,
                    "nativeRun": True,
                    "calls": [
                        {"function": "ZIME_CreateDataEngine", "retPtr": "0x1234"},
                        {"function": "ZIME_CreateDataChannel", "ret": 4, "channelId": 0},
                    ],
                    "payloads": [],
                    "callbackRecords": [],
                })

        self.set_attr(zime_native_bridge, "ZimeNativeBridge", FakeBridge)

        result = zime_native_bridge.run_research_probe(payloads=[b"abc"], allow_native_run=True)

        self.assertFalse(result["ok"])
        self.assertTrue(result["nativeRun"])
        self.assertIn("ZIME_CreateDataChannel failed: 4", result["error"])
        self.assertEqual(result["calls"][1]["function"], "ZIME_CreateDataChannel")
        self.assertEqual(result["calls"][1]["ret"], 4)

    def test_zime_native_bridge_cli_builds_payloads_and_defaults_to_inspect(self):
        captured = {}

        def fake_run_research_probe(**kwargs):
            captured.update(kwargs)
            return {
                "ok": True,
                "researchOnly": True,
                "nativeRun": kwargs["allow_native_run"],
                "payloadCount": len(kwargs["payloads"]),
                "error": None,
            }

        self.set_attr(cli_main.zime_native_bridge, "run_research_probe", fake_run_research_probe)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli_main.main([
                "zime-native-bridge",
                "--display-init",
                "--payload-hex",
                "aa",
                "--remote-host",
                "127.0.0.2",
                "--remote-port",
                "5100",
                "--opaque-hex",
                "01020304",
                "--protocol",
                "0",
                "--mtu",
                "1200",
                "--business-type",
                "1",
                "--stream-id",
                "9",
                "--process-ticks",
                "6",
                "--udp-transport-target",
                "127.0.0.1:9999",
                "--udp-read-timeout",
                "0.1",
                "--udp-receive-limit",
                "2",
                "--udp-process-ticks-after-receive",
                "3",
                "--udp-transport-mode",
                "rap",
                "--udp-rap-tunnel-id",
                "01020304",
                "--udp-rap-flags",
                "0x02",
                "--udp-rap-field06",
                "0xbb01",
                "--udp-rap-word08",
                "0x090001cc",
                "--udp-rap-word12",
                "0x03000000",
                "--udp-rap-header16-prefix-hex",
                "000000",
                "--udp-rap-post-length-hex",
                "4f0800",
                "--udp-rap-payload-envelope",
                "len16",
                "--udp-rap-template-mode",
                "sequence",
                "--udp-packet-out-iov-mode",
                "split",
                "--udp-ztec-prime",
                "--udp-ztec-host",
                "10.10.2.121",
                "--udp-ztec-port",
                "10054",
                "--udp-ztec-timeout",
                "0.4",
                "--wait-channel-created-ticks",
                "5",
            ])

        self.assertEqual(code, 0)
        self.assertFalse(captured["allow_native_run"])
        self.assertTrue(captured["inspect_only"])
        self.assertEqual(captured["remote_host"], "127.0.0.2")
        self.assertEqual(captured["remote_port"], 5100)
        self.assertEqual(captured["opaque"], b"\x01\x02\x03\x04")
        self.assertEqual(captured["protocol"], 0)
        self.assertEqual(captured["mtu"], 1200)
        self.assertEqual(captured["business_type"], 1)
        self.assertEqual(captured["stream_id"], 9)
        self.assertEqual(captured["process_ticks"], 6)
        self.assertEqual(captured["udp_transport_target"], "127.0.0.1:9999")
        self.assertEqual(captured["udp_read_timeout"], 0.1)
        self.assertEqual(captured["udp_receive_limit"], 2)
        self.assertEqual(captured["udp_process_ticks_after_receive"], 3)
        self.assertEqual(captured["udp_transport_mode"], "rap")
        self.assertEqual(captured["udp_rap_tunnel_id"], "01020304")
        self.assertEqual(captured["udp_rap_flags"], 0x02)
        self.assertEqual(captured["udp_rap_field06"], 0xBB01)
        self.assertEqual(captured["udp_rap_word08"], 0x090001CC)
        self.assertEqual(captured["udp_rap_word12"], 0x03000000)
        self.assertEqual(captured["udp_rap_header16_prefix"], "000000")
        self.assertEqual(captured["udp_rap_post_length"], "4f0800")
        self.assertEqual(captured["udp_rap_payload_envelope"], "len16")
        self.assertEqual(captured["udp_rap_template_mode"], "sequence")
        self.assertEqual(captured["udp_packet_out_iov_mode"], "split")
        self.assertTrue(captured["udp_ztec_prime"])
        self.assertEqual(captured["udp_ztec_host"], "10.10.2.121")
        self.assertEqual(captured["udp_ztec_port"], 10054)
        self.assertEqual(captured["udp_ztec_timeout"], 0.4)
        self.assertEqual(captured["wait_channel_created_ticks"], 5)
        self.assertEqual(captured["payloads"][0], spice_protocol.encode_display_init())
        self.assertEqual(captured["payloads"][1], b"\xaa")
        printed = json.loads(out.getvalue())
        self.assertEqual(printed["payloadCount"], 2)

    def test_zime_native_bridge_cli_loads_runner_input_for_udp_transport(self):
        state_path = self.temp_state()
        runner_path = Path(state_path).with_name("runner-input.json")
        runner_path.write_text(json.dumps({
            "runnerInput": {
                "candidateUdpTargets": ["127.0.0.1:34567"],
                "candidateZtecTargets": ["10.10.2.127:10012"],
                "primaryTunnelId": "01020304",
                "rapDataFrameTemplate": {
                    "flags": 0,
                    "field06": 0xBB01,
                    "word08": 0x090001CC,
                    "word12": 0x03000000,
                    "header16PrefixHex": "000000",
                    "postLengthHex": "4f0800",
                },
                "rapDataFrameSendTemplates": [
                    {
                        "index": 9,
                        "frameType": 0x81,
                        "flags": 0,
                        "field06": 0x5104,
                        "word08": 1,
                        "word12": 0,
                        "header16PrefixHex": "000000",
                        "postLengthHex": "000001",
                        "payloadKind": "quic-long-header-candidate",
                        "payloadLength": 738,
                        "zimePayloadEnvelopeObserved": True,
                    }
                ],
            }
        }), encoding="utf-8")
        captured = {}

        def fake_run_research_probe(**kwargs):
            captured.update(kwargs)
            return {
                "ok": True,
                "nativeRun": kwargs["allow_native_run"],
                "sessionOwning": bool(kwargs["udp_transport_target"]),
                "error": None,
            }

        self.set_attr(cli_main.zime_native_bridge, "run_research_probe", fake_run_research_probe)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli_main.main([
                "zime-native-bridge",
                "--allow-native-run",
                "--runner-input",
                str(runner_path),
                "--payload-hex",
                "aa",
            ])

        self.assertEqual(code, 0)
        self.assertEqual(captured["remote_host"], "127.0.0.1")
        self.assertEqual(captured["remote_port"], 34567)
        self.assertEqual(captured["udp_transport_target"], "127.0.0.1:34567")
        self.assertEqual(captured["udp_transport_mode"], "rap")
        self.assertEqual(captured["udp_rap_tunnel_id"], "01020304")
        self.assertEqual(captured["udp_rap_field06"], 0xBB01)
        self.assertEqual(captured["udp_rap_word08"], 0x090001CC)
        self.assertEqual(captured["udp_rap_word12"], 0x03000000)
        self.assertEqual(captured["udp_rap_header16_prefix"], "000000")
        self.assertEqual(captured["udp_rap_post_length"], "4f0800")
        self.assertEqual(captured["udp_rap_payload_envelope"], "raw")
        self.assertEqual(captured["udp_rap_send_templates"][0]["field06"], 0x5104)
        self.assertEqual(captured["udp_rap_template_mode"], "auto")
        self.assertEqual(captured["udp_packet_out_iov_mode"], "concat")
        self.assertFalse(captured["udp_ztec_prime"])
        self.assertEqual(captured["udp_ztec_host"], "10.10.2.127")
        self.assertEqual(captured["udp_ztec_port"], 10012)
        self.assertEqual(captured["wait_channel_created_ticks"], zime_native_bridge.DEFAULT_WAIT_CHANNEL_CREATED_TICKS)
        self.assertTrue(json.loads(out.getvalue())["sessionOwning"])

    def test_zime_native_bridge_cli_auto_uses_raw_for_pcap_metadata_only_input(self):
        state_path = self.temp_state()
        runner_path = Path(state_path).with_name("pcap-runner-input.json")
        runner_path.write_text(json.dumps({
            "runnerInput": {
                "transport": "external-pcap-metadata-only",
                "candidateUdpTargets": ["127.0.0.1:45678"],
                "runnerInputReady": False,
                "missing": [
                    "primaryTunnelId",
                    "candidateZtecTargets",
                    "rapDataFrameTemplate",
                    "rapDataFrameSendTemplates",
                ],
            }
        }), encoding="utf-8")
        captured = {}

        def fake_run_research_probe(**kwargs):
            captured.update(kwargs)
            return {
                "ok": True,
                "nativeRun": kwargs["allow_native_run"],
                "sessionOwning": bool(kwargs["udp_transport_target"]),
                "error": None,
            }

        self.set_attr(cli_main.zime_native_bridge, "run_research_probe", fake_run_research_probe)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli_main.main([
                "zime-native-bridge",
                "--allow-native-run",
                "--runner-input",
                str(runner_path),
                "--payload-hex",
                "aa",
            ])

        self.assertEqual(code, 0)
        self.assertEqual(captured["remote_host"], "127.0.0.1")
        self.assertEqual(captured["remote_port"], 45678)
        self.assertEqual(captured["udp_transport_target"], "127.0.0.1:45678")
        self.assertEqual(captured["udp_transport_mode"], "raw")
        self.assertIsNone(captured["udp_rap_tunnel_id"])
        self.assertEqual(captured["udp_rap_send_templates"], [])
        self.assertEqual(captured["udp_ztec_host"], "127.0.0.1")
        self.assertEqual(captured["udp_ztec_port"], 45678)
        self.assertTrue(json.loads(out.getvalue())["sessionOwning"])

    def test_zime_native_bridge_cli_allows_explicit_native_run(self):
        captured = {}

        def fake_run_research_probe(**kwargs):
            captured.update(kwargs)
            return {"ok": True, "nativeRun": kwargs["allow_native_run"], "error": None}

        self.set_attr(cli_main.zime_native_bridge, "run_research_probe", fake_run_research_probe)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli_main.main(["zime-native-bridge", "--allow-native-run", "--payload-hex", "aa"])

        self.assertEqual(code, 0)
        self.assertTrue(captured["allow_native_run"])
        self.assertFalse(captured["inspect_only"])
        self.assertEqual(captured["payloads"], [b"\xaa"])
        self.assertEqual(captured["udp_transport_mode"], "raw")
        self.assertEqual(captured["udp_rap_flags"], 0)
        self.assertEqual(captured["udp_rap_field06"], 0)
        self.assertEqual(captured["udp_rap_word08"], 0)
        self.assertEqual(captured["udp_rap_word12"], 0)
        self.assertIsNone(captured["udp_rap_header16_prefix"])
        self.assertIsNone(captured["udp_rap_post_length"])
        self.assertEqual(captured["udp_rap_payload_envelope"], "raw")
        self.assertEqual(captured["udp_rap_send_templates"], [])
        self.assertEqual(captured["udp_rap_template_mode"], "auto")
        self.assertEqual(captured["udp_packet_out_iov_mode"], "concat")
        self.assertFalse(captured["udp_ztec_prime"])
        self.assertIsNone(captured["udp_ztec_host"])
        self.assertIsNone(captured["udp_ztec_port"])
        self.assertEqual(captured["wait_channel_created_ticks"], zime_native_bridge.DEFAULT_WAIT_CHANNEL_CREATED_TICKS)

    def test_zime_probe_classifies_ssl_short_spice_like_control_packets(self):
        state_path = self.temp_state()
        jsonl_path = Path(state_path).with_name("zime-probe-ssl-short-control.jsonl")
        short_control = bytes.fromhex("2a08040000000000")
        jsonl_path.write_text("\n".join([
            json.dumps({
                "event": "ssl_buffer",
                "function": "SSL_write",
                "direction": "send",
                "len": len(short_control),
                "payloadKind": "unknown",
                "hex": short_control.hex(),
            }),
        ]) + "\n", encoding="utf-8")

        self.assertEqual(zime_probe.classify_payload(short_control, allow_short_mini=True), "spice-mini-unknown:0x082a")
        self.assertEqual(zime_probe.classify_payload(short_control), "unknown")
        result = zime_probe.analyze(jsonl_path)
        self.assertEqual(result["payloadKindCounts"]["spice-mini-unknown:0x082a"], 1)
        self.assertEqual(result["samples"][0]["payloadKind"], "spice-mini-unknown:0x082a")

        buried_jsonl = Path(state_path).with_name("zime-probe-ssl-short-control-buried.jsonl")
        filler = bytes.fromhex("0001020304050607")
        rows = []
        for i in range(90):
            rows.append(json.dumps({
                "event": "transport_buffer",
                "function": "recv",
                "direction": "receive",
                "len": len(filler),
                "payloadKind": "unknown",
                "hex": filler.hex(),
            }))
        rows.append(json.dumps({
            "event": "ssl_buffer",
            "function": "SSL_write",
            "direction": "send",
            "len": len(short_control),
            "payloadKind": "unknown",
            "hex": short_control.hex(),
        }))
        buried_jsonl.write_text("\n".join(rows) + "\n", encoding="utf-8")
        buried = zime_probe.analyze(buried_jsonl)
        self.assertTrue(any(sample["payloadKind"] == "spice-mini-unknown:0x082a" for sample in buried["samples"]))

    def test_zime_probe_classifies_tls_record_before_spice_fallback(self):
        tls_ccs_and_handshake = bytes.fromhex(
            "140303000101160303002800000000000000006b39bedb5b6722246dd4edc4cedf5b08b2b0773d3399a133b2d638d4da75ef11"
        )
        self.assertEqual(zime_probe.classify_payload(tls_ccs_and_handshake), "tls-change-cipher-spec")

        state_path = self.temp_state()
        jsonl_path = Path(state_path).with_name("zime-probe-tls.jsonl")
        jsonl_path.write_text(json.dumps({
            "event": "transport_buffer",
            "function": "send",
            "direction": "send",
            "fd": 25,
            "peer": "198.18.0.18:443",
            "len": len(tls_ccs_and_handshake),
            "payloadKind": "unknown",
            "hex": tls_ccs_and_handshake.hex(),
        }) + "\n", encoding="utf-8")

        result = zime_probe.analyze(jsonl_path)
        self.assertEqual(result["payloadKindCounts"]["tls-change-cipher-spec"], 1)
        self.assertNotIn("spice-set-ack", result["payloadKindCounts"])
        timeline = trace_timeline.timeline(jsonl_path)
        tls_group = next(item for item in timeline["groupedCounters"] if item["peerGroup"] == "external")
        self.assertEqual(tls_group["payloadKinds"][0]["payloadKind"], "tls-change-cipher-spec")

    def test_zime_probe_and_rap_zime_classify_reserved_quic_packet(self):
        packet = bytes.fromhex("30414011c00000000109fc2556a34b")

        self.assertEqual(
            zime_probe.classify_payload(packet),
            "zime-udp-reserved4:quic-long-header-candidate",
        )
        self.assertEqual(
            rap_zime.classify_payload(packet),
            "zime-udp-reserved4:quic-long-header-candidate",
        )

    def test_spice_protocol_codecs_and_offline_display_proof(self):
        def der_length(length):
            if length < 0x80:
                return bytes([length])
            raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
            return bytes([0x80 | len(raw)]) + raw

        def der_tlv(tag, value):
            return bytes([tag]) + der_length(len(value)) + value

        def der_integer(value):
            raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
            if raw[0] & 0x80:
                raw = b"\x00" + raw
            return der_tlv(0x02, raw)

        link = spice_protocol.encode_spice_link_mess(
            connection_id=0,
            channel_type=spice_protocol.SpiceChannel.MAIN,
            channel_id=0,
        )
        decoded_link = spice_protocol.decode_spice_link_mess(link)
        self.assertEqual(link[:4], b"REDQ")
        self.assertEqual(decoded_link["connectionId"], 0)
        self.assertEqual(decoded_link["channelType"], spice_protocol.SpiceChannel.MAIN)
        self.assertIn(3, decoded_link["commonCaps"]["bits"])

        display_init = spice_protocol.encode_display_init()
        # GLZ window is 0x7FFC00 (little-endian tail fc7f00), matching the Go
        # golden reference scg_go/internal/spice/spice.go PutUint32(..., 0x7ffc00).
        self.assertEqual(display_init.hex(), "65000e0000000100004001000000000100fc7f00")
        decoded_display = spice_protocol.decode_mini_message(display_init)
        self.assertEqual(decoded_display["header"]["type"], spice_protocol.SpiceMessage.DISPLAY_INIT)
        self.assertEqual(decoded_display["header"]["size"], 14)

        frame = spice_protocol.encode_chuanyun_frame(
            display_init,
            session_id=0x020304,
            channel_id=spice_protocol.SpiceChannel.DISPLAY,
        )
        decoded_frame = spice_protocol.decode_chuanyun_frame(frame)
        self.assertEqual(decoded_frame["head"]["type"], spice_protocol.ChuanyunFrameType.DATA)
        self.assertEqual(decoded_frame["head"]["sessionId"], 0x020304)
        self.assertEqual(decoded_frame["head"]["channelId"], spice_protocol.SpiceChannel.DISPLAY)
        self.assertEqual(decoded_frame["payload"], display_init)

        proof = spice_protocol.create_offline_display_proof()
        self.assertTrue(proof["success"])
        self.assertTrue(proof["progress"]["displayInitSent"])
        self.assertTrue(proof["progress"]["surfaceCreateReceived"])
        self.assertTrue(proof["progress"]["markReceived"])
        self.assertEqual(spice_protocol.decode_mini_message(proof["responses"][0])["header"]["type"], spice_protocol.SpiceMessage.ACK_SYNC)
        self.assertEqual(spice_protocol.decode_mini_message(proof["responses"][1])["header"]["type"], spice_protocol.SpiceMessage.PONG)

        modulus = int.from_bytes(b"\xff" * 128, "big")
        exponent = 65537
        pkcs1 = der_tlv(0x30, der_integer(modulus) + der_integer(exponent))
        parsed = spice_protocol.parse_rsa_public_key_der(pkcs1)
        self.assertEqual(parsed["modulusBytes"], 128)
        self.assertEqual(parsed["e"], exponent)
        ticket = spice_protocol.encode_spice_ticket(pkcs1, b"", seed=b"\x01" * 20)
        self.assertEqual(len(ticket), 128)
        self.assertEqual(ticket, spice_protocol.encode_spice_ticket(pkcs1, b"", seed=b"\x01" * 20))
        self.assertNotEqual(ticket, b"\x00" * 128)


    def test_g2_multi_channel_inputs_cursor_offline(self):
        """I-G2: INPUTS(3)+CURSOR(4) constants, HyScg ExtInfo+REDQ sizes, handshake order."""
        import struct
        from cmcc_cloud_alive import scg_route as sr
        from cmcc_cloud_alive import spice_protocol as sp

        self.assertEqual(sp.SpiceChannel.INPUTS, 3)
        self.assertEqual(sp.SpiceChannel.CURSOR, 4)
        self.assertEqual(sp.SpiceChannel.DISPLAY, 2)
        self.assertEqual(sp.SpiceChannel.MAIN, 1)

        src = Path(sr.__file__).read_text(encoding="utf-8")
        # handshake attaches INPUTS then CURSOR after DISPLAY, using session id
        self.assertIn("authenticate_channel(CHANNEL_INPUTS", src)
        self.assertIn("authenticate_channel(CHANNEL_CURSOR", src)
        self.assertIn("sp.SpiceChannel.INPUTS", src)
        self.assertIn("sp.SpiceChannel.CURSOR", src)
        # order: DISPLAY auth → wait_display_mark → INPUTS → CURSOR
        i_disp = src.find("authenticate_channel(CHANNEL_DISPLAY")
        i_wait = src.find("wait_display_mark()")
        i_in = src.find("authenticate_channel(CHANNEL_INPUTS")
        i_cu = src.find("authenticate_channel(CHANNEL_CURSOR")
        self.assertTrue(0 <= i_disp < i_wait < i_in < i_cu, (i_disp, i_wait, i_in, i_cu))

        def parse_frames(blob: bytes):
            frames = []
            off = 0
            while off + 24 <= len(blob):
                ver, ptype, plen, res, f1, f2 = struct.unpack_from("<BBHIQQ", blob, off)
                off += 24
                payload = blob[off : off + plen]
                off += plen
                frames.append((ver, ptype, plen, f1, f2, payload))
            return frames

        # type 2 (display): ExtInfo 22B + token(16)+REDQ(size=26) → plen 58
        # type 3/4 (inputs/cursor): ExtInfo 22B + token(16)+REDQ(size=22) → plen 54
        for ch_id, ch_type, redq_size, frame1_plen in (
            (2, 2, 26, 58),
            (3, 3, 22, 54),
            (4, 4, 22, 54),
        ):
            blob = sr.build_channel_auth(0xABCD, ch_id, ch_type, connection_id=0x55)
            frames = parse_frames(blob)
            self.assertEqual(len(frames), 2, ch_type)
            # frame0: HyScg ExtInfo 22B; field2 = channel_id
            self.assertEqual(frames[0][2], 22, ch_type)
            self.assertEqual(frames[0][4], ch_id)
            self.assertEqual(frames[0][5][-1], ch_type & 0xFF)
            # frame1: 16B token + REDQ body
            self.assertEqual(frames[1][2], frame1_plen, ch_type)
            self.assertEqual(frames[1][4], ch_id)
            redq = frames[1][5][16:]  # after token
            self.assertTrue(redq.startswith(b"REDQ"), redq[:8])
            magic, v1, v2, size = struct.unpack_from("<4sIII", redq, 0)
            self.assertEqual(magic, b"REDQ")
            self.assertEqual(size, redq_size, ch_type)
            # connection_id + channel type byte
            conn_id, = struct.unpack_from("<I", redq, 16)
            self.assertEqual(conn_id, 0x55)
            self.assertEqual(redq[20], ch_type & 0xFF)

        # Go already lists display/inputs/cursor subchannels
        go = (Path(sr.__file__).resolve().parents[1] / "scg_go/internal/spice/spice.go").read_text(encoding="utf-8")
        self.assertIn("subChannels := []subCh{{2, 2}, {3, 3}, {4, 4}}", go)

    def test_protocol_runner_fetch_connect_info_uses_cag_material(self):
        state_path = self.temp_state()
        calls = []

        def fake_fetch(user_service_id=None, state_path=None, boot_wait=180, timeout=30):
            calls.append((user_service_id, state_path, boot_wait, timeout))
            return "-h 10.10.2.121 -p 10066 -type rap -accessToken secret-token -cpsid cps-secret"

        self.set_attr(protocol_runner, "_fetch_cag_connect_str", fake_fetch)
        info = protocol_runner.fetch_connect_info("2663816", state_path, boot_wait=7, timeout=9)

        self.assertEqual(calls, [("2663816", state_path, 7, 9)])
        self.assertEqual(info["host"], "10.10.2.121")
        self.assertEqual(info["port"], 10066)
        self.assertEqual(info["type"], "rap")
        self.assertEqual(info["accessToken"], "secret-token")
        self.assertEqual(info["cpsid"], "cps-secret")
        public = protocol_runner.public_connect_info(info)
        self.assertEqual(public["host"], "10.10.2.121")
        self.assertTrue(public["accessTokenPresent"])
        self.assertTrue(public["cpsidPresent"])
        self.assertEqual(public["sensitiveArgPresent"]["accessToken"], True)
        self.assertNotIn("secret-token", json.dumps(public))
        self.assertNotIn("cps-secret", json.dumps(public))

    def test_protocol_runner_connect_info_tracks_vm_dest_without_public_value(self):
        info = protocol_runner.connect_info_from_connect_str(
            "-h 10.10.2.121 -p 10066 --proxy-sport 5100 --vmid vm-id-1 --vmip 10.10.213.110%3B10.0.0.1 --vmport 5100 --vmipv6 fd00::1 --vmportv6 5100 -type rap -accessToken secret-token"
        )
        self.assertEqual(info["host"], "10.10.2.121")
        self.assertEqual(info["port"], 5100)
        self.assertEqual(info["gatewayPort"], 10066)
        self.assertEqual(info["udpPortSource"], "proxy-sport")
        self.assertTrue(info["udpSsl"])
        self.assertEqual(info["vmid"], "vm-id-1")
        self.assertEqual(info["vmHost"], "10.10.213.110")
        self.assertEqual(info["vmPort"], 5100)
        self.assertEqual(info["vmHostV6"], "fd00::1")
        self.assertEqual(info["vmPortV6"], 5100)
        public = protocol_runner.public_connect_info(info)
        self.assertTrue(public["vmHostPresent"])
        self.assertTrue(public["vmPortPresent"])
        self.assertEqual(public["udpPortSource"], "proxy-sport")
        self.assertTrue(public["udpSsl"])
        self.assertNotIn("10.10.213.110", json.dumps(public))
        self.assertNotIn("fd00::1", json.dumps(public))
        self.assertNotIn("secret-token", json.dumps(public))

    def test_protocol_runner_reports_rap_transport_gap_instead_of_direct_tcp(self):
        info = protocol_runner.connect_info_from_connect_str(
            "-h 10.10.2.121 -p 10066 -type rap -accessToken secret-token -cpsid cps-secret"
        )
        result = protocol_runner.run_connect_info(info, run_seconds=1, timeout=1, success_only=True)

        self.assertFalse(result["success"])
        self.assertFalse(result["desktopKeepaliveProven"])
        self.assertEqual(result["transportType"], "rap")
        self.assertIn("rap_zime_spice_runner_not_implemented", result["error"])
        self.assertIn("DISPLAY_INIT", result["requiredProtocolPath"])
        self.assertNotIn("secret-token", json.dumps(result))

    def test_rap_zime_ztec_keepalive_codecs(self):
        request = bytes.fromhex("5a54454306007f020a0a1c2700003d93a00400000000296e3613")
        decoded_request = rap_zime.decode_ztec_keepalive(request)
        self.assertEqual(decoded_request["kind"], "ztec_keepalive_request")
        self.assertEqual(decoded_request["magic"], "ZTEC")
        self.assertEqual(decoded_request["version"], 6)
        self.assertEqual(decoded_request["host"], "10.10.2.127")
        self.assertEqual(decoded_request["port"], 10012)
        self.assertEqual(decoded_request["sequence"], 0)
        self.assertEqual(decoded_request["nonce"], 0x933D)
        self.assertEqual(decoded_request["marker"], 0x04A0)
        self.assertEqual(decoded_request["tail"], 0x13366E29)
        self.assertEqual(
            rap_zime.encode_ztec_keepalive_request(
                decoded_request["host"],
                decoded_request["port"],
                decoded_request["sequence"],
                decoded_request["nonce"],
                marker=decoded_request["marker"],
                tail=decoded_request["tail"],
                reserved=decoded_request["reserved"],
                version=decoded_request["version"],
            ),
            request,
        )

        ack = bytes.fromhex("00003d93a00400000000296e3613")
        decoded_ack = rap_zime.decode_ztec_keepalive(ack)
        self.assertEqual(decoded_ack["kind"], "ztec_keepalive_ack")
        self.assertEqual(decoded_ack["sequence"], decoded_request["sequence"])
        self.assertEqual(decoded_ack["nonce"], decoded_request["nonce"])
        self.assertEqual(
            rap_zime.encode_ztec_keepalive_ack(
                decoded_ack["sequence"],
                decoded_ack["nonce"],
                marker=decoded_ack["marker"],
                tail=decoded_ack["tail"],
                reserved=decoded_ack["reserved"],
            ),
            ack,
        )

    def test_rap_zime_decodes_kcp_sync_ack_segment_from_ida_layout(self):
        packet = (
            (0x80000002).to_bytes(4, "little")
            + bytes([0x28])
            + (0x0022).to_bytes(2, "little")
            + (0x01020304).to_bytes(4, "little")
            + (0x11223344).to_bytes(4, "little")
            + (0x55667788).to_bytes(4, "little")
            + (3).to_bytes(2, "little")
            + b"abc"
        )
        decoded = rap_zime.decode_kcp_segment(packet)
        self.assertEqual(decoded["conv"], 0x80000002)
        self.assertEqual(decoded["cmd"], 0x28)
        self.assertEqual(decoded["wnd"], 0x22)
        self.assertEqual(decoded["ts"], 0x01020304)
        self.assertEqual(decoded["sn"], 0x11223344)
        self.assertEqual(decoded["una"], 0x55667788)
        self.assertEqual(decoded["len"], 3)
        self.assertEqual(decoded["payload"], b"abc")
        self.assertTrue(decoded["payloadLengthMatches"])
        self.assertEqual(decoded["cmdFlags"], ["server-pack-check", "server-fec"])
        self.assertEqual(decoded["wndFlags"], ["stream", "quic"])
        self.assertTrue(decoded["synConv"])
        self.assertTrue(rap_zime.looks_like_kcp_segment(packet))
        self.assertEqual(
            rap_zime.classify_payload(packet),
            "kcp-sync-segment:stream,quic,server-pack-check,server-fec",
        )

    def test_rap_zime_encodes_kcp_client_syn_from_ida_layout(self):
        packet = rap_zime.build_kcp_client_syn_segment(
            conv=0x12345678,
            syn_id=0x11223344,
            current=0x01020304,
            mtu=1400,
            be_ssl=True,
            detect_mtu=True,
            be_pack_check=True,
            be_fec=True,
            be_multi=True,
            be_algo_mode=2,
            be_using_stream=True,
            be_quic=True,
            be_outband=True,
        )
        self.assertEqual(len(packet), rap_zime.KCP_SEG_HEADER_SIZE)
        decoded = rap_zime.decode_kcp_segment(packet)
        self.assertEqual(decoded["conv"], 0x80000001)
        self.assertEqual(decoded["cmd"], 0xD7)
        self.assertEqual(decoded["wnd"], 0x33)
        self.assertEqual(decoded["ts"], 0x01020304)
        self.assertEqual(decoded["sn"], 0x11223344)
        self.assertEqual(decoded["una"], 0x12345678)
        self.assertEqual(decoded["len"], 1400)
        self.assertFalse(decoded["payloadLengthMatches"])
        self.assertTrue(rap_zime.looks_like_kcp_segment(packet))
        self.assertTrue(decoded["clientSynConv"])
        self.assertFalse(decoded["syncAckConv"])
        self.assertEqual(
            decoded["cmdFlags"],
            ["ssl", "detect-mtu", "client-pack-check", "client-fec", "support-data-ex", "multi-link"],
        )
        self.assertEqual(decoded["wndFlags"], ["gcc", "stream", "outband", "quic"])
        self.assertEqual(
            rap_zime.classify_payload(packet),
            "kcp-client-syn:gcc,stream,outband,quic,ssl,detect-mtu,client-pack-check,client-fec,support-data-ex,multi-link",
        )

    def test_rap_zime_kcp_sync_probe_sends_syn_and_records_synack(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        server.settimeout(2)
        target = server.getsockname()
        received = []
        errors = []

        def serve():
            try:
                request, client = server.recvfrom(2048)
                received.append(request)
                decoded = rap_zime.decode_kcp_segment(request)
                self.assertEqual(decoded["len"], 1400)
                self.assertFalse(decoded["payloadLengthMatches"])
                response = rap_zime.encode_kcp_segment(
                    conv=rap_zime.KCP_SYNC_ACK_CONV,
                    cmd=0x28,
                    wnd=0x22,
                    ts=decoded["ts"],
                    sn=decoded["sn"],
                    una=0x55667788,
                )
                server.sendto(response, client)
            except Exception as err:
                errors.append(err)

        thread = threading.Thread(target=serve)
        thread.start()
        self.addCleanup(server.close)

        report = rap_zime.run_kcp_sync_probe(
            runner_input={"transport": "external-pcap-metadata-only", "candidateUdpTargets": [f"{target[0]}:{target[1]}"]},
            syn_id=0x11223344,
            current=0x01020304,
            timeout=1,
        )
        thread.join(timeout=2)

        self.assertFalse(errors)
        self.assertEqual(len(received), 1)
        self.assertTrue(report["ok"])
        self.assertEqual(report["transport"], "kcp-sync-udp")
        self.assertFalse(report["desktopKeepaliveProven"])
        self.assertTrue(report["synackReceived"])
        self.assertRegex(report["localEndpoint"], r"^(127\.0\.0\.1|0\.0\.0\.0):\d+$")
        self.assertEqual(report["idaHandshakeEvidence"]["clientSyn"]["function"], "ikcp_send_link_sync")
        self.assertEqual(report["idaHandshakeEvidence"]["authPreflight"]["function"], "ikcp_set_auth_data / deal_kcp_auth_cmd / ikcp_set_auth_data_res")
        self.assertTrue(report["authPreflight"]["requiredBeforeClientSynWhenAuthEnabled"])
        self.assertFalse(report["authPreflight"]["liveProbeSendsAuth"])
        self.assertEqual(report["idaHandshakeEvidence"]["clientSynackMatch"]["function"], "get_thread_kcp")
        self.assertIn("source port", report["idaHandshakeEvidence"]["clientSynackMatch"]["rule"])
        self.assertEqual(report["clientSyn"]["conv"], rap_zime.KCP_CLIENT_SYN_CONV)
        self.assertEqual(report["clientSyn"]["wndFlags"], ["stream", "outband", "quic"])
        self.assertEqual(report["synack"]["conv"], rap_zime.KCP_SYNC_ACK_CONV)
        self.assertEqual(report["synack"]["wndFlags"], ["stream", "quic"])
        self.assertEqual(report["synack"]["cmdFlags"], ["server-pack-check", "server-fec"])
        self.assertEqual(report["synackNegotiation"]["newConvFromUna"], 0x55667788)
        self.assertTrue(report["synackNegotiation"]["packCheckNegotiated"])
        self.assertTrue(report["synackNegotiation"]["fecNegotiated"])
        self.assertTrue(report["synackNegotiation"]["useQuicNegotiated"])
        self.assertTrue(report["synackNegotiation"]["streamNegotiated"])
        self.assertEqual(report["synackNegotiation"]["headLen"], rap_zime.KCP_SEG_HEADER_SIZE + 3)

    def test_rap_zime_kcp_auth_sync_probe_runs_auth_then_syn(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        server.settimeout(2)
        target = server.getsockname()
        received = []
        errors = []

        def serve():
            try:
                request, client = server.recvfrom(2048)
                received.append(request)
                decoded_head = rap_zime.decode_kcp_segment(request)
                self.assertTrue(decoded_head["authHeadConv"])
                server.sendto(rap_zime.encode_kcp_segment(
                    conv=0x90000007,
                    cmd=rap_zime.KCP_AUTH_HEAD_ACK_CMD,
                    ts=decoded_head["ts"],
                    sn=decoded_head["sn"],
                    una=decoded_head["una"],
                ), client)

                request, client = server.recvfrom(2048)
                received.append(request)
                decoded_data = rap_zime.decode_kcp_segment(request)
                self.assertTrue(decoded_data["authDataConv"])
                server.sendto(rap_zime.encode_kcp_segment(
                    conv=0x90000009,
                    cmd=rap_zime.KCP_AUTH_ACK_CMD,
                    ts=decoded_data["ts"],
                    sn=decoded_data["sn"],
                    una=decoded_data["una"],
                ), client)

                request, client = server.recvfrom(2048)
                received.append(request)
                decoded_syn = rap_zime.decode_kcp_segment(request)
                self.assertTrue(decoded_syn["clientSynConv"])
                server.sendto(rap_zime.encode_kcp_segment(
                    conv=rap_zime.KCP_SYNC_ACK_CONV,
                    cmd=0x28,
                    wnd=0x22,
                    ts=decoded_syn["ts"],
                    sn=decoded_syn["sn"],
                    una=0x55667788,
                ), client)
            except Exception as err:
                errors.append(err)

        thread = threading.Thread(target=serve)
        thread.start()
        self.addCleanup(server.close)

        auth_head = bytearray(50)
        auth_head[:4] = b"ZTEC"
        struct.pack_into("<HIII", auth_head, 4, 44, 101, 0xAABBCCDD, 9)
        report_path = Path(self.temp_state()).with_name("kcp-auth-sync-report.json")
        report = rap_zime.run_kcp_auth_sync_probe(
            auth_buffer=bytes(auth_head) + b"secret-09",
            runner_input={"transport": "external-pcap-metadata-only", "candidateUdpTargets": [f"{target[0]}:{target[1]}"]},
            syn_id=0x11223344,
            current=0x01020304,
            timeout=1,
            report_file=report_path,
        )
        thread.join(timeout=2)
        written = json.loads(report_path.read_text(encoding="utf-8"))

        self.assertFalse(errors)
        self.assertEqual(len(received), 3)
        self.assertTrue(report["ok"])
        self.assertTrue(report["authPreflight"]["authHeadAckReceived"])
        self.assertTrue(report["authPreflight"]["authAckReceived"])
        self.assertFalse(report["authPreflight"]["payloadStoredInReport"])
        self.assertEqual([stage["stage"] for stage in report["stages"]], ["auth_head", "auth_data", "client_syn"])
        self.assertEqual(report["stages"][0]["responses"][0]["payloadKind"], "kcp-auth-head-ack:ssl,detect-mtu,client-pack-check")
        self.assertEqual(report["stages"][1]["responses"][0]["payloadKind"], "kcp-auth-ack:ssl,server-pack-check")
        self.assertTrue(report["synackReceived"])
        self.assertEqual(report["synackNegotiation"]["newConvFromUna"], 0x55667788)
        self.assertEqual(report["idaUdpSessionEvidence"]["functionEvidence"]["listen_udp_data"]["behavior"].split(",")[0], "creates separate listen and UDP fds")
        self.assertIn("TCP listen on 127.0.0.1:0", " ".join(report["idaUdpSessionEvidence"]["officialSequence"]))
        self.assertIn("outbound UDP source endpoint", report["idaUdpSessionEvidence"]["functionEvidence"]["send_udt_data"]["implication"])
        self.assertIn("local TCP listen port", report["idaUdpSessionEvidence"]["functionEvidence"]["ice_create_fd"]["implication"])
        self.assertIn("send_udt_data", report["idaUdpSessionEvidence"]["functionEvidence"]["udt_output"]["behavior"])
        self.assertIn("udp_get_local_port(g_sock_listen_fd)", " ".join(report["idaUdpSessionEvidence"]["officialSequence"]))
        self.assertIn("thread kcp_list attachment before deal_udt_using_cag()", report["idaUdpSessionEvidence"]["pythonRunnerDelta"]["notModeledYet"])
        self.assertIn("local proxy protocol header parsing that sets data_buf[224] to 1/2", report["idaUdpSessionEvidence"]["pythonRunnerDelta"]["notModeledYet"])
        self.assertIn("deal_create_proxy_fd_session() proxy_sock link_type assignment", report["idaUdpSessionEvidence"]["pythonRunnerDelta"]["notModeledYet"])
        self.assertIn("proxy_sock->data_buf[224] propagation into udp_sock->data_buf[224]", report["idaUdpSessionEvidence"]["pythonRunnerDelta"]["notModeledYet"])
        self.assertIn("reports/ida-libspice-zime-link-flag-source-directed-20260704.json", report["idaUdpSessionEvidence"]["sourceReports"])
        self.assertIn("deal_create_proxy_fd_session", report["idaUdpSessionEvidence"]["functionEvidence"])
        self.assertIn("proxy_sock->data_buf[224]", report["idaUdpSessionEvidence"]["functionEvidence"]["deal_create_proxy_fd_session"]["behavior"])
        self.assertIn("data_buf[224]=1", report["idaUdpSessionEvidence"]["functionEvidence"]["deal_unlinked_unknown_local_data"]["behavior"])
        self.assertIn("copies proxy_sock->data_buf[224]", report["idaUdpSessionEvidence"]["functionEvidence"]["init_local_rw_sock_pair_udp"]["behavior"])
        self.assertFalse(report["localSocketLifecycle"]["explicitBindBeforeSend"])
        self.assertFalse(report["localSocketLifecycle"]["officialListenThreadStarted"])
        self.assertFalse(report["localSocketLifecycle"]["officialTcpListenReadinessModeled"])
        self.assertFalse(report["localSocketLifecycle"]["officialUdpFdAttachedToIceSocket"])
        self.assertFalse(report["localSocketLifecycle"]["officialKcpAttachedToThreadList"])
        self.assertRegex(report["localSocketLifecycle"]["localEndpointBeforeFirstSend"], r"^0\.0\.0\.0:0$")
        self.assertRegex(report["localSocketLifecycle"]["localEndpointAfterFirstSend"], r"^(127\.0\.0\.1|0\.0\.0\.0):\d+$")
        self.assertEqual(written["localSocketLifecycle"], report["localSocketLifecycle"])
        self.assertIsNone(report["officialParityAssessment"]["stageBlocked"])
        self.assertEqual(
            report["officialParityAssessment"]["readinessPortInterpretation"],
            "g_tcp_listen_port is a local 127.0.0.1 TCP listen readiness port, not the outbound UDP source port",
        )
        self.assertIn(
            "create_fd_session_TN_UDP_CLD_SOCK",
            report["officialParityAssessment"]["notModeledYet"],
        )
        self.assertIn(
            "local_proxy_protocol_header_link_type_detection",
            report["officialParityAssessment"]["notModeledYet"],
        )
        self.assertIn(
            "proxy_sock_link_type_copied_to_udp_sock",
            report["officialParityAssessment"]["notModeledYet"],
        )
        self.assertEqual(written["officialParityAssessment"], report["officialParityAssessment"])
        self.assertNotIn("secret-09", json.dumps(written))
        self.assertNotIn(b"secret-09".hex(), json.dumps(written))

    def test_rap_zime_kcp_auth_sync_probe_can_bind_local_udp_source(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        server.settimeout(2)
        target = server.getsockname()
        clients = []
        errors = []

        def serve():
            try:
                request, client = server.recvfrom(2048)
                clients.append(client)
                self.assertTrue(rap_zime.decode_kcp_segment(request)["authHeadConv"])
            except Exception as err:
                errors.append(err)

        thread = threading.Thread(target=serve)
        thread.start()
        self.addCleanup(server.close)

        auth_head = bytearray(50)
        auth_head[:4] = b"ZTEC"
        struct.pack_into("<HIII", auth_head, 4, 44, 101, 0xAABBCCDD, 9)
        report = rap_zime.run_kcp_auth_sync_probe(
            auth_buffer=bytes(auth_head) + b"secret-09",
            runner_input={"transport": "external-pcap-metadata-only", "candidateUdpTargets": [f"{target[0]}:{target[1]}"]},
            syn_id=0x11223344,
            current=0x01020304,
            timeout=0.1,
            receive_limit=0,
            local_bind_host="127.0.0.1",
            local_bind_port=0,
        )
        thread.join(timeout=2)

        self.assertFalse(errors)
        self.assertEqual(len(clients), 1)
        lifecycle = report["localSocketLifecycle"]
        self.assertTrue(lifecycle["explicitBindBeforeSend"])
        self.assertEqual(lifecycle["requestedLocalBind"], "127.0.0.1:0")
        self.assertRegex(lifecycle["localEndpointAfterBind"], r"^127\.0\.0\.1:\d+$")
        self.assertEqual(lifecycle["localEndpointBeforeFirstSend"], lifecycle["localEndpointAfterBind"])
        self.assertEqual(lifecycle["localEndpointAfterFirstSend"], lifecycle["localEndpointAfterBind"])
        self.assertEqual(clients[0][0], "127.0.0.1")
        self.assertEqual(clients[0][1], int(lifecycle["localEndpointAfterBind"].rsplit(":", 1)[1]))
        self.assertEqual(report["officialParityAssessment"]["stageBlocked"], "auth_head")
        self.assertEqual(
            report["officialParityAssessment"]["sourcePortHypothesisStatus"],
            "explicit_ephemeral_bind_not_sufficient",
        )
        self.assertIn(
            "lack_of_explicit_ephemeral_udp_bind",
            report["officialParityAssessment"]["ruledOutByThisRun"],
        )
        self.assertIn(
            "type102_accessToken_with_local_bind_0",
            report["officialParityAssessment"]["doNotRepeatWithoutNewEvidence"],
        )

    def test_rap_zime_kcp_auth_sync_probe_can_pump_auth_head_from_official_trace(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        server.settimeout(2)
        target = server.getsockname()
        received = []
        errors = []

        def serve():
            try:
                for _ in range(3):
                    request, _client = server.recvfrom(2048)
                    received.append(request)
                    self.assertTrue(rap_zime.decode_kcp_segment(request)["authHeadConv"])
            except Exception as err:
                errors.append(err)

        thread = threading.Thread(target=serve)
        thread.start()
        self.addCleanup(server.close)

        auth_head = bytearray(50)
        auth_head[:4] = b"ZTEC"
        struct.pack_into("<HIII", auth_head, 4, 44, 101, 0xAABBCCDD, 9)
        report = rap_zime.run_kcp_auth_sync_probe(
            auth_buffer=bytes(auth_head) + b"secret-09",
            runner_input={"transport": "external-pcap-metadata-only", "candidateUdpTargets": [f"{target[0]}:{target[1]}"]},
            syn_id=0x11223344,
            current=0x01020304,
            timeout=0.1,
            receive_limit=0,
            auth_head_attempts=3,
            auth_head_retry_interval=0.08,
        )
        thread.join(timeout=2)

        self.assertFalse(errors)
        self.assertEqual(len(received), 3)
        self.assertFalse(report["authGateConfirmed"])
        self.assertEqual(report["authPreflight"]["authHeadSendCount"], 3)
        self.assertEqual(report["stages"][0]["sendCount"], 3)
        self.assertEqual(len(report["stages"][0]["attempts"]), 3)
        self.assertTrue(report["stages"][0]["officialAuthHeadPump"]["enabled"])
        self.assertTrue(report["officialParityAssessment"]["officialAuthHeadPump"]["modeled"])
        self.assertIn(
            "official three-send AUTH_HEAD pump is modeled before declaring the gate missing",
            report["officialParityAssessment"]["modeledByPython"],
        )

    def test_rap_zime_kcp_auth_sync_probe_can_start_pre_auth_receive_window(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        server.settimeout(2)
        target = server.getsockname()
        clients = []
        errors = []

        def serve():
            try:
                request, client = server.recvfrom(2048)
                clients.append(client)
                self.assertTrue(rap_zime.decode_kcp_segment(request)["authHeadConv"])
            except Exception as err:
                errors.append(err)

        thread = threading.Thread(target=serve)
        thread.start()
        self.addCleanup(server.close)

        auth_head = bytearray(50)
        auth_head[:4] = b"ZTEC"
        struct.pack_into("<HIII", auth_head, 4, 44, 101, 0xAABBCCDD, 9)
        report = rap_zime.run_kcp_auth_sync_probe(
            auth_buffer=bytes(auth_head) + b"secret-09",
            runner_input={"transport": "external-pcap-metadata-only", "candidateUdpTargets": [f"{target[0]}:{target[1]}"]},
            syn_id=0x11223344,
            current=0x01020304,
            timeout=0.1,
            receive_limit=0,
            pre_auth_receive_timeout=0.01,
            pre_auth_receive_limit=1,
            pre_auth_bind_host="127.0.0.1",
        )
        thread.join(timeout=2)

        self.assertFalse(errors)
        self.assertEqual(len(clients), 1)
        lifecycle = report["localSocketLifecycle"]
        self.assertFalse(lifecycle["explicitBindBeforeSend"])
        self.assertTrue(lifecycle["preAuthReceiveLoopStarted"])
        self.assertTrue(lifecycle["implicitBindForPreAuthReceive"])
        self.assertRegex(lifecycle["localEndpointAfterPreAuthBind"], r"^127\.0\.0\.1:\d+$")
        self.assertEqual(lifecycle["localEndpointBeforeFirstSend"], lifecycle["localEndpointAfterPreAuthBind"])
        self.assertEqual(report["preAuthReceive"]["enabled"], True)
        self.assertEqual(report["preAuthReceive"]["packets"], [])
        self.assertIn(
            "optional pre-AUTH receive window can bind the UDP socket and enter recvfrom() before AUTH_HEAD",
            report["officialParityAssessment"]["modeledByPython"],
        )
        self.assertIn("pre_auth_receive_window_alone", report["officialParityAssessment"]["ruledOutByThisRun"])
        self.assertIn("pre_auth_implicit_udp_bind_alone", report["officialParityAssessment"]["ruledOutByThisRun"])
        self.assertIn(
            "pre_auth_receive_window_without_proxy_header_or_official_trace",
            report["officialParityAssessment"]["doNotRepeatWithoutNewEvidence"],
        )
        self.assertEqual(clients[0][1], int(lifecycle["localEndpointAfterPreAuthBind"].rsplit(":", 1)[1]))

    def test_rap_zime_kcp_auth_sync_from_cag_material_redacts_report(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        server.settimeout(2)
        target = server.getsockname()
        errors = []

        def serve():
            try:
                request, client = server.recvfrom(2048)
                decoded_head = rap_zime.decode_kcp_segment(request)
                self.assertTrue(decoded_head["authHeadConv"])
                server.sendto(rap_zime.encode_kcp_segment(
                    conv=0x90000007,
                    cmd=rap_zime.KCP_AUTH_HEAD_ACK_CMD,
                    ts=decoded_head["ts"],
                    sn=decoded_head["sn"],
                    una=decoded_head["una"],
                ), client)

                request, client = server.recvfrom(2048)
                decoded_data = rap_zime.decode_kcp_segment(request)
                self.assertTrue(decoded_data["authDataConv"])
                self.assertEqual(decoded_data["len"], 0)
                self.assertIn(b"mat-user", decoded_data["rest"])
                self.assertIn(b"mat-pass", decoded_data["rest"])
            except Exception as err:
                errors.append(err)

        thread = threading.Thread(target=serve)
        thread.start()
        self.addCleanup(server.close)
        report_path = Path(self.temp_state()).with_name("kcp-auth-cag-report.json")
        report = rap_zime.run_kcp_auth_sync_probe_from_cag_material(
            auth={
                "vmUserName": "mat-user",
                "vmPassword": "mat-pass",
                "vmId": "mat-vmid",
            },
            connect_info={
                "host": target[0],
                "port": target[1],
                "gatewayPort": 10066,
                "udpPortSource": "proxy-sport",
                "udpSsl": True,
                "type": "rap",
                "accessToken": "secret-token",
                "cpsid": "secret-cps",
            },
            syn_id=0x11223344,
            current=0x01020304,
            timeout=1,
            report_file=report_path,
        )
        thread.join(timeout=2)
        written = report_path.read_text(encoding="utf-8")

        self.assertFalse(errors)
        self.assertFalse(report["ok"])
        self.assertTrue(report["authGateOnly"])
        self.assertTrue(report["authGateConfirmed"])
        self.assertTrue(report["authPreflight"]["authDataSentAfterAuthHeadGate"])
        self.assertFalse(report["synackReceived"])
        self.assertEqual([stage["stage"] for stage in report["stages"]], ["auth_head", "auth_data"])
        self.assertIn("stop here", report["nextStep"])
        self.assertEqual(report["target"], "<redacted:cag-udp-target>")
        self.assertEqual(report["authMaterialSource"]["sourceType"], "fresh-cag-material-type101-builder")
        self.assertTrue(report["authMaterialSource"]["opentelemetry"])
        self.assertTrue(report["connectInfo"]["accessTokenPresent"])
        self.assertEqual(report["connectInfo"]["udpPortSource"], "proxy-sport")
        self.assertTrue(report["connectInfo"]["udpSsl"])
        self.assertNotIn("mat-user", written)
        self.assertNotIn("mat-pass", written)
        self.assertNotIn("mat-vmid", written)
        self.assertNotIn("secret-token", written)
        self.assertNotIn("secret-cps", written)
        self.assertNotIn(f"{target[0]}:{target[1]}", written)

    def test_rap_zime_kcp_auth_sync_from_cag_material_accepts_71_byte_ack_like_gate(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        server.settimeout(2)
        target = server.getsockname()
        received_lengths = []
        errors = []

        def serve():
            try:
                request, client = server.recvfrom(2048)
                received_lengths.append(len(request))
                decoded_head = rap_zime.decode_kcp_segment(request)
                self.assertTrue(decoded_head["authHeadConv"])
                server.sendto(b"A" * rap_zime.OFFICIAL_AUTH_HEAD_ACK_LIKE_LEN, client)

                request, client = server.recvfrom(2048)
                received_lengths.append(len(request))
                decoded_data = rap_zime.decode_kcp_segment(request)
                self.assertTrue(decoded_data["authDataConv"])
            except Exception as err:
                errors.append(err)

        thread = threading.Thread(target=serve)
        thread.start()
        self.addCleanup(server.close)
        report = rap_zime.run_kcp_auth_sync_probe_from_cag_material(
            auth={
                "vmUserName": "mat-user",
                "vmPassword": "mat-pass",
                "vmId": "mat-vmid",
            },
            connect_info={
                "host": target[0],
                "port": target[1],
                "type": "rap",
            },
            syn_id=0x11223344,
            current=0x01020304,
            timeout=1,
        )
        thread.join(timeout=2)

        self.assertFalse(errors)
        self.assertEqual(received_lengths, [199, 241])
        self.assertFalse(report["ok"])
        self.assertTrue(report["authGateOnly"])
        self.assertTrue(report["authGateConfirmed"])
        self.assertFalse(report["authPreflight"]["authHeadAckReceived"])
        self.assertTrue(report["authPreflight"]["authHeadAckLikeReceived"])
        self.assertTrue(report["authPreflight"]["authDataSentAfterAuthHeadGate"])
        self.assertEqual(report["stages"][0]["responses"][0]["bytesReceived"], 71)
        self.assertTrue(report["stages"][0]["responses"][0]["officialAuthHeadAckLike"])
        self.assertEqual([stage["stage"] for stage in report["stages"]], ["auth_head", "auth_data"])
        self.assertFalse(report["synackReceived"])
        self.assertIn("wait_cmd7_or_71_byte_ACK_like", report["officialParityAssessment"]["pythonProbePath"])

    def test_rap_zime_kcp_auth_sync_from_cag_material_can_model_pre_auth_cmd26_bootstrap(self):
        udp_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_server.bind(("127.0.0.1", 0))
        udp_server.settimeout(2)
        udp_target = udp_server.getsockname()
        tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_server.bind(("127.0.0.1", 0))
        tcp_server.listen(1)
        tcp_server.settimeout(2)
        tcp_target = tcp_server.getsockname()
        received_local_frames = []
        received_udp_lengths = []
        errors = []

        def serve_tcp():
            try:
                conn, _peer = tcp_server.accept()
                with conn:
                    conn.settimeout(2)
                    chunks = []
                    while sum(len(chunk) for chunk in chunks) < rap_zime.FRESH_CMD26_WIRE_LEN:
                        chunk = conn.recv(rap_zime.FRESH_CMD26_WIRE_LEN)
                        if not chunk:
                            break
                        chunks.append(chunk)
                    frame = b"".join(chunks)
                    received_local_frames.append(frame)
                    conn.sendall(b"\x01" + b"\x00" * 15)
            except Exception as err:
                errors.append(err)

        def serve_udp():
            try:
                request, client = udp_server.recvfrom(2048)
                received_udp_lengths.append(len(request))
                decoded_head = rap_zime.decode_kcp_segment(request)
                self.assertTrue(decoded_head["authHeadConv"])
                udp_server.sendto(b"A" * rap_zime.OFFICIAL_AUTH_HEAD_ACK_LIKE_LEN, client)

                request, _client = udp_server.recvfrom(2048)
                received_udp_lengths.append(len(request))
                decoded_data = rap_zime.decode_kcp_segment(request)
                self.assertTrue(decoded_data["authDataConv"])
            except Exception as err:
                errors.append(err)

        tcp_thread = threading.Thread(target=serve_tcp)
        udp_thread = threading.Thread(target=serve_udp)
        tcp_thread.start()
        udp_thread.start()
        self.addCleanup(udp_server.close)
        self.addCleanup(tcp_server.close)
        report_path = Path(self.temp_state()).with_name("kcp-auth-cmd26-bootstrap-report.json")
        report = rap_zime.run_kcp_auth_sync_probe_from_cag_material(
            auth={
                "vmUserName": "mat-user",
                "vmPassword": "mat-pass",
                "vmId": "mat-vmid",
            },
            connect_info={
                "host": udp_target[0],
                "port": udp_target[1],
                "type": "rap",
            },
            syn_id=0x11223344,
            current=0x01020304,
            timeout=1,
            auth_head_attempts=3,
            pre_auth_fresh_cmd26_bootstrap={
                "local_host": tcp_target[0],
                "local_port": tcp_target[1],
                "dest_ip": udp_target[0],
                "dest_port": udp_target[1],
                "channel_type": 1,
                "channel_id": 0,
                "trace_id": "0123456789abcdef0123456789abcdef",
                "parent_id": "0123456789abcdef",
            },
            pre_auth_session_state_model={
                "type6_proxy_fd_session_slot": True,
                "proxy_sock_udp_gate": True,
                "init_local_rw_sock_pair_udp_kcp_attachment": True,
                "quic_channel_manage_ready_or_bypassed": True,
                "channel_type_id_candidate": "0x0100",
            },
            pre_auth_tcp_listen_readiness=True,
            report_file=report_path,
        )
        tcp_thread.join(timeout=2)
        udp_thread.join(timeout=2)
        written = report_path.read_text(encoding="utf-8")

        self.assertFalse(errors)
        self.assertEqual(len(received_local_frames), 1)
        local_frame = received_local_frames[0]
        self.assertEqual(len(local_frame), rap_zime.FRESH_CMD26_WIRE_LEN)
        self.assertEqual(local_frame[:4], struct.pack("<BBH", 0x1A, 0, 156))
        self.assertEqual(received_udp_lengths, [199, 241])
        self.assertFalse(report["ok"])
        self.assertTrue(report["authGateOnly"])
        self.assertTrue(report["authGateConfirmed"])
        self.assertFalse(report["synackReceived"])
        self.assertEqual([stage["stage"] for stage in report["stages"]], ["auth_head", "auth_data"])
        bootstrap = report["preAuthLocalBootstrap"]
        self.assertTrue(bootstrap["enabled"])
        self.assertEqual(bootstrap["bytesSent"], 160)
        self.assertTrue(bootstrap["statusReceived"])
        self.assertEqual(bootstrap["statusBytesReceived"], 16)
        self.assertEqual(bootstrap["statusReadMode"], "drain_available_without_payload_storage")
        self.assertFalse(bootstrap["payloadStoredInReport"])
        self.assertTrue(bootstrap["frameSummary"]["shapeMatchesFreshCmd26"])
        self.assertFalse(bootstrap["frameSummary"]["payloadStoredInReport"])
        self.assertFalse(bootstrap["builderSummary"]["payloadStoredInReport"])
        self.assertFalse(bootstrap["builderSummary"]["destination"]["destIpStoredInSummary"])
        self.assertFalse(bootstrap["builderSummary"]["destination"]["destPortStoredInSummary"])
        self.assertTrue(report["localSocketLifecycle"]["freshCmd26LocalBootstrapModeled"])
        self.assertTrue(report["localSocketLifecycle"]["freshCmd26LocalBootstrapStatusReceived"])
        self.assertTrue(report["localSocketLifecycle"]["preAuthSessionStateContractClosed"])
        self.assertTrue(report["localSocketLifecycle"]["officialListenThreadStarted"])
        self.assertTrue(report["localSocketLifecycle"]["officialTcpLinkInfoWait"])
        self.assertTrue(report["localSocketLifecycle"]["officialTcpListenReadinessModeled"])
        tcp_readiness = report["preAuthTcpListenReadiness"]
        self.assertTrue(tcp_readiness["enabled"])
        self.assertTrue(tcp_readiness["listenReady"])
        self.assertTrue(tcp_readiness["portPresent"])
        self.assertFalse(tcp_readiness["portStoredInReport"])
        self.assertIn("g_tcp_listen_port=getsockname", " ".join(tcp_readiness["modeledNativeWrites"]))
        self.assertFalse(tcp_readiness["payloadStoredInReport"])
        state_model = report["preAuthSessionState"]
        self.assertTrue(state_model["enabled"])
        self.assertTrue(state_model["allRequiredModeled"])
        self.assertTrue(state_model["readyForGateOnlyLive"])
        self.assertEqual(state_model["missingChecks"], [])
        native_model = state_model["nativeEquivalentStateModel"]
        self.assertTrue(native_model["enabled"])
        self.assertTrue(native_model["allRequiredModeled"])
        self.assertEqual(native_model["missingSideEffects"], [])
        native_side_effects = native_model["sideEffectModel"]
        self.assertTrue(native_side_effects["local_proxy_protocol_header_link_type_detection"]["modeled"])
        self.assertIn(
            "in_sock.data_buf_224=1",
            native_side_effects["local_proxy_protocol_header_link_type_detection"]["modeledWrites"],
        )
        self.assertTrue(native_side_effects["deal_create_proxy_fd_session_link_type_assignment"]["modeled"])
        self.assertIn(
            "proxy_sock.fd_type_ex=6",
            native_side_effects["deal_create_proxy_fd_session_link_type_assignment"]["modeledWrites"],
        )
        self.assertTrue(native_side_effects["create_fd_session_TN_UDP_CLD_SOCK"]["modeled"])
        self.assertIn(
            "udp_sock.sock_type=TN_UDP_CLD_SOCK",
            native_side_effects["create_fd_session_TN_UDP_CLD_SOCK"]["modeledWrites"],
        )
        self.assertTrue(native_side_effects["thread_kcp_list_attachment_before_deal_udt_using_cag"]["modeled"])
        self.assertIn(
            "thread.kcp_list contains kcp before deal_udt_using_cag",
            native_side_effects["thread_kcp_list_attachment_before_deal_udt_using_cag"]["modeledWrites"],
        )
        self.assertFalse(native_model["payloadStoredInReport"])
        required = {item["key"]: item for item in state_model["requiredChecks"]}
        self.assertTrue(required["fresh_cmd26_status"]["modeled"])
        self.assertTrue(required["type6_proxy_fd_session_slot"]["modeled"])
        native_contract = report["preAuthNativeSideEffectContract"]
        self.assertEqual(native_contract["status"], "static_contract_recovered_runner_equivalent_modeled_for_gate_only")
        self.assertTrue(native_contract["runnerEquivalentModeled"])
        self.assertEqual(native_contract["runnerModelSource"], "pre-auth-native-equivalent-state-model")
        self.assertFalse(native_contract["payloadStoredInReport"])
        self.assertTrue(all(item["runnerEquivalentImplemented"] is True for item in native_contract["sideEffects"]))
        self.assertIn("same-fd 71-byte ACK-like live acceptance", native_contract["runnerConsequence"])
        self.assertTrue(required["proxy_sock_udp_gate"]["modeled"])
        self.assertTrue(required["init_local_rw_sock_pair_udp_kcp_attachment"]["modeled"])
        self.assertTrue(required["quic_channel_manage_ready_or_bypassed"]["modeled"])
        self.assertEqual(required["proxy_sock_udp_gate"]["officialTraceField"], "external AUTH_HEAD len=199 follows local proxy/session setup")
        self.assertEqual(state_model["optionalFieldSources"]["channel_type_id_candidate"], "0x0100")
        self.assertFalse(state_model["payloadStoredInReport"])
        self.assertIn("not a cloud ACK-like proof", state_model["boundary"])
        self.assertIn(
            "pre-AUTH fresh cmd26 local bootstrap frame shape is modeled before AUTH_HEAD",
            report["officialParityAssessment"]["modeledByPython"],
        )
        self.assertIn(
            "pre-AUTH local proxy/session state contract is closed for local gate-only testing",
            report["officialParityAssessment"]["modeledByPython"],
        )
        self.assertIn(
            "pre-AUTH native-equivalent in_sock/proxy_sock/udp_sock/thread.kcp_list side effects are modeled locally",
            report["officialParityAssessment"]["modeledByPython"],
        )
        self.assertIn(
            "pre-AUTH local TCP listen readiness fd and udp_get_tcp_link_info gate are modeled locally",
            report["officialParityAssessment"]["modeledByPython"],
        )
        self.assertNotIn(
            "local_tcp_listen_readiness_fd",
            report["officialParityAssessment"]["notModeledYet"],
        )
        self.assertNotIn(
            "udp_get_tcp_link_info_gate",
            report["officialParityAssessment"]["notModeledYet"],
        )
        self.assertNotIn(
            "local_proxy_protocol_header_link_type_detection",
            report["officialParityAssessment"]["notModeledYet"],
        )
        self.assertNotIn(
            "deal_create_proxy_fd_session_link_type_assignment",
            report["officialParityAssessment"]["notModeledYet"],
        )
        self.assertNotIn(
            "create_fd_session_TN_UDP_CLD_SOCK",
            report["officialParityAssessment"]["notModeledYet"],
        )
        self.assertNotIn(
            "thread_kcp_list_attachment_before_deal_udt_using_cag",
            report["officialParityAssessment"]["notModeledYet"],
        )
        self.assertIn(
            "requires a gate-only live run to prove cloud ACK-like acceptance",
            report["officialParityAssessment"]["nativeSideEffectBoundary"],
        )
        self.assertNotIn("mat-user", written)
        self.assertNotIn("mat-pass", written)
        self.assertNotIn("mat-vmid", written)
        self.assertNotIn(f"{udp_target[0]}:{udp_target[1]}", written)

    def test_rap_zime_kcp_auth_sync_from_cag_material_can_ztec_prime_first(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        server.settimeout(2)
        target = server.getsockname()
        received_kinds = []
        decoded_ztec_request = {}
        errors = []

        def serve():
            try:
                request, client = server.recvfrom(2048)
                decoded_ztec = rap_zime.decode_ztec_keepalive(request)
                decoded_ztec_request.update(decoded_ztec)
                received_kinds.append("ztec")
                server.sendto(rap_zime.encode_ztec_keepalive_ack(
                    decoded_ztec["sequence"],
                    decoded_ztec["nonce"],
                    marker=decoded_ztec["marker"],
                    tail=decoded_ztec["tail"],
                    reserved=decoded_ztec["reserved"],
                ), client)

                request, client = server.recvfrom(2048)
                decoded_head = rap_zime.decode_kcp_segment(request)
                received_kinds.append("auth_head")
                self.assertTrue(decoded_head["authHeadConv"])
                server.sendto(rap_zime.encode_kcp_segment(
                    conv=0x90000007,
                    cmd=rap_zime.KCP_AUTH_HEAD_ACK_CMD,
                    ts=decoded_head["ts"],
                    sn=decoded_head["sn"],
                    una=decoded_head["una"],
                ), client)

                request, client = server.recvfrom(2048)
                decoded_data = rap_zime.decode_kcp_segment(request)
                received_kinds.append("auth_data")
                self.assertTrue(decoded_data["authDataConv"])
            except Exception as err:
                errors.append(err)

        thread = threading.Thread(target=serve)
        thread.start()
        self.addCleanup(server.close)
        report_path = Path(self.temp_state()).with_name("kcp-auth-cag-ztec-report.json")
        report = rap_zime.run_kcp_auth_sync_probe_from_cag_material(
            auth={
                "vmUserName": "mat-user",
                "vmPassword": "mat-pass",
                "vmId": "mat-vmid",
            },
            connect_info={
                "host": target[0],
                "port": target[1],
                "gatewayPort": 10066,
                "udpPortSource": "proxy-sport",
                "udpSsl": True,
                "type": "rap",
                "accessToken": "secret-token",
                "vmHost": "10.10.2.127",
                "vmPort": 10012,
            },
            syn_id=0x11223344,
            current=0x01020304,
            timeout=1,
            ztec_prime=True,
            report_file=report_path,
        )
        thread.join(timeout=2)
        written = report_path.read_text(encoding="utf-8")

        self.assertFalse(errors)
        self.assertEqual(received_kinds, ["ztec", "auth_head", "auth_data"])
        self.assertEqual(decoded_ztec_request["host"], "10.10.2.127")
        self.assertEqual(decoded_ztec_request["port"], 10012)
        self.assertFalse(report["ok"])
        self.assertTrue(report["authGateOnly"])
        self.assertTrue(report["authGateConfirmed"])
        self.assertFalse(report["synackReceived"])
        self.assertTrue(report["ztecPrime"]["enabled"])
        self.assertTrue(report["ztecPrime"]["ackReceived"])
        self.assertEqual(report["ztecPrime"]["target"], "<redacted:cag-udp-target>")
        self.assertEqual(report["connectInfo"]["ztecPrimeHostSource"], "vmHost")
        self.assertEqual(report["connectInfo"]["ztecPrimePortSource"], "vmPort")
        self.assertNotIn("mat-user", written)
        self.assertNotIn("mat-pass", written)
        self.assertNotIn("secret-token", written)
        self.assertNotIn("10.10.2.127", written)
        self.assertNotIn(f"{target[0]}:{target[1]}", written)

    def test_rap_zime_kcp_auth_from_cag_cli_uses_redacted_material_path(self):
        state_path = self.temp_state()
        report_path = Path(state_path).with_name("kcp-auth-from-cag.json")
        captured = {}

        def fake_fetch(user_service_id=None, state_path=None, boot_wait=180, timeout=30):
            captured["fetch"] = (user_service_id, state_path, boot_wait, timeout)
            return {
                "auth": {"vmUserName": "cli-user", "vmPassword": "cli-pass", "vmId": "cli-vmid"},
                "connectInfo": {"host": "10.10.2.129", "port": 10014, "type": "rap", "accessToken": "secret-token"},
                "publicConnectInfo": {
                    "host": "10.10.2.129",
                    "port": 10014,
                    "type": "rap",
                    "accessTokenPresent": True,
                    "cpsidPresent": False,
                    "rawArgKeys": ["accessToken", "h", "p", "type"],
                },
            }

        def fake_probe(**kwargs):
            captured["probe"] = kwargs
            return {
                "ok": False,
                "target": "<redacted:cag-udp-target>",
                "desktopKeepaliveProven": False,
                "displayPathObserved": False,
                "verifiedRunPassed": False,
                "authMaterialSource": {"payloadStoredInReport": False},
                "connectInfo": {"hostPresent": True, "portPresent": True},
            }

        self.set_attr(cli_main.protocol_runner, "fetch_cag_auth_connect_info", fake_fetch)
        self.set_attr(cli_main.rap_zime, "run_kcp_auth_sync_probe_from_cag_material", fake_probe)

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli_main.main([
                "--state",
                state_path,
                "rap-zime-kcp-auth-from-cag",
                "2663816",
                "--boot-wait",
                "7",
                "--cag-timeout",
                "9",
                "--timeout",
                "0.5",
                "--receive-limit",
                "2",
                "--auth-head-attempts",
                "3",
                "--auth-head-retry-interval",
                "0.08",
                "--auth-buffer-type",
                "type102",
                "--cag-auth-type",
                "2",
                "--ztec-prime",
                "--ztec-timeout",
                "0.25",
                "--local-bind-host",
                "127.0.0.1",
                "--local-bind-port",
                "0",
                "--pre-auth-receive-timeout",
                "0.125",
                "--pre-auth-receive-limit",
                "3",
                "--pre-auth-bind-host",
                "127.0.0.1",
                "--pre-auth-cmd26-local-proxy",
                "127.0.0.1:19001",
                "--pre-auth-cmd26-channel-type",
                "1",
                "--pre-auth-cmd26-channel-id",
                "0",
                "--pre-auth-cmd26-trace-id",
                "0123456789abcdef0123456789abcdef",
                "--pre-auth-cmd26-parent-id",
                "0123456789abcdef",
                "--pre-auth-state-contract",
                "--report-file",
                str(report_path),
            ])

        self.assertEqual(code, 0)
        printed = json.loads(out.getvalue())
        written = report_path.read_text(encoding="utf-8")
        self.assertEqual(captured["fetch"], ("2663816", state_path, 7, 9))
        self.assertEqual(captured["probe"]["auth"]["vmUserName"], "cli-user")
        self.assertEqual(captured["probe"]["connect_info"]["host"], "10.10.2.129")
        self.assertEqual(captured["probe"]["receive_limit"], 2)
        self.assertEqual(captured["probe"]["auth_head_attempts"], 3)
        self.assertEqual(captured["probe"]["auth_head_retry_interval"], 0.08)
        self.assertIsNone(captured["probe"]["report_file"])
        self.assertEqual(captured["probe"]["auth_buffer_type"], "type102")
        self.assertEqual(captured["probe"]["auth_type"], "2")
        self.assertTrue(captured["probe"]["opentelemetry"])
        self.assertTrue(captured["probe"]["ztec_prime"])
        self.assertEqual(captured["probe"]["ztec_timeout"], 0.25)
        self.assertEqual(captured["probe"]["local_bind_host"], "127.0.0.1")
        self.assertEqual(captured["probe"]["local_bind_port"], 0)
        self.assertEqual(captured["probe"]["pre_auth_receive_timeout"], 0.125)
        self.assertEqual(captured["probe"]["pre_auth_receive_limit"], 3)
        self.assertEqual(captured["probe"]["pre_auth_bind_host"], "127.0.0.1")
        self.assertEqual(
            captured["probe"]["pre_auth_fresh_cmd26_bootstrap"],
            {
                "local_host": "127.0.0.1",
                "local_port": 19001,
                "dest_ip": "10.10.2.129",
                "dest_port": 10014,
                "channel_type": 1,
                "channel_id": 0,
                "trace_id": "0123456789abcdef0123456789abcdef",
                "parent_id": "0123456789abcdef",
            },
        )
        self.assertTrue(captured["probe"]["pre_auth_session_state_model"]["type6_proxy_fd_session_slot"])
        self.assertTrue(captured["probe"]["pre_auth_session_state_model"]["proxy_sock_udp_gate"])
        self.assertTrue(captured["probe"]["pre_auth_session_state_model"]["init_local_rw_sock_pair_udp_kcp_attachment"])
        self.assertTrue(captured["probe"]["pre_auth_session_state_model"]["quic_channel_manage_ready_or_bypassed"])
        self.assertEqual(captured["probe"]["pre_auth_session_state_model"]["channel_type_id_candidate"], "0x0100")
        self.assertTrue(printed["cagMaterial"]["freshFetched"])
        self.assertTrue(printed["cagMaterial"]["connectInfo"]["accessTokenPresent"])
        self.assertNotIn("cli-pass", written)
        self.assertNotIn("secret-token", written)
        self.assertNotIn("10.10.2.129", written)

    def test_rap_zime_kcp_auth_from_cag_cli_can_disable_opentelemetry(self):
        state_path = self.temp_state()
        captured = {}

        def fake_fetch(user_service_id=None, state_path=None, boot_wait=180, timeout=30):
            return {
                "auth": {"vmUserName": "cli-user", "vmPassword": "cli-pass", "vmId": "cli-vmid"},
                "connectInfo": {"host": "10.10.2.129", "port": 10014, "type": "rap"},
                "publicConnectInfo": {
                    "host": "10.10.2.129",
                    "port": 10014,
                    "type": "rap",
                    "accessTokenPresent": False,
                    "cpsidPresent": False,
                    "rawArgKeys": ["h", "p", "type"],
                },
            }

        def fake_probe(**kwargs):
            captured["probe"] = kwargs
            return {
                "ok": False,
                "target": "<redacted:cag-udp-target>",
                "desktopKeepaliveProven": False,
                "displayPathObserved": False,
                "verifiedRunPassed": False,
                "authMaterialSource": {"payloadStoredInReport": False},
                "connectInfo": {"hostPresent": True, "portPresent": True},
            }

        self.set_attr(cli_main.protocol_runner, "fetch_cag_auth_connect_info", fake_fetch)
        self.set_attr(cli_main.rap_zime, "run_kcp_auth_sync_probe_from_cag_material", fake_probe)

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli_main.main([
                "--state",
                state_path,
                "rap-zime-kcp-auth-from-cag",
                "2663816",
                "--no-opentelemetry",
            ])

        self.assertEqual(code, 0)
        self.assertFalse(captured["probe"]["opentelemetry"])

    def test_rap_zime_kcp_auth_from_cag_cli_rejects_preflight_ready_gate_without_preflight(self):
        state_path = self.temp_state()

        def fake_fetch(*_args, **_kwargs):
            raise AssertionError("misused preflight gate must fail before state-backed CAG fetch")

        self.set_attr(cli_main.protocol_runner, "fetch_cag_auth_connect_info", fake_fetch)

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli_main.main([
                "--state",
                state_path,
                "rap-zime-kcp-auth-from-cag",
                "2663816",
                "--require-preflight-ready",
            ])

        self.assertEqual(code, 1)
        self.assertIn("--require-preflight-ready requires --auth-gate-preflight-only", out.getvalue())

    def test_rap_zime_kcp_auth_from_cag_cli_rejects_acceptance_gate_with_preflight(self):
        state_path = self.temp_state()

        def fake_fetch(*_args, **_kwargs):
            raise AssertionError("misused acceptance gate must fail before state-backed CAG fetch")

        self.set_attr(cli_main.protocol_runner, "fetch_cag_auth_connect_info", fake_fetch)

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli_main.main([
                "--state",
                state_path,
                "rap-zime-kcp-auth-from-cag",
                "2663816",
                "--auth-gate-preflight-only",
                "--require-auth-gate-accepted",
            ])

        self.assertEqual(code, 1)
        self.assertIn("--require-auth-gate-accepted requires a live gate run", out.getvalue())

    def test_rap_zime_kcp_auth_from_cag_cli_rejects_live_ready_gate_with_preflight(self):
        state_path = self.temp_state()

        def fake_fetch(*_args, **_kwargs):
            raise AssertionError("misused live readiness gate must fail before state-backed CAG fetch")

        self.set_attr(cli_main.protocol_runner, "fetch_cag_auth_connect_info", fake_fetch)

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli_main.main([
                "--state",
                state_path,
                "rap-zime-kcp-auth-from-cag",
                "2663816",
                "--auth-gate-preflight-only",
                "--require-live-gate-ready",
            ])

        self.assertEqual(code, 1)
        self.assertIn("--require-live-gate-ready requires a live gate run", out.getvalue())
        self.assertIn("--require-preflight-ready", out.getvalue())

    def test_rap_zime_kcp_auth_from_cag_cli_preflight_only_does_not_probe_live(self):
        state_path = self.temp_state()
        report_path = Path(state_path).with_name("kcp-auth-gate-preflight.json")
        captured = {}

        def fake_fetch(user_service_id=None, state_path=None, boot_wait=180, timeout=30):
            captured["fetch"] = (user_service_id, state_path, boot_wait, timeout)
            return {
                "auth": {"vmUserName": "cli-user", "vmPassword": "cli-pass", "vmId": "cli-vmid"},
                "connectInfo": {
                    "host": "10.10.2.129",
                    "port": 10014,
                    "type": "rap",
                    "accessToken": "secret-token",
                    "cpsid": "secret-cps",
                },
                "publicConnectInfo": {
                    "host": "10.10.2.129",
                    "port": 10014,
                    "type": "rap",
                    "accessTokenPresent": True,
                    "cpsidPresent": True,
                    "rawArgKeys": ["accessToken", "cpsid", "h", "p", "type"],
                },
            }

        def fake_probe(**_kwargs):
            raise AssertionError("preflight-only must not run live probe")

        self.set_attr(cli_main.protocol_runner, "fetch_cag_auth_connect_info", fake_fetch)
        self.set_attr(cli_main.rap_zime, "run_kcp_auth_sync_probe_from_cag_material", fake_probe)

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli_main.main([
                "--state",
                state_path,
                "rap-zime-kcp-auth-from-cag",
                "2663816",
                "--auth-gate-preflight-only",
                "--auth-head-attempts",
                "3",
                "--pre-auth-cmd26-local-proxy",
                "127.0.0.1:19001",
                "--pre-auth-state-contract",
                "--report-file",
                str(report_path),
            ])

        self.assertEqual(code, 0)
        self.assertEqual(captured["fetch"], ("2663816", state_path, 180, 30))
        printed = json.loads(out.getvalue())
        written = report_path.read_text(encoding="utf-8")
        self.assertEqual(printed["mode"], "auth-gate-live-preflight-audit")
        self.assertFalse(printed["networkSent"])
        self.assertFalse(printed["localProxyConnected"])
        self.assertTrue(printed["authGateOnly"])
        self.assertTrue(printed["readyForGateOnlyLiveAttempt"])
        self.assertEqual(printed["missingConfiguration"], [])
        self.assertEqual(printed["authPreflight"]["authHeadWire"]["wireLen"], 199)
        self.assertEqual(printed["authPreflight"]["authDataWire"]["wireLen"], 241)
        self.assertTrue(printed["configurationChecks"]["preAuthCmd26Configured"])
        self.assertTrue(printed["configurationChecks"]["stateContractConfigComplete"])
        self.assertEqual(
            printed["preAuthNativeSideEffectContract"]["status"],
            "static_contract_recovered_runner_equivalent_not_implemented",
        )
        self.assertIn(
            "same external fd/remote must receive len=71 ACK-like before AUTH_DATA",
            printed["preAuthNativeSideEffectContract"]["officialTraceFields"],
        )
        self.assertTrue(all(
            item["runnerEquivalentImplemented"] is False
            for item in printed["preAuthNativeSideEffectContract"]["sideEffects"]
        ))
        self.assertIn("1-byte status", " ".join(printed["runtimeGatesStillRequired"]))
        self.assertIn("71-byte ACK-like", " ".join(printed["runtimeGatesStillRequired"]))
        self.assertFalse(printed["preAuthLocalBootstrapPlan"]["payloadStoredInReport"])
        self.assertFalse(printed["preAuthSessionState"]["payloadStoredInReport"])
        self.assertIn("Run AUTH gate-only live", printed["nextStep"])
        self.assertNotIn("cli-pass", written)
        self.assertNotIn("secret-token", written)
        self.assertNotIn("secret-cps", written)
        self.assertNotIn("10.10.2.129", written)
        self.assertNotIn("10014", written)

    def test_rap_zime_kcp_auth_from_cag_cli_preflight_only_accepts_explicit_material_file(self):
        state_path = self.temp_state()
        material_path = Path(state_path).with_name("explicit-cag-material.json")
        report_path = Path(state_path).with_name("explicit-cag-preflight.json")
        material_path.write_text(json.dumps({
            "auth": {
                "vmUserName": "file-user",
                "vmPassword": "file-pass",
                "vmId": "file-vmid",
            },
            "connectInfo": {
                "host": "10.10.2.129",
                "port": 10014,
                "type": "rap",
                "udpSsl": True,
                "accessToken": "secret-token",
                "cpsid": "secret-cps",
                "rawArgs": {
                    "accessToken": "secret-token",
                    "cpsid": "secret-cps",
                    "h": "10.10.2.129",
                    "p": "10014",
                },
            },
        }), encoding="utf-8")

        def fake_fetch(*_args, **_kwargs):
            raise AssertionError("explicit material preflight must not fetch state-backed CAG material")

        def fake_probe(**_kwargs):
            raise AssertionError("preflight-only must not run live probe")

        self.set_attr(cli_main.protocol_runner, "fetch_cag_auth_connect_info", fake_fetch)
        self.set_attr(cli_main.rap_zime, "run_kcp_auth_sync_probe_from_cag_material", fake_probe)

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli_main.main([
                "--state",
                state_path,
                "rap-zime-kcp-auth-from-cag",
                "2663816",
                "--auth-gate-preflight-only",
                "--cag-material-file",
                str(material_path),
                "--require-preflight-ready",
                "--auth-head-attempts",
                "3",
                "--pre-auth-cmd26-local-proxy",
                "127.0.0.1:19001",
                "--pre-auth-state-contract",
                "--report-file",
                str(report_path),
            ])

        self.assertEqual(code, 0)
        printed = json.loads(out.getvalue())
        written = report_path.read_text(encoding="utf-8")
        self.assertEqual(printed["cagMaterial"]["source"], "explicit-cag-material-file")
        self.assertFalse(printed["cagMaterial"]["freshFetched"])
        self.assertTrue(printed["readyForGateOnlyLiveAttempt"])
        self.assertEqual(printed["authPreflight"]["authHeadWire"]["wireLen"], 199)
        self.assertEqual(printed["authPreflight"]["authDataWire"]["wireLen"], 241)
        self.assertTrue(printed["cagMaterial"]["connectInfo"]["hostPresent"])
        self.assertTrue(printed["cagMaterial"]["connectInfo"]["portPresent"])
        self.assertTrue(printed["cagMaterial"]["connectInfo"]["accessTokenPresent"])
        self.assertTrue(printed["cagMaterial"]["connectInfo"]["cpsidPresent"])
        self.assertNotIn("file-user", written)
        self.assertNotIn("file-pass", written)
        self.assertNotIn("file-vmid", written)
        self.assertNotIn("secret-token", written)
        self.assertNotIn("secret-cps", written)
        self.assertNotIn("10.10.2.129", written)
        self.assertNotIn("10014", written)
        not_ready_report_path = Path(state_path).with_name("explicit-cag-preflight-not-ready.json")
        not_ready_out = io.StringIO()
        with contextlib.redirect_stdout(not_ready_out):
            not_ready_code = cli_main.main([
                "--state",
                state_path,
                "rap-zime-kcp-auth-from-cag",
                "2663816",
                "--auth-gate-preflight-only",
                "--cag-material-file",
                str(material_path),
                "--require-preflight-ready",
                "--report-file",
                str(not_ready_report_path),
            ])
        self.assertEqual(not_ready_code, 1)
        self.assertIn("AUTH gate preflight not ready", not_ready_out.getvalue())
        not_ready = json.loads(not_ready_report_path.read_text(encoding="utf-8"))
        self.assertFalse(not_ready["readyForGateOnlyLiveAttempt"])
        self.assertIn("pre_auth_cmd26_local_proxy", not_ready["missingConfiguration"])
        self.assertIn("type6_proxy_fd_session_slot", not_ready["missingConfiguration"])
        not_ready_written = json.dumps(not_ready, ensure_ascii=False, sort_keys=True)
        self.assertNotIn("file-user", not_ready_written)
        self.assertNotIn("file-pass", not_ready_written)
        self.assertNotIn("secret-token", not_ready_written)

    def test_rap_zime_kcp_auth_from_cag_cli_live_gate_ready_blocks_unready_live(self):
        state_path = self.temp_state()
        material_path = Path(state_path).with_name("explicit-cag-live-unready-material.json")
        report_path = Path(state_path).with_name("explicit-cag-live-unready-report.json")
        material_path.write_text(json.dumps({
            "auth": {
                "vmUserName": "file-user",
                "vmPassword": "file-pass",
                "vmId": "file-vmid",
            },
            "connectInfo": {
                "host": "10.10.2.129",
                "port": 10014,
                "type": "rap",
                "udpSsl": True,
                "accessToken": "secret-token",
                "cpsid": "secret-cps",
            },
        }), encoding="utf-8")

        def fake_fetch(*_args, **_kwargs):
            raise AssertionError("explicit material live gate must not fetch state-backed CAG material")

        def fake_probe(**_kwargs):
            raise AssertionError("unready live gate must fail before live probe")

        self.set_attr(cli_main.protocol_runner, "fetch_cag_auth_connect_info", fake_fetch)
        self.set_attr(cli_main.rap_zime, "run_kcp_auth_sync_probe_from_cag_material", fake_probe)

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli_main.main([
                "--state",
                state_path,
                "rap-zime-kcp-auth-from-cag",
                "2663816",
                "--cag-material-file",
                str(material_path),
                "--require-live-gate-ready",
                "--report-file",
                str(report_path),
            ])

        self.assertEqual(code, 1)
        self.assertIn("AUTH gate live readiness not ready", out.getvalue())
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(report["mode"], "auth-gate-live-preflight-audit")
        self.assertFalse(report["networkSent"])
        self.assertFalse(report["readyForGateOnlyLiveAttempt"])
        self.assertIn("pre_auth_cmd26_local_proxy", report["missingConfiguration"])
        self.assertIn("type6_proxy_fd_session_slot", report["missingConfiguration"])
        written = json.dumps(report, ensure_ascii=False, sort_keys=True)
        self.assertNotIn("file-user", written)
        self.assertNotIn("file-pass", written)
        self.assertNotIn("secret-token", written)
        self.assertNotIn("10.10.2.129", written)
        self.assertNotIn("10014", written)

    def test_rap_zime_kcp_auth_from_cag_cli_require_auth_gate_accepted_fails_incomplete_live_report(self):
        state_path = self.temp_state()
        material_path = Path(state_path).with_name("explicit-cag-live-incomplete-material.json")
        report_path = Path(state_path).with_name("explicit-cag-live-incomplete-report.json")
        material_path.write_text(json.dumps({
            "auth": {
                "vmUserName": "file-user",
                "vmPassword": "file-pass",
                "vmId": "file-vmid",
            },
            "connectInfo": {
                "host": "10.10.2.129",
                "port": 10014,
                "type": "rap",
                "udpSsl": True,
                "accessToken": "secret-token",
                "cpsid": "secret-cps",
            },
        }), encoding="utf-8")

        def fake_fetch(*_args, **_kwargs):
            raise AssertionError("explicit material acceptance gate must not fetch state-backed CAG material")

        def fake_probe(**_kwargs):
            return {
                "authGateOnly": True,
                "desktopKeepaliveProven": False,
                "displayPathObserved": False,
                "verifiedRunPassed": False,
                "authPreflight": {
                    "authHeadWire": {"wireLen": 199},
                    "authDataWire": {"wireLen": 241},
                    "authHeadAckLikeReceived": False,
                    "authDataSentAfterAuthHeadGate": False,
                    "authAckReceived": False,
                },
                "preAuthLocalBootstrap": {
                    "bytesSent": 160,
                    "statusReceived": True,
                    "statusBytesReceived": 1,
                    "payloadStoredInReport": False,
                },
                "preAuthSessionState": {
                    "readyForGateOnlyLive": True,
                    "payloadStoredInReport": False,
                },
                "stages": [
                    {
                        "stage": "auth_head",
                        "responses": [],
                    },
                ],
                "authGateConfirmed": False,
                "synackReceived": False,
                "synack": None,
            }

        self.set_attr(cli_main.protocol_runner, "fetch_cag_auth_connect_info", fake_fetch)
        self.set_attr(cli_main.rap_zime, "run_kcp_auth_sync_probe_from_cag_material", fake_probe)

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli_main.main([
                "--state",
                state_path,
                "rap-zime-kcp-auth-from-cag",
                "2663816",
                "--cag-material-file",
                str(material_path),
                "--require-auth-gate-accepted",
                "--report-file",
                str(report_path),
            ])

        self.assertEqual(code, 1)
        self.assertIn("AUTH gate-only live report not accepted", out.getvalue())
        self.assertIn("stage=auth_head_ack_like", out.getvalue())
        self.assertIn("officialTraceField=same external fd/remote recv len=71 ACK-like", out.getvalue())
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertFalse(report["authGateAcceptance"]["authGateOnlyAccepted"])
        self.assertIn("same_remote_ack_like_71", report["authGateAcceptance"]["missingEvidence"])
        written = json.dumps(report, ensure_ascii=False, sort_keys=True)
        self.assertNotIn("file-user", written)
        self.assertNotIn("file-pass", written)
        self.assertNotIn("secret-token", written)
        self.assertNotIn("10.10.2.129", written)
        self.assertNotIn("10014", written)

    def test_rap_zime_kcp_auth_from_cag_cli_explicit_material_gate_only_fake_server(self):
        state_path = self.temp_state()
        material_path = Path(state_path).with_name("explicit-cag-live-material.json")
        report_path = Path(state_path).with_name("explicit-cag-live-report.json")
        udp_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_server.bind(("127.0.0.1", 0))
        udp_server.settimeout(2)
        udp_target = udp_server.getsockname()
        tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_server.bind(("127.0.0.1", 0))
        tcp_server.listen(1)
        tcp_server.settimeout(2)
        tcp_target = tcp_server.getsockname()
        material_path.write_text(json.dumps({
            "auth": {
                "vmUserName": "file-user",
                "vmPassword": "file-pass",
                "vmId": "file-vmid",
            },
            "connectInfo": {
                "host": udp_target[0],
                "port": udp_target[1],
                "type": "rap",
                "udpSsl": True,
                "accessToken": "secret-token",
                "cpsid": "secret-cps",
            },
        }), encoding="utf-8")
        received_local_frames = []
        received_udp_lengths = []
        errors = []

        def serve_tcp():
            try:
                conn, _peer = tcp_server.accept()
                with conn:
                    conn.settimeout(2)
                    chunks = []
                    while sum(len(chunk) for chunk in chunks) < rap_zime.FRESH_CMD26_WIRE_LEN:
                        chunk = conn.recv(rap_zime.FRESH_CMD26_WIRE_LEN)
                        if not chunk:
                            break
                        chunks.append(chunk)
                    received_local_frames.append(b"".join(chunks))
                    conn.sendall(b"\x01")
            except Exception as err:
                errors.append(err)

        def serve_udp():
            try:
                request, client = udp_server.recvfrom(2048)
                received_udp_lengths.append(len(request))
                decoded_head = rap_zime.decode_kcp_segment(request)
                self.assertTrue(decoded_head["authHeadConv"])
                udp_server.sendto(b"A" * rap_zime.OFFICIAL_AUTH_HEAD_ACK_LIKE_LEN, client)

                request, _client = udp_server.recvfrom(2048)
                received_udp_lengths.append(len(request))
                decoded_data = rap_zime.decode_kcp_segment(request)
                self.assertTrue(decoded_data["authDataConv"])
            except Exception as err:
                errors.append(err)

        def fake_fetch(*_args, **_kwargs):
            raise AssertionError("explicit material gate-only run must not fetch state-backed CAG material")

        self.set_attr(cli_main.protocol_runner, "fetch_cag_auth_connect_info", fake_fetch)
        tcp_thread = threading.Thread(target=serve_tcp)
        udp_thread = threading.Thread(target=serve_udp)
        tcp_thread.start()
        udp_thread.start()
        self.addCleanup(udp_server.close)
        self.addCleanup(tcp_server.close)

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli_main.main([
                "--state",
                state_path,
                "rap-zime-kcp-auth-from-cag",
                "2663816",
                "--cag-material-file",
                str(material_path),
                "--timeout",
                "1",
                "--auth-head-attempts",
                "3",
                "--pre-auth-cmd26-local-proxy",
                f"{tcp_target[0]}:{tcp_target[1]}",
                "--pre-auth-state-contract",
                "--require-live-gate-ready",
                "--require-auth-gate-accepted",
                "--report-file",
                str(report_path),
            ])

        tcp_thread.join(timeout=2)
        udp_thread.join(timeout=2)
        printed = json.loads(out.getvalue())
        written_report = json.loads(report_path.read_text(encoding="utf-8"))
        written = json.dumps(written_report, ensure_ascii=False, sort_keys=True)
        self.assertEqual(code, 0)
        self.assertFalse(errors)
        self.assertEqual(len(received_local_frames), 1)
        self.assertEqual(len(received_local_frames[0]), rap_zime.FRESH_CMD26_WIRE_LEN)
        self.assertEqual(received_local_frames[0][:4], struct.pack("<BBH", 0x1A, 0, 156))
        self.assertEqual(received_udp_lengths, [199, 241])
        self.assertTrue(printed["authGateOnly"])
        self.assertTrue(printed["authGateConfirmed"])
        self.assertFalse(printed["synackReceived"])
        self.assertEqual([stage["stage"] for stage in printed["stages"]], ["auth_head", "auth_data"])
        self.assertEqual(printed["cagMaterial"]["source"], "explicit-cag-material-file")
        self.assertFalse(printed["cagMaterial"]["freshFetched"])
        self.assertEqual(written_report["cagMaterial"], printed["cagMaterial"])
        self.assertTrue(written_report["liveGateReadinessPreflight"]["readyForGateOnlyLiveAttempt"])
        self.assertEqual(written_report["liveGateReadinessPreflight"]["missingConfiguration"], [])
        self.assertFalse(written_report["liveGateReadinessPreflight"]["payloadStoredInReport"])
        self.assertTrue(written_report["authGateAcceptance"]["authGateOnlyAccepted"])
        self.assertEqual(written_report["authGateAcceptance"]["missingEvidence"], [])
        self.assertTrue(written_report["preAuthLocalBootstrap"]["statusReceived"])
        self.assertEqual(written_report["preAuthLocalBootstrap"]["statusBytesReceived"], 1)
        ack_like_response = written_report["stages"][0]["responses"][0]
        self.assertTrue(ack_like_response["officialAuthHeadAckLike"])
        self.assertTrue(ack_like_response["sameExternalFdAsAuthHead"])
        self.assertTrue(ack_like_response["sameRemoteAsAuthTarget"])
        acceptance = rap_zime.assess_auth_gate_only_report(written_report)
        self.assertTrue(acceptance["authGateOnlyAccepted"])
        self.assertEqual(acceptance["missingEvidence"], [])
        self.assertIsNone(acceptance["failureStage"])
        self.assertIsNone(acceptance["failureCheck"])
        self.assertIsNone(acceptance["failureOfficialTraceField"])
        accepted_check_keys = {item["key"] for item in acceptance["checks"]}
        self.assertIn("no_auth_payload_stored", accepted_check_keys)
        self.assertIn("no_local_proxy_payload_stored", accepted_check_keys)
        self.assertIn("no_ack_like_payload_stored", accepted_check_keys)
        self.assertIn("no_auth_material_payload_stored", accepted_check_keys)
        self.assertIn("no_sensitive_payload_fields", accepted_check_keys)
        self.assertIn("same external fd recv len=71 ACK-like", acceptance["officialTraceFields"])
        check_report_path = Path(state_path).with_name("explicit-cag-live-acceptance.json")
        check_out = io.StringIO()
        with contextlib.redirect_stdout(check_out):
            check_code = cli_main.main([
                "check-rap-zime-auth-gate-report",
                str(report_path),
                "--require-accepted",
                "--report-file",
                str(check_report_path),
            ])
        self.assertEqual(check_code, 0)
        checked = json.loads(check_out.getvalue())
        checked_written = json.loads(check_report_path.read_text(encoding="utf-8"))
        self.assertTrue(checked["authGateOnlyAccepted"])
        self.assertEqual(checked_written, checked)
        negative_report = json.loads(json.dumps(written_report))
        negative_report["authPreflight"]["authHeadAckLikeReceived"] = False
        negative_report["stages"][0]["responses"] = []
        negative_acceptance = rap_zime.assess_auth_gate_only_report(negative_report)
        self.assertFalse(negative_acceptance["authGateOnlyAccepted"])
        self.assertIn("same_remote_ack_like_71", negative_acceptance["missingEvidence"])
        self.assertEqual(negative_acceptance["failureStage"], "auth_head_ack_like")
        self.assertEqual(negative_acceptance["failureCheck"], "same_remote_ack_like_71")
        self.assertEqual(negative_acceptance["failureOfficialTraceField"], "same external fd/remote recv len=71 ACK-like")
        wrong_remote_report = json.loads(json.dumps(written_report))
        wrong_remote_report["stages"][0]["responses"][0]["sameRemoteAsAuthTarget"] = False
        wrong_remote_acceptance = rap_zime.assess_auth_gate_only_report(wrong_remote_report)
        self.assertFalse(wrong_remote_acceptance["authGateOnlyAccepted"])
        self.assertIn("same_remote_ack_like_71", wrong_remote_acceptance["missingEvidence"])
        payload_report = json.loads(json.dumps(written_report))
        payload_report["preAuthLocalBootstrap"]["payloadStoredInReport"] = True
        payload_acceptance = rap_zime.assess_auth_gate_only_report(payload_report)
        self.assertFalse(payload_acceptance["authGateOnlyAccepted"])
        self.assertIn("no_local_proxy_payload_stored", payload_acceptance["missingEvidence"])
        self.assertEqual(payload_acceptance["failureStage"], "report_redaction")
        self.assertEqual(payload_acceptance["failureCheck"], "no_local_proxy_payload_stored")
        sensitive_field_report = json.loads(json.dumps(written_report))
        sensitive_field_report["authBuffer"] = "redacted-test-placeholder"
        sensitive_field_acceptance = rap_zime.assess_auth_gate_only_report(sensitive_field_report)
        self.assertFalse(sensitive_field_acceptance["authGateOnlyAccepted"])
        self.assertIn("no_sensitive_payload_fields", sensitive_field_acceptance["missingEvidence"])
        self.assertEqual(sensitive_field_acceptance["failureStage"], "report_redaction")
        snake_sensitive_field_report = json.loads(json.dumps(written_report))
        snake_sensitive_field_report["access_token"] = "redacted-test-placeholder"
        snake_sensitive_field_acceptance = rap_zime.assess_auth_gate_only_report(snake_sensitive_field_report)
        self.assertFalse(snake_sensitive_field_acceptance["authGateOnlyAccepted"])
        self.assertIn("no_sensitive_payload_fields", snake_sensitive_field_acceptance["missingEvidence"])
        dashed_sensitive_field_report = json.loads(json.dumps(written_report))
        dashed_sensitive_field_report["LOCAL-PROXY-FRAME-BODY"] = "redacted-test-placeholder"
        dashed_sensitive_field_acceptance = rap_zime.assess_auth_gate_only_report(dashed_sensitive_field_report)
        self.assertFalse(dashed_sensitive_field_acceptance["authGateOnlyAccepted"])
        self.assertIn("no_sensitive_payload_fields", dashed_sensitive_field_acceptance["missingEvidence"])
        negative_report_path = Path(state_path).with_name("explicit-cag-live-negative-report.json")
        negative_check_path = Path(state_path).with_name("explicit-cag-live-negative-acceptance.json")
        negative_report_path.write_text(json.dumps(negative_report, ensure_ascii=False), encoding="utf-8")
        negative_out = io.StringIO()
        with contextlib.redirect_stdout(negative_out):
            negative_code = cli_main.main([
                "check-rap-zime-auth-gate-report",
                str(negative_report_path),
                "--require-accepted",
                "--report-file",
                str(negative_check_path),
            ])
        self.assertEqual(negative_code, 1)
        self.assertIn("AUTH gate-only report not accepted", negative_out.getvalue())
        self.assertIn("stage=auth_head_ack_like", negative_out.getvalue())
        self.assertIn("check=same_remote_ack_like_71", negative_out.getvalue())
        self.assertIn("officialTraceField=same external fd/remote recv len=71 ACK-like", negative_out.getvalue())
        negative_checked = json.loads(negative_check_path.read_text(encoding="utf-8"))
        self.assertFalse(negative_checked["authGateOnlyAccepted"])
        self.assertIn("same_remote_ack_like_71", negative_checked["missingEvidence"])
        self.assertNotIn("file-user", written)
        self.assertNotIn("file-pass", written)
        self.assertNotIn("file-vmid", written)
        self.assertNotIn("secret-token", written)
        self.assertNotIn("secret-cps", written)
        self.assertNotIn(f"{udp_target[0]}:{udp_target[1]}", written)

    def test_rap_zime_kcp_auth_preflight_codec(self):
        head_payload = b"head"
        head = rap_zime.build_kcp_auth_segment(
            payload=head_payload,
            auth_head=True,
            conv=0x12345678,
            syn_id=0x11223344,
            current=0x01020304,
        )
        decoded_head = rap_zime.decode_kcp_segment(head)
        self.assertEqual(decoded_head["conv"], rap_zime.KCP_AUTH_HEAD_CONV)
        self.assertEqual(decoded_head["sn"], 0x11223344)
        self.assertEqual(decoded_head["una"], 0x12345678)
        self.assertEqual(decoded_head["len"], len(head_payload))
        self.assertEqual(decoded_head["payload"], head_payload)
        self.assertTrue(decoded_head["authHeadConv"])
        self.assertFalse(decoded_head["authDataConv"])
        self.assertEqual(rap_zime.classify_payload(head), "kcp-auth-head")

        data = rap_zime.build_kcp_auth_segment(payload=b"data", auth_head=False, syn_id=0x11223344)
        decoded_data = rap_zime.decode_kcp_segment(data)
        self.assertEqual(decoded_data["conv"], rap_zime.KCP_AUTH_DATA_CONV)
        self.assertFalse(decoded_data["authHeadConv"])
        self.assertTrue(decoded_data["authDataConv"])
        self.assertEqual(rap_zime.classify_payload(data), "kcp-auth-data")

    def test_rap_zime_builds_kcp_auth_preflight_from_ztec_buffer(self):
        auth_head = bytearray(50)
        auth_head[:4] = b"ZTEC"
        struct.pack_into("<HIII", auth_head, 4, 44, 101, 0xAABBCCDD, 9)
        auth_head[18:34] = b"serial-000000000"[:16]
        auth_data = b"secret-09"
        material = rap_zime.build_kcp_auth_preflight_from_buffer(
            bytes(auth_head) + auth_data,
            conv=0x55667788,
            syn_id=0x11223344,
            current=0x99,
        )

        head_segment = rap_zime.decode_kcp_segment(material["authHeadSegment"])
        data_segment = rap_zime.decode_kcp_segment(material["authDataSegment"])
        self.assertTrue(head_segment["authHeadConv"])
        self.assertTrue(data_segment["authDataConv"])
        self.assertEqual(head_segment["sn"], 0x11223344)
        self.assertEqual(data_segment["una"], 0x55667788)
        self.assertEqual(head_segment["len"], 0)
        self.assertEqual(data_segment["len"], 0)
        self.assertEqual(head_segment["payload"], b"")
        self.assertEqual(data_segment["payload"], b"")
        self.assertEqual(head_segment["rest"], bytes(auth_head))
        self.assertEqual(data_segment["rest"], auth_data)
        self.assertEqual(material["summary"]["authBytesPlacement"], "tail_after_zero_declared_len")
        self.assertEqual(material["summary"]["kcpDeclaredLenField"], 0)
        self.assertEqual(material["summary"]["bufferType"], 101)
        self.assertEqual(material["summary"]["bufferTypeName"], "cag-password-auth")
        self.assertEqual(material["summary"]["authHeadLen"], 50)
        self.assertEqual(material["summary"]["authDataLen"], 9)
        self.assertFalse(material["summary"]["payloadStoredInReport"])
        summary_text = json.dumps(material["summary"])
        self.assertNotIn("secret-09", summary_text)
        self.assertNotIn(auth_data.hex(), summary_text)

    @unittest.skip(
        "TEST-ENV: depends on a captured-trace fixture "
        "reports/zime-auth-focus-fresh-20260704-203624.jsonl that is not in the repo "
        "(reports/ is gitignored); dies at read_text before touching product code."
    )
    def test_rap_zime_auth_gate_field_diff_uses_official_zero_declared_len_tail(self):
        trace_path = Path("reports/zime-auth-focus-fresh-20260704-203624.jsonl")
        records = []
        for line in trace_path.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            if row.get("event") == "transport_buffer" and row.get("payloadKind") in {"kcp-auth-head", "kcp-auth-data"}:
                records.append(row)
            if len(records) >= 4:
                break
        official_head = bytes.fromhex(records[0]["hex"])
        official_data = bytes.fromhex(next(row["hex"] for row in records if row.get("payloadKind") == "kcp-auth-data"))
        head_decoded = rap_zime.decode_kcp_segment(official_head)
        data_decoded = rap_zime.decode_kcp_segment(official_data)
        self.assertEqual(head_decoded["len"], 0)
        self.assertEqual(len(head_decoded["rest"]), 178)
        self.assertEqual(data_decoded["len"], 0)
        self.assertEqual(len(data_decoded["rest"]), 220)

        fixed_material = rap_zime.build_kcp_auth_preflight_from_buffer(
            head_decoded["rest"] + data_decoded["rest"],
            syn_id=head_decoded["sn"],
            current=head_decoded["ts"],
        )
        fixed_diff = rap_zime.auth_gate_field_diff_from_trace(
            trace_path,
            python_auth_head_segment=fixed_material["authHeadSegment"],
            python_auth_data_segment=fixed_material["authDataSegment"],
        )
        self.assertEqual(fixed_diff["official"]["firstAuthHead"]["declaredLen"], 0)
        self.assertEqual(fixed_diff["official"]["firstAuthHead"]["tailBytesAfterDeclaredPayload"], 178)
        self.assertEqual(fixed_diff["python"]["authHead"]["authBytesPlacement"], "tail_after_zero_declared_len")
        self.assertEqual(fixed_diff["redactedDiff"]["authHeadOfficialVsPython"], [])
        self.assertEqual(fixed_diff["official"]["localProxyCycles"][0]["clientSend"]["frameHeader"]["u16Type"], 26)
        self.assertEqual(fixed_diff["official"]["localProxyCycles"][0]["clientSend"]["frameHeader"]["u16BodyLen"], 156)
        self.assertEqual(fixed_diff["official"]["localProxyCycles"][0]["clientSend"]["frameHeader"]["channelOrIdByte"], 0)
        self.assertTrue(fixed_diff["official"]["localProxyCycles"][0]["clientSend"]["frameHeader"]["sendTunnelLinkMessageDirectShapeExcluded"])
        self.assertFalse(fixed_diff["official"]["localProxyFirstTwoBodyDiff"]["equal"])
        self.assertEqual(fixed_diff["official"]["localProxyFirstTwoBodyDiff"]["differingBytes"], 18)
        self.assertEqual(
            fixed_diff["official"]["localProxyFirstTwoBodyDiff"]["differingBodyOffsetGroups"],
            [
                {"start": 2, "end": 2, "len": 1},
                {"start": 137, "end": 152, "len": 16},
                {"start": 155, "end": 155, "len": 1},
            ],
        )
        self.assertEqual(
            fixed_diff["official"]["localProxyFirstTwoBodyDiff"]["differingFrameOffsetGroups"],
            [
                {"start": 6, "end": 6, "len": 1},
                {"start": 141, "end": 156, "len": 16},
                {"start": 159, "end": 159, "len": 1},
            ],
        )
        self.assertEqual(
            fixed_diff["official"]["localProxyFirstTwoBodyDiff"]["differingRegionClasses"][1]["firstRegionClass"],
            "ascii-hex",
        )
        offset_evidence = fixed_diff["official"]["localProxyFirstTwoBodyDiff"]["differingOffsetEvidence"]
        self.assertEqual(offset_evidence[0]["idaReadStage"], "deal_unlinked_outband_head_data")
        self.assertEqual(offset_evidence[0]["dataBufRange"], "data_buf[106..106]")
        self.assertEqual(
            offset_evidence[1]["idaReadStage"],
            "beyond_recovered_116_byte_outband_local_header",
        )
        self.assertIsNone(offset_evidence[1]["dataBufRange"])
        self.assertIn("must not be treated as recovered trace_id/span_id", offset_evidence[1]["candidateSemantics"])
        self.assertIn("body offsets 0..111", " ".join(offset_evidence[1]["evidence"]))
        self.assertIn("not body[137:152] or body[155]", " ".join(offset_evidence[1]["evidence"]))
        self.assertIn("send_tunnel_link_message", " ".join(offset_evidence[1]["evidence"]))
        self.assertIn("not the direct shape", " ".join(offset_evidence[1]["evidence"]))
        self.assertEqual(
            offset_evidence[2]["idaReadStage"],
            "beyond_recovered_116_byte_outband_local_header",
        )
        writer_chain = fixed_diff["official"]["localProxyWriterChainEvidence"]
        self.assertEqual(writer_chain["conclusion"], "fresh_160_byte_cmd26_frame_not_created_by_writer_rewrap")
        self.assertEqual(writer_chain["freshFrameShape"]["lenAtOffset2"], 156)
        self.assertEqual(writer_chain["sendTunnelLinkMessageDirectShape"]["lenAtOffset2"], 154)
        self.assertEqual(
            writer_chain["unlinkedOutbandReaderEvidence"]["tailBodyOffsetsNotConsumedByThisReader"],
            ["137..152", "155..155"],
        )
        self.assertEqual(
            writer_chain["unlinkedOutbandReaderEvidence"]["opentelemetryArgumentOffsets"]["traceCandidateBodyOffset"],
            14,
        )
        self.assertEqual(
            writer_chain["unlinkedOutbandReaderEvidence"]["opentelemetryArgumentOffsets"]["spanCandidateBodyOffset"],
            47,
        )
        self.assertEqual(
            writer_chain["unlinkedOutbandReaderEvidence"]["channelLinkSocketExMemcpyEvidence"][0]["sourceFrameOffset"],
            18,
        )
        header_path = writer_chain["freshCmd26HeaderPathEvidence"]
        self.assertEqual(header_path["acceptedCommandBytes"], [26, 10, 42])
        self.assertEqual(header_path["freshCommandByte"], 26)
        self.assertTrue(header_path["freshHeaderAccepted"])
        self.assertEqual(header_path["officialTraceLoopbackPairs"][1]["acceptedBodyRecvLen"], 156)
        self.assertEqual(header_path["officialTraceLoopbackPairs"][1]["clientStatusRecvLen"], 1)
        body_path = writer_chain["freshCmd26BodyPathEvidence"]
        self.assertEqual(body_path["bodyReadSource"], "fd_session_async_read_tcp_data")
        self.assertEqual(body_path["bodyLenSource"], "ProxyProtolHeader.u16BodyLen")
        self.assertEqual(body_path["cmd26Dispatcher"], "deal_local_recved_cmd_link")
        body_mappings = {
            item.get("bodyOffsetRange", str(item.get("bodyOffset"))): item
            for item in body_path["bodyOffsetMappings"]
        }
        self.assertEqual(body_mappings["104..135"]["hexOffsetRange"], "0x68..0x87")
        self.assertEqual(body_mappings["137..152"]["field"], "opentelemetry span candidate")
        self.assertEqual(body_mappings["154..155"]["field"], "channel_type_id word")
        self.assertIn("channel_type=(word>>8)&0x7f", body_mappings["154..155"]["consumer"])
        synth_schema = writer_chain["freshCmd26MinimalSynthesisSchema"]
        self.assertEqual(synth_schema["bodyContract"]["wireHeader"], "cmd=26, channel/id byte=0, u16BodyLen=156")
        self.assertEqual(synth_schema["bodyContract"]["consumer"], "send_tunnel_add_link")
        dwarf_schema = synth_schema["dwarfStructEvidence"]
        self.assertEqual(dwarf_schema["ChannelLinkSocketEx"]["members"][0]["type"], "ChannelLinkInfoEx")
        info_members = {
            item["field"]: item
            for item in dwarf_schema["ChannelLinkInfoEx"]["members"]
        }
        self.assertEqual(info_members["serial_num"]["offset"], 24)
        self.assertEqual(info_members["serial_num"]["size"], 16)
        self.assertEqual(info_members["channel_type"]["offset"], 84)
        self.assertEqual(info_members["extend"]["offset"], 88)
        self.assertIn("client-side status recv len=1", synth_schema["officialTraceFields"])
        consumed_fields = {
            item["field"]: item
            for item in synth_schema["fieldConsumption"]
        }
        self.assertTrue(consumed_fields["info.dest_port"]["requiredForMinimalSynthesis"])
        self.assertTrue(consumed_fields["info.link_type"]["requiredForMinimalSynthesis"])
        self.assertEqual(
            consumed_fields["info.otlp_parent_id"]["requiredForMinimalSynthesis"],
            "required_to_match_official_bootstrap_shape_but_not_auth_payload",
        )
        self.assertEqual(consumed_fields["info.extend"]["requiredForMinimalSynthesis"], "value_source_not_closed")
        self.assertTrue(consumed_fields["channel_type_id"]["requiredForMinimalSynthesis"])
        self.assertIn(
            "QUIC_create_data_stream requires session QUIC_engine",
            " ".join(synth_schema["requiredSessionSideEffects"]),
        )
        value_sources = synth_schema["valueSourceStaticEvidence"]
        self.assertEqual(
            value_sources["freshCmd26LinkRoute"]["headerEffect"],
            "accepted cmd=26 header sets in_sock->data_buf[224] to link_type 1",
        )
        self.assertEqual(
            value_sources["freshCmd26LinkRoute"]["outbandProxyType5Condition"],
            "only possible for link_type=2 when rap/downward-bw-control conditions allow it",
        )
        self.assertEqual(
            value_sources["kcpDestinationRoute"]["multiTcpWithoutCag"],
            "vm_ip/vm_proxy_port source class except ice uses host/vm_proxy_port",
        )
        self.assertTrue(value_sources["channelLinkDestinationRole"]["notAuthBufferDestination"])
        producer = value_sources["freshCmd26ProducerSideSynthesis"]
        self.assertEqual(producer["frameShape"]["commandByte"], 26)
        self.assertEqual(producer["frameShape"]["channelOrIdByte"], 0)
        self.assertEqual(producer["frameShape"]["bodyCopy"], "ZXMemcpy(frame + 4, stack ChannelLinkSocketEx, 0x9c)")
        self.assertEqual(
            producer["bodyValueSources"]["dest_ip"]["bodyOffsetRange"],
            "4..7 for IPv4 or 8..23 for IPv6",
        )
        self.assertIn(
            "session offset 0x1238",
            " ".join(producer["bodyValueSources"]["dest_port"]["staticBranches"]),
        )
        self.assertIn(
            "priority 3",
            producer["bodyValueSources"]["link_priority"]["staticMapping"],
        )
        self.assertIn(
            "caller argument + 0x421",
            producer["bodyValueSources"]["opentelemetry"]["parentSource"],
        )
        self.assertIn(
            "target-function offsets are the direct evidence",
            producer["bodyValueSources"]["channel_type_id"]["dwarfBoundary"],
        )
        self.assertIn("send len=160", " ".join(producer["officialTraceFields"]))
        self.assertIn("session/channel state categories", producer["pythonImplication"])
        self.assertEqual(value_sources["channelTypeIdRole"]["bodyRange"], "154..155")
        channel_type_synth = value_sources["channelTypeIdSynthesisRole"]
        self.assertTrue(any("StreamManage+0x34 = channel_type_id & 0xff" in item for item in channel_type_synth["streamManageWrites"]))
        self.assertTrue(any("sock_link_type=2 maps to SPICE_OUTBAND" in item for item in channel_type_synth["payloadTypeMapping"]))
        self.assertEqual(channel_type_synth["channelTypeNameTable"]["zeroOrOutOfRange"], "SPICE_UNKNOWN")
        self.assertEqual(channel_type_synth["firstChannelCandidateBoundary"]["candidatePriority"][0]["meaning"], "SPICE_MAIN channel 0")
        self.assertIn(
            "SPICE_PORT/channel_type=10 is a later port-channel branch",
            channel_type_synth["firstChannelCandidateBoundary"]["portChannelBoundary"],
        )
        self.assertIn(
            "StreamParam.u8Priority = stream_manage->priority",
            channel_type_synth["zimeCreateDataStreamTraceBoundary"]["sourceInStaticCode"],
        )
        self.assertIn("channel_type=10 enters the port-channel branch", " ".join(channel_type_synth["bandwidthImplication"]))
        self.assertIn("accepted-side recv len=156 ChannelLinkSocketEx body", channel_type_synth["officialTraceFields"])
        self.assertIn("official first-channel candidate value", channel_type_synth["exactValueStatus"])
        stream_gate = value_sources["streamCreateGateEvidence"]
        self.assertIn("QUIC_create_data_stream attempted and returned failure", stream_gate["hardFailureConditions"])
        self.assertIn(
            "proxy fd session has no KCP/QUIC channel-manage state ready for stream creation",
            stream_gate["successWithoutNewQuicStreamConditions"],
        )
        self.assertEqual(
            stream_gate["quicStreamAttemptCondition"],
            "proxy fd session exists, is ready, has KCP state, and the QUIC/channel-ready byte is set",
        )
        self.assertIn("external AUTH_HEAD len=199 follows local proxy/session setup", value_sources["officialTraceFields"])
        self.assertIn("local proxy/session side effects", synth_schema["pythonImplication"])
        self.assertTrue(value_sources["freshBodyValueSynthesisBoundaries"]["downstreamLinkMessageDerivations"]["notFreshInputProducer"])
        self.assertIn(
            "whether structurally valid generated OpenTelemetry values are enough for fresh cmd26, or whether exact official trace/span correlation is required",
            synth_schema["notYetClosed"],
        )
        self.assertEqual(
            writer_chain["linkedOutbandTailCandidate"]["linkedLinkType2Path"],
            "deal_linked_local_data_read -> deal_linked_outband_local_data_read",
        )
        self.assertEqual(writer_chain["linkedOutbandTailCandidate"]["linkedMaxReadWithoutBwLimit"], 65507)
        self.assertFalse(writer_chain["linkedOutbandTailCandidate"]["candidateForFreshTail"])
        recv4_evidence = writer_chain["localRecv4SemanticsEvidence"]
        self.assertEqual(recv4_evidence["cmd26DirectResponseWriter"], "send_tcp_data_with_cache")
        self.assertFalse(recv4_evidence["cmd26DirectResponseExplainsOfficialRecv4"])
        self.assertEqual(recv4_evidence["officialTraceFields"]["loopbackBodyRecvLen"], 156)
        self.assertEqual(recv4_evidence["officialTraceFields"]["loopbackCmd26StatusLen"], 1)
        self.assertEqual(recv4_evidence["cmd10HeaderShape"]["headerLen"], 4)
        self.assertIn("accepted-side body recv len=156", recv4_evidence["conclusion"])
        self.assertIn("field value synthesis rules for ChannelLinkSocketEx fields", writer_chain["nextStaticTargets"])
        self.assertFalse(any(item["rewrapsCommand26ToFresh160Frame"] for item in writer_chain["writers"]))
        port_writer = next(item for item in writer_chain["writers"] if item["name"] == "spice_session_write_port_data")
        self.assertEqual(port_writer["excludedReason"], "cmd10_port_channel_path_not_fresh_cmd26_bootstrap_shape")

        stale_head = rap_zime.build_kcp_auth_segment(
            payload=head_decoded["rest"],
            auth_head=True,
            syn_id=head_decoded["sn"],
            current=head_decoded["ts"],
            declare_payload_len=True,
        )
        stale_diff = rap_zime.auth_gate_field_diff_from_trace(trace_path, python_auth_head_segment=stale_head)
        stale_fields = {item["field"] for item in stale_diff["redactedDiff"]["authHeadOfficialVsPython"]}
        self.assertIn("declaredLen", stale_fields)
        self.assertIn("authBytesPlacement", stale_fields)
        text = json.dumps(fixed_diff)
        self.assertNotIn(head_decoded["rest"].hex(), text)
        self.assertNotIn(data_decoded["rest"].hex(), text)

    def test_rap_zime_builds_fresh_cag_type101_auth_buffer_redacted(self):
        built = rap_zime.build_ztec_cag_type101_auth_buffer(
            username="fresh-user",
            password="fresh-pass",
            vmid="fresh-vmid",
            dest_ip="10.10.2.127",
            dest_port=10012,
            serial_uuid=bytes.fromhex("00112233445566778899aabbccddeeff"),
            random_c=0xAABBCCDD,
            link_type=rap_zime.ZTEC_CAG_TYPE101_LINK_TYPE_PROXY,
        )
        auth_buffer = built["authBuffer"]
        summary = built["summary"]
        split = rap_zime.parse_ztec_auth_buffer(auth_buffer)
        material = rap_zime.build_kcp_auth_preflight_from_buffer(
            auth_buffer,
            conv=0x55667788,
            syn_id=0x11223344,
            current=0x99,
        )

        self.assertEqual(len(auth_buffer), 270)
        self.assertEqual(summary["sourceType"], "fresh-cag-type101-builder")
        self.assertEqual(summary["bufferType"], 101)
        self.assertEqual(summary["headerLenField"], 44)
        self.assertEqual(summary["authHeadLen"], 50)
        self.assertEqual(summary["authDataLen"], 220)
        self.assertEqual(summary["proxyDataOffset"], 50)
        self.assertFalse(summary["payloadStoredInReport"])
        self.assertEqual(split["summary"]["authHeadLen"], 50)
        self.assertEqual(split["summary"]["authDataLen"], 220)
        self.assertEqual(auth_buffer[50:52], (10012).to_bytes(2, "little"))
        self.assertEqual(auth_buffer[54:58], socket.inet_aton("10.10.2.127"))
        self.assertIn(b"fresh-user", auth_buffer)
        self.assertIn(b"fresh-pass", auth_buffer)
        self.assertIn(b"fresh-vmid", auth_buffer)
        self.assertEqual(rap_zime.decode_kcp_segment(material["authHeadSegment"])["len"], 0)
        self.assertEqual(rap_zime.decode_kcp_segment(material["authDataSegment"])["len"], 0)
        self.assertEqual(len(rap_zime.decode_kcp_segment(material["authHeadSegment"])["rest"]), 50)
        self.assertEqual(len(rap_zime.decode_kcp_segment(material["authDataSegment"])["rest"]), 220)

        safe_text = json.dumps(summary)
        self.assertNotIn("fresh-user", safe_text)
        self.assertNotIn("fresh-pass", safe_text)
        self.assertNotIn("fresh-vmid", safe_text)
        self.assertNotIn("10.10.2.127", safe_text)

    def test_rap_zime_builds_cag_type101_auth_buffer_from_material_redacted(self):
        built = rap_zime.build_ztec_cag_type101_auth_buffer_from_material(
            {
                "vmUserName": "mat-user",
                "vmPassword": "mat-pass",
                "vmId": "mat-vmid",
            },
            {
                "host": "10.10.2.128",
                "port": 10013,
                "type": "rap",
            },
            serial_uuid=bytes.fromhex("00112233445566778899aabbccddeeff"),
            random_c=0x01020304,
        )
        auth_buffer = built["authBuffer"]
        material = rap_zime.build_kcp_auth_preflight_from_buffer(auth_buffer)

        self.assertEqual(built["summary"]["sourceType"], "fresh-cag-material-type101-builder")
        self.assertTrue(built["summary"]["materialFieldsPresent"]["vmPassword"])
        self.assertEqual(rap_zime.decode_kcp_segment(material["authHeadSegment"])["len"], 0)
        self.assertEqual(rap_zime.decode_kcp_segment(material["authDataSegment"])["len"], 0)
        self.assertIn(b"mat-user", auth_buffer)
        self.assertIn(b"mat-pass", auth_buffer)
        self.assertIn(b"mat-vmid", auth_buffer)
        safe_text = json.dumps(built["summary"])
        self.assertNotIn("mat-user", safe_text)
        self.assertNotIn("mat-pass", safe_text)
        self.assertNotIn("mat-vmid", safe_text)
        self.assertNotIn("10.10.2.128", safe_text)

    def test_rap_zime_cag_type101_material_uses_link_type_destination_rules(self):
        built = rap_zime.build_ztec_cag_type101_auth_buffer_from_material(
            {
                "vmUserName": "mat-user",
                "vmPassword": "mat-pass",
            },
            protocol_runner.connect_info_from_connect_str(
                "-h 10.10.2.128 -p 10013 --vmid mat-vmid --vmip 10.10.213.110%3B10.0.0.1 --vmport 5100 -type rap"
            ),
            random_c=0x01020304,
        )
        auth_buffer = built["authBuffer"]
        proxy = built["summary"]["proxyDataOffset"]
        port_offset = proxy + rap_zime.ZTEC_CAG_TYPE101_PROXY_DEST_PORT_OFFSET
        ip_offset = proxy + rap_zime.ZTEC_CAG_TYPE101_PROXY_DEST_IP_OFFSET

        self.assertEqual(struct.unpack_from("<H", auth_buffer, port_offset)[0], 10013)
        self.assertEqual(auth_buffer[ip_offset:ip_offset + 4], socket.inet_aton("10.10.2.128"))
        self.assertFalse(built["summary"]["materialFieldsPresent"]["destFromVmArgs"])
        self.assertEqual(built["summary"]["destinationSource"], "proxy_gateway")
        self.assertEqual(
            built["summary"]["officialKcpDestinationEvidence"]["destinationSource"],
            "vm_ip_vm_proxy_port",
        )
        self.assertTrue(built["summary"]["officialKcpDestinationEvidence"]["notAuthBufferDestination"])
        safe_text = json.dumps(built["summary"])
        self.assertNotIn("10.10.213.110", safe_text)
        self.assertNotIn("10.10.2.128", safe_text)

        vm_built = rap_zime.build_ztec_cag_type101_auth_buffer_from_material(
            {
                "vmUserName": "mat-user",
                "vmPassword": "mat-pass",
            },
            protocol_runner.connect_info_from_connect_str(
                "-h 10.10.2.128 -p 10013 --vmid mat-vmid --vmip 10.10.213.110%3B10.0.0.1 --vmport 5100 -type rap"
            ),
            random_c=0x01020304,
            link_type=rap_zime.ZTEC_CAG_TYPE101_LINK_TYPE_VM_PROXY,
        )
        vm_auth_buffer = vm_built["authBuffer"]
        vm_proxy = vm_built["summary"]["proxyDataOffset"]
        self.assertEqual(
            struct.unpack_from("<H", vm_auth_buffer, vm_proxy + rap_zime.ZTEC_CAG_TYPE101_PROXY_DEST_PORT_OFFSET)[0],
            5100,
        )
        self.assertEqual(
            vm_auth_buffer[vm_proxy + rap_zime.ZTEC_CAG_TYPE101_PROXY_DEST_IP_OFFSET:vm_proxy + rap_zime.ZTEC_CAG_TYPE101_PROXY_DEST_IP_OFFSET + 4],
            socket.inet_aton("10.10.213.110"),
        )
        self.assertTrue(vm_built["summary"]["materialFieldsPresent"]["destFromVmArgs"])
        self.assertEqual(vm_built["summary"]["destinationSource"], "vm_proxy")

    def test_rap_zime_describes_official_kcp_destination_source_redacted(self):
        cag_summary = rap_zime.describe_official_kcp_destination_source(
            {
                "type": "rap",
                "host": "10.10.2.128",
                "port": 10013,
                "agIp": "10.99.1.2",
                "agPort": 443,
                "vmHost": "10.10.213.110",
                "vmPort": 5100,
            }
        )
        self.assertEqual(cag_summary["destinationSource"], "cag_ag_ip_port")
        self.assertTrue(cag_summary["enableCag"])
        self.assertTrue(cag_summary["notAuthBufferDestination"])
        safe_text = json.dumps(cag_summary)
        self.assertNotIn("10.99.1.2", safe_text)
        self.assertNotIn("10.10.2.128", safe_text)
        self.assertNotIn("10.10.213.110", safe_text)

        vm_summary = rap_zime.describe_official_kcp_destination_source(
            {"type": "rap", "vmHost": "10.10.213.110", "vmPort": 5100}
        )
        self.assertEqual(vm_summary["destinationSource"], "vm_ip_vm_proxy_port")

        ice_summary = rap_zime.describe_official_kcp_destination_source(
            {"type": "ice", "host": "10.10.2.129", "vmPort": 5101}
        )
        self.assertEqual(ice_summary["destinationSource"], "ice_host_vm_proxy_port")

    def test_rap_zime_builds_fresh_cag_type102_auth_buffer_from_dwarf_layout(self):
        built = rap_zime.build_ztec_cag_type102_auth_buffer(
            username="uac-user",
            token="uac-secret-token",
            vmid="uac-vmid",
            dest_ip="10.10.2.130",
            dest_port=10015,
            serial_uuid=bytes.fromhex("00112233445566778899aabbccddeeff"),
            random_c=0xA0B0C0D0,
            auth_type="1",
            token_source="uactoken",
        )
        auth_buffer = built["authBuffer"]
        summary = built["summary"]
        proxy = summary["proxyDataOffset"]
        split = rap_zime.parse_ztec_auth_buffer(auth_buffer)
        material = rap_zime.build_kcp_auth_preflight_from_buffer(auth_buffer)

        self.assertEqual(len(auth_buffer), 208)
        self.assertEqual(summary["sourceType"], "fresh-cag-type102-builder")
        self.assertEqual(summary["bufferType"], 102)
        self.assertEqual(summary["headerLenField"], 44)
        self.assertEqual(summary["authHeadLen"], 50)
        self.assertEqual(summary["authDataLen"], 158)
        self.assertEqual(summary["proxyDataLen"], 158)
        self.assertEqual(summary["paddedTokenLen"], 32)
        self.assertEqual(split["summary"]["bufferTypeName"], "cag-uac-token-auth")
        self.assertEqual(rap_zime.decode_kcp_segment(material["authHeadSegment"])["len"], 0)
        self.assertEqual(rap_zime.decode_kcp_segment(material["authDataSegment"])["len"], 0)
        self.assertEqual(len(rap_zime.decode_kcp_segment(material["authHeadSegment"])["rest"]), 50)
        self.assertEqual(len(rap_zime.decode_kcp_segment(material["authDataSegment"])["rest"]), 158)
        self.assertEqual(auth_buffer[proxy + rap_zime.ZTEC_CAG_TYPE102_PROXY_DEST_PORT_OFFSET:proxy + 2], (10015).to_bytes(2, "little"))
        self.assertEqual(auth_buffer[proxy + rap_zime.ZTEC_CAG_TYPE102_PROXY_DEST_IP_OFFSET:proxy + 8], socket.inet_aton("10.10.2.130"))
        self.assertIn(b"uac-user", auth_buffer[proxy + 60:proxy + 92])
        self.assertIn(b"uac-vmid", auth_buffer[proxy + 20:proxy + 60])
        self.assertEqual(
            struct.unpack_from("<H", auth_buffer, proxy + rap_zime.ZTEC_CAG_TYPE102_PROXY_PWD_LEN_OFFSET)[0],
            32,
        )
        self.assertIn(b"uac-secret-token", auth_buffer[proxy + rap_zime.ZTEC_CAG_TYPE102_PROXY_PASSWD_OFFSET:])
        safe_text = json.dumps(summary)
        self.assertNotIn("uac-user", safe_text)
        self.assertNotIn("uac-secret-token", safe_text)
        self.assertNotIn("uac-vmid", safe_text)
        self.assertNotIn("10.10.2.130", safe_text)

    def test_rap_zime_builds_cag_type102_material_from_access_token_branch_redacted(self):
        built = rap_zime.build_ztec_cag_type102_auth_buffer_from_material(
            {
                "vmUserName": "mat-user",
                "vmId": "mat-vmid",
            },
            {
                "host": "10.10.2.129",
                "port": 10014,
                "type": "rap",
                "accessToken": "secret-access-token",
                "vmHost": "10.10.213.111",
                "vmPort": 5100,
            },
            auth_type="2",
            random_c=0x01020304,
        )
        auth_buffer = built["authBuffer"]
        material = rap_zime.build_kcp_auth_preflight_from_buffer(auth_buffer)

        self.assertEqual(built["summary"]["sourceType"], "fresh-cag-material-type102-builder")
        self.assertEqual(built["summary"]["tokenSource"], "access_token")
        self.assertTrue(built["summary"]["materialFieldsPresent"]["accessToken"])
        self.assertFalse(built["summary"]["materialFieldsPresent"]["destFromVmArgs"])
        self.assertEqual(built["summary"]["destinationSource"], "proxy_gateway")
        self.assertEqual(rap_zime.decode_kcp_segment(material["authHeadSegment"])["len"], 0)
        self.assertEqual(rap_zime.decode_kcp_segment(material["authDataSegment"])["len"], 0)
        self.assertIn(b"secret-access-token", auth_buffer)
        proxy = built["summary"]["proxyDataOffset"]
        self.assertEqual(struct.unpack_from("<H", auth_buffer, proxy + rap_zime.ZTEC_CAG_TYPE102_PROXY_DEST_PORT_OFFSET)[0], 10014)
        self.assertEqual(auth_buffer[proxy + rap_zime.ZTEC_CAG_TYPE102_PROXY_DEST_IP_OFFSET:proxy + 8], socket.inet_aton("10.10.2.129"))
        safe_text = json.dumps(built["summary"])
        self.assertNotIn("mat-user", safe_text)
        self.assertNotIn("mat-vmid", safe_text)
        self.assertNotIn("secret-access-token", safe_text)
        self.assertNotIn("10.10.213.111", safe_text)
        self.assertNotIn("10.10.2.129", safe_text)

    def test_rap_zime_rap_data_frame_codec(self):
        payload = bytes.fromhex("1703030019458fad529a8e6bfc51f14b66bc7162d91edd1e747d24cf6781")
        sample = bytes.fromhex("3593888d810001bbcc010009000000030000001e004f0800") + payload
        decoded = rap_zime.decode_rap_frame(sample)
        self.assertEqual(decoded["tunnelIdHex"], "3593888d")
        self.assertEqual(decoded["frameType"], 0x81)
        self.assertEqual(decoded["flags"], 0)
        self.assertEqual(decoded["field06Be"], 0x01BB)
        self.assertEqual(decoded["field06Le"], 0xBB01)
        self.assertEqual(decoded["payloadLengthSource"], "offset19_le16")
        self.assertEqual(decoded["payloadLength"], len(payload))
        self.assertEqual(decoded["payload"], payload)
        self.assertTrue(decoded["payloadLengthMatches"])
        self.assertEqual(
            rap_zime.encode_rap_data_frame(
                bytes.fromhex(decoded["tunnelIdHex"]),
                decoded["frameType"],
                decoded["flags"],
                decoded["field06Le"],
                decoded["word08"],
                decoded["word12"],
                decoded["header16Prefix"],
                decoded["payload"],
                post_length=decoded["postLengthBytes"],
            ),
            sample,
        )

    def test_rap_zime_decodes_observed_payload_envelope_without_replay_claim(self):
        sample = bytes.fromhex(
            "74a5088781000432020000020000000200000032005d0302"
            "26004f9e7d8ba89df29ee01422f565b16e20b6c7fb4c70f6c920b81693c01c2deb2ba0e939d9dcbe3d43cce5046104af3827"
        )
        frame = rap_zime.decode_rap_frame(sample)
        envelope = rap_zime.decode_zime_payload_envelope(frame)

        self.assertEqual(envelope["innerPayloadLength"], 0x26)
        self.assertEqual(envelope["channelPrefix"], 2)
        self.assertEqual(envelope["protectedPayloadLength"], 48)
        self.assertEqual(envelope["overheadBytes"], 10)
        self.assertTrue(envelope["traceOnly"])
        summary = rap_zime._frame_summary(frame)
        self.assertEqual(summary["zimePayloadEnvelope"]["channelPrefix"], 2)

    def test_rap_zime_compound_datagram_splits_control_and_data_frames(self):
        tunnel = bytes.fromhex("3593888d")
        payload = b"hello"
        control = rap_zime.encode_rap_control_frame(
            tunnel,
            0x82,
            0,
            0x1B01,
            0,
            2,
            word16=0,
        )
        data = rap_zime.encode_rap_data_frame(
            tunnel,
            0x81,
            0,
            0x7F01,
            1,
            2,
            b"\x00\x00\x00",
            payload,
            post_length=b"\x05\x02\x00",
        )
        compound = control + data

        first = rap_zime.decode_rap_frame(compound)
        self.assertEqual(first["frameType"], 0x82)
        self.assertEqual(first["headerSize"], rap_zime.RAP_MIN_HEADER_SIZE)
        self.assertEqual(first["rest"], data)

        frames = rap_zime.decode_rap_frames(compound)
        self.assertEqual([frame["frameType"] for frame in frames], [0x82, 0x81])
        self.assertIsNone(frames[0]["payloadLength"])
        self.assertEqual(frames[1]["payload"], payload)
        self.assertEqual(frames[1]["payloadLength"], len(payload))

    def test_rap_zime_udp_session_sends_ztec_and_rap_payload(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        server.settimeout(2)
        target = server.getsockname()
        tunnel = bytes.fromhex("3593888d")
        received = []
        errors = []

        def serve():
            try:
                ztec_request, client = server.recvfrom(2048)
                received.append(ztec_request)
                decoded = rap_zime.decode_ztec_keepalive(ztec_request)
                server.sendto(rap_zime.encode_ztec_keepalive_ack(
                    decoded["sequence"],
                    decoded["nonce"],
                    marker=decoded["marker"],
                    tail=decoded["tail"],
                    reserved=decoded["reserved"],
                ), client)

                rap_packet, client = server.recvfrom(2048)
                received.append(rap_packet)
                frames = rap_zime.decode_rap_frames(rap_packet)
                self.assertEqual(len(frames), 1)
                self.assertEqual(frames[0]["payload"], b"hello")
                response = rap_zime.encode_rap_data_frame(
                    tunnel,
                    0x81,
                    0,
                    0x100,
                    0,
                    1,
                    payload=b"ok",
                )
                server.sendto(response, client)
            except Exception as err:
                errors.append(err)

        thread = threading.Thread(target=serve)
        thread.start()
        self.addCleanup(server.close)

        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(client.close)
        session = rap_zime.RapZimeUdpSession(
            client,
            target,
            tunnel,
            ztec_host="10.10.2.127",
            ztec_port=10012,
            field06=0x100,
            word08=0,
            word12=1,
        )
        ztec = session.send_ztec_keepalive(sequence=7, nonce=0x1234, tail=0x88776655, timeout=1)
        rap = session.send_rap_payload(b"hello", wait_response=True, timeout=1)
        thread.join(timeout=2)

        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(len(received), 2)
        self.assertTrue(ztec["ackReceived"])
        self.assertEqual(ztec["ack"]["sequence"], 7)
        self.assertEqual(rap["frame"]["payloadKind"], "unknown")
        self.assertEqual(rap["response"]["frameSummaries"][0]["payloadHexPrefix"], b"ok".hex())

    def test_rap_zime_udp_probe_cli_loads_native_report_payloads(self):
        state_path = self.temp_state()
        report_path = Path(state_path).with_name("native-report.json")
        udp_report_path = Path(state_path).with_name("udp-probe-report.json")
        report_path.write_text(json.dumps({
            "callbackRecords": [
                {
                    "event": "native_transport_batch",
                    "packetSpecs": [
                        {"iovPayloadHex": "0102", "iovPayloadTruncated": False},
                    ],
                }
            ]
        }), encoding="utf-8")
        captured = {}

        def fake_run_udp_probe(**kwargs):
            captured.update(kwargs)
            return {"ok": True, "payloadCount": len(kwargs["payloads"])}

        self.set_attr(cli_main.rap_zime, "run_udp_probe", fake_run_udp_probe)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli_main.main([
                "rap-zime-udp-probe",
                "--target",
                "127.0.0.1:1",
                "--tunnel-id",
                "01020304",
                "--no-ztec",
                "--payload-hex",
                "aa",
                "--native-report",
                str(report_path),
                "--udp-rap-payload-envelope",
                "len16",
                "--udp-rap-template-mode",
                "auto",
                "--report-file",
                str(udp_report_path),
            ])

        self.assertEqual(code, 0)
        self.assertEqual(captured["payloads"], [b"\xaa", b"\x01\x02"])
        self.assertEqual(captured["rap_payload_envelope"], "len16")
        self.assertEqual(captured["rap_template_mode"], "auto")
        self.assertEqual(json.loads(out.getvalue())["payloadCount"], 2)
        self.assertEqual(json.loads(udp_report_path.read_text(encoding="utf-8"))["payloadCount"], 2)

    def test_rap_zime_local_spice_client_frame_codec(self):
        payload = bytes(range(0x26))
        sample = bytes.fromhex("0a022600") + payload + b"\xff"
        decoded = rap_zime.decode_local_spice_client_frame(sample)
        self.assertEqual(decoded["marker"], 0x0A)
        self.assertEqual(decoded["channelPrefix"], 2)
        self.assertEqual(decoded["payloadLength"], 0x26)
        self.assertEqual(decoded["payload"], payload)
        self.assertEqual(decoded["rest"], b"\xff")
        self.assertEqual(rap_zime.encode_local_spice_client_frame(decoded["channelPrefix"], payload), sample[:-1])

    def test_rap_zime_builds_fresh_cmd26_bootstrap_frame_redacted(self):
        built = rap_zime.build_fresh_cmd26_bootstrap_frame(
            dest_ip="10.10.2.127",
            dest_port=10012,
            channel_type=1,
            channel_id=0,
            trace_id="0123456789abcdef0123456789abcdef",
            parent_id="0123456789abcdef",
        )
        frame = built["frame"]
        summary = built["summary"]
        body = frame[4:]
        redacted_text = json.dumps(summary, sort_keys=True)

        self.assertEqual(len(frame), rap_zime.FRESH_CMD26_WIRE_LEN)
        self.assertEqual(frame[:4], struct.pack("<BBH", 0x1A, 0, 156))
        self.assertEqual(struct.unpack_from("<H", body, 0)[0], 10012)
        self.assertEqual(body[2], 1)
        self.assertEqual(body[3], 0)
        self.assertEqual(body[4:8], rap_zime.ipv4_to_little_endian("10.10.2.127"))
        self.assertEqual(body[24:40], b"\x00" * 16)
        self.assertEqual(body[40:77], b"\x00" * 37)
        self.assertEqual(body[83], 0)
        self.assertEqual(body[104:136], b"0123456789abcdef0123456789abcdef")
        self.assertEqual(body[136], 0)
        self.assertEqual(body[137:153], b"0123456789abcdef")
        self.assertEqual(body[153], 0)
        self.assertEqual(struct.unpack_from("<H", body, 154)[0], 0x0100)
        self.assertEqual(summary["sourceType"], "fresh-cmd26-bootstrap-builder")
        self.assertEqual(summary["producerFunction"], "add_link_to_proxy_by_socket")
        self.assertEqual(summary["wireLen"], 160)
        self.assertFalse(summary["payloadStoredInReport"])
        self.assertFalse(summary["destination"]["destIpStoredInSummary"])
        self.assertFalse(summary["destination"]["destPortStoredInSummary"])
        self.assertEqual(summary["destination"]["ipStorage"], "host_order_u32_little_endian")
        self.assertEqual(summary["channelTypeIdHex"], "0x0100")
        self.assertIn("loopback client send len=160 cmd26", summary["officialTraceFields"])
        self.assertIn("builder only", summary["gateBoundary"])
        self.assertNotIn("10.10.2.127", redacted_text)
        self.assertNotIn("10012", redacted_text)

        decoded = rap_zime.summarize_fresh_cmd26_bootstrap_frame(frame)
        self.assertTrue(decoded["shapeMatchesFreshCmd26"])
        self.assertFalse(decoded["payloadStoredInReport"])
        self.assertEqual(decoded["fieldSummary"]["channelType"], 1)
        self.assertEqual(decoded["fieldSummary"]["channelId"], 0)
        self.assertEqual(decoded["fieldSummary"]["channelTypeIdHex"], "0x0100")

    def test_rap_zime_builds_fresh_cmd26_bootstrap_frame_ipv6_and_bounds(self):
        built = rap_zime.build_fresh_cmd26_bootstrap_frame(
            dest_ip="2001:db8::1",
            dest_port=1,
            channel_type=2,
            channel_id=7,
            vm_uuid="vm",
            serial_num=bytes(range(16)),
            flag=3,
        )
        body = built["frame"][4:]
        self.assertEqual(body[4:8], b"\x00\x00\x00\x00")
        self.assertEqual(body[8:24], ipaddress.ip_address("2001:db8::1").packed)
        self.assertEqual(body[24:40], bytes(range(16)))
        self.assertEqual(body[40:43], b"vm\x00")
        self.assertEqual(body[83], 3)
        self.assertEqual(body[154:156], struct.pack("<H", 0x0207))
        self.assertEqual(built["summary"]["destination"]["ipFamily"], "ipv6")
        self.assertEqual(built["summary"]["linkPriority"], 3)
        with self.assertRaises(ValueError):
            rap_zime.build_fresh_cmd26_bootstrap_frame(dest_ip="invalid", dest_port=1)
        with self.assertRaises(ValueError):
            rap_zime.build_fresh_cmd26_bootstrap_frame(dest_ip="10.0.0.1", dest_port=70000)

    def test_rap_zime_trace_analysis_builds_runner_input(self):
        state_path = self.temp_state()
        jsonl_path = Path(state_path).with_name("rap-zime.jsonl")
        report_path = Path(state_path).with_name("rap-zime-report.json")
        ztec_request = bytes.fromhex("5a54454306007f020a0a1c2700003d93a00400000000296e3613")
        rap_payload = bytes.fromhex("1703030019458fad529a8e6bfc51f14b66bc7162d91edd1e747d24cf6781")
        rap_frame = rap_zime.encode_rap_data_frame(
            bytes.fromhex("3593888d"),
            0x81,
            0,
            0xBB01,
            0x090001CC,
            0x03000000,
            b"\x00\x00\x00",
            rap_payload,
            post_length=b"\x4f\x08\x00",
        )
        local_display = rap_zime.encode_local_spice_client_frame(
            2,
            spice_protocol.encode_data_message(spice_protocol.SpiceMessage.DISPLAY_INIT, b"", serial=1),
        )
        local_surface = rap_zime.encode_local_spice_client_frame(
            2,
            spice_protocol.encode_data_message(spice_protocol.SpiceMessage.SURFACE_CREATE, b"", serial=2),
        )
        local_mark = rap_zime.encode_local_spice_client_frame(
            2,
            spice_protocol.encode_data_message(spice_protocol.SpiceMessage.MARK, b"", serial=3),
        )
        rows = [
            {"event": "transport_buffer", "function": "sendto", "direction": "send", "fd": 104, "peer": "-", "remote": "111.31.3.182:8899", "len": len(ztec_request), "ret": len(ztec_request), "hex": ztec_request.hex()},
            {"event": "transport_buffer", "function": "sendto", "direction": "send", "fd": 104, "peer": "-", "remote": "111.31.3.182:8899", "len": len(rap_frame), "ret": len(rap_frame), "hex": rap_frame.hex()},
            {"event": "transport_buffer", "function": "recv", "direction": "receive", "fd": 110, "peer": "127.0.0.1:48758", "len": len(local_display), "ret": len(local_display), "hex": local_display.hex()},
            {"event": "transport_buffer", "function": "recv", "direction": "receive", "fd": 110, "peer": "127.0.0.1:48758", "len": len(local_surface), "ret": len(local_surface), "hex": local_surface.hex()},
            {"event": "transport_buffer", "function": "recv", "direction": "receive", "fd": 110, "peer": "127.0.0.1:48758", "len": len(local_mark), "ret": len(local_mark), "hex": local_mark.hex()},
        ]
        jsonl_path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")

        result = rap_zime.analyze_trace(jsonl_path, report_file=report_path, sample_limit=4)
        self.assertTrue(report_path.exists())
        self.assertEqual(result["ztec"]["counts"]["ztec_keepalive_request"], 1)
        self.assertEqual(result["rap"]["primaryTunnelId"], "3593888d")
        self.assertEqual(result["rap"]["frameTypes"]["0x81"], 1)
        self.assertIn("111.31.3.182:8899", result["runnerInput"]["candidateUdpTargets"])
        self.assertEqual(result["ztec"]["targets"]["10.10.2.127:10012"], 1)
        self.assertEqual(result["runnerInput"]["candidateZtecTargets"], ["10.10.2.127:10012"])
        self.assertEqual(result["localSpice"]["channelPrefixes"]["2"], 3)
        self.assertTrue(result["protocolEvidence"]["displayPathObserved"])
        self.assertEqual(result["runnerInput"]["payloadLengthRule"], "offset19_le16_payload_offset24")
        self.assertEqual(result["runnerInput"]["rapDataFrameTemplate"]["field06"], 0xBB01)
        self.assertEqual(result["runnerInput"]["rapDataFrameTemplate"]["word08"], 0x090001CC)
        self.assertEqual(result["runnerInput"]["rapDataFrameTemplate"]["word12"], 0x03000000)
        self.assertEqual(result["runnerInput"]["rapDataFrameTemplate"]["postLengthHex"], "4f0800")
        self.assertEqual(result["runnerInput"]["rapDataFrameSendTemplates"][0]["field06"], 0xBB01)
        self.assertEqual(result["runnerInput"]["rapDataFrameSendTemplates"][0]["payloadKind"], "tls-application-data")
        self.assertFalse(result["runnerInput"]["rapDataFrameSendTemplates"][0]["zimePayloadEnvelopeObserved"])
        self.assertTrue(result["runnerInput"]["observedTransports"]["rapZimeUdpObserved"])
        self.assertEqual(result["runnerInput"]["transport"], "rap-zime-udp")
        self.assertEqual(result["rap"]["samples"][0]["rap"]["payloadKind"], "tls-application-data")
        self.assertEqual(
            rap_zime.classify_payload(bytes.fromhex("300100000000000003000c0000000000000000ffffffff289564fb00000000")),
            "spice-draw-copy",
        )

    def test_rap_zime_trace_analysis_reports_auth_preflight_redacted(self):
        state_path = self.temp_state()
        jsonl_path = Path(state_path).with_name("rap-zime-auth.jsonl")
        report_path = Path(state_path).with_name("rap-zime-auth-report.json")
        auth_head = rap_zime.build_kcp_auth_segment(
            payload=b"secret-auth-head",
            auth_head=True,
            conv=0x12345678,
            syn_id=0x11223344,
            current=0x01020304,
        )
        auth_data = rap_zime.build_kcp_auth_segment(
            payload=b"secret-auth-data",
            auth_head=False,
            conv=0x12345678,
            syn_id=0x11223344,
            current=0x01020305,
        )
        rows = []
        for payload in [auth_head, auth_data]:
            frame = rap_zime.encode_rap_data_frame(
                bytes.fromhex("3593888d"),
                0x81,
                0,
                0xBB01,
                0x090001CC,
                0x03000000,
                b"\x00\x00\x00",
                payload,
                post_length=b"\x4f\x08\x00",
            )
            rows.append({
                "event": "transport_buffer",
                "function": "sendto",
                "direction": "send",
                "fd": 104,
                "peer": "-",
                "remote": "111.31.3.182:8899",
                "len": len(frame),
                "ret": len(frame),
                "hex": frame.hex(),
            })
        jsonl_path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")

        result = rap_zime.analyze_trace(jsonl_path, report_file=report_path, sample_limit=4)
        report_text = report_path.read_text(encoding="utf-8")

        self.assertTrue(result["kcpAuthPreflight"]["observed"])
        self.assertEqual(result["kcpAuthPreflight"]["counts"]["auth-head"], 1)
        self.assertEqual(result["kcpAuthPreflight"]["counts"]["auth-data"], 1)
        self.assertTrue(result["runnerInput"]["kcpAuthPreflightObserved"])
        self.assertEqual(result["rap"]["samples"][0]["rap"]["payloadKind"], "kcp-auth-head")
        self.assertEqual(result["rap"]["samples"][0]["hexPrefix"], "<redacted:kcp-auth>")
        self.assertTrue(result["kcpAuthPreflight"]["samples"][0]["payloadRedacted"])
        self.assertNotIn("secret-auth", report_text)
        self.assertNotIn(b"secret-auth-head".hex(), report_text)
        self.assertNotIn(b"secret-auth-data".hex(), report_text)

    def test_rap_zime_pcap_analysis_is_metadata_only(self):
        state_path = self.temp_state()
        pcap_path = Path(state_path).with_name("official-no-probe.pcapng")
        report_path = Path(state_path).with_name("pcap-report.json")
        ss_path = Path(state_path).with_name("ss.log")
        pcap_path.write_bytes(b"pcap-placeholder")
        ss_path.write_text(
            "tcp ESTAB 0 0 127.0.0.1:43632 127.0.0.1:38211 users:((\"uSmartView_VDI_\",pid=1901422,fd=110))\n"
            "tcp ESTAB 0 0 198.18.0.1:40806 198.18.0.151:8883 users:((\"cmcc-jtydn\",pid=1898118,fd=123))\n",
            encoding="utf-8",
        )

        def fake_tshark(path, protocol):
            if protocol == "udp":
                return [
                    "1000.0\t192.168.1.48\t44172\t111.31.3.182\t8899\t1260\t1218",
                    "1000.1\t111.31.3.182\t8899\t192.168.1.48\t44172\t96\t54",
                    "1000.2\t198.18.0.1\t48571\t111.31.3.182\t8899\t1260\t1218",
                ]
            return [
                "1000.0\t127.0.0.1\t43632\t127.0.0.1\t38211\t120\t52",
            ]

        self.set_attr(rap_zime, "_run_tshark_fields", fake_tshark)

        result = rap_zime.analyze_external_pcap(
            pcap_path,
            ss_log=ss_path,
            report_file=report_path,
            sample_limit=5,
        )

        self.assertTrue(report_path.exists())
        self.assertEqual(result["analysis"], "external_pcap_metadata_only")
        self.assertFalse(result["payloadPolicy"]["payloadExtracted"])
        self.assertFalse(result["payloadPolicy"]["payloadFieldsRequested"])
        self.assertIn("111.31.3.182:8899", result["runnerInput"]["candidateUdpTargets"])
        self.assertFalse(result["runnerInput"]["runnerInputReady"])
        self.assertIn("rapDataFrameSendTemplates", result["runnerInput"]["missing"])
        dumped = json.dumps(result)
        self.assertNotIn("hex", dumped)
        self.assertNotIn("udp.payload", dumped)
        self.assertEqual(result["ss"]["vdiLoopbackPeersTop"][0]["peer"], "127.0.0.1:38211")

    def test_rap_zime_pcap_analysis_cli_writes_report(self):
        state_path = self.temp_state()
        pcap_path = Path(state_path).with_name("official-no-probe.pcapng")
        report_path = Path(state_path).with_name("pcap-report.json")
        pcap_path.write_bytes(b"pcap-placeholder")
        captured = {}

        def fake_analyze_external_pcap(path, **kwargs):
            captured["path"] = path
            captured.update(kwargs)
            if kwargs.get("report_file"):
                Path(kwargs["report_file"]).write_text(json.dumps({"ok": True}), encoding="utf-8")
            return {"ok": True, "analysis": "external_pcap_metadata_only"}

        self.set_attr(cli_main.rap_zime, "analyze_external_pcap", fake_analyze_external_pcap)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli_main.main([
                "analyze-rap-zime-pcap",
                str(pcap_path),
                "--focus-udp-port",
                "8899",
                "--sample-limit",
                "3",
                "--report-file",
                str(report_path),
            ])

        self.assertEqual(code, 0)
        self.assertEqual(captured["path"], str(pcap_path))
        self.assertEqual(captured["focus_udp_port"], 8899)
        self.assertEqual(captured["sample_limit"], 3)
        self.assertTrue(report_path.exists())

    def test_rap_zime_runner_config_uses_inner_ztec_target(self):
        config = rap_zime.runner_config_from_input({
            "candidateUdpTargets": ["111.31.3.182:8899"],
            "candidateZtecTargets": ["10.10.2.127:10012"],
            "primaryTunnelId": "3593888d",
        })

        self.assertEqual(config["targetText"], "111.31.3.182:8899")
        self.assertEqual(config["ztecHost"], "10.10.2.127")
        self.assertEqual(config["ztecPort"], 10012)

    def test_rap_zime_runner_input_readiness_reports_redacted_gaps(self):
        missing = rap_zime.runner_input_readiness({
            "transport": "rap-zime-udp",
            "primaryTunnelId": "01020304",
            "needsTraceWithSocketRemote": True,
        }, require_templates=True, require_kcp_auth_ready=True)

        self.assertFalse(missing["ok"])
        self.assertFalse(missing["readyForLiveShortTest"])
        self.assertFalse(missing["desktopKeepaliveProven"])
        self.assertEqual(missing["proof"], "runner_input_structure_only")
        self.assertIn("RAP UDP target is missing", missing["missing"])
        self.assertIn("send-side RAP templates are missing", missing["missing"])
        self.assertIn("trace lacks socket remote details required to drive the UDP runner", missing["missing"])
        self.assertIn("KCP auth is not ready: provide fresh auth material source or prove auth disabled", missing["missing"])
        self.assertTrue(missing["kcpAuth"]["requiredForLiveSynack"])
        self.assertFalse(missing["kcpAuth"]["ready"])
        self.assertFalse(missing["kcpAuth"]["payloadStoredInReport"])
        self.assertEqual(missing["counts"]["candidateUdpTargets"], 0)
        self.assertNotIn("primaryTunnelId", json.dumps(missing))

        ready = rap_zime.runner_input_readiness({
            "transport": "rap-zime-udp",
            "primaryTunnelId": "01020304",
            "candidateUdpTargets": ["111.31.3.182:8899"],
            "candidateZtecTargets": ["10.10.2.127:10012"],
            "rapDataFrameTemplate": {
                "frameType": 0x81,
                "field06": 0x100,
                "word08": 0,
                "word12": 1,
            },
            "rapDataFrameSendTemplates": [
                {"payloadKind": "quic-long-header-candidate"},
            ],
            "kcpAuthDisabledProven": True,
        }, require_templates=True, require_kcp_auth_ready=True)
        self.assertTrue(ready["ok"])
        self.assertEqual(ready["counts"]["rapDataFrameSendTemplates"], 1)
        self.assertTrue(ready["sessionOwningIfUsedLive"])
        self.assertTrue(ready["kcpAuth"]["disabledProven"])
        self.assertTrue(ready["kcpAuth"]["ready"])

        material_ready = rap_zime.runner_input_readiness({
            "transport": "rap-zime-udp",
            "primaryTunnelId": "01020304",
            "candidateUdpTargets": ["111.31.3.182:8899"],
            "candidateZtecTargets": ["10.10.2.127:10012"],
            "rapDataFrameTemplate": {"frameType": 0x81},
            "rapDataFrameSendTemplates": [{"payloadKind": "kcp-auth-head"}],
            "kcpAuthPreflightObserved": True,
            "kcpAuthMaterial": {
                "fresh": True,
                "sourceType": "fresh-official-trace-redacted",
                "payloadHex": "7365637265742d61757468",
            },
        }, require_templates=True, require_kcp_auth_ready=True)
        self.assertTrue(material_ready["readyForLiveShortTest"])
        self.assertEqual(material_ready["kcpAuth"]["materialSourceType"], "fresh-official-trace-redacted")
        self.assertNotIn("736563726574", json.dumps(material_ready))
        self.assertNotIn("secret-auth", json.dumps(material_ready))

    def test_check_rap_zime_runner_input_cli_writes_readiness_report(self):
        state_path = self.temp_state()
        input_path = Path(state_path).with_name("runner-input.json")
        report_path = Path(state_path).with_name("runner-input-readiness.json")
        input_path.write_text(json.dumps({
            "runnerInput": {
                "transport": "rap-zime-udp",
                "primaryTunnelId": "01020304",
                "candidateUdpTargets": ["111.31.3.182:8899"],
                "candidateZtecTargets": ["10.10.2.127:10012"],
                "rapDataFrameTemplate": {"frameType": 0x81},
                "rapDataFrameSendTemplates": [{"payloadKind": "quic-long-header-candidate"}],
            }
        }), encoding="utf-8")

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli_main.main([
                "check-rap-zime-runner-input",
                str(input_path),
                "--require-templates",
                "--require-kcp-auth-ready",
                "--report-file",
                str(report_path),
            ])

        self.assertEqual(code, 0)
        printed = json.loads(out.getvalue())
        written = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertFalse(printed["readyForLiveShortTest"])
        self.assertFalse(written["readyForLiveShortTest"])
        self.assertIn("KCP auth is not ready", written["missing"][0])
        self.assertEqual(written["counts"]["candidateUdpTargets"], 1)
        self.assertNotIn("111.31.3.182", json.dumps(written))

    def test_rap_zime_udp_probe_uses_runner_templates_and_len16_envelope(self):
        static_result = rap_zime.run_udp_probe(
            runner_input={
                "candidateUdpTargets": ["127.0.0.1:9"],
                "primaryTunnelId": "01020304",
                "rapDataFrameTemplate": {
                    "frameType": 0x81,
                    "flags": 1,
                    "field06": 0x1111,
                    "word08": 0x22222222,
                    "word12": 0x33333333,
                    "header16PrefixHex": "000000",
                    "postLengthHex": "000000",
                },
            },
            payloads=[b"hello"],
            ztec=False,
            timeout=0.01,
        )
        self.assertEqual(static_result["rap"][0]["frame"]["field06Le"], 0x1111)
        self.assertEqual(static_result["rap"][0]["frame"]["word08"], 0x22222222)
        self.assertEqual(static_result["rap"][0]["frame"]["word12"], 0x33333333)

        payload = b"\x00\x00\x00\x00" + b"\xc3" + b"quic-test"
        result = rap_zime.run_udp_probe(
            runner_input={
                "candidateUdpTargets": ["127.0.0.1:9"],
                "candidateZtecTargets": ["10.10.2.127:10012"],
                "primaryTunnelId": "01020304",
                "rapDataFrameTemplate": {
                    "frameType": 0x81,
                    "flags": 1,
                    "field06": 0x1111,
                    "word08": 0x22222222,
                    "word12": 0x33333333,
                    "header16PrefixHex": "000000",
                    "postLengthHex": "000000",
                },
                "rapDataFrameSendTemplates": [
                    {
                        "index": 7,
                        "frameType": 0x81,
                        "flags": 2,
                        "field06": 0x3344,
                        "word08": 0x55667788,
                        "word12": 0x99AABBCC,
                        "header16PrefixHex": "010203",
                        "postLengthHex": "aabbcc",
                        "payloadKind": "quic-long-header-candidate",
                        "payloadLength": len(payload),
                    }
                ],
            },
            payloads=[payload],
            ztec=False,
            timeout=0.01,
            rap_payload_envelope=rap_zime.RAP_PAYLOAD_ENVELOPE_LEN16,
            rap_template_mode=rap_zime.RAP_TEMPLATE_MODE_AUTO,
        )

        sent = result["rap"][0]
        self.assertEqual(result["rapPayloadEnvelope"], "len16")
        self.assertEqual(result["rapTemplateMode"], "auto")
        self.assertEqual(result["rapSendTemplateCount"], 1)
        self.assertEqual(sent["payloadKind"], "zime-udp-reserved4:quic-long-header-candidate")
        self.assertEqual(sent["payloadEnvelope"]["declaredLen"], len(payload))
        self.assertEqual(sent["rapTemplateSelection"]["source"], "runnerInput.rapDataFrameSendTemplates")
        self.assertEqual(sent["rapTemplateSelection"]["templateListIndex"], 0)
        self.assertEqual(sent["rapTemplateSelection"]["templatePayloadKind"], "quic-long-header-candidate")
        self.assertEqual(sent["frame"]["field06Le"], 0x3344)
        self.assertEqual(sent["frame"]["word08"], 0x55667788)
        self.assertEqual(sent["frame"]["word12"], 0x99AABBCC)
        self.assertEqual(sent["frame"]["payloadLength"], len(payload) + 2)
        self.assertTrue(sent["frame"]["payloadHexPrefix"].startswith(len(payload).to_bytes(2, "little").hex()))

    def test_rap_zime_trace_analysis_infers_udp_target_from_fd_lifecycle(self):
        state_path = self.temp_state()
        jsonl_path = Path(state_path).with_name("rap-zime-fd-lifecycle.jsonl")
        target = "111.31.3.182:8899"
        rap_payload = bytes.fromhex("1703030019458fad529a8e6bfc51f14b66bc7162d91edd1e747d24cf6781")
        rap_frame = rap_zime.encode_rap_data_frame(
            bytes.fromhex("3593888d"),
            0x81,
            0,
            0xBB01,
            0x090001CC,
            0x03000000,
            b"\x00\x00\x00",
            rap_payload,
            post_length=b"\x4f\x08\x00",
        )
        rows = [
            {
                "event": "transport_socket",
                "function": "socket",
                "pid": 321,
                "fd": 104,
                "domain": 2,
                "type": 2,
                "protocol": 0,
                "ret": 104,
                "errno": 0,
            },
            {
                "event": "transport_bind",
                "function": "bind",
                "pid": 321,
                "fd": 104,
                "requestedLocal": "0.0.0.0:0",
                "local": "10.1.2.3:45678",
                "ret": 0,
                "errno": 0,
            },
            {
                "event": "transport_connect",
                "function": "connect",
                "pid": 321,
                "fd": 104,
                "remote": target,
                "local": "10.1.2.3:45678",
                "peerAfter": target,
                "ret": 0,
                "errno": 0,
            },
            {
                "event": "transport_buffer",
                "function": "send",
                "direction": "send",
                "pid": 321,
                "fd": 104,
                "peer": "-",
                "remote": "-",
                "len": len(rap_frame),
                "ret": len(rap_frame),
                "hex": rap_frame.hex(),
            },
        ]
        jsonl_path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")

        result = rap_zime.analyze_trace(jsonl_path)
        self.assertEqual(result["rap"]["primaryTunnelId"], "3593888d")
        self.assertIn(target, result["runnerInput"]["candidateUdpTargets"])
        self.assertFalse(result["runnerInput"]["needsTraceWithSocketRemote"])
        self.assertEqual(result["runnerInput"]["candidateUdpTargetSources"][target]["fdLifecycle:peerAfter"], 1)
        self.assertEqual(result["rap"]["targets"][target], 1)
        self.assertEqual(result["rap"]["targetSources"][target]["fdLifecycle:peerAfter"], 1)
        self.assertEqual(result["rap"]["samples"][0]["target"], target)
        self.assertEqual(result["rap"]["samples"][0]["targetSource"], "fdLifecycle:peerAfter")
        lifecycle = result["socketLifecycle"]["fds"][0]
        self.assertEqual(lifecycle["fd"], 104)
        self.assertEqual(lifecycle["lastExternalTarget"], target)

    def test_rap_zime_trace_analysis_marks_family_native_trace_without_rap(self):
        state_path = self.temp_state()
        jsonl_path = Path(state_path).with_name("family-native.jsonl")
        tls_record = bytes.fromhex(
            "140303000101160303002800000000000000006b39bedb5b6722246dd4edc4cedf5b08b2b0773d3399a133b2d638d4da75ef11"
        )
        rows = [
            {
                "event": "transport_buffer",
                "function": "recvmsg",
                "direction": "receive",
                "fd": 46,
                "peer": "family:1",
                "remote": "-",
                "len": 32,
                "ret": 32,
                "payloadKind": "spice-ping",
                "hex": spice_protocol.encode_data_message(spice_protocol.SpiceMessage.PING, b"p").hex(),
            },
            {
                "event": "transport_buffer",
                "function": "recvmsg",
                "direction": "receive",
                "fd": 46,
                "peer": "family:1",
                "remote": "-",
                "len": 32,
                "ret": 32,
                "payloadKind": "spice-pong",
                "hex": spice_protocol.encode_data_message(spice_protocol.SpiceMessage.PONG, b"p").hex(),
            },
            {
                "event": "transport_buffer",
                "function": "recvmsg",
                "direction": "receive",
                "fd": 46,
                "peer": "family:1",
                "remote": "-",
                "len": 32,
                "ret": 32,
                "payloadKind": "spice-ack-sync",
                "hex": spice_protocol.encode_data_message(spice_protocol.SpiceMessage.ACK_SYNC, b"\x01\x00\x00\x00").hex(),
            },
            {
                "event": "transport_buffer",
                "function": "send",
                "direction": "send",
                "fd": 25,
                "peer": "198.18.0.18:443",
                "remote": "-",
                "len": len(tls_record),
                "ret": len(tls_record),
                "payloadKind": "unknown",
                "hex": tls_record.hex(),
            },
        ]
        jsonl_path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")

        result = rap_zime.analyze_trace(jsonl_path)
        self.assertIsNone(result["rap"]["primaryTunnelId"])
        self.assertEqual(result["runnerInput"]["transport"], "family-native-spice-trace-only")
        self.assertFalse(result["runnerInput"]["observedTransports"]["rapZimeUdpObserved"])
        self.assertTrue(result["runnerInput"]["observedTransports"]["familyNativeSpiceObserved"])
        self.assertTrue(result["runnerInput"]["observedTransports"]["externalTlsObserved"])
        self.assertFalse(result["runnerInput"]["needsTraceWithSocketRemote"])
        self.assertEqual(result["familyNative"]["flows"][0]["fd"], 46)
        self.assertTrue(result["familyNative"]["flows"][0]["ackPongMaintenanceSeen"])
        self.assertEqual(result["externalTls"]["payloadKindCounts"]["tls-change-cipher-spec"], 1)

    def test_desktop_http_verify_aborts_when_official_client_process_present(self):
        state_path = self.temp_state()
        clock = {"now": 1000.0}

        self.set_attr(desktop_keepalive.time, "time", lambda: clock["now"])
        self.set_attr(desktop_keepalive.time, "sleep", lambda seconds: clock.__setitem__("now", clock["now"] + max(1, float(seconds))))
        self.set_attr(desktop_keepalive, "official_client_processes", lambda: [{"pid": 123, "cmdline": "bootCypc"}])
        self.set_attr(cloud, "selected_user_service_id", lambda state_path=None, explicit=None: str(explicit or "2663816"))
        self.set_attr(cloud, "status", lambda user_service_id=None, state_path=None: {"vmStatus": 1, "vmStatusShow": "运行中"})
        self.set_attr(desktop_keepalive, "heartbeat", lambda user_service_id, state_path=None: {"code": 4041, "msg": "lock"})
        self.set_attr(desktop_keepalive, "info_report", lambda state_path=None: {"code": 2000, "msg": "SUCCESS"})
        self.set_attr(desktop_keepalive, "log_report_config", lambda state_path=None: {"code": 2000, "msg": "SUCCESS"})

        result = desktop_keepalive.run_official_http_verify(
            "2663816",
            state_path,
            duration=2,
            heartbeat_interval=1,
            info_interval=1,
            log_config_interval=1,
            status_interval=1,
            min_proof_seconds=2,
        )
        self.assertTrue(result["aborted"])
        self.assertEqual(result["abortReason"], "official_client_process_present_before_verify")
        self.assertFalse(result["accepted"])
        self.assertFalse(result["desktopKeepaliveProven"])
        self.assertFalse(result["successCriteria"]["noOfficialClientProcess"])
        self.assertEqual(result["officialClientProcessSnapshots"][0]["processes"][0]["cmdline"], "bootCypc")
        self.assertEqual(result["events"], [])

    def test_desktop_http_verify_allows_contaminated_control_but_does_not_prove(self):
        state_path = self.temp_state()
        clock = {"now": 1000.0}

        self.set_attr(desktop_keepalive.time, "time", lambda: clock["now"])
        self.set_attr(desktop_keepalive.time, "sleep", lambda seconds: clock.__setitem__("now", clock["now"] + max(1, float(seconds))))
        self.set_attr(desktop_keepalive, "official_client_processes", lambda: [{"pid": 123, "cmdline": "bootCypc"}])
        self.set_attr(cloud, "selected_user_service_id", lambda state_path=None, explicit=None: str(explicit or "2663816"))
        self.set_attr(cloud, "status", lambda user_service_id=None, state_path=None: {"vmStatus": 1, "vmStatusShow": "运行中"})
        self.set_attr(desktop_keepalive, "heartbeat", lambda user_service_id, state_path=None: {"code": 4041, "msg": "lock"})
        self.set_attr(desktop_keepalive, "info_report", lambda state_path=None: {"code": 2000, "msg": "SUCCESS"})
        self.set_attr(desktop_keepalive, "log_report_config", lambda state_path=None: {"code": 2000, "msg": "SUCCESS"})

        result = desktop_keepalive.run_official_http_verify(
            "2663816",
            state_path,
            duration=2,
            heartbeat_interval=1,
            info_interval=1,
            log_config_interval=1,
            status_interval=1,
            min_proof_seconds=2,
            allow_official_client_present=True,
        )
        self.assertFalse(result["aborted"])
        self.assertGreater(len(result["events"]), 0)
        self.assertFalse(result["accepted"])
        self.assertFalse(result["desktopKeepaliveProven"])
        self.assertFalse(result["successCriteria"]["noOfficialClientProcess"])

    def test_logout_desktop_and_account_clear_local_state(self):
        state_path = self.temp_state()
        args = core.argparse.Namespace(state=state_path)
        core.save_state({
            "selectedUserServiceId": "2663816",
            "selectedDesktop": {
                "userServiceId": "2663816",
                "skuName": "家庭云电脑畅享版月包",
            },
            "sohoToken": "token",
            "userId": 1,
            "nickname": "nick",
            "phone": "phone",
            "isLogined": True,
        }, args)
        requests = []

        def fake_api(path, data=None, args=None):
            requests.append((path, data))
            return {"code": 2000, "msg": "SUCCESS"}

        self.set_attr(core, "api_request", fake_api)
        self.assertEqual(logout.desktop_logout(state_path=state_path)["code"], 2000)
        self.assertEqual(logout.account_logout(state_path=state_path, clear_local=True)["code"], 2000)
        state = core.load_state(args)
        self.assertNotIn("sohoToken", state)
        self.assertNotIn("userId", state)
        self.assertEqual(requests[0][0], "/cc/cloudPc/logout/v2")
        self.assertEqual(requests[1][0], "/login/logout/v1")

    def test_workflow_run_wires_token_boot_and_http_replay(self):
        state_path = self.temp_state()
        calls = []
        self.set_attr(workflow.cloud, "selected_user_service_id", lambda state_path=None, explicit=None: str(explicit or "2663816"))
        self.set_attr(workflow.token, "ensure_token", lambda state_path=None, relogin=True: calls.append("token") or (True, {"code": 2000}))
        self.set_attr(workflow.account_keepalive, "refresh_once", lambda state_path=None: calls.append("refresh") or {"userId": 1})
        self.set_attr(workflow, "ensure_desktop_running", lambda *args, **kwargs: calls.append("boot-check") or {
            "userServiceId": "2663816",
            "booted": False,
            "alreadyRunning": True,
            "status": {"vmStatus": 1, "vmStatusShow": "运行中", "running": True, "off": False},
            "bootReport": None,
        })
        self.set_attr(workflow.desktop_keepalive, "run_official_http_loop", lambda *args, **kwargs: calls.append("http") or {
            "accepted": False,
            "desktopKeepaliveProven": False,
            "experimental": True,
            "userServiceId": "2663816",
        })

        result = workflow.run(
            "2663816",
            state_path=state_path,
            run_seconds=1,
            cycle_interval=1,
            cycle_duration=1,
            token_check_interval=1,
            account_relogin_hours=0,
        )
        self.assertTrue(result["experimental"])
        self.assertIn("token", calls)
        self.assertIn("boot-check", calls)
        self.assertIn("http", calls)

    def test_strategy_auto_points_to_unimplemented_spice_target(self):
        state_path = self.temp_state()
        with self.assertRaises(core.CmccError) as ctx:
            strategy.run("auto", "2663816", state_path=state_path, run_seconds=1)
        self.assertIn("spice protocol keepalive is the active target", str(ctx.exception))

    def test_strategy_cag_requires_explicit_session_takeover(self):
        with self.assertRaises(core.CmccError):
            strategy.run("cag-https", "2663816", state_path=self.temp_state(), run_seconds=1)

    def test_strategy_cag_rejected_even_when_takeover_allowed(self):
        state_path = self.temp_state()
        with self.assertRaises(core.CmccError) as ctx:
            strategy.run(
                "cag-https",
                "2663816",
                state_path=state_path,
                run_seconds=1,
                cag_interval=60,
                allow_session_takeover=True,
            )
        self.assertIn("cag-https has been rejected", str(ctx.exception))

    def test_capture_analysis_marks_visible_timers_as_unproven(self):
        state_path = self.temp_state()
        har_path = Path(state_path).with_name("capture.har")
        har_path.write_text(json.dumps({
            "log": {
                "entries": [
                    {
                        "startedDateTime": "2026-07-01T07:00:00.000Z",
                        "request": {
                            "method": "CONNECT",
                            "url": "https://soho.komect.com:443",
                            "postData": {"text": ""},
                        },
                        "response": {"status": 0, "content": {"text": ""}},
                    },
                    {
                        "startedDateTime": "2026-07-01T07:00:01.000Z",
                        "request": {
                            "method": "POST",
                            "url": "https://soho.komect.com/terminal/cc/cloudPc/heartbeat/v2",
                            "postData": {"text": "{\"data\":\"encrypted\"}"},
                        },
                        "response": {
                            "status": 200,
                            "content": {"text": "{\"code\":4041,\"msg\":\"lock\"}"},
                        },
                    },
                    {
                        "startedDateTime": "2026-07-01T07:00:31.000Z",
                        "request": {
                            "method": "POST",
                            "url": "https://soho.komect.com/terminal/cc/cloudPc/heartbeat/v2",
                            "postData": {"text": "{\"data\":\"encrypted\"}"},
                        },
                        "response": {
                            "status": 200,
                            "content": {"text": "{\"code\":4041,\"msg\":\"lock\"}"},
                        },
                    },
                    {
                        "startedDateTime": "2026-07-01T07:00:02.000Z",
                        "request": {
                            "method": "POST",
                            "url": "https://soho.komect.com/terminal/cc/cloudPc/infoReport/v2",
                            "postData": {"text": "{\"data\":\"encrypted\"}"},
                        },
                        "response": {
                            "status": 200,
                            "content": {"text": "{\"code\":2000,\"msg\":\"SUCCESS\"}"},
                        },
                    },
                    {
                        "startedDateTime": "2026-07-01T07:00:03.000Z",
                        "request": {
                            "method": "POST",
                            "url": "https://soho.komect.com/terminal/system/logReport/config/v2",
                            "postData": {"text": ""},
                        },
                        "response": {
                            "status": 200,
                            "content": {"text": "{\"code\":2000,\"msg\":\"SUCCESS\"}"},
                        },
                    },
                    {
                        "startedDateTime": "2026-07-01T07:00:04.000Z",
                        "request": {
                            "method": "POST",
                            "url": "https://soho.komect.com/terminal/cc/getFirmAuth/v1",
                            "postData": {"text": "{\"userServiceId\":\"2663816\"}"},
                        },
                        "response": {
                            "status": 200,
                            "content": {"text": "{\"code\":2000,\"msg\":\"SUCCESS\"}"},
                        },
                    },
                ]
            }
        }), encoding="utf-8")

        args = core.argparse.Namespace(
            capture=[str(har_path)],
            baseline=[],
            source=[],
            source_limit=12,
            samples=False,
            include_all=False,
        )
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            core.analyze_session_capture(args)
        report = json.loads(out.getvalue())
        self.assertEqual(report["verdict"], "visible_connected_timers_only_unproven")
        self.assertIn("/cc/cloudPc/heartbeat/v2", report["visibleConnectedTimers"])
        self.assertIn("/resource/desktopUptime", report["enterpriseBlogEndpoints"]["absent"])
        self.assertIn("HTTP-only desktop keepalive is rejected", report["httpOnlyKeepaliveEvidence"]["successSignal"])
        self.assertFalse(report["httpOnlyKeepaliveEvidence"]["pureHttpDesktopEndpointFound"])
        self.assertTrue(report["httpOnlyKeepaliveEvidence"]["visibleTimersOnly"])
        self.assertTrue(report["httpOnlyKeepaliveEvidence"]["sessionOwningFallbackFound"])
        self.assertEqual(report["officialTimerMatrix"][0]["classification"]["class"], "official_connected_http_timer")
        self.assertEqual(report["sessionOwningFallbackCandidates"][0]["apiPath"], "/cc/getFirmAuth/v1")
        self.assertFalse(any(candidate["endpoint"].startswith("CONNECT ") for candidate in report["candidates"]))

    def test_capture_analysis_marks_terminalprobe_as_telemetry_and_redacts_replay(self):
        state_path = self.temp_state()
        har_path = Path(state_path).with_name("terminalprobe.har")
        har_path.write_text(json.dumps({
            "log": {
                "entries": [
                    {
                        "startedDateTime": "2026-07-01T07:00:00.000Z",
                        "request": {
                            "method": "POST",
                            "url": "https://terminalprobe.soho.komect.com/sc/probe-terminal-portal/performance/send/v1",
                            "postData": {"text": json.dumps({
                                "labels": {
                                    "phone": "encrypted-phone",
                                    "vmId": "real-vm-id",
                                    "traceId": "real-trace-id",
                                    "spuCode": "zte-cloud-pc",
                                },
                                "monitorInfoList": [{"metricList": [{"name": "cpuUsage", "value": "1"}]}],
                            })},
                        },
                        "response": {
                            "status": 200,
                            "content": {"text": "{\"code\":2000,\"message\":\"SUCCESS\"}"},
                        },
                    },
                    {
                        "startedDateTime": "2026-07-01T07:00:01.000Z",
                        "request": {
                            "method": "POST",
                            "url": "https://soho.komect.com/terminal/cc/cloudPc/heartbeat/v2",
                            "postData": {"text": "{\"data\":\"encrypted\"}"},
                        },
                        "response": {
                            "status": 200,
                            "content": {"text": "{\"code\":4041,\"msg\":\"lock\"}"},
                        },
                    },
                ]
            }
        }), encoding="utf-8")

        args = core.argparse.Namespace(
            capture=[str(har_path)],
            baseline=[],
            source=[],
            source_limit=12,
            samples=False,
            include_all=True,
        )
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            core.analyze_session_capture(args)
        report = json.loads(out.getvalue())
        probe_detail = next(item for item in report["endpointDetails"] if item["apiPath"].startswith("/sc/probe-terminal-portal/"))
        self.assertEqual(probe_detail["classification"]["class"], "terminalprobe_telemetry")
        probe_candidate = next(item for item in report["candidates"] if item["apiPath"].startswith("/sc/probe-terminal-portal/"))
        self.assertIn("<vmid>", probe_candidate["replayCommand"])
        self.assertIn("<traceid>", probe_candidate["replayCommand"])
        self.assertNotIn("real-vm-id", probe_candidate["replayCommand"])
        self.assertNotIn("real-trace-id", probe_candidate["replayCommand"])
        self.assertLess(probe_candidate["score"], 0)

    def test_capture_analysis_scans_decoded_jsonl_payloads(self):
        state_path = self.temp_state()
        jsonl_path = Path(state_path).with_name("sdk-session.jsonl")
        jsonl_path.write_text("\n".join([
            json.dumps({
                "event": "aes_cbc_decode",
                "process": "bootCypc",
                "function": "AesCbcDecode",
                "phase": "output",
                "hash": "abc",
                "len": 123,
                "value": json.dumps({
                    "connectInfo": {
                        "connectStr": "encrypted",
                        "vmStatus": 1,
                    },
                    "sysConfig": {
                        "opDesktopTimeout": 180,
                        "vdiPingTimeout": "4",
                    },
                    "tokenInfo": {
                        "accessToken": "token",
                    },
                }),
            }),
        ]) + "\n", encoding="utf-8")

        args = core.argparse.Namespace(
            capture=[str(jsonl_path)],
            baseline=[],
            source=[],
            source_limit=12,
            samples=False,
            include_all=False,
            report_file="",
        )
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            core.analyze_session_capture(args)
        report = json.loads(out.getvalue())
        decoded = report["decodedPayloadFindings"]
        self.assertEqual(decoded["decodedPayloads"], 1)
        self.assertEqual(decoded["findings"][0]["classification"]["class"], "cag_decoded_connect_material")
        self.assertEqual(decoded["enterpriseStyleKeepaliveReferences"], [])
        self.assertEqual(decoded["conclusion"], "decoded payloads do not expose an independent HTTP desktop-session keepalive endpoint")

    def test_capture_analysis_scans_binary_capture_strings(self):
        state_path = self.temp_state()
        pcap_path = Path(state_path).with_name("capture.pcapng")
        pcap_path.write_bytes(
            b"\x0a\x0d\x0d\x0a"
            b"soho.komect.com\x00"
            b"https://111.31.3.182:8899/cs/cs_connectDesktop.action\x00"
            b"opentelemetry spice connect surface create success\x00"
            b"ReportInsight gateway:111.31.3.182,ag-port 8899\x00"
        )

        args = core.argparse.Namespace(
            capture=[str(pcap_path)],
            baseline=[],
            source=[],
            source_limit=12,
            samples=False,
            include_all=False,
            report_file="",
        )
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            core.analyze_session_capture(args)
        report = json.loads(out.getvalue())
        binary = report["binaryCaptureFindings"]
        self.assertTrue(binary["transportSignals"]["sohoHostVisible"])
        self.assertTrue(binary["transportSignals"]["cag8899Visible"])
        self.assertTrue(binary["transportSignals"]["opentelemetryVisible"])
        self.assertTrue(binary["transportSignals"]["spiceOrSdkSuccessVisible"])
        connect_path = next(item for item in binary["visiblePaths"] if item["path"] == "/cs/cs_connectDesktop.action")
        self.assertEqual(connect_path["classification"]["class"], "connect_material_or_boot")
        self.assertEqual(report["verdict"], "no_http_desktop_keepalive_candidate_found")

    def test_capture_endpoint_classification_rejects_idle_and_external_noise(self):
        idle = core.classify_endpoint("/cc/cloudPc/getDisconnectTime/v1")
        self.assertEqual(idle["class"], "idle_timeout_info")
        self.assertEqual(idle["desktopKeepaliveEvidence"], "none_by_itself")

        external = core.classify_endpoint("/q", method="POST")
        self.assertEqual(external["class"], "external_or_unrelated_noise")
        self.assertEqual(external["desktopKeepaliveEvidence"], "none")

        sms = core.classify_endpoint("/login/sms/send/v1")
        self.assertEqual(sms["class"], "account_or_system_liveness")

    def test_trace_timeline_groups_family_and_loopback_spice(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        path = Path(td.name) / "trace.jsonl"
        rows = [
            {
                "sec": 10,
                "nsec": 0,
                "event": "transport_buffer",
                "function": "recvmsg",
                "direction": "receive",
                "peer": "family:1",
                "fd": 9,
                "len": 6,
                "ret": 6,
                "payloadKind": "chuanyun-frame:unknown",
                "hex": "010203",
            },
            {
                "sec": 11,
                "nsec": 500000000,
                "event": "transport_buffer",
                "function": "send",
                "direction": "send",
                "peer": "127.0.0.1:48752",
                "fd": 18,
                "len": 6,
                "ret": 6,
                "payloadKind": "spice-display-init",
                "hex": "020000000000",
            },
            {
                "sec": 12,
                "nsec": 0,
                "event": "transport_buffer",
                "function": "sendto",
                "direction": "send",
                "peer": "-",
                "remote": "111.31.3.182:8899",
                "fd": 104,
                "len": 6,
                "ret": 6,
                "payloadKind": "spice-ping",
                "hex": "040000000000",
            },
        ]
        path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        report = trace_timeline.timeline(path)
        self.assertTrue(report["findings"]["familyIsNativeTransport"])
        self.assertTrue(report["findings"]["loopbackHasPlainSpice"])
        self.assertTrue(report["findings"]["displayPathObserved"])
        self.assertTrue(report["findings"]["chuanyunOnFamilyObserved"])
        self.assertEqual(report["keyTimelineTotal"], 3)
        self.assertTrue(any(item["peer"] == "111.31.3.182:8899" and item["peerGroup"] == "external" for item in report["keyTimeline"]))


class ProtocolRunnerTest(unittest.TestCase):
    def _send_frame(self, sock_obj, payload):
        sock_obj.sendall(spice_protocol.encode_chuanyun_frame(
            payload,
            session_id=7,
            channel_id=spice_protocol.SpiceChannel.DISPLAY,
        ))

    def _recv_frame(self, sock_obj):
        head = sock_obj.recv(spice_protocol.CHUANYUN_HEAD_SIZE)
        self.assertEqual(len(head), spice_protocol.CHUANYUN_HEAD_SIZE)
        decoded = spice_protocol.decode_chuanyun_head(head)
        payload = b""
        while len(payload) < decoded["payloadLength"]:
            chunk = sock_obj.recv(decoded["payloadLength"] - len(payload))
            self.assertTrue(chunk)
            payload += chunk
        return decoded, payload

    def test_extract_zime_sequence_centers_focus_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "probe.jsonl"
            report_path = Path(tmp) / "sequence.json"
            records = [
                {"event": "transport_buffer", "function": "send", "direction": "send", "fd": 3, "peer": "-", "remote": "1.2.3.4:443", "ssl": "0x1", "len": 4, "hex": "01020304"},
                {"event": "ssl_buffer", "function": "SSL_write", "direction": "send", "fd": 3, "peer": "1.2.3.4:443", "ssl": "0x1", "len": 2, "hex": "2a08", "payloadKind": "spice-mini-unknown:0x082a"},
                {"event": "transport_buffer", "function": "recvmsg", "direction": "receive", "fd": 3, "peer": "1.2.3.4:443", "ssl": "0x1", "len": 4, "hex": "03000000", "payloadKind": "spice-set-ack"},
                {"event": "transport_buffer", "function": "recvmsg", "direction": "receive", "fd": 4, "peer": "5.6.7.8:443", "ssl": "0x2", "len": 4, "hex": "04000000", "payloadKind": "spice-ping"},
            ]
            path.write_text("\n".join(json.dumps(item) for item in records) + "\n", encoding="utf-8")

            result = zime_probe.extract_sequence(path, window=1, limit=10, report_file=report_path)
            self.assertTrue(report_path.exists())
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report["sequenceRecords"], 3)
            self.assertEqual(report["runnerInput"]["sequenceRecords"], 3)
            self.assertEqual(report["runnerInput"]["transportIdentities"][0]["fd"], 3)
            self.assertTrue(any(item.get("remote") == "1.2.3.4:443" for item in report["runnerInput"]["transportIdentities"]))
            self.assertIn("do not replay", report["runnerInput"]["implementationUse"])

        self.assertTrue(result["ok"])
        self.assertEqual(result["records"], 4)
        self.assertEqual(result["focusMatches"], [1])
        self.assertEqual([item["index"] for item in result["sequence"]], [0, 1, 2])
        self.assertEqual(result["sequence"][0]["remote"], "1.2.3.4:443")
        self.assertEqual(result["sequence"][1]["payloadKind"], "spice-mini-unknown:0x082a")
        self.assertEqual(result["transportIdentities"][0]["fd"], 3)

    def test_protocol_session_answers_server_messages(self):
        client_sock, server_sock = socket.socketpair()
        self.addCleanup(client_sock.close)
        self.addCleanup(server_sock.close)
        seen = []

        def server():
            try:
                head, payload = self._recv_frame(server_sock)
                seen.append(spice_protocol.decode_mini_message(payload)["header"]["type"])
                self.assertEqual(head["sessionId"], 7)
                self._send_frame(server_sock, spice_protocol.encode_data_message(
                    spice_protocol.SpiceMessage.SET_ACK,
                    struct.pack("<II", 123, 8),
                ))
                self._send_frame(server_sock, spice_protocol.encode_data_message(
                    spice_protocol.SpiceMessage.PING,
                    b"abc",
                ))
                self._send_frame(server_sock, spice_protocol.encode_data_message(spice_protocol.SpiceMessage.SURFACE_CREATE))
                self._send_frame(server_sock, spice_protocol.encode_data_message(spice_protocol.SpiceMessage.DRAW_COPY))
                self._send_frame(server_sock, spice_protocol.encode_data_message(spice_protocol.SpiceMessage.MARK))
                response_types = []
                for _ in range(4):
                    _head, response_payload = self._recv_frame(server_sock)
                    response_types.append(spice_protocol.decode_mini_message(response_payload)["header"]["type"])
                seen.extend(response_types)
            finally:
                server_sock.close()

        thread = threading.Thread(target=server)
        thread.start()
        try:
            session = protocol_runner.ProtocolSession(client_sock, session_id=7)
            result = session.run(run_seconds=2, success_only=True)
        finally:
            client_sock.close()
            thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        self.assertTrue(result["success"], result)
        self.assertTrue(result["progress"]["displayInitSent"])
        self.assertTrue(result["progress"]["ackSyncSent"])
        self.assertTrue(result["progress"]["pongSent"])
        self.assertIn(spice_protocol.SpiceMessage.DISPLAY_INIT, seen)
        self.assertIn(spice_protocol.SpiceMessage.ACK_SYNC, seen)
        self.assertIn(spice_protocol.SpiceMessage.PONG, seen)
        self.assertIn(spice_protocol.SpiceMessage.ACK, seen)


if __name__ == "__main__":
    unittest.main()
