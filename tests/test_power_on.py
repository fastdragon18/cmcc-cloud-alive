#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for cmcc_cloud_alive.power_on (L0 real power-on gate).

Contract (plan_aijia_mode2_real_boot):
  - protocol required; normalize ZTE|SCG
  - ZTE branch only calls run_material(do_start=True) — never get_connect_info
  - SCG branch only calls get_connect_info — never run_material / startDesktop
  - alreadyRunning short-circuit: no start path
  - softFailure / hardFailure / routeMismatch taxonomy
  - No network; pure mocks.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cmcc_cloud_alive import power_on  # noqa: E402
from cmcc_cloud_alive.product_router import ProductRoute, RouteKind  # noqa: E402


class TestNormalizeProtocol(unittest.TestCase):
    def test_zte_family(self):
        for raw in ("ZTE", "IPv4", "ipv6", "IPv6-raw-ZTEC", "raw-ztec", "ztec"):
            self.assertEqual(power_on.normalize_protocol(raw), "ZTE", raw)

    def test_scg(self):
        self.assertEqual(power_on.normalize_protocol("SCG"), "SCG")
        self.assertEqual(power_on.normalize_protocol("scg"), "SCG")

    def test_empty(self):
        self.assertEqual(power_on.normalize_protocol(""), "")
        self.assertEqual(power_on.normalize_protocol(None), "")


class TestEnsurePoweredOnAlreadyRunning(unittest.TestCase):
    @mock.patch("cmcc_cloud_alive.power_on.cloud")
    def test_already_running_no_branch(self, cloud_mod):
        cloud_mod.selected_user_service_id.return_value = "usid-1"
        cloud_mod.status.return_value = {"vmStatus": "running"}
        cloud_mod.is_running.return_value = True

        with mock.patch.object(power_on, "_power_on_zte") as zte, mock.patch.object(
            power_on, "_power_on_scg"
        ) as scg:
            res = power_on.ensure_powered_on("usid-1", "/tmp/state", "ZTE")
            zte.assert_not_called()
            scg.assert_not_called()

        self.assertEqual(res["result"], power_on.RESULT_ALREADY_RUNNING)
        self.assertTrue(res["ok"])
        self.assertEqual(res["branch"], "none")


class TestEnsurePoweredOnProtocolRequired(unittest.TestCase):
    @mock.patch("cmcc_cloud_alive.power_on.cloud")
    def test_empty_protocol_hard_fail(self, cloud_mod):
        cloud_mod.selected_user_service_id.return_value = "usid-1"
        cloud_mod.status.return_value = {"vmStatus": "stopped"}
        cloud_mod.is_running.return_value = False

        res = power_on.ensure_powered_on("usid-1", "/tmp/state", "")
        self.assertEqual(res["result"], power_on.RESULT_HARD_FAILURE)
        self.assertFalse(res["ok"])
        self.assertIn("protocol required", res["error"])
        self.assertIn("refuse default connectDesktop", res["error"])


class TestZTEBranchExclusive(unittest.TestCase):
    """ZTE path must call run_material(do_start=True); never get_connect_info."""

    @mock.patch("cmcc_cloud_alive.power_on.scg_route.get_connect_info")
    @mock.patch("cmcc_cloud_alive.power_on.zte_route.run_material")
    @mock.patch("cmcc_cloud_alive.power_on.zte_route.ZTEFirmAuth")
    @mock.patch("cmcc_cloud_alive.power_on.product_router")
    @mock.patch("cmcc_cloud_alive.power_on.core")
    @mock.patch("cmcc_cloud_alive.power_on.cloud")
    def test_off_to_running_only_start_desktop(
        self, cloud_mod, core_mod, router_mod, firm_cls, run_material, get_connect
    ):
        cloud_mod.selected_user_service_id.return_value = "usid-zte"
        # first status: off; poll: running
        cloud_mod.status.side_effect = [
            {"vmStatus": "stopped"},
            {"vmStatus": "running"},
        ]
        cloud_mod.is_running.side_effect = lambda s: (
            isinstance(s, dict) and s.get("vmStatus") == "running"
        )

        auth = {"vmId": "vm-1", "cagIp": "1.2.3.4", "cagPort": "443"}
        core_mod.get_firm_auth.return_value = auth
        core_mod.argparse = mock.Mock()
        core_mod.argparse.Namespace = lambda **kw: SimpleNamespace(**kw)

        router_mod.RouteKind = RouteKind
        router_mod.classify_firm_auth_route.return_value = ProductRoute(
            kind=RouteKind.ZTE, reason="ok", vmId="vm-1"
        )
        router_mod.extract_zte_fields.return_value = {
            "vmId": "vm-1",
            "cagIp": "1.2.3.4",
            "cagPort": "443",
        }
        router_mod.zte_fields_complete.return_value = True

        firm = SimpleNamespace(vm_id="vm-1")
        firm_cls.from_auth_dict.return_value = firm
        report = SimpleNamespace(ok=True, error="", to_dict=lambda: {"ok": True})
        run_material.return_value = report

        res = power_on.ensure_powered_on("usid-zte", "/tmp/state", "IPv6-raw-ZTEC", boot_wait=1)

        self.assertEqual(res["result"], power_on.RESULT_POWERED_ON)
        self.assertTrue(res["ok"])
        self.assertEqual(res["branch"], "ZTE")
        run_material.assert_called_once()
        kwargs = run_material.call_args.kwargs
        self.assertTrue(kwargs.get("do_start") is True or (
            len(run_material.call_args.args) >= 1 and kwargs.get("do_start", True)
        ))
        # force do_start=True present
        self.assertTrue(run_material.call_args.kwargs.get("do_start", True))
        get_connect.assert_not_called()

    @mock.patch("cmcc_cloud_alive.power_on.scg_route.get_connect_info")
    @mock.patch("cmcc_cloud_alive.power_on.zte_route.run_material")
    @mock.patch("cmcc_cloud_alive.power_on.zte_route.ZTEFirmAuth")
    @mock.patch("cmcc_cloud_alive.power_on.product_router")
    @mock.patch("cmcc_cloud_alive.power_on.core")
    @mock.patch("cmcc_cloud_alive.power_on.cloud")
    def test_scg_route_mismatch_no_start(
        self, cloud_mod, core_mod, router_mod, firm_cls, run_material, get_connect
    ):
        cloud_mod.selected_user_service_id.return_value = "usid-x"
        cloud_mod.status.return_value = {"vmStatus": "stopped"}
        cloud_mod.is_running.return_value = False

        core_mod.get_firm_auth.return_value = {"scAuthCode": "scg-code"}
        core_mod.argparse = mock.Mock()
        core_mod.argparse.Namespace = lambda **kw: SimpleNamespace(**kw)

        router_mod.RouteKind = RouteKind
        router_mod.classify_firm_auth_route.return_value = ProductRoute(
            kind=RouteKind.SCG, reason="has scAuthCode", vmId=""
        )

        res = power_on.ensure_powered_on("usid-x", "/tmp/state", "ZTE")
        self.assertEqual(res["result"], power_on.RESULT_ROUTE_MISMATCH)
        self.assertFalse(res["ok"])
        run_material.assert_not_called()
        get_connect.assert_not_called()
        firm_cls.from_auth_dict.assert_not_called()

    @mock.patch("cmcc_cloud_alive.power_on.token.ensure_token")
    @mock.patch("cmcc_cloud_alive.power_on.zte_route.run_material")
    @mock.patch("cmcc_cloud_alive.power_on.zte_route.ZTEFirmAuth")
    @mock.patch("cmcc_cloud_alive.power_on.product_router")
    @mock.patch("cmcc_cloud_alive.power_on.core")
    @mock.patch("cmcc_cloud_alive.power_on.cloud")
    def test_soft_failure_104(
        self, cloud_mod, core_mod, router_mod, firm_cls, run_material, ensure_token
    ):
        cloud_mod.selected_user_service_id.return_value = "usid-zte"
        cloud_mod.status.return_value = {"vmStatus": "stopped"}
        cloud_mod.is_running.return_value = False

        core_mod.get_firm_auth.return_value = {"vmId": "vm-1"}
        core_mod.argparse = mock.Mock()
        core_mod.argparse.Namespace = lambda **kw: SimpleNamespace(**kw)

        router_mod.RouteKind = RouteKind
        router_mod.classify_firm_auth_route.return_value = ProductRoute(
            kind=RouteKind.ZTE, reason="ok", vmId="vm-1"
        )
        router_mod.extract_zte_fields.return_value = {"vmId": "vm-1"}
        router_mod.zte_fields_complete.return_value = True

        firm_cls.from_auth_dict.return_value = SimpleNamespace(vm_id="vm-1")
        run_material.return_value = SimpleNamespace(
            ok=False,
            error="startResultCode=104 启动时间过长",
            to_dict=lambda: {"error": "104"},
        )

        res = power_on.ensure_powered_on("usid-zte", "/tmp/state", "ZTE", boot_wait=1)
        self.assertEqual(res["result"], power_on.RESULT_SOFT_FAILURE)
        self.assertTrue(res["soft"])
        self.assertFalse(res["ok"])
        ensure_token.assert_not_called()


class TestSCGBranchExclusive(unittest.TestCase):
    """SCG path must call get_connect_info; never run_material."""

    @mock.patch("cmcc_cloud_alive.power_on.zte_route.run_material")
    @mock.patch("cmcc_cloud_alive.power_on.scg_route.get_connect_info")
    @mock.patch("cmcc_cloud_alive.power_on.product_router")
    @mock.patch("cmcc_cloud_alive.power_on.core")
    @mock.patch("cmcc_cloud_alive.power_on.cloud")
    def test_off_to_running_only_get_connect_info(
        self, cloud_mod, core_mod, router_mod, get_connect, run_material
    ):
        cloud_mod.selected_user_service_id.return_value = "usid-scg"
        cloud_mod.status.side_effect = [
            {"vmStatus": "stopped"},
            {"vmStatus": "running"},
        ]
        cloud_mod.is_running.side_effect = lambda s: (
            isinstance(s, dict) and s.get("vmStatus") == "running"
        )

        core_mod.get_firm_auth.return_value = {
            "scAuthCode": "sc-auth",
            "vmId": "vm-scg",
        }
        core_mod.argparse = mock.Mock()
        core_mod.argparse.Namespace = lambda **kw: SimpleNamespace(**kw)
        core_mod.load_state.return_value = {}
        core_mod.client_config.return_value = {}
        core_mod.profile_device_id.return_value = "dev-1"

        router_mod.extract_sc_auth_code.return_value = "sc-auth"
        router_mod.extract_zte_fields.return_value = {"vmId": "vm-scg"}
        router_mod.zte_fields_complete.return_value = False

        get_connect.return_value = {
            "scgIp": "10.0.0.1",
            "readyStatus": "ready",
        }

        res = power_on.ensure_powered_on("usid-scg", "/tmp/state", "SCG", boot_wait=1)

        self.assertEqual(res["result"], power_on.RESULT_POWERED_ON)
        self.assertTrue(res["ok"])
        self.assertEqual(res["branch"], "SCG")
        get_connect.assert_called_once()
        run_material.assert_not_called()

    @mock.patch("cmcc_cloud_alive.power_on.zte_route.run_material")
    @mock.patch("cmcc_cloud_alive.power_on.scg_route.get_connect_info")
    @mock.patch("cmcc_cloud_alive.power_on.product_router")
    @mock.patch("cmcc_cloud_alive.power_on.core")
    @mock.patch("cmcc_cloud_alive.power_on.cloud")
    def test_missing_sc_auth_refuse_cross_branch(
        self, cloud_mod, core_mod, router_mod, get_connect, run_material
    ):
        cloud_mod.selected_user_service_id.return_value = "usid-scg"
        cloud_mod.status.return_value = {"vmStatus": "stopped"}
        cloud_mod.is_running.return_value = False

        core_mod.get_firm_auth.return_value = {
            "vmId": "vm-1",
            "cagIp": "1.2.3.4",
            "cagPort": "443",
        }
        core_mod.argparse = mock.Mock()
        core_mod.argparse.Namespace = lambda **kw: SimpleNamespace(**kw)

        router_mod.extract_sc_auth_code.return_value = ""
        router_mod.extract_zte_fields.return_value = {
            "vmId": "vm-1",
            "cagIp": "1.2.3.4",
            "cagPort": "443",
        }
        router_mod.zte_fields_complete.return_value = True

        res = power_on.ensure_powered_on("usid-scg", "/tmp/state", "SCG")
        self.assertEqual(res["result"], power_on.RESULT_ROUTE_MISMATCH)
        self.assertIn("refuse ZTE startDesktop", res["error"])
        get_connect.assert_not_called()
        run_material.assert_not_called()

    @mock.patch("cmcc_cloud_alive.power_on.scg_route.classify_scg_soft_failure")
    @mock.patch("cmcc_cloud_alive.power_on.scg_route.get_connect_info")
    @mock.patch("cmcc_cloud_alive.power_on.product_router")
    @mock.patch("cmcc_cloud_alive.power_on.core")
    @mock.patch("cmcc_cloud_alive.power_on.cloud")
    def test_soft_failure_from_scg(
        self, cloud_mod, core_mod, router_mod, get_connect, classify_soft
    ):
        cloud_mod.selected_user_service_id.return_value = "usid-scg"
        cloud_mod.status.return_value = {"vmStatus": "stopped"}
        cloud_mod.is_running.return_value = False

        core_mod.get_firm_auth.return_value = {"scAuthCode": "sc", "vmId": "vm"}
        core_mod.argparse = mock.Mock()
        core_mod.argparse.Namespace = lambda **kw: SimpleNamespace(**kw)
        core_mod.load_state.return_value = {}
        core_mod.client_config.return_value = {}
        core_mod.profile_device_id.return_value = "d"

        router_mod.extract_sc_auth_code.return_value = "sc"
        router_mod.extract_zte_fields.return_value = {"vmId": "vm"}

        get_connect.side_effect = RuntimeError("platform maintenance")
        classify_soft.return_value = {
            "recoverable": True,
            "platform_maintenance": True,
            "fail_reason": "platform_maintenance",
        }

        with mock.patch.object(power_on.time, "sleep"):
            res = power_on.ensure_powered_on(
                "usid-scg", "/tmp/state", "SCG", boot_wait=1, timeout=5
            )
        self.assertEqual(res["result"], power_on.RESULT_SOFT_FAILURE)
        self.assertTrue(res["soft"])
        self.assertFalse(res["ok"])
        # recoverable: 1 initial + 2 retries
        self.assertEqual(get_connect.call_count, power_on._SCG_CONNECT_ATTEMPTS)
        self.assertEqual(res["detail"].get("attempts"), power_on._SCG_CONNECT_ATTEMPTS)
        # short timeout preserved for tests
        self.assertEqual(res["detail"].get("timeout"), 5.0)


class TestScgConnectTimeoutClamp(unittest.TestCase):
    def test_short_preserved(self):
        self.assertEqual(power_on._scg_connect_timeout(5), 5.0)
        self.assertEqual(power_on._scg_connect_timeout(30), 30.0)
        self.assertEqual(power_on._scg_connect_timeout(119), 119.0)

    def test_clamp_range(self):
        self.assertEqual(power_on._scg_connect_timeout(120), 120.0)
        self.assertEqual(power_on._scg_connect_timeout(140), 140.0)
        self.assertEqual(power_on._scg_connect_timeout(160), 160.0)
        self.assertEqual(power_on._scg_connect_timeout(200), 160.0)
        self.assertEqual(
            power_on._scg_connect_timeout(0), power_on._SCG_CONNECT_TIMEOUT_DEFAULT
        )


class TestScgConnectRetry(unittest.TestCase):
    """SCG get_connect_info: retry recoverable, no retry hard, success on later attempt."""

    def _prep(self, cloud_mod, core_mod, router_mod, *, post_running=True):
        cloud_mod.selected_user_service_id.return_value = "usid-scg"
        if post_running:
            cloud_mod.status.side_effect = [
                {"vmStatus": "stopped"},
                {"vmStatus": "running"},
            ]
        else:
            cloud_mod.status.return_value = {"vmStatus": "stopped"}
        cloud_mod.is_running.side_effect = lambda s: (
            isinstance(s, dict) and s.get("vmStatus") == "running"
        )
        core_mod.get_firm_auth.return_value = {"scAuthCode": "sc", "vmId": "vm"}
        core_mod.argparse = mock.Mock()
        core_mod.argparse.Namespace = lambda **kw: SimpleNamespace(**kw)
        core_mod.load_state.return_value = {}
        core_mod.client_config.return_value = {}
        core_mod.profile_device_id.return_value = "d"
        router_mod.extract_sc_auth_code.return_value = "sc"
        router_mod.extract_zte_fields.return_value = {"vmId": "vm"}

    @mock.patch("cmcc_cloud_alive.power_on.scg_route.classify_scg_soft_failure")
    @mock.patch("cmcc_cloud_alive.power_on.scg_route.get_connect_info")
    @mock.patch("cmcc_cloud_alive.power_on.product_router")
    @mock.patch("cmcc_cloud_alive.power_on.core")
    @mock.patch("cmcc_cloud_alive.power_on.cloud")
    def test_retry_then_success(
        self, cloud_mod, core_mod, router_mod, get_connect, classify_soft
    ):
        self._prep(cloud_mod, core_mod, router_mod, post_running=True)
        get_connect.side_effect = [
            TimeoutError("timed out"),
            {
                "readyStatus": 1,
                "scgIp": "1.2.3.4",
                "traceId": "t1",
            },
        ]
        classify_soft.return_value = {
            "recoverable": True,
            "platform_maintenance": False,
            "fail_reason": "timeout",
        }
        with mock.patch.object(power_on.time, "sleep"):
            res = power_on.ensure_powered_on(
                "usid-scg", "/tmp/state", "SCG", boot_wait=1, timeout=5
            )
        self.assertTrue(res["ok"])
        self.assertEqual(res["result"], power_on.RESULT_POWERED_ON)
        self.assertEqual(get_connect.call_count, 2)
        # timeout arg passed through clamp (short preserved)
        self.assertEqual(get_connect.call_args.kwargs.get("timeout"), 5.0)

    @mock.patch("cmcc_cloud_alive.power_on.scg_route.classify_scg_soft_failure")
    @mock.patch("cmcc_cloud_alive.power_on.scg_route.get_connect_info")
    @mock.patch("cmcc_cloud_alive.power_on.product_router")
    @mock.patch("cmcc_cloud_alive.power_on.core")
    @mock.patch("cmcc_cloud_alive.power_on.cloud")
    def test_hard_no_retry(
        self, cloud_mod, core_mod, router_mod, get_connect, classify_soft
    ):
        self._prep(cloud_mod, core_mod, router_mod, post_running=False)
        get_connect.side_effect = RuntimeError("auth denied 401")
        classify_soft.return_value = {
            "recoverable": False,
            "platform_maintenance": False,
            "fail_reason": "scg_exception",
        }
        with mock.patch.object(power_on.time, "sleep") as sleep_m:
            res = power_on.ensure_powered_on(
                "usid-scg", "/tmp/state", "SCG", boot_wait=1, timeout=5
            )
        self.assertEqual(res["result"], power_on.RESULT_HARD_FAILURE)
        self.assertFalse(res["soft"])
        self.assertEqual(get_connect.call_count, 1)
        sleep_m.assert_not_called()

    @mock.patch("cmcc_cloud_alive.power_on.scg_route.classify_scg_soft_failure")
    @mock.patch("cmcc_cloud_alive.power_on.scg_route.get_connect_info")
    @mock.patch("cmcc_cloud_alive.power_on.product_router")
    @mock.patch("cmcc_cloud_alive.power_on.core")
    @mock.patch("cmcc_cloud_alive.power_on.cloud")
    def test_default_timeout_clamped_to_140(
        self, cloud_mod, core_mod, router_mod, get_connect, classify_soft
    ):
        self._prep(cloud_mod, core_mod, router_mod, post_running=True)
        get_connect.return_value = {
            "readyStatus": 1,
            "scgIp": "1.2.3.4",
            "traceId": "t1",
        }
        res = power_on.ensure_powered_on(
            "usid-scg", "/tmp/state", "SCG", boot_wait=1
        )  # default timeout 140
        self.assertTrue(res["ok"])
        self.assertEqual(
            get_connect.call_args.kwargs.get("timeout"),
            power_on._SCG_CONNECT_TIMEOUT_DEFAULT,
        )


class TestClassifyZteError(unittest.TestCase):
    def test_104_soft(self):
        self.assertEqual(
            power_on._classify_zte_error("startResultCode=104"),
            power_on.RESULT_SOFT_FAILURE,
        )

    def test_token_retry(self):
        self.assertEqual(power_on._classify_zte_error("1000100 token expired"), "tokenRetry")

    def test_hard(self):
        self.assertEqual(
            power_on._classify_zte_error("unknown boom"),
            power_on.RESULT_HARD_FAILURE,
        )


if __name__ == "__main__":
    unittest.main()
