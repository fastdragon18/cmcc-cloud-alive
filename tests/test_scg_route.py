#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for cmcc_cloud_alive.scg_route (pure-Python SCG keepalive).

Retired Go binary / subprocess shim APIs:
  build_keepalive_args, is_binary_available, write_binary_config,
  DEFAULT_BINARY, DEFAULT_CONFIG_NAME
(I-PHASE-I residual #347 — do not restore).

Current surface under test:
  SCGKeepaliveResult, run_scg_keepalive (mocked _run_once),
  enforce_honesty_flags. No real network.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cmcc_cloud_alive.scg_route import (  # noqa: E402
    SCGKeepaliveResult,
    build_channel_auth,
    classify_scg_soft_failure,
    enforce_honesty_flags,
    run_scg_keepalive,
)


class TestSCGKeepaliveResult(unittest.TestCase):
    def test_defaults_and_ok_property(self):
        r = SCGKeepaliveResult(returncode=1, stdout="", stderr="x")
        self.assertEqual(r.returncode, 1)
        self.assertFalse(r.ok)
        self.assertEqual(r.stderr, "x")
        self.assertEqual(r.command, [])
        self.assertIsNone(r.config_path)
        self.assertEqual(r.stats, {})

    def test_ok_when_returncode_zero(self):
        r = SCGKeepaliveResult(returncode=0, stdout="out", stderr="")
        self.assertTrue(r.ok)
        self.assertEqual(r.stdout, "out")

    def test_stats_roundtrip(self):
        stats = {"rounds": 1, "last": {"spice_ok": True}, "mode": "spice"}
        r = SCGKeepaliveResult(0, "out", "", stats=stats)
        self.assertEqual(r.stats["rounds"], 1)
        self.assertTrue(r.stats["last"]["spice_ok"])


class TestRetiredBinaryAPIs(unittest.TestCase):
    """Confirm Go-binary shim symbols are gone (residual #347)."""

    def test_build_keepalive_args_absent(self):
        import cmcc_cloud_alive.scg_route as m
        self.assertFalse(hasattr(m, "build_keepalive_args"))

    def test_is_binary_available_absent(self):
        import cmcc_cloud_alive.scg_route as m
        self.assertFalse(hasattr(m, "is_binary_available"))

    def test_write_binary_config_absent(self):
        import cmcc_cloud_alive.scg_route as m
        self.assertFalse(hasattr(m, "write_binary_config"))

    def test_default_binary_symbols_absent(self):
        import cmcc_cloud_alive.scg_route as m
        self.assertFalse(hasattr(m, "DEFAULT_BINARY"))
        self.assertFalse(hasattr(m, "DEFAULT_CONFIG_NAME"))


class TestRunScgKeepaliveMocked(unittest.TestCase):
    """run_scg_keepalive with _run_once mocked — no sockets."""

    def _ok_once(self, *a, **kw):
        return {
            "spice_ok": True,
            "tls_hold_ok": False,
            "degraded": False,
            "keepalive_mode": "spice",
            "fail_reason": "",
            "connected_channels": ["main", "inputs"],
            "heartbeats": 5,
            "sohoHeartbeats": 1,
            "progress": "done",
        }

    def _fail_once(self, *a, **kw):
        return {
            "spice_ok": False,
            "tls_hold_ok": False,
            "degraded": True,
            "keepalive_mode": "spice",
            "fail_reason": "spice_main_init_timeout_or_missing",
            "connected_channels": [],
            "heartbeats": 0,
            "sohoHeartbeats": 0,
            "progress": "fail",
        }

    def test_single_round_returns_result_with_stats(self):
        with mock.patch(
            "cmcc_cloud_alive.scg_route._run_once", side_effect=self._ok_once
        ):
            r = run_scg_keepalive(
                scg_ip="1.2.3.4",
                scg_port="443",
                sc_auth_code="code",
                vm_id="vm-1",
                duration=5,
                forever=False,
                mode="spice",
            )
        self.assertIsInstance(r, SCGKeepaliveResult)
        # no exception path → returncode 0 by current contract
        self.assertEqual(r.returncode, 0)
        self.assertTrue(r.ok)
        self.assertEqual(r.stats.get("rounds"), 1)
        self.assertEqual(r.stats.get("mode"), "spice")
        last = r.stats.get("last") or {}
        self.assertTrue(last.get("spice_ok"))
        self.assertIn("SCG round 1", r.stdout)

    def test_failure_stats_preserved_in_last(self):
        with mock.patch(
            "cmcc_cloud_alive.scg_route._run_once", side_effect=self._fail_once
        ):
            r = run_scg_keepalive(
                scg_ip="1.2.3.4",
                scg_port="443",
                sc_auth_code="code",
                vm_id="vm-1",
                duration=5,
                forever=False,
                mode="spice",
            )
        last = r.stats.get("last") or {}
        self.assertFalse(last.get("spice_ok"))
        self.assertTrue(last.get("degraded"))
        self.assertIn("spice_main_init", str(last.get("fail_reason")))

    def test_exception_path_returncode_nonzero(self):
        with mock.patch(
            "cmcc_cloud_alive.scg_route._run_once",
            side_effect=RuntimeError("boom"),
        ):
            r = run_scg_keepalive(
                scg_ip="1.2.3.4",
                scg_port="443",
                sc_auth_code="code",
                vm_id="vm-1",
                duration=5,
                forever=False,
                mode="spice",
            )
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(r.ok)
        self.assertIn("RuntimeError", r.stderr)

    def test_tls_hold_mode_passed_to_run_once(self):
        seen = {}

        def capture(*a, **kw):
            seen.update(kw)
            return {
                "spice_ok": False,
                "tls_hold_ok": True,
                "degraded": True,
                "keepalive_mode": "tls_hold",
                "fail_reason": "tls_hold_mode_spice_skipped",
                "connected_channels": [],
                "heartbeats": 0,
                "sohoHeartbeats": 1,
                "progress": "hold",
            }

        with mock.patch(
            "cmcc_cloud_alive.scg_route._run_once", side_effect=capture
        ):
            r = run_scg_keepalive(
                scg_ip="1.2.3.4",
                scg_port="443",
                sc_auth_code="code",
                vm_id="vm-1",
                duration=5,
                forever=False,
                mode="tls_hold",
            )
        self.assertEqual(seen.get("mode"), "tls_hold")
        self.assertEqual(r.stats.get("mode"), "tls_hold")
        last = r.stats.get("last") or {}
        self.assertEqual(last.get("keepalive_mode"), "tls_hold")
        self.assertFalse(last.get("spice_ok"))


class TestEnforceHonestyFlagsIntegration(unittest.TestCase):
    def test_tls_hold_clamps_spice_ok(self):
        raw = {"spice_ok": True, "degraded": False, "fail_reason": ""}
        out = enforce_honesty_flags(raw, mode="tls_hold")
        self.assertFalse(out["spice_ok"])
        self.assertTrue(out["degraded"])
        self.assertEqual(out["keepalive_mode"], "tls_hold")

    def test_spice_pass_keeps_spice_ok(self):
        raw = {
            "spice_ok": True,
            "degraded": False,
            "fail_reason": "",
            "tls_hold_ok": False,
        }
        out = enforce_honesty_flags(raw, mode="spice")
        self.assertTrue(out["spice_ok"])
        self.assertFalse(out["degraded"])
        self.assertEqual(out["keepalive_mode"], "spice")


class TestClassifyScgSoftFailure(unittest.TestCase):
    """Maintenance / CEM blip classification for soft-recover tags."""

    def test_maintenance_hint_sets_platform_maintenance(self):
        tags = classify_scg_soft_failure(RuntimeError("VM powered off during maintenance"))
        self.assertTrue(tags["recoverable"])
        self.assertTrue(tags["platform_maintenance"])
        self.assertEqual(tags["fail_reason"], "vm_powered_off")

    def test_cem_502_is_recoverable_and_maint(self):
        tags = classify_scg_soft_failure(RuntimeError("CEM HTTP Error 502: Bad Gateway"))
        self.assertTrue(tags["recoverable"])
        self.assertTrue(tags["platform_maintenance"])
        self.assertIn(tags["fail_reason"], ("scg_cem_blip", "token_transient", "scg_exception"))

    def test_plain_timeout_recoverable(self):
        tags = classify_scg_soft_failure(TimeoutError("connection timed out"))
        self.assertTrue(tags["recoverable"])


class TestForeverSoftRecover(unittest.TestCase):
    """forever=True must not exit the process on transient exceptions."""

    def test_forever_exception_continues_then_ok(self):
        calls = {"n": 0}

        def flaky(*a, **kw):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("CEM HTTP Error 503: maintenance window")
            return {
                "spice_ok": True,
                "tls_hold_ok": False,
                "degraded": False,
                "keepalive_mode": "spice",
                "fail_reason": "",
                "connected_channels": ["main"],
                "heartbeats": 1,
                "sohoHeartbeats": 0,
                "progress": "done",
            }

        # Break forever after 2 successful post-recover rounds via side effect
        rounds_ok = {"n": 0}

        def flaky_then_stop(*a, **kw):
            out = flaky(*a, **kw)
            rounds_ok["n"] += 1
            if rounds_ok["n"] >= 2:
                # raise KeyboardInterrupt-equivalent via stop: monkeypatch sleep+break
                raise SystemExit("test-stop-after-recover")
            return out

        with mock.patch("cmcc_cloud_alive.scg_route._run_once", side_effect=flaky_then_stop):
            with mock.patch("cmcc_cloud_alive.scg_route.time.sleep", return_value=None):
                with self.assertRaises(SystemExit):
                    run_scg_keepalive(
                        scg_ip="1.2.3.4",
                        scg_port="443",
                        sc_auth_code="code",
                        vm_id="vm-1",
                        duration=1,
                        forever=True,
                        mode="spice",
                        backoff_base_s=0.01,
                        backoff_cap_s=0.05,
                    )
        # First call raised, second succeeded then SystemExit — at least 2 _run_once
        self.assertGreaterEqual(calls["n"], 2)

    def test_forever_reconnect_fn_called_after_fail(self):
        reconnect_calls = {"n": 0}
        run_calls = {"n": 0}

        def reconnect():
            reconnect_calls["n"] += 1
            return {"scgIp": "9.9.9.9", "scgPort": "8443", "scAuthCode": "fresh"}

        def once(ip, port, auth, *a, **kw):
            run_calls["n"] += 1
            if run_calls["n"] == 1:
                raise RuntimeError("getConnectInfo 502 maintenance")
            if run_calls["n"] >= 2:
                # verify reconnect applied
                self.assertEqual(ip, "9.9.9.9")
                self.assertEqual(str(port), "8443")
                raise SystemExit("stop")
            return {
                "spice_ok": True,
                "tls_hold_ok": False,
                "degraded": False,
                "keepalive_mode": "spice",
                "fail_reason": "",
                "connected_channels": ["main"],
                "heartbeats": 1,
                "sohoHeartbeats": 0,
                "progress": "done",
            }

        with mock.patch("cmcc_cloud_alive.scg_route._run_once", side_effect=once):
            with mock.patch("cmcc_cloud_alive.scg_route.time.sleep", return_value=None):
                with self.assertRaises(SystemExit):
                    run_scg_keepalive(
                        scg_ip="1.2.3.4",
                        scg_port="443",
                        sc_auth_code="code",
                        vm_id="vm-1",
                        duration=1,
                        forever=True,
                        mode="spice",
                        reconnect_fn=reconnect,
                        backoff_base_s=0.01,
                        backoff_cap_s=0.05,
                    )
        self.assertGreaterEqual(reconnect_calls["n"], 1)

    def test_finite_exception_still_returns_rc1(self):
        def boom(*a, **kw):
            raise RuntimeError("hard fail")

        with mock.patch("cmcc_cloud_alive.scg_route._run_once", side_effect=boom):
            r = run_scg_keepalive(
                scg_ip="1.2.3.4",
                scg_port="443",
                sc_auth_code="code",
                vm_id="vm-1",
                duration=1,
                forever=False,
                mode="spice",
            )
        self.assertEqual(r.returncode, 1)
        self.assertFalse(r.ok)
        last = r.stats.get("last") or {}
        self.assertTrue(last.get("recoverable"))
        self.assertIn("hard fail", r.stderr)


class TestBuildChannelAuthExtInfoVmId(unittest.TestCase):
    """T49: ExtInfo[10:14] must carry pin vmId (not hard-coded 0x00010820)."""

    def _ext_info_bytes(self, blob: bytes) -> bytes:
        # frame_head is 24 bytes; ExtInfo body is next 22 bytes (len from head).
        self.assertGreaterEqual(len(blob), 24 + 22)
        return blob[24:46]

    def test_default_keeps_legacy_magic_when_vm_id_zero(self):
        blob = build_channel_auth(sid=1, channel_id=1, channel_type=1, connection_id=0, vm_id=0)
        ext = self._ext_info_bytes(blob)
        self.assertEqual(ext[10:14], bytes.fromhex("00010820"))

    def test_pin_vmid_written_be_into_extinfo(self):
        pin = 0x007A1201  # synthetic pin for BE/LE wire encoding (not a personal id)
        blob = build_channel_auth(
            sid=1628349, channel_id=1, channel_type=1, connection_id=0, vm_id=pin
        )
        ext = self._ext_info_bytes(blob)
        self.assertEqual(ext[10:14], pin.to_bytes(4, "big"))
        self.assertNotEqual(ext[10:14], bytes.fromhex("00010820"))
        # pin must appear as BE bytes on wire; LE of pin must not be default path
        self.assertIn(pin.to_bytes(4, "big"), blob)

    def test_vmid_endian_le_option(self):
        pin = 0x007A1201
        blob = build_channel_auth(
            sid=1, channel_id=1, channel_type=1, vm_id=pin, vmid_endian="le"
        )
        ext = self._ext_info_bytes(blob)
        self.assertEqual(ext[10:14], pin.to_bytes(4, "little"))


if __name__ == "__main__":
    unittest.main()
