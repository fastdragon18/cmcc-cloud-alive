#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for cmcc_cloud_alive.kpi_hooks (I-G4 observed-only KPI).

No network. Asserts counters, session lifecycle, merge_into_stats, wire points.
Never synthesizes 174-byte WAN pads.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from cmcc_cloud_alive import kpi_hooks
from cmcc_cloud_alive import scg_route


class TestKpiCollector(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="kpi_ig4_"))
        self.kpi_path = self.tmp / "kpi.json"
        try:
            kpi_hooks.end_session(flush=False)
        except Exception:
            pass

    def tearDown(self):
        try:
            kpi_hooks.end_session(flush=False)
        except Exception:
            pass
        for f in self.tmp.glob("*"):
            try:
                f.unlink()
            except Exception:
                pass
        try:
            self.tmp.rmdir()
        except Exception:
            pass

    def test_maybe_noop_without_session(self):
        kpi_hooks.maybe("note_redq", 1)
        kpi_hooks.maybe("note_ticket", 1, True)
        kpi_hooks.maybe("note_hold_reply")
        self.assertIsNone(kpi_hooks.get_active())

    def test_start_end_session_and_flush(self):
        c = kpi_hooks.start_session(session_tag="t-sess", path=self.kpi_path)
        self.assertIs(kpi_hooks.get_active(), c)
        c.note_redq(1)
        c.note_ticket(1, True)
        c.note_channel_open(1, True)
        c.note_hold_heartbeat()
        c.note_hold_reply()
        c.set_spice_ok(True)
        snap = c.snapshot()
        self.assertEqual(snap.redq_count, 1)
        self.assertEqual(snap.ticket_count, 1)
        self.assertEqual(snap.hold_heartbeats, 1)
        self.assertEqual(snap.hold_replies, 1)
        self.assertTrue(snap.spice_ok)
        path = c.flush_json()
        self.assertTrue(Path(path).is_file())
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        self.assertEqual(data.get("redq_count"), 1)
        blob = json.dumps(data)
        self.assertNotIn("password", blob.lower())
        self.assertNotIn("ticket_bytes", blob.lower())
        ended = kpi_hooks.end_session()
        self.assertIsNone(kpi_hooks.get_active())
        self.assertIsNotNone(ended)

    def test_no_synthetic_174(self):
        """Collector only increments wan_174b when note_wan_174b is called with observed size."""
        c = kpi_hooks.start_session(session_tag="t-174", path=self.kpi_path)
        try:
            self.assertEqual(c.snapshot().wan_174b_ticks, 0)
            c.note_wan_174b(100)  # wrong size -> ignore
            self.assertEqual(c.snapshot().wan_174b_ticks, 0)
            c.note_wan_174b(174)
            self.assertEqual(c.snapshot().wan_174b_ticks, 1)
            c.note_wan_174b(174)
            self.assertEqual(c.snapshot().wan_174b_ticks, 2)
        finally:
            kpi_hooks.end_session(flush=False)

    def test_note_ticket_fail_and_channel_map(self):
        c = kpi_hooks.start_session(session_tag="t-map", path=self.kpi_path)
        try:
            # open first so redq/ticket attach to channel info
            c.note_channel_open(2, False, error="ticket_fail")
            c.note_redq(2)
            c.note_ticket(2, False)
            c.note_hyscg()
            snap = c.snapshot()
            self.assertEqual(snap.ticket_fail, 1)
            self.assertEqual(snap.ticket_count, 0)
            # map keys are str(channel_id); name field carries display label
            self.assertIn("2", snap.channel_open_map)
            info = snap.channel_open_map["2"]
            self.assertEqual(info.get("channel_id"), 2)
            self.assertEqual(info.get("name"), "display")
            self.assertFalse(info.get("auth_ok", False))
            self.assertFalse(info.get("ticket_ok", True))
            self.assertTrue(info.get("redq_ok", False))
            self.assertEqual(info.get("last_error"), "ticket_fail")
            self.assertIsNotNone(snap.last_hyscg_age_s)
        finally:
            kpi_hooks.end_session(flush=False)

    def test_merge_into_stats(self):
        c = kpi_hooks.start_session(session_tag="t-merge", path=self.kpi_path)
        try:
            c.note_hold_heartbeat()
            c.note_hold_reply()
            c.note_redq(1)
            stats = {"ok": True}
            c.merge_into_stats(stats)
            self.assertIn("kpi", stats)
            kpi = stats["kpi"]
            self.assertEqual(kpi.get("hold_heartbeats"), 1)
            self.assertEqual(kpi.get("hold_replies"), 1)
            self.assertEqual(kpi.get("redq_count"), 1)
        finally:
            kpi_hooks.end_session(flush=False)


class TestVmSampleFourPhase(unittest.TestCase):
    """I-PHASE-I-KPI: 4-sample VM power via power_monitor.snapshot."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="kpi_vm4_"))
        self.kpi_path = self.tmp / "kpi.json"
        try:
            kpi_hooks.end_session(flush=False)
        except Exception:
            pass

    def tearDown(self):
        try:
            kpi_hooks.end_session(flush=False)
        except Exception:
            pass
        for f in self.tmp.glob("*"):
            try:
                f.unlink()
            except Exception:
                pass
        try:
            self.tmp.rmdir()
        except Exception:
            pass

    def _running_snap(self, idx=0):
        return {
            "running": True,
            "off": False,
            "vmStatus": "running",
            "vmStatusShow": "运行中",
            "at": 1_700_000_000 + idx,
            "userServiceId": "svc-test",
            "index": idx,
            "elapsedSeconds": idx * 30,
        }

    def _off_snap(self, idx=0):
        return {
            "running": False,
            "off": True,
            "vmStatus": "stopped",
            "vmStatusShow": "已关机",
            "at": 1_700_000_000 + idx,
            "userServiceId": "svc-test",
            "index": idx,
            "elapsedSeconds": idx * 30,
        }

    def test_four_phases_powered_throughout(self):
        c = kpi_hooks.start_session(session_tag="t-vm4-ok", path=self.kpi_path)
        try:
            for i, phase in enumerate(kpi_hooks.VM_SAMPLE_PHASES):
                c.note_vm_sample(phase, self._running_snap(i))
            c.set_wall_hold_seconds(120.0)
            snap = c.snapshot()
            self.assertEqual(snap.vm_sample_count, 4)
            phases = [s["phase"] for s in snap.vm_samples]
            self.assertEqual(phases, list(kpi_hooks.VM_SAMPLE_PHASES))
            self.assertTrue(snap.vm_powered_throughout)
            stats = c.merge_into_stats({})
            self.assertTrue(stats.get("vm_running_throughout"))
            self.assertEqual(stats.get("vm_sample_count"), 4)
            self.assertEqual(snap.wall_hold_seconds, 120.0)
            # wall clock alone is NOT proof of VM power — fields are distinct
            self.assertIsNotNone(snap.wall_hold_seconds)
            self.assertIsNot(snap.wall_hold_seconds, snap.vm_powered_throughout)
            stats = {}
            c.merge_into_stats(stats)
            self.assertEqual(stats["vm_sample_count"], 4)
            self.assertTrue(stats["vm_powered_throughout"])
            self.assertEqual(stats["wall_hold_seconds"], 120.0)
            self.assertEqual(len(stats["vm_samples"]), 4)
        finally:
            kpi_hooks.end_session(flush=False)

    def test_wall_ok_but_vm_off_not_powered(self):
        """Honesty: long wall hold + off samples => vm_powered_throughout False."""
        c = kpi_hooks.start_session(session_tag="t-vm4-off", path=self.kpi_path)
        try:
            c.note_vm_sample("start", self._running_snap(0))
            c.note_vm_sample("one_third", self._off_snap(1))
            c.note_vm_sample("two_thirds", self._off_snap(2))
            c.note_vm_sample("end", self._off_snap(3))
            c.set_wall_hold_seconds(600.0)
            snap = c.snapshot()
            self.assertEqual(snap.vm_sample_count, 4)
            self.assertFalse(snap.vm_powered_throughout)
            self.assertEqual(snap.wall_hold_seconds, 600.0)
            # wall duration must not imply VM powered
            self.assertGreater(snap.wall_hold_seconds, 0)
            self.assertIs(snap.vm_powered_throughout, False)
        finally:
            kpi_hooks.end_session(flush=False)

    def test_no_samples_returns_none_not_true(self):
        c = kpi_hooks.start_session(session_tag="t-vm4-empty", path=self.kpi_path)
        try:
            c.set_wall_hold_seconds(90.0)
            snap = c.snapshot()
            self.assertEqual(snap.vm_sample_count, 0)
            self.assertIsNone(snap.vm_powered_throughout)
            stats = {"ok": True}
            c.merge_into_stats(stats)
            self.assertIsNone(stats["vm_powered_throughout"])
            self.assertEqual(stats["wall_hold_seconds"], 90.0)
        finally:
            kpi_hooks.end_session(flush=False)

    def test_phase_dedupe_keeps_first(self):
        c = kpi_hooks.start_session(session_tag="t-vm4-dedupe", path=self.kpi_path)
        try:
            c.note_vm_sample("start", self._running_snap(0))
            c.note_vm_sample("start", self._off_snap(99))  # should be ignored
            snap = c.snapshot()
            self.assertEqual(snap.vm_sample_count, 1)
            self.assertTrue(snap.vm_samples[0]["running"])
            self.assertIs(snap.vm_powered_throughout, False)
        finally:
            kpi_hooks.end_session(flush=False)

    def test_single_sample_not_powered_throughout(self):
        """P06 honesty: one green sample never yields throughout=True."""
        c = kpi_hooks.start_session(session_tag="t-vm1-single", path=self.kpi_path)
        try:
            c.note_vm_sample("start", self._running_snap(0))
            c.set_wall_hold_seconds(30.0)
            snap = c.snapshot()
            self.assertEqual(snap.vm_sample_count, 1)
            self.assertIs(snap.vm_powered_throughout, False)
            stats = c.merge_into_stats({})
            self.assertIs(stats["vm_powered_throughout"], False)
            self.assertIs(stats["vm_running_throughout"], False)
            self.assertEqual(stats["vm_sample_count"], 1)
        finally:
            kpi_hooks.end_session(flush=False)

    def test_two_samples_powered_throughout(self):
        """P06: >=2 all-powered conclusive samples => True."""
        c = kpi_hooks.start_session(session_tag="t-vm2-ok", path=self.kpi_path)
        try:
            c.note_vm_sample("start", self._running_snap(0))
            c.note_vm_sample("end", self._running_snap(1))
            c.set_wall_hold_seconds(60.0)
            snap = c.snapshot()
            self.assertEqual(snap.vm_sample_count, 2)
            self.assertIs(snap.vm_powered_throughout, True)
            stats = c.merge_into_stats({})
            self.assertIs(stats["vm_running_throughout"], True)
        finally:
            kpi_hooks.end_session(flush=False)

    def test_error_sample_makes_not_powered(self):
        c = kpi_hooks.start_session(session_tag="t-vm4-err", path=self.kpi_path)
        try:
            c.note_vm_sample("start", self._running_snap(0))
            c.note_vm_sample("one_third", None, error="snapshot_failed:Timeout")
            c.note_vm_sample("two_thirds", self._running_snap(2))
            c.note_vm_sample("end", self._running_snap(3))
            snap = c.snapshot()
            self.assertEqual(snap.vm_sample_count, 4)
            self.assertFalse(snap.vm_powered_throughout)
        finally:
            kpi_hooks.end_session(flush=False)

    def test_maybe_vm_sample_via_power_monitor_mocked(self):
        """maybe_vm_sample_via_power_monitor records without LIVE network."""
        c = kpi_hooks.start_session(session_tag="t-vm4-maybe", path=self.kpi_path)
        try:
            # inject via note path used by helper on failure (no network in unit)
            # helper catches exception and notes error — force that path with bad id
            # but avoid network: call note_vm_sample directly for phases then
            # verify helper no-ops without active is not needed (we have active)
            import cmcc_cloud_alive.power_monitor as pm

            orig = pm.snapshot

            def fake_snapshot(**kwargs):
                return self._running_snap(kwargs.get("index") or 0)

            pm.snapshot = fake_snapshot
            try:
                kpi_hooks.maybe_vm_sample_via_power_monitor(
                    "start", user_service_id="svc", started_wall=1.0, index=0
                )
                kpi_hooks.maybe_vm_sample_via_power_monitor(
                    "one_third", user_service_id="svc", started_wall=1.0, index=1
                )
                kpi_hooks.maybe_vm_sample_via_power_monitor(
                    "two_thirds", user_service_id="svc", started_wall=1.0, index=2
                )
                kpi_hooks.maybe_vm_sample_via_power_monitor(
                    "end", user_service_id="svc", started_wall=1.0, index=3
                )
            finally:
                pm.snapshot = orig
            snap = c.snapshot()
            self.assertEqual(snap.vm_sample_count, 4)
            self.assertTrue(snap.vm_powered_throughout)
            phases = [s["phase"] for s in snap.vm_samples]
            self.assertEqual(phases, ["start", "one_third", "two_thirds", "end"])
        finally:
            kpi_hooks.end_session(flush=False)


class TestScgRouteWire(unittest.TestCase):
    def test_import_and_wire_points(self):
        src = Path(scg_route.__file__).read_text(encoding="utf-8")
        self.assertIn("from . import kpi_hooks", src)
        for needle in [
            'kpi_hooks.maybe("note_redq"',
            'kpi_hooks.maybe("note_ticket"',
            'kpi_hooks.maybe("note_channel_open"',
            'kpi_hooks.maybe("note_hold_reply"',
            'kpi_hooks.maybe("note_hold_heartbeat"',
            "kpi_hooks.start_session",
            "kpi_hooks.end_session",
            "merge_into_stats",
            "maybe_vm_sample_via_power_monitor",
            'kpi_hooks.maybe("set_wall_hold_seconds"',
            "one_third",
            "two_thirds",
            "vm_powered_throughout",
        ]:
            self.assertIn(needle, src, msg=f"missing wire: {needle}")

    def test_no_fake174_synthesis_in_scg_route(self):
        src = Path(scg_route.__file__).read_text(encoding="utf-8")
        banned = [
            "b'\\x00' * 174",
            'b"\\x00" * 174',
            "bytes(174)",
            "bytearray(174)",
            "os.urandom(174)",
            "synthesize_174",
            "fake_174",
            "make_wan_174",
        ]
        for b in banned:
            self.assertNotIn(b, src, msg=f"banned pattern: {b}")


if __name__ == "__main__":
    unittest.main()
