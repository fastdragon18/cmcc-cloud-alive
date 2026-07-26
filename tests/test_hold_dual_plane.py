#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""I-PHASE-I-HOLD: dual-plane hold loop unit tests (OFFLINE only).

Covers:
- HOLD_SELECT_SECONDS ≈ 1.0 / HOLD_KEEPALIVE_INTERVAL ≈ 25.0
- _hold_should_run_slow_plane gate (first tick + interval)
- outer 25s sleep_drain removed; drain uses select_budget ≤ 1s
- native 174 observe only (no synthetic writer)
- SOHO/mouse fire on slow plane, not every select tick
- D2 P-01 accept: select called frequently; no ≥5s pure-sleep when spice_ok; stats keys
"""

from __future__ import annotations

import ast
import socket
import sys
import time
import unittest
from pathlib import Path
from typing import Any, Dict, List
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cmcc_cloud_alive import scg_route  # noqa: E402
from cmcc_cloud_alive.scg_route import (  # noqa: E402
    HOLD_KEEPALIVE_INTERVAL,
    HOLD_SELECT_SECONDS,
    _hold_should_run_slow_plane,
    _scg_sleep_drain,
)


class TestHoldConstants(unittest.TestCase):
    def test_select_is_one_second(self):
        self.assertAlmostEqual(HOLD_SELECT_SECONDS, 1.0, places=3)

    def test_keepalive_interval_is_25s(self):
        self.assertAlmostEqual(HOLD_KEEPALIVE_INTERVAL, 25.0, places=3)

    def test_select_much_faster_than_keepalive(self):
        self.assertLess(HOLD_SELECT_SECONDS * 10, HOLD_KEEPALIVE_INTERVAL)


class TestSlowPlaneGate(unittest.TestCase):
    def test_first_tick_fires_when_last_none(self):
        self.assertTrue(_hold_should_run_slow_plane(100.0, None, 25.0))

    def test_within_interval_does_not_fire(self):
        self.assertFalse(_hold_should_run_slow_plane(110.0, 100.0, 25.0))

    def test_at_interval_fires(self):
        self.assertTrue(_hold_should_run_slow_plane(125.0, 100.0, 25.0))

    def test_past_interval_fires(self):
        self.assertTrue(_hold_should_run_slow_plane(130.0, 100.0, 25.0))

    def test_zero_last_is_not_sentinel(self):
        # 0.0 is a valid monotonic timestamp, not "never"
        self.assertFalse(_hold_should_run_slow_plane(1.0, 0.0, 25.0))
        self.assertTrue(_hold_should_run_slow_plane(25.0, 0.0, 25.0))


class TestSourceInvariants(unittest.TestCase):
    """Static checks on scg_route.py dual-plane hold loop (no LIVE)."""

    @classmethod
    def setUpClass(cls):
        cls.src = (ROOT / "cmcc_cloud_alive" / "scg_route.py").read_text(encoding="utf-8")

    def test_no_outer_25s_sleep_drain_call(self):
        # Old pattern: _scg_sleep_drain(sock, 25.0, ...) or min(25.0, remaining)
        self.assertNotIn("_scg_sleep_drain(sock, 25.0", self.src)
        self.assertNotIn("_scg_sleep_drain(sock, min(25.0", self.src)

    def test_uses_select_budget_from_hold_select(self):
        self.assertIn("select_budget = HOLD_SELECT_SECONDS", self.src)
        self.assertIn("_scg_sleep_drain(sock, select_budget, sid, stats)", self.src)

    def test_slow_plane_gated(self):
        self.assertIn("_hold_should_run_slow_plane", self.src)
        self.assertIn("last_keepalive_plane", self.src)

    def test_hold_plane_stats_marked_dual(self):
        self.assertIn('stats["hold_plane"] = "dual"', self.src)
        self.assertIn('stats["hold_select_seconds"] = HOLD_SELECT_SECONDS', self.src)

    def test_no_synthetic_174_writer(self):
        # Must not fabricate 174B payloads; only observe len==174
        banned = [
            "bytes(174)",
            "b'\\x00' * 174",
            'b"\\x00" * 174',
            "pad_to_174",
            "synthetic_174",
            "fabricate_174",
        ]
        for b in banned:
            self.assertNotIn(b, self.src, msg=f"banned pattern present: {b}")
        # observe-only path must exist
        self.assertIn('len(getattr(frame, "payload", b"") or b"") == 174', self.src)
        self.assertIn('kpi_hooks.maybe("note_wan_174b", 174)', self.src)

    def test_source_parses(self):
        ast.parse(self.src)


class TestSleepDrainObserve174(unittest.TestCase):
    """_scg_sleep_drain observes native 174 payload only (mocked socket)."""

    def test_note_wan_174b_on_native_payload(self):
        sock = mock.MagicMock(spec=socket.socket)
        stats: Dict[str, int] = {}
        frame = mock.MagicMock()
        frame.payload = b"\x00" * 174
        frame.pkt_type = 0  # not TRUNK_SWITCH
        frame.field1 = 0

        with mock.patch("cmcc_cloud_alive.scg_route.select.select", return_value=([sock], [], [])), \
             mock.patch("cmcc_cloud_alive.scg_route.recv_all_frames", return_value=[frame]), \
             mock.patch("cmcc_cloud_alive.scg_route.kpi_hooks.maybe") as maybe, \
             mock.patch("cmcc_cloud_alive.scg_route.time.monotonic", side_effect=[0.0, 0.0, 2.0]):
            # deadline = 0+0.01 → first remaining>0 then second call exits
            # Use tiny interval and force one drain then exit
            pass

        # more controlled: patch monotonic to allow one loop then exit
        times = [0.0, 0.0, 0.0, 0.05]  # start, check, remaining calc, after
        # Simpler approach: call with interval that allows one select

        times_iter = iter([0.0, 0.0, 0.0, 1.5])  # deadline=1.0; after drain next check exits

        def mono():
            try:
                return next(times_iter)
            except StopIteration:
                return 99.0

        with mock.patch("cmcc_cloud_alive.scg_route.select.select", return_value=([sock], [], [])) as sel, \
             mock.patch("cmcc_cloud_alive.scg_route.recv_all_frames", return_value=[frame]), \
             mock.patch("cmcc_cloud_alive.scg_route.kpi_hooks.maybe") as maybe, \
             mock.patch("cmcc_cloud_alive.scg_route.time.monotonic", side_effect=mono):
            _scg_sleep_drain(sock, 1.0, 1, stats)

        note_calls = [c for c in maybe.call_args_list if c.args and c.args[0] == "note_wan_174b"]
        self.assertTrue(note_calls, msg=f"expected note_wan_174b, got {maybe.call_args_list}")
        self.assertEqual(note_calls[0].args[1], 174)

    def test_non_174_does_not_note_wan(self):
        sock = mock.MagicMock(spec=socket.socket)
        stats: Dict[str, int] = {}
        frame = mock.MagicMock()
        frame.payload = b"\x01" * 32
        frame.pkt_type = 0
        frame.field1 = 0

        times_iter = iter([0.0, 0.0, 0.0, 1.5])

        def mono():
            try:
                return next(times_iter)
            except StopIteration:
                return 99.0

        with mock.patch("cmcc_cloud_alive.scg_route.select.select", return_value=([sock], [], [])), \
             mock.patch("cmcc_cloud_alive.scg_route.recv_all_frames", return_value=[frame]), \
             mock.patch("cmcc_cloud_alive.scg_route.kpi_hooks.maybe") as maybe, \
             mock.patch("cmcc_cloud_alive.scg_route.time.monotonic", side_effect=mono):
            _scg_sleep_drain(sock, 1.0, 1, stats)

        note_calls = [c for c in maybe.call_args_list if c.args and c.args[0] == "note_wan_174b"]
        self.assertFalse(note_calls, msg=f"must not note non-174: {maybe.call_args_list}")


class TestDualPlaneLoopCadence(unittest.TestCase):
    """Simulate hold loop body: slow plane count vs fast drain count."""

    def test_slow_plane_fires_once_per_interval_across_ticks(self):
        """With 1s ticks over 26s, slow plane should fire at t0 and t25 only."""
        last = None
        fires: List[float] = []
        # simulate 27 ticks at t=0..26
        for t in range(0, 27):
            now = float(t)
            if _hold_should_run_slow_plane(now, last, HOLD_KEEPALIVE_INTERVAL):
                last = now
                fires.append(now)
        self.assertEqual(fires, [0.0, 25.0])

    def test_fast_plane_budget_capped_at_one_second(self):
        # mirror loop budget math
        duration_seconds = 100.0
        started = 0.0
        now = 10.0
        remaining = duration_seconds - (now - started)
        select_budget = min(HOLD_SELECT_SECONDS, remaining)
        self.assertEqual(select_budget, HOLD_SELECT_SECONDS)

    def test_fast_plane_budget_shrinks_near_end(self):
        duration_seconds = 10.0
        started = 0.0
        now = 9.4
        remaining = duration_seconds - (now - started)
        select_budget = min(HOLD_SELECT_SECONDS, remaining)
        self.assertAlmostEqual(select_budget, 0.6, places=3)




class TestD2AcceptCadence(unittest.TestCase):
    """D2 P-01 accept (OPEN#430 / D1 §P-01): mock sock select freq + no ≥5s pure-sleep."""

    def test_select_called_frequently_over_simulated_hold(self):
        """Over ~6s simulated wall, select must be invoked ≥5 times (≈1s cadence)."""
        sock = mock.MagicMock(spec=socket.socket)
        stats: Dict[str, Any] = {}
        select_timeouts: List[float] = []
        # virtual clock: each select advances by its timeout (chunk ≤1.0)
        clock = {"t": 0.0}

        def fake_mono():
            return clock["t"]

        def fake_select(r, w, x, timeout=0.0):
            select_timeouts.append(float(timeout if timeout is not None else 0.0))
            clock["t"] += float(timeout if timeout is not None else 0.0)
            return [], [], []  # always timeout → pure drain path

        # Simulate hold outer loop: 6 × select_budget=1.0 drains
        with mock.patch("cmcc_cloud_alive.scg_route.select.select", side_effect=fake_select), \
             mock.patch("cmcc_cloud_alive.scg_route.time.monotonic", side_effect=fake_mono):
            for _ in range(6):
                _scg_sleep_drain(sock, HOLD_SELECT_SECONDS, 1, stats)

        self.assertGreaterEqual(len(select_timeouts), 5, msg=f"select calls={len(select_timeouts)}")
        # each outer drain of 1.0s yields one select with chunk≈1.0 when idle
        self.assertTrue(all(t <= HOLD_SELECT_SECONDS + 1e-6 for t in select_timeouts))
        # frequency band: ≥ ~0.8 selects per simulated wall second over the run
        wall = clock["t"]
        self.assertGreater(wall, 0)
        rate = len(select_timeouts) / wall
        self.assertGreaterEqual(rate, 0.8, msg=f"select/s={rate:.3f} wall={wall}")

    def test_no_ge_5s_pure_sleep_in_hold_region(self):
        """AST: hold dual-plane region must not call time.sleep; drain args ≤1s or select_budget."""
        src_path = ROOT / "cmcc_cloud_alive" / "scg_route.py"
        src = src_path.read_text(encoding="utf-8")
        tree = ast.parse(src)
        lines = src.splitlines()

        # locate dual-plane hold comment block start
        hold_start = None
        for i, line in enumerate(lines, 1):
            if "I-PHASE-I-HOLD dual-plane hold loop" in line or (
                "dual-plane hold" in line.lower() and "fast:" in line.lower()
            ):
                hold_start = i
                break
        if hold_start is None:
            for i, line in enumerate(lines, 1):
                if "last_keepalive_plane" in line and "None" in line:
                    hold_start = max(1, i - 10)
                    break
        self.assertIsNotNone(hold_start, "hold region not found")

        # end at next top-level def after hold_start, or sample #4 end marker
        hold_end = len(lines)
        for i in range(hold_start, len(lines)):
            if i + 1 > hold_start + 5 and lines[i].startswith("def "):
                hold_end = i + 1
                break
            if "sample #4" in lines[i] or "maybe_vm_sample_via_power_monitor" in lines[i]:
                # include a few lines then stop soon
                hold_end = min(len(lines), i + 8)
                break

        # collect time.sleep calls with constant ≥5
        class SleepVisitor(ast.NodeVisitor):
            def __init__(self):
                self.bad = []

            def visit_Call(self, node: ast.Call):
                fn = node.func
                name = None
                if isinstance(fn, ast.Attribute) and fn.attr == "sleep":
                    if isinstance(fn.value, ast.Name) and fn.value.id == "time":
                        name = "time.sleep"
                elif isinstance(fn, ast.Name) and fn.id == "sleep":
                    name = "sleep"
                if name and node.lineno >= hold_start and node.lineno <= hold_end:
                    # constant arg?
                    if node.args:
                        a0 = node.args[0]
                        val = None
                        if isinstance(a0, ast.Constant) and isinstance(a0.value, (int, float)):
                            val = float(a0.value)
                        elif isinstance(a0, ast.Num):  # py3.7 compat
                            val = float(a0.n)
                        if val is not None and val >= 5.0:
                            self.bad.append((node.lineno, val))
                self.generic_visit(node)

        v = SleepVisitor()
        v.visit(tree)
        self.assertEqual(v.bad, [], msg=f"≥5s pure-sleep in hold: {v.bad}")

        # region text must not contain time.sleep at all (stricter for spice_ok path)
        region = "\n".join(lines[hold_start - 1 : hold_end])
        self.assertNotIn("time.sleep", region)

        # every _scg_sleep_drain call in region uses select_budget or HOLD_SELECT, not HOLD_KEEPALIVE
        for i, line in enumerate(lines[hold_start - 1 : hold_end], start=hold_start):
            if "_scg_sleep_drain" in line:
                self.assertNotIn("HOLD_KEEPALIVE", line)
                self.assertTrue(
                    "select_budget" in line or "HOLD_SELECT" in line,
                    msg=f"L{i}: unexpected drain arg: {line.strip()}",
                )

    def test_stats_keys_exposed_in_source(self):
        src = (ROOT / "cmcc_cloud_alive" / "scg_route.py").read_text(encoding="utf-8")
        self.assertIn('stats["hold_select_seconds"]', src)
        self.assertIn('stats["hold_keepalive_interval"]', src)
        self.assertIn('stats["hold_plane"]', src)
        # assignment values
        self.assertIn("HOLD_SELECT_SECONDS", src)
        self.assertIn("HOLD_KEEPALIVE_INTERVAL", src)

    def test_drain_chunk_never_exceeds_one_second(self):
        """_scg_sleep_drain internal chunk = min(1.0, remaining) — no multi-second select block."""
        sock = mock.MagicMock(spec=socket.socket)
        stats: Dict[str, Any] = {}
        timeouts: List[float] = []
        clock = {"t": 0.0}

        def fake_mono():
            return clock["t"]

        def fake_select(r, w, x, timeout=0.0):
            t = float(timeout if timeout is not None else 0.0)
            timeouts.append(t)
            clock["t"] += t
            return [], [], []

        with mock.patch("cmcc_cloud_alive.scg_route.select.select", side_effect=fake_select), \
             mock.patch("cmcc_cloud_alive.scg_route.time.monotonic", side_effect=fake_mono):
            # even if caller mistakenly passes 25s, chunk must cap at 1.0
            _scg_sleep_drain(sock, 25.0, 1, stats)

        self.assertGreaterEqual(len(timeouts), 20)  # 25 × 1s chunks
        self.assertTrue(all(t <= 1.0 + 1e-9 for t in timeouts), msg=f"max chunk={max(timeouts)}")


if __name__ == "__main__":
    unittest.main()
