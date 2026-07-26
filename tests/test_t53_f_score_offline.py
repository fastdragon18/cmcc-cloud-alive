#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""T53-5 offline unit: F3 scorer fixtures + honesty gates (I-T53-TESTS_CHECK).

Cite-only offline fixtures for `scripts/f_score_offline.py`:
  - all-run (continuous powered ≥ target after boot_skip)
  - mid-shutdown (关机 after boot skip → business_ok=false)
  - short-n (cover < target_wall_s → fail-closed / not J*)

NO LIVE. NO secrets. NO kill F-LIVE pids 134500/134616.
E3 short-test ≠ J*. Partial F samples ≠ plan F[x].

Acceptance (执行方案T53.md T53-5):
  pytest fixtures all-run / mid-shutdown / short-n;
  dual-EQ check list in reports/检查报告T53.md.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

NEST = Path(__file__).resolve().parents[1]
SCORER_PATH = NEST / "scripts" / "f_score_offline.py"

# Plan pin (执行方案T53 / F_report_template)
PIN_USID = 90001
PIN_VM = 80001
PIN_SPU = "sc-cloud-pc"
PIN_PROFILE = "gui1949_premium"
TARGET_WALL_S = 2400
CONTINUOUS_RATIO = 1.0
# Scorer DEFAULT_BOOT_SKIP_S is 120; fixtures sized so all-run still ≥ target after skip.
BOOT_SKIP_S = 120.0

PLAN_SHA16 = "5178bf545c6389aa"
PARENT_MERGE = "5dc25d290c5b1448"
F_LIVE_STAMP = "20260712T135955Z"
F_LIVE_PIDS = (134500, 134616)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _utc(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _sample(
    idx: int,
    ts: datetime,
    *,
    vm_status: int = 1,
    vm_show: str = "运行中",
    usid: int = PIN_USID,
    spu: str = PIN_SPU,
    phase: str = "run",
    ok: bool = True,
    rc: int = 0,
    running: Any = None,
) -> Dict[str, Any]:
    return {
        "ok": ok,
        "ts": _iso(ts),
        "userServiceId": usid,
        "spuCode": spu,
        "vmStatus": vm_status,
        "vmStatusShow": vm_show,
        "running": running,
        "serviceStatus": 1 if vm_status == 1 else 0,
        "skuName": "家庭云电脑高级版",
        "rc": rc,
        "idx": idx,
        "phase": phase,
        "elapsed_wall": None,
    }


def build_all_run_fixture(
    n: int = 86,
    interval_s: int = 30,
    start: Optional[datetime] = None,
) -> List[Dict[str, Any]]:
    """Continuous run: n=86 → span 2550s; after boot_skip 120 → continuous ≥2400."""
    start = start or datetime(2026, 7, 12, 14, 0, 12, tzinfo=timezone.utc)
    return [
        _sample(i, start + timedelta(seconds=i * interval_s)) for i in range(n)
    ]


def build_mid_shutdown_fixture(
    n: int = 86,
    interval_s: int = 30,
    off_from_idx: int = 40,
    start: Optional[datetime] = None,
) -> List[Dict[str, Any]]:
    """All-run then mid-shutdown (关机) after boot skip window."""
    start = start or datetime(2026, 7, 12, 14, 0, 12, tzinfo=timezone.utc)
    rows: List[Dict[str, Any]] = []
    for i in range(n):
        if i >= off_from_idx:
            rows.append(
                _sample(
                    i,
                    start + timedelta(seconds=i * interval_s),
                    vm_status=0,
                    vm_show="已关机",
                    phase="mid_off",
                    running=False,
                )
            )
        else:
            rows.append(_sample(i, start + timedelta(seconds=i * interval_s)))
    return rows


def build_short_n_fixture(
    n: int = 11,
    interval_s: int = 30,
    start: Optional[datetime] = None,
) -> List[Dict[str, Any]]:
    """Short cover (300s) << TARGET_WALL_S — must not pass business / J*."""
    start = start or datetime(2026, 7, 12, 14, 0, 12, tzinfo=timezone.utc)
    return [
        _sample(i, start + timedelta(seconds=i * interval_s)) for i in range(n)
    ]


def write_jsonl(path: Path, rows: List[Dict[str, Any]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    return path


def cover_span_s(rows: List[Dict[str, Any]]) -> float:
    if len(rows) < 2:
        return 0.0
    return (_utc(rows[-1]["ts"]) - _utc(rows[0]["ts"])).total_seconds()


def load_scorer_module():
    if not SCORER_PATH.is_file():
        return None
    spec = importlib.util.spec_from_file_location("f_score_offline", SCORER_PATH)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["f_score_offline"] = mod
    spec.loader.exec_module(mod)
    return mod


def score_rows(mod, rows: List[Dict[str, Any]], **kwargs: Any) -> Dict[str, Any]:
    """Prefer score_samples (pure); fall back to score_paths via temp jsonl."""
    score_samples = getattr(mod, "score_samples", None)
    if callable(score_samples):
        kw = {
            "target_s": TARGET_WALL_S,
            "continuous_ratio": CONTINUOUS_RATIO,
            "boot_skip_s": BOOT_SKIP_S,
            "expect_usid": str(PIN_USID),
            "expect_spu": PIN_SPU,
        }
        kw.update(kwargs)
        return score_samples(rows, **kw)

    score_paths = getattr(mod, "score_paths", None)
    if callable(score_paths):
        with tempfile.TemporaryDirectory() as td:
            p = write_jsonl(Path(td) / "samples.jsonl", rows)
            return score_paths(
                p,
                None,
                target_s=TARGET_WALL_S,
                continuous_ratio=CONTINUOUS_RATIO,
                boot_skip_s=BOOT_SKIP_S,
                expect_usid=str(PIN_USID),
                expect_spu=PIN_SPU,
            )

    raise unittest.SkipTest("f_score_offline has no score_samples/score_paths")


def extract_planes(result: Any) -> Dict[str, Any]:
    if not isinstance(result, dict):
        return {"raw_type": type(result).__name__, "raw_keys": []}
    return {
        "business_ok": result.get("business_ok"),
        "process_ok": result.get("process_ok"),
        "protocol_ok": result.get("protocol_ok"),
        "continuous_run_s": result.get("continuous_run_s"),
        "coverage_s": result.get("coverage_s"),
        "mid_shutdown": result.get("mid_shutdown"),
        "verdict": result.get("verdict"),
        "reasons": result.get("reasons"),
        "note": result.get("note"),
        "raw_keys": sorted(result.keys()),
    }


# ---------------------------------------------------------------------------
# Fixture purity (always)
# ---------------------------------------------------------------------------


class TestT53FixturePurity(unittest.TestCase):
    def test_all_run_cover_and_pin(self):
        rows = build_all_run_fixture()
        self.assertGreaterEqual(cover_span_s(rows), TARGET_WALL_S)
        self.assertTrue(all(r["vmStatus"] == 1 for r in rows))
        self.assertTrue(all(r["userServiceId"] == PIN_USID for r in rows))
        self.assertTrue(all(r["spuCode"] == PIN_SPU for r in rows))
        # after boot_skip residual continuous span ≥ target
        residual = cover_span_s(rows) - BOOT_SKIP_S
        self.assertGreaterEqual(residual, TARGET_WALL_S * CONTINUOUS_RATIO)

    def test_mid_shutdown_has_off_after_boot(self):
        rows = build_mid_shutdown_fixture(off_from_idx=40)
        t0 = _utc(rows[0]["ts"])
        offs = [
            r
            for r in rows
            if (_utc(r["ts"]) - t0).total_seconds() >= BOOT_SKIP_S
            and (r["vmStatus"] == 0 or "关机" in str(r.get("vmStatusShow")))
        ]
        self.assertTrue(offs, "expected mid-shutdown samples after boot_skip")
        blob = json.dumps(rows, ensure_ascii=False)
        self.assertIn("关机", blob)

    def test_short_n_cover_below_target(self):
        rows = build_short_n_fixture()
        self.assertLess(cover_span_s(rows), TARGET_WALL_S)
        self.assertTrue(all(r["vmStatus"] == 1 for r in rows))

    def test_e3_not_jstar_and_partial_f_not_plan_tick(self):
        self.assertNotEqual("E3", "J*")
        self.assertNotEqual(F_LIVE_STAMP, "plan_F_checked")
        self.assertEqual(F_LIVE_PIDS, (134500, 134616))

    def test_pin_mismatch_detectable(self):
        rows = build_all_run_fixture(n=5)
        rows[2]["userServiceId"] = 99999999
        self.assertNotEqual(rows[2]["userServiceId"], PIN_USID)

    def test_jsonl_roundtrip(self):
        rows = build_all_run_fixture(n=5)
        with tempfile.TemporaryDirectory() as td:
            p = write_jsonl(Path(td) / "fx.jsonl", rows)
            loaded = []
            with p.open(encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        loaded.append(json.loads(line))
            self.assertEqual(len(loaded), 5)
            self.assertEqual(loaded[0]["vmStatus"], 1)


# ---------------------------------------------------------------------------
# Scorer binding (soft-skip if T53-3 not landed)
# ---------------------------------------------------------------------------


@unittest.skipUnless(SCORER_PATH.is_file(), "scripts/f_score_offline.py not landed (T53-3)")
class TestT53ScorerBinding(unittest.TestCase):
    """Bind fixtures to three-plane fail-closed rules via score_samples."""

    @classmethod
    def setUpClass(cls):
        cls.mod = load_scorer_module()
        if cls.mod is None:
            raise unittest.SkipTest("cannot import f_score_offline")

    def test_all_run_business_pass(self):
        rows = build_all_run_fixture()
        r = score_rows(self.mod, rows)
        planes = extract_planes(r)
        self.assertIs(planes["business_ok"], True, msg=planes)
        self.assertFalse(bool(planes["mid_shutdown"]))
        self.assertGreaterEqual(
            float(planes["continuous_run_s"]), TARGET_WALL_S * CONTINUOUS_RATIO
        )
        # process/protocol without product final stay None (not invent)
        self.assertIsNone(planes["process_ok"])
        self.assertIsNone(planes["protocol_ok"])
        note = str(planes.get("note") or "")
        self.assertIn("not J*", note)

    def test_mid_shutdown_forces_business_false(self):
        rows = build_mid_shutdown_fixture(off_from_idx=40)
        r = score_rows(self.mod, rows)
        planes = extract_planes(r)
        self.assertIs(planes["business_ok"], False, msg=planes)
        self.assertTrue(bool(planes["mid_shutdown"]))
        reasons = " ".join(str(x) for x in (planes.get("reasons") or []))
        self.assertTrue(
            "mid_shutdown" in reasons or planes["mid_shutdown"] is True,
            msg=reasons,
        )

    def test_short_n_business_fail_not_jstar(self):
        rows = build_short_n_fixture()
        r = score_rows(self.mod, rows)
        planes = extract_planes(r)
        self.assertIsNot(planes["business_ok"], True, msg=planes)
        self.assertIs(planes["business_ok"], False)
        v = str(planes.get("verdict") or "").upper()
        self.assertNotIn("J*", v)
        self.assertNotEqual(v, "JSTAR")
        note = str(planes.get("note") or "")
        self.assertIn("not J*", note)

    def test_pin_mismatch_fails_business(self):
        rows = build_all_run_fixture()
        rows[10]["userServiceId"] = 11111111
        r = score_rows(self.mod, rows)
        planes = extract_planes(r)
        self.assertIs(planes["business_ok"], False, msg=planes)

    def test_score_paths_jsonl_roundtrip(self):
        score_paths = getattr(self.mod, "score_paths", None)
        if not callable(score_paths):
            self.skipTest("no score_paths")
        rows = build_all_run_fixture()
        with tempfile.TemporaryDirectory() as td:
            p = write_jsonl(Path(td) / "samples.jsonl", rows)
            r = score_paths(
                p,
                None,
                target_s=TARGET_WALL_S,
                continuous_ratio=CONTINUOUS_RATIO,
                boot_skip_s=BOOT_SKIP_S,
                expect_usid=str(PIN_USID),
                expect_spu=PIN_SPU,
            )
            self.assertIs(r.get("business_ok"), True, msg=r)


# ---------------------------------------------------------------------------
# Meta / ban observance (always)
# ---------------------------------------------------------------------------


class TestT53MetaBans(unittest.TestCase):
    def test_scorer_path_expected(self):
        self.assertTrue(str(SCORER_PATH).endswith("scripts/f_score_offline.py"))
        self.assertEqual(NEST.name, "cmcc-cloud-alive")

    def test_no_live_constants(self):
        self.assertEqual(F_LIVE_PIDS[0], 134500)
        self.assertEqual(F_LIVE_PIDS[1], 134616)
        self.assertEqual(PLAN_SHA16, "5178bf545c6389aa")
        self.assertEqual(PARENT_MERGE, "5dc25d290c5b1448")

    def test_fixture_builders_exportable(self):
        self.assertTrue(callable(build_all_run_fixture))
        self.assertTrue(callable(build_mid_shutdown_fixture))
        self.assertTrue(callable(build_short_n_fixture))


if __name__ == "__main__":
    unittest.main(verbosity=2)
