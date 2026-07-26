#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""T52-3 offline unit: plane field-lift + business fail-closed (I-T52-UNIT_LIFT).

Cite-only replay of E3 product truth (E_20260712T124751Z) through
`derive_planes_from_report`. NO LIVE. NO secrets. E3 short-test ≠ J*.

Acceptance (执行方案T52.md T52-3):
  * load E3 json / embedded minimal scg_stats clone
  * after T52-1: frames/hb/vm_powered no longer null when present under scg_stats
  * business_ok fail-closed on sample_count=2 without powered-lift honesty
  * if runner not patched yet: document expected vs baseline (skip hard asserts)
  * dual-EQ test file · no LIVE
"""
from __future__ import annotations

import importlib.util
import inspect
import json
import sys
import unittest
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

RUNNER_PATH = ROOT / "scripts" / "e_shorttest_runner.py"
E3_HARNESS_JSON = ROOT / "reports" / "E_20260712T124751Z.json"
E3_LOG = ROOT / "reports" / "E_20260712T124751Z.log"

# ---------------------------------------------------------------------------
# Embedded minimal clone of E3 product scg_stats (cite residual RCA / E3 log).
# Top-level frames/heartbeats intentionally null — product nests under scg_stats.
# Pin usid is public in plan; no passwords/tokens/auth codes.
# ---------------------------------------------------------------------------
E3_PRODUCT_MINIMAL: dict = {
    "ok": True,
    "spice_ok": True,
    "business_ok": True,  # product flag alone must NOT promote after R4
    "degraded": False,
    "keepalive_mode": "spice",
    "kind": "scg",
    "stage": "scg-keepalive-done",
    "frames": None,
    "heartbeats": None,
    "scg_stats": {
        "frames": 215,
        "responses": 21,
        "hold_plane": "dual",
        "kpi": {
            "hold_heartbeats": 0,
            "hold_replies": 18,
            "vm_powered_throughout": True,
            "vm_sample_count": 2,
        },
        "vm_samples": [
            {
                "phase": "start",
                "running": True,
                "off": False,
                "vmStatus": 1,
                "vmStatusShow": "运行中",
                "userServiceId": "90001",
                "index": 0,
            },
            {
                "phase": "end",
                "running": True,
                "off": False,
                "vmStatus": 1,
                "vmStatusShow": "运行中",
                "userServiceId": "90001",
                "index": 3,
            },
        ],
    },
    "vm_samples": [
        {"phase": "start", "running": True, "off": False, "vmStatus": 1},
        {"phase": "end", "running": True, "off": False, "vmStatus": 1},
    ],
}

# Post-T52-1 expected contract (R1/R3/R4 prefer rule from 执行方案T52).
EXPECTED_FRAMES = 215
# Prefer hold_heartbeats (0 is a real counter, not null); hold_replies=18 is alias.
EXPECTED_HEARTBEATS_CANDIDATES = (0, 18)  # either alias is honest lift
EXPECTED_VM_POWERED = True
EXPECTED_VM_SAMPLE_COUNT = 2


def _load_runner():
    spec = importlib.util.spec_from_file_location("e_shorttest_runner_t52", RUNNER_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _runner_source() -> str:
    return RUNNER_PATH.read_text(encoding="utf-8", errors="replace")


def _t52_lift_patched() -> bool:
    """Heuristic: T52-1 lands scg_stats (+kpi) in derive_planes field path."""
    src = _runner_source()
    if "scg_stats" not in src:
        return False
    # require scg_stats near derive_planes_from_report body (not just comments elsewhere)
    try:
        start = src.index("def derive_planes_from_report")
        body = src[start : start + 8000]
    except ValueError:
        body = src
    return "scg_stats" in body and (
        "hold_heartbeats" in body
        or "vm_powered_throughout" in body
        or "kpi" in body
    )


def _extract_product_from_e3_log() -> dict | None:
    """Best-effort: parse product-keepalive JSON from E3 log (cite-only)."""
    if not E3_LOG.is_file():
        return None
    text = E3_LOG.read_text(encoding="utf-8", errors="replace")
    idx = text.find("[product-keepalive]")
    if idx < 0:
        return None
    start = text.find("{", idx)
    if start < 0:
        return None
    depth = 0
    end = None
    for i, ch in enumerate(text[start : start + 120000]):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = start + i + 1
                break
    if end is None:
        return None
    try:
        return json.loads(text[start:end])
    except json.JSONDecodeError:
        return None


def _derive(report: dict, scg_mode: str = "spice", process_ok: bool = True):
    mod = _load_runner()
    return mod.derive_planes_from_report(report, scg_mode, process_ok)


class TestT52PlaneLiftOffline(unittest.TestCase):
    """Offline replay of E3 scg_stats → protocol/business planes."""

    @classmethod
    def setUpClass(cls):
        cls.patched = _t52_lift_patched()
        cls.runner_sha16 = __import__("hashlib").sha256(
            RUNNER_PATH.read_bytes()
        ).hexdigest()[:16]
        cls.product = deepcopy(E3_PRODUCT_MINIMAL)
        # Prefer live cite of log product when available (still offline file read)
        extracted = _extract_product_from_e3_log()
        if isinstance(extracted, dict) and isinstance(extracted.get("scg_stats"), dict):
            # keep only non-secret structural fields used by derive
            ss = extracted["scg_stats"]
            kpi = ss.get("kpi") if isinstance(ss.get("kpi"), dict) else {}
            cls.product = {
                "ok": extracted.get("ok", True),
                "spice_ok": extracted.get("spice_ok", True),
                "business_ok": extracted.get("business_ok", True),
                "degraded": extracted.get("degraded", False),
                "keepalive_mode": extracted.get("keepalive_mode")
                or extracted.get("scg_mode")
                or "spice",
                "kind": extracted.get("kind", "scg"),
                "stage": extracted.get("stage"),
                "frames": extracted.get("frames"),  # E3 top-level null
                "heartbeats": extracted.get("heartbeats"),
                "scg_stats": {
                    "frames": ss.get("frames"),
                    "responses": ss.get("responses"),
                    "hold_plane": ss.get("hold_plane"),
                    "kpi": {
                        "hold_heartbeats": kpi.get("hold_heartbeats"),
                        "hold_replies": kpi.get("hold_replies"),
                        "vm_powered_throughout": kpi.get("vm_powered_throughout"),
                        "vm_sample_count": kpi.get("vm_sample_count"),
                    },
                    "vm_samples": ss.get("vm_samples"),
                },
                "vm_samples": extracted.get("vm_samples") or ss.get("vm_samples"),
            }

    # --- fixture honesty -------------------------------------------------

    def test_fixture_scg_stats_has_product_truth(self):
        ss = self.product["scg_stats"]
        self.assertEqual(ss["frames"], EXPECTED_FRAMES)
        kpi = ss["kpi"]
        self.assertIn(kpi["hold_heartbeats"], (0, 18))
        self.assertEqual(kpi["vm_powered_throughout"], True)
        self.assertEqual(kpi["vm_sample_count"], EXPECTED_VM_SAMPLE_COUNT)
        # top-level intentionally null (E3 product shape)
        self.assertIsNone(self.product.get("frames"))
        self.assertIsNone(self.product.get("heartbeats"))

    def test_e3_harness_json_cites_null_protocol_counters(self):
        """Harness E3 json (pre-T52-1 merge) still has null protocol counters."""
        if not E3_HARNESS_JSON.is_file():
            self.skipTest("E3 harness json missing")
        har = json.loads(E3_HARNESS_JSON.read_text(encoding="utf-8"))
        planes = har.get("planes") or {}
        proto = planes.get("protocol") or {}
        # document baseline residual (R1)
        self.assertIsNone(proto.get("frames"))
        # heartbeats may be null on E3 product path
        self.assertTrue(
            proto.get("heartbeats") is None or isinstance(proto.get("heartbeats"), int)
        )
        biz = planes.get("business") or {}
        self.assertIsNone(biz.get("vm_powered_throughout"))
        # honesty: short-test stamp is not J*
        self.assertNotEqual(har.get("plan"), "J*")

    # --- baseline documentation (always runs) ----------------------------

    def test_baseline_or_lifted_derive_on_e3_product(self):
        """Call derive_planes_from_report on E3 product fixture.

        Baseline (sha 404691701578a8a6): frames/hb/vm_powered stay null;
        business_ok True from product flag alone (R4 residual).
        Post T52-1: frames=215, hb lifted, vm_powered True; R4 prefer
        sample_count<3 → business_ok False even if product flag True.
        """
        protocol_ok, business_ok, pf, bf, notes = _derive(self.product)
        self.assertTrue(protocol_ok)  # spice_ok path
        self.assertIsInstance(pf, dict)
        self.assertIsInstance(bf, dict)

        if self.patched:
            self.assertEqual(
                pf.get("frames"),
                EXPECTED_FRAMES,
                msg=f"R1 frames lift failed; notes={notes!r}",
            )
            hb = pf.get("heartbeats")
            self.assertIsNotNone(hb, msg=f"R1 heartbeats still null; notes={notes!r}")
            self.assertIn(
                hb,
                EXPECTED_HEARTBEATS_CANDIDATES,
                msg=f"unexpected hb alias {hb}; expect {EXPECTED_HEARTBEATS_CANDIDATES}",
            )
            self.assertEqual(
                bf.get("vm_powered_throughout"),
                EXPECTED_VM_POWERED,
                msg=f"R3 vm_powered lift failed; bf={bf}",
            )
            # R4 prefer: sample_count=2 < 3 → fail-closed despite product business_ok
            self.assertFalse(
                bool(business_ok),
                msg=(
                    "R4 prefer: sample_count=2 must not yield business_ok=True; "
                    f"business_ok={business_ok} bf={bf}"
                ),
            )
        else:
            # Document baseline residual (must not silently invent counters)
            self.assertIsNone(
                pf.get("frames"),
                msg="baseline must not invent frames without scg_stats path",
            )
            self.assertIsNone(
                pf.get("heartbeats"),
                msg="baseline must not invent heartbeats without scg_stats path",
            )
            self.assertIsNone(
                bf.get("vm_powered_throughout"),
                msg="baseline leaves vm_powered null (not lifted from kpi)",
            )
            # baseline currently promotes product business_ok (residual R4)
            # document only — hard fail-closed asserted under patched branch / synthetic tests
            self.assertTrue(
                business_ok is True or business_ok is False,
                msg="business_ok must be bool",
            )

    # --- hard post-patch contracts (skip until T52-1) --------------------

    @unittest.skipUnless(_t52_lift_patched(), "T52-1 runner patch not landed yet")
    def test_post_patch_frames_lifted_from_scg_stats(self):
        _, _, pf, _, _ = _derive(self.product)
        self.assertEqual(pf.get("frames"), EXPECTED_FRAMES)

    @unittest.skipUnless(_t52_lift_patched(), "T52-1 runner patch not landed yet")
    def test_post_patch_heartbeats_lifted_from_kpi(self):
        _, _, pf, _, _ = _derive(self.product)
        self.assertIn(pf.get("heartbeats"), EXPECTED_HEARTBEATS_CANDIDATES)

    @unittest.skipUnless(_t52_lift_patched(), "T52-1 runner patch not landed yet")
    def test_post_patch_vm_powered_lifted_from_kpi(self):
        _, _, _, bf, _ = _derive(self.product)
        self.assertIs(bf.get("vm_powered_throughout"), True)

    # --- R4 fail-closed (synthetic; meaningful once patched) -------------

    def test_business_fail_closed_sample2_without_powered_lift(self):
        """sample_count=2, powered not lifted/False, product business_ok=True.

        After T52-1 R4: must be business_ok False (product flag insufficient).
        Before patch: documents dishonest True promotion as residual.
        """
        report = {
            "ok": True,
            "spice_ok": True,
            "business_ok": True,
            "degraded": False,
            "keepalive_mode": "spice",
            "scg_stats": {
                "frames": 100,
                "kpi": {
                    "hold_heartbeats": 3,
                    "hold_replies": 3,
                    # deliberately omit vm_powered_throughout
                    "vm_sample_count": 2,
                },
            },
            "vm_sample_count": 2,
        }
        protocol_ok, business_ok, pf, bf, notes = _derive(report)
        self.assertTrue(protocol_ok)

        if self.patched:
            self.assertFalse(
                bool(business_ok),
                msg=(
                    "R4: sample_count=2 without powered=True must fail-closed; "
                    f"got business_ok={business_ok} notes={notes!r} bf={bf}"
                ),
            )
            # powered should remain not-True (None or False)
            self.assertTrue(
                bf.get("vm_powered_throughout") is not True,
                msg=f"powered must not be True when omitted; bf={bf}",
            )
        else:
            # baseline residual: product flag may promote — document, do not invent fix
            self.assertIs(
                bf.get("vm_powered_throughout"),
                None,
                msg="baseline: powered not lifted when only under missing kpi path",
            )

    def test_business_fail_closed_product_flag_alone_no_samples(self):
        """No multi-sample evidence at all → business_ok must not be True after R4."""
        report = {
            "ok": True,
            "spice_ok": True,
            "business_ok": True,
            "degraded": False,
            "keepalive_mode": "spice",
            "scg_stats": {"frames": 50, "kpi": {"hold_heartbeats": 1}},
        }
        _, business_ok, _, bf, notes = _derive(report)
        if self.patched:
            self.assertFalse(
                bool(business_ok),
                msg=f"R4 product flag alone insufficient; notes={notes!r} bf={bf}",
            )
        else:
            # baseline residual documentation
            self.assertTrue(business_ok in (True, False, None))

    def test_tls_hold_never_business_pass(self):
        """Invariant unchanged: tls_hold forces business_ok False."""
        report = {
            "ok": True,
            "tls_hold_ok": True,
            "business_ok": True,
            "keepalive_mode": "tls_hold",
            "scg_stats": {
                "frames": 10,
                "kpi": {
                    "hold_heartbeats": 1,
                    "vm_powered_throughout": True,
                    "vm_sample_count": 5,
                },
            },
        }
        _, business_ok, _, bf, notes = _derive(report, scg_mode="tls_hold")
        self.assertFalse(bool(business_ok))
        self.assertIn("tls_hold", (bf.get("notes") or notes or "").lower())

    def test_no_invent_when_scg_stats_missing_counters(self):
        """Honesty: missing counters stay null — never invent frames/hb."""
        report = {
            "ok": True,
            "spice_ok": True,
            "business_ok": False,
            "keepalive_mode": "spice",
            "scg_stats": {"kpi": {}},
        }
        _, _, pf, _, _ = _derive(report)
        self.assertIsNone(pf.get("frames"))
        self.assertIsNone(pf.get("heartbeats"))

    def test_runner_baseline_sha_documented(self):
        """Plan baseline sha16=404691701578a8a6 until T52-1 lands."""
        self.assertEqual(len(self.runner_sha16), 16)
        # If still baseline, record; if patched, sha must change
        if not self.patched:
            self.assertEqual(
                self.runner_sha16,
                "404691701578a8a6",
                msg="unpatched runner should match plan baseline sha16",
            )
        else:
            self.assertNotEqual(
                self.runner_sha16,
                "404691701578a8a6",
                msg="patched runner sha must differ from T51/T52 baseline",
            )


class TestT52ContractDoc(unittest.TestCase):
    """Static contract notes for T52-4/T52-5 consumers (no LIVE)."""

    def test_expected_vs_baseline_table(self):
        rows = [
            # field, product truth, baseline plane, post-T52-1 plane
            ("protocol.frames", 215, None, 215),
            ("protocol.heartbeats", "kpi.hold_heartbeats=0|hold_replies=18", None, "0|18"),
            ("business.vm_powered_throughout", True, None, True),
            ("business.vm_sample_count", 2, 2, 2),
            (
                "business.business_ok",
                "product True",
                "True (product flag)",
                "False (R4 prefer sample_count<3)",
            ),
        ]
        self.assertEqual(len(rows), 5)
        # E3 ≠ J*
        self.assertNotEqual("E3", "J*")


if __name__ == "__main__":
    unittest.main(verbosity=2)
