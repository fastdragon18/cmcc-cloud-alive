#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""I-PHASE-I-FLAGS: fail-closed honesty for spice_ok / degraded / tls_hold."""
from __future__ import annotations

import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cmcc_cloud_alive.scg_route import (  # noqa: E402
    enforce_honesty_flags,
    FAIL_REASON_TAXONOMY,
)


class TestEnforceHonestyFlags(unittest.TestCase):
    def test_tls_hold_forces_spice_ok_false_degraded_true(self):
        r = enforce_honesty_flags(
            {"spice_ok": True, "degraded": False, "fail_reason": ""},
            mode="tls_hold",
        )
        self.assertFalse(r["spice_ok"])
        self.assertTrue(r["degraded"])
        self.assertEqual(r["keepalive_mode"], "tls_hold")
        self.assertEqual(r["fail_reason"], "tls_hold_mode_spice_skipped")
        self.assertFalse(r.get("tls_hold_ok"))

    def test_invariant_never_tls_hold_and_spice_ok(self):
        for mode in ("tls_hold", "spice"):
            for spice_ok in (True, False):
                r = enforce_honesty_flags(
                    {
                        "spice_ok": spice_ok,
                        "degraded": False,
                        "keepalive_mode": "tls_hold" if mode == "tls_hold" else "spice",
                        "fail_reason": "",
                    },
                    mode=mode,
                )
                km = str(r.get("keepalive_mode") or "")
                if km == "tls_hold":
                    self.assertFalse(
                        r["spice_ok"],
                        msg=f"violated not(tls_hold and spice_ok): {r}",
                    )
                    self.assertTrue(r["degraded"])

    def test_spice_fail_sets_degraded_and_reason(self):
        r = enforce_honesty_flags({"spice_ok": False}, mode="spice")
        self.assertFalse(r["spice_ok"])
        self.assertTrue(r["degraded"])
        self.assertEqual(r["fail_reason"], "spice_main_init_timeout_or_missing")

    def test_spice_ok_pass_path(self):
        r = enforce_honesty_flags(
            {"spice_ok": True, "degraded": False, "fail_reason": ""},
            mode="spice",
        )
        self.assertTrue(r["spice_ok"])
        self.assertFalse(r["degraded"])
        self.assertEqual(r["fail_reason"], "")
        self.assertEqual(r["keepalive_mode"], "spice")

    def test_unknown_fail_reason_coerced(self):
        r = enforce_honesty_flags(
            {"spice_ok": False, "fail_reason": "weird_custom_reason"},
            mode="spice",
        )
        self.assertEqual(r["fail_reason"], "unknown")
        self.assertEqual(r["fail_reason_raw"], "weird_custom_reason")
        self.assertIn(r["fail_reason"], FAIL_REASON_TAXONOMY)

    def test_tls_hold_preserves_explicit_tls_hold_ok_true(self):
        r = enforce_honesty_flags(
            {
                "spice_ok": True,  # will be forced False
                "tls_hold_ok": True,
                "fail_reason": "tls_hold_mode_spice_skipped",
            },
            mode="tls_hold",
        )
        self.assertFalse(r["spice_ok"])
        self.assertTrue(r["tls_hold_ok"])
        self.assertTrue(r["degraded"])

    def test_taxonomy_closed(self):
        expected = {
            "",
            "tls_hold_mode_spice_skipped",
            "spice_main_init_timeout_or_missing",
            "auth_failed",
            "tls_hold_interrupted",
            "scg_exception",
            "unknown",
        }
        self.assertEqual(set(FAIL_REASON_TAXONOMY), expected)


class TestHonestyStaticGuards(unittest.TestCase):
    def test_enforce_present_in_scg_route(self):
        src = (ROOT / "cmcc_cloud_alive" / "scg_route.py").read_text(encoding="utf-8")
        self.assertIn("def enforce_honesty_flags", src)
        self.assertIn("FAIL_REASON_TAXONOMY", src)
        self.assertIn("enforce_honesty_flags(result", src)

    def test_main_forever_not_ok_true(self):
        src = (ROOT / "cmcc_cloud_alive" / "main.py").read_text(encoding="utf-8")
        # forever branch must not claim product PASS
        self.assertIn("scg-keepalive-running", src)
        # find forever block near scg and ensure ok = False pattern nearby
        idx = src.find("scg-keepalive-running")
        self.assertGreater(idx, 0)
        window = src[max(0, idx - 400) : idx + 200]
        self.assertIn('report["ok"] = False', window)

    def test_main_calls_enforce_or_inline_honesty(self):
        src = (ROOT / "cmcc_cloud_alive" / "main.py").read_text(encoding="utf-8")
        self.assertTrue(
            "enforce_honesty_flags" in src
            or "not (keepalive_mode == \"tls_hold\" and spice_ok)" in src
            or 'keepalive_mode == "tls_hold"' in src and "spice_ok" in src,
            msg="main must re-enforce honesty on product report",
        )


if __name__ == "__main__":
    unittest.main()
