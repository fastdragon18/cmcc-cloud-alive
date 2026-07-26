#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""I-D3-SUCCESS-CRITERIA / T17: mode ok vs business_ok fail-closed + product pin."""
from __future__ import annotations

import os
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Synthetic pin values for unit tests only (never real personal product IDs).
# Must be set BEFORE importing product_pin / compute_business_ok so module-level
# PRODUCT_* snapshots and pin-gated tests see a configured triad.
_TEST_USID = "90001"
_TEST_VMID = "80001"
_TEST_SPU = "sc-cloud-pc"

# module-level pin env removed; set in setUpClass/setUp only
os.environ["CMCC_PRODUCT_USID"] = _TEST_USID
os.environ["CMCC_PRODUCT_VMID"] = _TEST_VMID
os.environ["CMCC_PRODUCT_SPU"] = _TEST_SPU
# Clear any host-local forbidden overrides so unit tests are hermetic.
os.environ.pop("CMCC_FORBIDDEN_USID", None)
os.environ.pop("CMCC_FORBIDDEN_SPU", None)

from cmcc_cloud_alive.main import compute_business_ok  # noqa: E402
from cmcc_cloud_alive import product_pin  # noqa: E402

product_pin.refresh_pin_constants()

# Canonical product pin fields for True-path synthetic reports (T17/R7).
PIN_OK = {
    "userServiceId": product_pin.PRODUCT_USID,
    "vmId": product_pin.PRODUCT_VMID,
    "lastSpuCode": product_pin.PRODUCT_SPU,
}


def _spice_green(**extra):
    """Base spice mode/VM plane green report; pin must be supplied via extra or PIN_OK."""
    base = {
        "ok": True,
        "spice_ok": True,
        "degraded": False,
        "keepalive_mode": "spice",
        "vm_running": True,
        "vm_running_throughout": True,
        "vm_sample_count": 4,
    }
    base.update(extra)
    return base


class TestD3SuccessCriteria(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Snapshot host env so we can restore after this class (suite hermetic).
        cls._saved_env = {
            k: os.environ.get(k)
            for k in (
                "CMCC_ENFORCE_PIN",
                "CMCC_PRODUCT_USID",
                "CMCC_PRODUCT_VMID",
                "CMCC_PRODUCT_SPU",
                "CMCC_FORBIDDEN_USID",
                "CMCC_FORBIDDEN_SPU",
            )
        }
        os.environ["CMCC_ENFORCE_PIN"] = "1"
        os.environ["CMCC_PRODUCT_USID"] = _TEST_USID
        os.environ["CMCC_PRODUCT_VMID"] = _TEST_VMID
        os.environ["CMCC_PRODUCT_SPU"] = _TEST_SPU
        os.environ.pop("CMCC_FORBIDDEN_USID", None)
        os.environ.pop("CMCC_FORBIDDEN_SPU", None)
        product_pin.refresh_pin_constants()

    @classmethod
    def tearDownClass(cls):
        for k, v in getattr(cls, "_saved_env", {}).items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        product_pin.refresh_pin_constants()

    def setUp(self):
        # Keep pin enforcement on with synthetic triad for the whole class,
        # even if other tests mutate env.
        os.environ["CMCC_ENFORCE_PIN"] = "1"
        os.environ["CMCC_PRODUCT_USID"] = _TEST_USID
        os.environ["CMCC_PRODUCT_VMID"] = _TEST_VMID
        os.environ["CMCC_PRODUCT_SPU"] = _TEST_SPU
        product_pin.refresh_pin_constants()

    def test_tls_hold_ok_true_business_ok_false(self):
        report = {
            "ok": True,
            "spice_ok": False,
            "degraded": True,
            "keepalive_mode": "tls_hold",
            "tls_hold_ok": True,
            "vm_running": True,
            **PIN_OK,
        }
        self.assertFalse(compute_business_ok(report))
        self.assertTrue(report["ok"])  # mode plane may succeed

    def test_spice_full_business_ok(self):
        report = _spice_green(**PIN_OK)
        self.assertTrue(compute_business_ok(report))

    def test_spice_single_sample_not_business_ok(self):
        """P06/P07: single VM sample is not throughout; business_ok fail-closed."""
        report = _spice_green(vm_sample_count=1, **PIN_OK)
        self.assertFalse(compute_business_ok(report))

    def test_spice_zero_sample_not_business_ok(self):
        report = _spice_green(vm_sample_count=0, **PIN_OK)
        self.assertFalse(compute_business_ok(report))

    def test_spice_two_samples_throughout_business_ok(self):
        report = {
            "ok": True,
            "spice_ok": True,
            "degraded": False,
            "keepalive_mode": "spice",
            "vm_running": True,
            "vm_running_throughout": True,
            "vm_sample_count": 2,
            **PIN_OK,
        }
        self.assertTrue(compute_business_ok(report))

    def test_spice_vm_not_running_fail_closed(self):
        report = _spice_green(vm_running=False, vm_running_throughout=False, **PIN_OK)
        self.assertFalse(compute_business_ok(report))

    def test_spice_ok_vm_none_fail_closed(self):
        report = {
            "ok": True,
            "spice_ok": True,
            "degraded": False,
            "keepalive_mode": "spice",
            "vm_running": None,
            "vm_sample_count": 4,
            **PIN_OK,
        }
        self.assertFalse(compute_business_ok(report))

    def test_degraded_spice_not_business_ok(self):
        report = _spice_green(degraded=True, **PIN_OK)
        self.assertFalse(compute_business_ok(report))

    def test_pin_usid_mismatch_fail_closed(self):
        report = _spice_green(userServiceId="1", vmId=product_pin.PRODUCT_VMID, lastSpuCode=product_pin.PRODUCT_SPU)
        self.assertFalse(compute_business_ok(report))

    def test_pin_vmid_mismatch_fail_closed(self):
        report = _spice_green(
            userServiceId=product_pin.PRODUCT_USID,
            vmId="9999999",
            lastSpuCode=product_pin.PRODUCT_SPU,
        )
        self.assertFalse(compute_business_ok(report))

    def test_pin_spu_mismatch_fail_closed(self):
        report = _spice_green(
            userServiceId=product_pin.PRODUCT_USID,
            vmId=product_pin.PRODUCT_VMID,
            lastSpuCode="zte-cloud-pc",  # FORBIDDEN-style mismatch
        )
        self.assertFalse(compute_business_ok(report))

    def test_pin_nested_product_pin_dict_ok(self):
        """Accept nested report['product_pin'] triad."""
        report = _spice_green(
            product_pin={
                "userServiceId": product_pin.PRODUCT_USID,
                "vmId": product_pin.PRODUCT_VMID,
                "lastSpuCode": product_pin.PRODUCT_SPU,
            }
        )
        self.assertTrue(compute_business_ok(report))

    def test_pin_nested_mismatch_fail_closed(self):
        report = _spice_green(
            product_pin={
                "userServiceId": "2663816",
                "vmId": product_pin.PRODUCT_VMID,
                "spu": "zte-cloud-pc",
            }
        )
        self.assertFalse(compute_business_ok(report))

    def test_tls_hold_even_with_pin_not_business_ok(self):
        report = {
            "ok": True,
            "spice_ok": True,
            "degraded": False,
            "keepalive_mode": "tls_hold",
            "tls_hold_ok": True,
            "vm_running": True,
            "vm_sample_count": 4,
            **PIN_OK,
        }
        self.assertFalse(compute_business_ok(report))

    def test_pin_disabled_any_product_business_ok(self):
        """Public mode: pin off => any product fields accepted for business_ok."""
        os.environ.pop("CMCC_ENFORCE_PIN", None)
        product_pin.refresh_pin_constants()
        try:
            report = _spice_green(
                userServiceId="any-usid",
                vmId="any-vmid",
                lastSpuCode="any-spu",
            )
            self.assertTrue(compute_business_ok(report))
        finally:
            os.environ["CMCC_ENFORCE_PIN"] = "1"
            product_pin.refresh_pin_constants()

    def test_main_surfaces_d3_fields(self):
        src = (ROOT / "cmcc_cloud_alive" / "main.py").read_text(encoding="utf-8")
        for needle in (
            "def compute_business_ok",
            'report["vm_running"]',
            'report["vm_running_throughout"]',
            'report["vm_sample_count"]',
            'report["wall_hold_seconds"]',
            'report["business_ok"]',
            "business_ok must never be True under tls_hold",
            "sample_count < 2",
            "_product_pin_matches",
            "product_pin.PRODUCT_USID",
        ):
            self.assertIn(needle, src, msg=f"missing D3/T17 surface: {needle}")


if __name__ == "__main__":
    unittest.main()
