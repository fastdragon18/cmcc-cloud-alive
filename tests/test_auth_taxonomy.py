#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Offline unit tests for cmcc_cloud_alive.auth_taxonomy (I-PHASE-I-AUTH-TAX / G6).

No network. No desk. No fake 174. No password material in assertions.
"""
from __future__ import annotations

import json
import unittest

from cmcc_cloud_alive import auth_taxonomy as tax
from cmcc_cloud_alive import scg_route

class TestClosedSets(unittest.TestCase):
    def test_phase_t_fail_closed_matches_d1(self):
        expected = {
            "auth_fail",
            "channel_open_fail",
            "hold_timeout",
            "vm_powered_off",
            "client_interference",
            "degraded_mode_used",
            "exception",
            "sku_mismatch",
        }
        self.assertEqual(set(tax.PHASE_T_FAIL_CLOSED), expected)

    def test_wire_fail_reasons_superset_scg_route(self):
        # Must stay in sync with scg_route closed taxonomy
        self.assertTrue(
            set(scg_route.FAIL_REASON_TAXONOMY).issubset(set(tax.WIRE_FAIL_REASONS))
            or set(tax.WIRE_FAIL_REASONS) == set(scg_route.FAIL_REASON_TAXONOMY)
        )
        self.assertEqual(set(tax.WIRE_FAIL_REASONS), set(scg_route.FAIL_REASON_TAXONOMY))

    def test_invalid_token_codes_match_token_module(self):
        from cmcc_cloud_alive import token

        self.assertEqual(set(tax.INVALID_TOKEN_CODES), set(token.INVALID_TOKEN_CODES))


class TestClassifyToken(unittest.TestCase):
    def test_valid_token(self):
        c = tax.classify_token_response({"code": 2000, "msg": "ok"})
        self.assertEqual(c.phase_t_class, "")
        self.assertEqual(c.wire_reason, "")
        self.assertFalse(c.allow_relogin)

    def test_invalid_business_code(self):
        c = tax.classify_token_response({"code": 4014, "msg": "expired"})
        self.assertEqual(c.phase_t_class, "auth_fail")
        self.assertEqual(c.auth_subclass, "token_invalid")
        self.assertTrue(c.allow_relogin)
        self.assertTrue(c.permanent)

    def test_transient_skips_relogin(self):
        c = tax.classify_token_response(
            {"code": 0, "msg": "HTTP 502 bad gateway", "transient": True}
        )
        self.assertEqual(c.auth_subclass, "token_transient")
        self.assertFalse(c.allow_relogin)
        self.assertFalse(c.permanent)
        self.assertEqual(c.retry.max_attempts, 3)
        self.assertFalse(tax.should_relogin(c, 0))

    def test_missing_response(self):
        c = tax.classify_token_response(None)
        self.assertEqual(c.auth_subclass, "token_missing")
        self.assertTrue(c.allow_relogin)


class TestClassifyWire(unittest.TestCase):
    def test_pass_empty(self):
        c = tax.classify_wire_fail_reason("")
        self.assertEqual(c.phase_t_class, "")
        self.assertEqual(c.wire_reason, "")

    def test_auth_failed(self):
        c = tax.classify_wire_fail_reason("auth_failed")
        self.assertEqual(c.phase_t_class, "auth_fail")
        self.assertEqual(c.auth_subclass, "main_channel_auth_fail")
        self.assertFalse(c.allow_relogin)

    def test_main_init(self):
        c = tax.classify_wire_fail_reason("spice_main_init_timeout_or_missing")
        self.assertEqual(c.phase_t_class, "channel_open_fail")
        self.assertEqual(c.auth_subclass, "main_init_timeout")

    def test_tls_hold_is_degraded_not_auth_smoke(self):
        c = tax.classify_wire_fail_reason("tls_hold_mode_spice_skipped")
        self.assertEqual(c.phase_t_class, "degraded_mode_used")
        self.assertEqual(c.auth_subclass, "")

    def test_unknown_coerced(self):
        c = tax.classify_wire_fail_reason("totally_new_reason_xyz")
        self.assertEqual(c.wire_reason, "unknown")
        self.assertEqual(c.phase_t_class, "exception")


class TestClassifySpiceHandshake(unittest.TestCase):
    def test_pass(self):
        c = tax.classify_spice_handshake(
            auth_ok=True,
            spice_session_id=42,
            connected_channels=["main", "display"],
        )
        self.assertEqual(c.phase_t_class, "")
        self.assertIn("PASS", c.detail)

    def test_main_auth_fail(self):
        c = tax.classify_spice_handshake(auth_ok=False, spice_session_id=None)
        self.assertEqual(c.phase_t_class, "auth_fail")
        self.assertEqual(c.wire_reason, "auth_failed")

    def test_main_init_missing(self):
        c = tax.classify_spice_handshake(auth_ok=True, spice_session_id=None)
        self.assertEqual(c.phase_t_class, "channel_open_fail")
        self.assertEqual(c.wire_reason, "spice_main_init_timeout_or_missing")

    def test_sc_auth_missing(self):
        c = tax.classify_spice_handshake(
            auth_ok=True, spice_session_id=1, sc_auth_code_present=False
        )
        self.assertEqual(c.auth_subclass, "sc_auth_code_missing")

    def test_pre_tls(self):
        c = tax.classify_spice_handshake(
            auth_ok=False, pre_tls_error="connection refused"
        )
        self.assertEqual(c.auth_subclass, "pre_tls_connect_fail")
        self.assertTrue(tax.should_retry_transport(c, attempts_used=0))
        self.assertFalse(tax.should_retry_transport(c, attempts_used=2))


class TestRetryBudget(unittest.TestCase):
    def test_relogin_once_only(self):
        c = tax.classify_token_response({"code": 4200, "msg": "bad"})
        self.assertTrue(tax.should_relogin(c, 0))
        self.assertFalse(tax.should_relogin(c, 1))

    def test_transient_never_relogin(self):
        c = tax.classify_token_response({"code": 0, "transient": True, "msg": "timeout"})
        self.assertFalse(tax.should_relogin(c, 0))
        self.assertTrue(tax.should_retry_transport(c, 0))
        self.assertTrue(tax.should_retry_transport(c, 2))
        self.assertFalse(tax.should_retry_transport(c, 3))


class TestRedact(unittest.TestCase):
    def test_password_redacted(self):
        raw = {
            "password": "super-secret",
            "scAuthCode": "CODE123",
            "token": "abc",
            "code": 4014,
            "nested": {"vmPassword": "x", "ok": 1},
        }
        out = tax.redact_sensitive(raw)
        self.assertEqual(out["password"], "<redacted>")
        self.assertEqual(out["scAuthCode"], "<redacted>")
        self.assertEqual(out["token"], "<redacted>")
        self.assertEqual(out["nested"]["vmPassword"], "<redacted>")
        self.assertEqual(out["nested"]["ok"], 1)
        self.assertEqual(out["code"], 4014)

    def test_safe_log_fields_no_password(self):
        fields = tax.safe_log_fields(
            phase_t_class="auth_fail",
            password="SHOULD_NOT_APPEAR",
            msg="user failed",
        )
        self.assertEqual(fields.get("password"), "<redacted>")
        blob = str(fields)
        self.assertNotIn("SHOULD_NOT_APPEAR", blob)


class TestMapToPhaseT(unittest.TestCase):
    def test_identity(self):
        for name in tax.PHASE_T_FAIL_CLOSED:
            self.assertEqual(tax.map_to_phase_t(name), name)

    def test_wire_to_phase_t(self):
        self.assertEqual(tax.map_to_phase_t("auth_failed"), "auth_fail")
        self.assertEqual(
            tax.map_to_phase_t("spice_main_init_timeout_or_missing"), "channel_open_fail"
        )
        self.assertEqual(
            tax.map_to_phase_t("tls_hold_mode_spice_skipped"), "degraded_mode_used"
        )
        self.assertEqual(tax.map_to_phase_t(""), "")


class TestLaneMap(unittest.TestCase):
    def test_all_subclasses_have_lane(self):
        for sub in tax.AUTH_SUBCLASSES:
            self.assertIn(sub, tax.LANE_MAP, msg=sub)

    def test_all_phase_t_have_budget(self):
        for name in tax.PHASE_T_FAIL_CLOSED:
            self.assertIn(name, tax.RETRY_BUDGETS, msg=name)



class TestAnnotateResult(unittest.TestCase):
    """annotate_result schema attach + P1-5 spice_ok DiD."""

    def test_annotate_result_auth_failed_fields(self):
        r = {"fail_reason": "auth_failed", "spice_ok": False}
        out = tax.annotate_result(r)
        self.assertIs(out, r)
        self.assertEqual(r["auth_class"], "auth_fail")
        self.assertEqual(r["auth_subclass"], "main_channel_auth_fail")
        self.assertTrue(r["auth_permanent"])
        self.assertFalse(r["auth_allow_relogin"])
        self.assertIsInstance(r["auth_taxonomy"], dict)
        self.assertEqual(r["auth_taxonomy"]["wire_reason"], "auth_failed")

    def test_annotate_result_pass_path(self):
        r = {"fail_reason": "", "spice_ok": True, "spice_session_id": "abc"}
        tax.annotate_result(r)
        self.assertEqual(r["auth_class"], "")
        self.assertEqual(r["auth_subclass"], "")
        self.assertFalse(r["auth_permanent"])
        self.assertEqual(r["auth_taxonomy"]["wire_reason"], "")
        self.assertTrue(r["spice_ok"])

    def test_annotate_result_unknown_coerced(self):
        r = {"fail_reason": "totally_unknown_xyz"}
        tax.annotate_result(r)
        self.assertEqual(r["auth_class"], "exception")
        self.assertEqual(r["auth_taxonomy"]["wire_reason"], "unknown")
        self.assertIn("raw=", r["auth_detail"])
        # DiD: non-PASS forces spice_ok False even if caller left it True
        r2 = {"fail_reason": "totally_unknown_xyz", "spice_ok": True}
        tax.annotate_result(r2)
        self.assertIs(r2["spice_ok"], False)

    def test_annotate_result_safe_no_secrets(self):
        r = {
            "fail_reason": "auth_failed",
            "password": "SECRET",
            "token": "tok123",
            "spice_ok": False,
        }
        tax.annotate_result(r)
        safe = tax.safe_log_fields(r)
        blob = json.dumps(safe, default=str)
        self.assertNotIn("SECRET", blob)
        self.assertNotIn("tok123", blob)

    def test_sparse_empty_session_forces_spice_ok_false(self):
        """P1-5: spice_ok=True + empty/missing session -> channel_open_fail + spice_ok False."""
        for sess in (None, "", False):
            r = {"spice_ok": True, "spice_session_id": sess, "fail_reason": ""}
            tax.annotate_result(r)
            self.assertIs(r["spice_ok"], False, msg=repr(r))
            self.assertEqual(r["phase_t_class"], "channel_open_fail", msg=repr(r))
            self.assertIn(r["phase_t_class"], tax.PHASE_T_FAIL_CLOSED)

    def test_sparse_main_init_wire_forces_spice_ok_false(self):
        """P1-5: spice_main_init_timeout_or_missing with spice_ok True -> forced False."""
        r = {
            "spice_ok": True,
            "fail_reason": "spice_main_init_timeout_or_missing",
            "spice_session_id": "x",
        }
        tax.annotate_result(r)
        self.assertIs(r["spice_ok"], False, msg=repr(r))
        self.assertEqual(r["phase_t_class"], "channel_open_fail")
        self.assertEqual(r["auth_subclass"], "main_init_timeout")

    def test_sparse_channel_open_fail_forces_spice_ok_false(self):
        r = {"spice_ok": True, "fail_reason": "channel_open_fail"}
        tax.annotate_result(r)
        # unknown/coerced or mapped — must not leave spice_ok True
        self.assertIs(r["spice_ok"], False, msg=repr(r))
        self.assertIn(r["phase_t_class"], tax.PHASE_T_FAIL_CLOSED)

    def test_auth_failed_forces_spice_ok_false(self):
        r = {"spice_ok": True, "fail_reason": "auth_failed"}
        tax.annotate_result(r)
        self.assertIs(r["spice_ok"], False)
        self.assertEqual(r["phase_t_class"], "auth_fail")

    def test_pass_keeps_spice_ok_true(self):
        r = {"spice_ok": True, "spice_session_id": "sess-ok", "fail_reason": ""}
        tax.annotate_result(r)
        self.assertIs(r["spice_ok"], True)
        self.assertEqual(r.get("phase_t_class") or "", "")



if __name__ == "__main__":
    unittest.main()
