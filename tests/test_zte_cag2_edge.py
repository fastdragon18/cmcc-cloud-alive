#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for CAG2.0 edge auto-detect + connectDesktop material path.

Evidence: reports/OL3v0I_cag2/ (clear JSON body, V7.25.40-HY, requestFrom=5,
encrypt=5, async via tokenInfo.accessToken).
Does NOT touch IPv4-CAGMux / IPv6-raw-ZTEC transport.
"""

from __future__ import annotations

import unittest
from unittest import mock

from cmcc_cloud_alive import zte_route


def _firm(**kw):
    base = dict(
        vm_user_name="u_test",
        vm_password="p_test",
        vm_id="vm-1",
        cag_ip="36.140.220.118",
        cag_port=8899,
    )
    base.update(kw)
    return zte_route.ZTEFirmAuth(**base)


def _cag2_probe(**kw):
    p = zte_route.CagEdgeProbe(
        kind="CAG2.0",
        status=404,
        proxy_agent="CAG2.0",
        server="",
        body_len=0,
    )
    for k, v in kw.items():
        setattr(p, k, v)
    return p


def _iag_probe(**kw):
    p = zte_route.CagEdgeProbe(
        kind="IAG",
        status=200,
        proxy_agent="",
        server="IAG",
        body_len=128,
    )
    for k, v in kw.items():
        setattr(p, k, v)
    return p


class TestConstants(unittest.TestCase):
    def test_cag2_constants_locked(self):
        self.assertEqual(zte_route.CAG2_CLIENT_VERSION, "V7.25.40-HY")
        # int, matching official JSON body (not query-string "5")
        self.assertEqual(zte_route.CAG2_REQUEST_FROM, 5)
        self.assertEqual(zte_route.CAG2_ENCRYPT, 5)


class TestConnectDesktopBody(unittest.TestCase):
    # RSA-2048 toy key (N/E text form) for offline body length check only.
    _TOY_RSAPUB = (
        "N = "
        "C1F0A3B2D4E5F60718293A4B5C6D7E8F901A2B3C4D5E6F708192A3B4C5D6E7F8"
        "091A2B3C4D5E6F708192A3B4C5D6E7F8091A2B3C4D5E6F708192A3B4C5D6E7F8"
        "091A2B3C4D5E6F708192A3B4C5D6E7F8091A2B3C4D5E6F708192A3B4C5D6E7F8"
        "091A2B3C4D5E6F708192A3B4C5D6E7F8091A2B3C4D5E6F708192A3B4C5D6E7F8"
        "091A2B3C4D5E6F708192A3B4C5D6E7F8091A2B3C4D5E6F708192A3B4C5D6E7F8"
        "091A2B3C4D5E6F708192A3B4C5D6E7F8091A2B3C4D5E6F708192A3B4C5D6E7F8"
        "091A2B3C4D5E6F708192A3B4C5D6E7F8091A2B3C4D5E6F708192A3B4C5D6E7F8"
        "091A2B3C4D5E6F708192A3B4C5D6E7F8091A2B3C4D5E6F708192A3B4C5D6E7F"
        "\r\nE = 010001\r\n"
    )

    def test_body_fields_locked(self):
        firm = _firm()
        client = zte_route.ZTEClient(firm)
        # CAG2 encrypt=5: RSA-PKCS1v1.5 → hex.upper → b64 (not AES-VDI)
        body = client._connect_desktop_body(
            vmid="vm-abc", rsa_public_key=self._TOY_RSAPUB
        )
        self.assertEqual(body["version"], "V7.25.40-HY")
        self.assertEqual(body["requestFrom"], 5)
        self.assertEqual(body["encrypt"], 5)
        self.assertEqual(body["vmid"], "vm-abc")
        self.assertEqual(body["username"], "u_test")
        # password must be RSA-encoded, not plaintext; RSA-2048 → ~684 chars
        self.assertNotEqual(body["password"], "p_test")
        self.assertTrue(isinstance(body["password"], str))
        self.assertGreaterEqual(len(body["password"]), 680)
        self.assertLessEqual(len(body["password"]), 688)
        # locked shape fields from official pcap
        self.assertEqual(body["type"], 0)
        self.assertEqual(body["raptype"], 2)
        self.assertEqual(body["supportAsync"], 1)
        self.assertIn("supportCustomConfig", body)
        self.assertEqual(body["language"], "zh")


class TestExtractConnectStr(unittest.TestCase):
    def test_flat(self):
        self.assertEqual(
            zte_route.ZTEClient.extract_connect_str({"connectStr": "abc"}),
            "abc",
        )

    def test_nested_connectInfo(self):
        self.assertEqual(
            zte_route.ZTEClient.extract_connect_str(
                {"connectInfo": {"connectStr": "nested-cs", "success": True}}
            ),
            "nested-cs",
        )

    def test_missing(self):
        self.assertEqual(zte_route.ZTEClient.extract_connect_str({}), "")
        self.assertEqual(zte_route.ZTEClient.extract_connect_str(None), "")
        self.assertEqual(
            zte_route.ZTEClient.extract_connect_str({"connectInfo": {"result": "0"}}),
            "",
        )


class TestRunMaterialCAG2(unittest.TestCase):
    def test_cag2_immediate_connectStr(self):
        firm = _firm()
        probe = _cag2_probe()
        payload = {
            "success": True,
            "result": "0",
            "mesg": "Success",
            "connectInfo": {
                "success": True,
                "result": "0",
                "connectStr": "CS_IMMEDIATE_XYZ",
                "vmId": "vm-1",
            },
            "tokenInfo": {
                "success": True,
                "accessToken": "tok-imm",
                "result": "0",
            },
        }

        with mock.patch.object(zte_route, "probe_cag_edge", return_value=probe):
            with mock.patch.object(
                zte_route.ZTEClient, "connect_desktop", return_value=payload
            ) as cd:
                # ensure IAG path not dialed
                with mock.patch.object(
                    zte_route.ZTEClient, "sys_config",
                    side_effect=AssertionError("IAG sys_config must not run on CAG2"),
                ):
                    report = zte_route.run_material(firm, target_vm_id="vm-1", do_start=True)

        self.assertTrue(report.ok)
        self.assertEqual(report.edge_kind, "CAG2.0")
        self.assertEqual(report.zte_path, "CAG2.0-connectDesktop")
        self.assertTrue(report.has_connect_str)
        self.assertEqual(report.connect_str, "CS_IMMEDIATE_XYZ")
        self.assertTrue(report.has_token)
        self.assertEqual(report.stage, "zte_material_done")
        cd.assert_called_once()

    def test_cag2_async_fallback_uses_tokenInfo(self):
        """Legacy async poll is opt-in via cag2_allow_async=True."""
        firm = _firm()
        probe = _cag2_probe()
        # L9504 shape: no connectStr yet, has tokenInfo + async interval
        payload = {
            "success": True,
            "result": "0",
            "connectInfo": {
                "success": True,
                "result": "0",
                "asyncQueryTimeInterval": 25,
                "vmId": "vm-1",
                "vmStatus": 0,
            },
            "tokenInfo": {
                "success": True,
                "accessToken": "tok-async-1",
                "result": "0",
            },
        }

        with mock.patch.object(zte_route, "probe_cag_edge", return_value=probe):
            with mock.patch.object(
                zte_route.ZTEClient, "connect_desktop", return_value=payload
            ):
                with mock.patch.object(
                    zte_route, "_async_query_connect_str", return_value="CS_ASYNC_OK"
                ) as aq:
                    report = zte_route.run_material(
                        firm, target_vm_id="vm-1", do_start=True,
                        async_retries=3, async_interval=0.01,
                        cag2_allow_async=True,
                    )

        self.assertTrue(report.ok)
        self.assertEqual(report.connect_str, "CS_ASYNC_OK")
        self.assertTrue(report.has_connect_str)
        self.assertEqual(report.zte_path, "CAG2.0-connectDesktop")
        # async must receive token from tokenInfo.accessToken
        self.assertTrue(aq.called)
        args, kwargs = aq.call_args
        self.assertEqual(args[1], "tok-async-1")

    def test_cag2_default_skips_async_404_poll(self):
        """Live CAG2: empty connectStr must NOT call async_query (404 noise)."""
        firm = _firm()
        probe = _cag2_probe()
        payload = {
            "success": True,
            "result": "0",
            "connectInfo": {
                "success": True,
                "result": "0",
                "asyncQueryTimeInterval": 25,
                "vmId": "vm-1",
                "vmStatus": 0,
            },
            "tokenInfo": {
                "success": True,
                "accessToken": "tok-async-1",
                "result": "0",
            },
        }
        with mock.patch.object(zte_route, "probe_cag_edge", return_value=probe):
            with mock.patch.object(
                zte_route.ZTEClient, "connect_desktop", return_value=payload
            ):
                with mock.patch.object(
                    zte_route, "_async_query_connect_str", return_value="CS_SHOULD_NOT"
                ) as aq:
                    report = zte_route.run_material(
                        firm, target_vm_id="vm-1", do_start=True,
                    )
        self.assertFalse(report.ok)
        self.assertFalse(report.has_connect_str)
        self.assertFalse(aq.called)
        self.assertIn("async skipped", report.error or "")
        self.assertEqual(report.zte_path, "CAG2.0-connectDesktop")

    def test_cag2_sticky_preferred_skips_probe(self):
        """preferred_edge_kind=CAG2.0 skips edge probe and still hits connectDesktop."""
        firm = _firm()
        payload = {
            "success": True,
            "connectInfo": {"connectStr": "CS_STICKY"},
            "tokenInfo": {"accessToken": "t"},
        }
        with mock.patch.object(
            zte_route, "probe_cag_edge", side_effect=AssertionError("probe must skip")
        ) as probe:
            with mock.patch.object(
                zte_route.ZTEClient, "connect_desktop", return_value=payload
            ):
                report = zte_route.run_material(
                    firm,
                    preferred_edge_kind="CAG2.0",
                    skip_edge_probe=True,
                )
        self.assertTrue(report.ok)
        self.assertEqual(report.connect_str, "CS_STICKY")
        self.assertEqual(report.edge_kind, "CAG2.0")
        self.assertEqual(report.zte_path, "CAG2.0-connectDesktop")
        self.assertTrue(report.redacted.get("edgeProbe", {}).get("sticky"))
        self.assertEqual(probe.call_count, 0)

    def test_cag2_no_token_no_connectStr_fails_clean(self):
        firm = _firm()
        probe = _cag2_probe()
        payload = {
            "success": True,
            "connectInfo": {"success": True, "result": "0", "vmStatus": 0},
            # no tokenInfo
        }
        with mock.patch.object(zte_route, "probe_cag_edge", return_value=probe):
            with mock.patch.object(
                zte_route.ZTEClient, "connect_desktop", return_value=payload
            ):
                # default: async skipped
                report = zte_route.run_material(firm, do_start=True)

        self.assertFalse(report.ok)
        self.assertFalse(report.has_connect_str)
        self.assertIn("async skipped", report.error or "")
        self.assertEqual(report.zte_path, "CAG2.0-connectDesktop")

        # opt-in async still surfaces tokenInfo absence
        with mock.patch.object(zte_route, "probe_cag_edge", return_value=probe):
            with mock.patch.object(
                zte_route.ZTEClient, "connect_desktop", return_value=payload
            ):
                report2 = zte_route.run_material(
                    firm, do_start=True, cag2_allow_async=True
                )
        self.assertFalse(report2.ok)
        self.assertIn("tokenInfo", report2.error or "")

    def test_cag2_no_longer_failfast_unsupported(self):
        """Regression: must NOT raise/return zte_cag2_unsupported."""
        firm = _firm()
        probe = _cag2_probe()
        payload = {
            "success": True,
            "connectInfo": {"connectStr": "CS_REGRESSION"},
            "tokenInfo": {"accessToken": "t"},
        }
        with mock.patch.object(zte_route, "probe_cag_edge", return_value=probe):
            with mock.patch.object(
                zte_route.ZTEClient, "connect_desktop", return_value=payload
            ):
                report = zte_route.run_material(firm)
        self.assertNotIn("unsupported", (report.error or "").lower())
        self.assertTrue(report.ok)
        self.assertEqual(report.zte_path, "CAG2.0-connectDesktop")

    def test_iag_path_still_uses_legacy_material(self):
        firm = _firm()
        probe = _iag_probe()

        class Tok:
            access_token = "iag-tok"

        with mock.patch.object(zte_route, "probe_cag_edge", return_value=probe):
            with mock.patch.object(zte_route.ZTEClient, "sys_config", return_value={}):
                with mock.patch.object(
                    zte_route.ZTEClient, "get_access_token", return_value=Tok()
                ):
                    with mock.patch.object(
                        zte_route.ZTEClient, "get_desktop_list",
                        return_value={"desktopList": [{"id": "vm-1", "vmId": "vm-1"}]},
                    ):
                        with mock.patch.object(
                            zte_route, "first_desktop",
                            return_value={"id": "vm-1", "vmId": "vm-1"},
                        ):
                            with mock.patch.object(
                                zte_route.ZTEClient, "start_desktop", return_value={}
                            ):
                                with mock.patch.object(
                                    zte_route, "_async_query_connect_str",
                                    return_value="CS_IAG",
                                ):
                                    report = zte_route.run_material(
                                        firm, target_vm_id="vm-1", do_start=True
                                    )

        self.assertEqual(report.edge_kind, "IAG")
        self.assertEqual(report.zte_path, "IAG-material")
        self.assertTrue(report.has_connect_str)
        self.assertEqual(report.connect_str, "CS_IAG")


class TestConnectDesktopWire(unittest.TestCase):
    def test_connect_desktop_posts_clear_json_path(self):
        firm = _firm()
        client = zte_route.ZTEClient(firm)
        captured = {}
        calls = []

        def fake_request(path, values, body, **kw):
            calls.append({"path": path, "values": values, "body": body, "kw": kw})
            if path == "/cs/cs_sysConfig.action":
                # CAG2 ensure_cag_rsa_pub: return toy RSA-2048 rsapub
                return {
                    "success": True,
                    "rsapub": TestConnectDesktopBody._TOY_RSAPUB,
                }
            captured["path"] = path
            captured["values"] = values
            captured["body"] = body
            captured["kw"] = kw
            return {
                "success": True,
                "connectInfo": {"connectStr": "CS_WIRE"},
                "tokenInfo": {"accessToken": "tw"},
            }

        with mock.patch.object(client, "_request", side_effect=fake_request):
            out = client.connect_desktop(vmid="vm-wire")

        # first call: CAG2 sysConfig for rsapub; second: connectDesktop
        self.assertEqual(calls[0]["path"], "/cs/cs_sysConfig.action")
        self.assertEqual(captured["path"], "/cs/cs_connectDesktop.action")
        # official CAG2 path: empty query values; version/requestFrom in JSON body
        self.assertEqual(captured["values"], [])
        # body is clear dict (not ZTE_Security envelope at this layer)
        self.assertIsInstance(captured["body"], dict)
        self.assertNotIn("ZTE_Security_Params", captured["body"])
        self.assertEqual(captured["body"]["version"], "V7.25.40-HY")
        self.assertEqual(captured["body"]["requestFrom"], 5)
        self.assertEqual(captured["body"]["encrypt"], 5)
        self.assertEqual(captured["body"]["vmid"], "vm-wire")
        # RSA-2048 password field length ≈684 (official pcap)
        self.assertGreaterEqual(len(captured["body"]["password"]), 680)
        self.assertLessEqual(len(captured["body"]["password"]), 688)
        self.assertEqual(out["connectInfo"]["connectStr"], "CS_WIRE")


if __name__ == "__main__":
    unittest.main()
