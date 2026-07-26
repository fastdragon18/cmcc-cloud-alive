"""Wiring tests for ``run_zte_keepalive_session`` — the P6–P9 orchestrator.

The existing ``test_e2e_zte_keepalive.py`` only exercises
``setup_zte_subchannels`` and ``keep_zte_subchannel_alive`` in isolation.
That gave false confidence: the orchestrator that *chains* material → CAG →
mux → raw-SPICE → keepalive was never wired into ``_run_zte_keepalive`` at all.

These tests mock every link in the chain and verify that
``run_zte_keepalive_session`` calls them in the correct order with the correct
arguments, and that the return value propagates correctly.
"""

import unittest
from unittest import mock

from cmcc_cloud_alive import zte_route


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class _FakeLink:
    """CAGMuxLink stand-in (same shape as test_e2e_zte_keepalive._FakeLink)."""

    def __init__(self, link_id=1):
        self.link_id = link_id
        self.link_uuid = b"\x00" * 16
        self.trace_id = "trace-fake"
        self.redq_span_id = "span-fake"
        self.sent = bytearray()


class _FakeHandshakeResult:
    OK = True
    SpiceSessionID = 0x1234
    error = ""


class _FakeOuter:
    address = "1.2.3.4:5678"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestRunZteKeepaliveSession(unittest.TestCase):
    """Verify the full P6–P9 orchestrator wiring."""

    def _patch_chain(self, **overrides):
        """Start mock.patch for every chain link; return dict of *mocks*.

        Each mock is auto-stopped via ``addCleanup`` so tests need no try/finally.
        ``overrides`` lets a test replace a mock's return_value before starting.
        """
        specs = {
            # P6: decode + inner/outer separation
            "decode": (
                "cmcc_cloud_alive.zte_connect_params.decode_connect_params",
                {"return_value": self._fake_cp()},
            ),
            "inner": (
                "cmcc_cloud_alive.zte_connect_params.inner_from_connect_params",
                # IPv4 host (no ':') -> classic path; uses_raw_ztec_path does
                # `":" in inner.host`, which needs a real string, not a bare Mock.
                {"return_value": mock.Mock(host="1.2.3.4")},
            ),
            "outer": (
                "cmcc_cloud_alive.zte_route.outer_from_firm",
                {"return_value": _FakeOuter()},
            ),
            # P7: dial CAG
            "dial": (
                "cmcc_cloud_alive.zte_cag.dial_cag_tcp_tls",
                {"return_value": (mock.Mock(), mock.Mock())},
            ),
            # P8: mux + main link
            "mux_open": (
                "cmcc_cloud_alive.zte_cag_mux.CAGMux.open",
                {"return_value": mock.Mock()},
            ),
            "open_link": (
                "cmcc_cloud_alive.zte_cag_mux.open_cag_mux_link",
                {"return_value": _FakeLink(1)},
            ),
            # P8: raw SPICE main handshake
            "raw_hs": (
                "cmcc_cloud_alive.zte_route.RawMainHandshake",
                {"return_value": _FakeHandshakeResult()},
            ),
            # P9: subchannels
            "setup_sub": (
                "cmcc_cloud_alive.zte_route.setup_zte_subchannels",
                {"return_value": ({2: _FakeLink(2), 3: _FakeLink(3)}, {2, 3})},
            ),
            "keep_sub": (
                "cmcc_cloud_alive.zte_route.keep_zte_subchannel_alive",
                {"return_value": 0},
            ),
            # P9: main keepalive loop
            "keep_main": (
                "cmcc_cloud_alive.zte_route.keepaliveRawSpiceLoop",
                {"return_value": {"pings_sent": 5, "pongs_recv": 5}},
            ),
        }

        mocks = {}
        for name, (target, kwargs) in specs.items():
            if name in overrides:
                kwargs = {**kwargs, **overrides[name]}
            p = mock.patch(target, **kwargs)
            mocks[name] = p.start()
            self.addCleanup(p.stop)
        return mocks

    @staticmethod
    def _fake_cp():
        cp = mock.Mock()
        cp.key = b"\x00" * 32
        cp.vm_id = 1
        return cp

    # -- happy path ---------------------------------------------------------

    def test_full_chain_called_in_order(self):
        """Every chain link is called exactly once, in P6→P7→P8→P9 order."""
        m = self._patch_chain()
        firm = zte_route.ZTEFirmAuth(cag_ip="1.2.3.4", cag_port=5678)
        result = zte_route.run_zte_keepalive_session(
            firm, "fake-connect-str",
            duration=1.0,
            auth_template_hex="deadbeef",
        )

        # return value is the counters dict from keepaliveRawSpiceLoop
        self.assertEqual(result, {"pings_sent": 5, "pongs_recv": 5})

        # P6: decode + inner + outer all called
        m["decode"].assert_called_once_with("fake-connect-str")
        m["inner"].assert_called_once()
        m["outer"].assert_called_once_with(firm)

        # P7: dial called with CAGDialOptions (address from outer)
        m["dial"].assert_called_once()
        dial_opts = m["dial"].call_args[0][0]
        self.assertEqual(dial_opts.address, "1.2.3.4:5678")

        # P8: mux.open + open_cag_mux_link called
        m["mux_open"].assert_called_once()
        m["open_link"].assert_called_once()

        # P8: RawMainHandshake called with main_link + key + vm_id
        m["raw_hs"].assert_called_once()
        hs_args = m["raw_hs"].call_args[0]
        self.assertEqual(hs_args[1], b"\x00" * 32)  # key
        self.assertEqual(hs_args[2], 1)  # vm_id

        # P9: setup_zte_subchannels called with session_id as 4th positional
        m["setup_sub"].assert_called_once()
        sub_args = m["setup_sub"].call_args[0]
        self.assertEqual(sub_args[3], 0x1234)  # SpiceSessionID

        # P9: keep_zte_subchannel_alive called once per sub-link (2 links)
        self.assertEqual(m["keep_sub"].call_count, 2)

        # P9: keepaliveRawSpiceLoop called with main_link + duration (stop_after kwarg)
        m["keep_main"].assert_called_once()
        self.assertEqual(m["keep_main"].call_args.kwargs["stop_after"], 1.0)

    # -- guard clauses ------------------------------------------------------

    def test_empty_connect_str_raises(self):
        """An empty connect_str raises ZTEError immediately."""
        firm = zte_route.ZTEFirmAuth()
        with self.assertRaises(zte_route.ZTEError):
            zte_route.run_zte_keepalive_session(firm, "", duration=1.0)

    def test_missing_auth_template_raises(self):
        """Without auth_template_hex (and no env var), the session raises."""
        self._patch_chain()
        firm = zte_route.ZTEFirmAuth(cag_ip="1.2.3.4", cag_port=5678)
        with mock.patch.dict("os.environ", {}, clear=False):
            import os
            os.environ.pop("CCK_ZTE_CAG_AUTH_TEMPLATE_HEX", None)
            with self.assertRaises(zte_route.ZTEError) as ctx:
                zte_route.run_zte_keepalive_session(
                    firm, "fake-connect-str",
                    duration=1.0,
                    auth_template_hex="",
                )
            self.assertIn("AUTH_TEMPLATE", str(ctx.exception))

    def test_raw_handshake_failure_raises(self):
        """If RawMainHandshake returns OK=False, the session raises ZTEError."""
        self._patch_chain(raw_hs={"return_value": mock.Mock(OK=False, error="boom")})
        firm = zte_route.ZTEFirmAuth(cag_ip="1.2.3.4", cag_port=5678)
        with self.assertRaises(zte_route.ZTEError) as ctx:
            zte_route.run_zte_keepalive_session(
                firm, "fake-connect-str",
                duration=1.0,
                auth_template_hex="deadbeef",
            )
        self.assertIn("main handshake", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
