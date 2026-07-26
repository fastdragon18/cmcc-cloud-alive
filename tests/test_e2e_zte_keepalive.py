"""End-to-end integration tests for the ZTE raw-SPICE keepalive pipeline (P12).

Verifies the final acceptance criteria:
  * L12 — ``setup_zte_subchannels`` writes the raw DISPLAY_INIT to sub-channels
    5 & 7 and the raw INPUT_INIT to sub-channel 6.
  * L13 — ``keep_zte_subchannel_alive`` runs its read/auto-reply loop without
    interruption (time-compressed via mocked socket I/O).

All network I/O is mocked (``_FakeLink`` / ``_FakeMux`` mirroring the pattern in
``test_zte_raw_spice.py``); no real connection is ever opened.  The tests use the
stdlib ``unittest`` framework so they are collected by ``unittest discover``.
"""

import struct
import threading
import unittest
from unittest import mock

from cmcc_cloud_alive import zte_raw_spice, zte_route


# ---------------------------------------------------------------------------
# Mock socket / mux / params (same shape as test_zte_raw_spice.py)
# ---------------------------------------------------------------------------

class _FakeLink:
    """Minimal CAGMuxLink stand-in: recv/sendall/settimeout + sent buffer."""

    def __init__(self, link_id):
        self.link_id = link_id
        self.link_uuid = b"\x00" * 16
        self.trace_id = "trace"
        self.redq_span_id = "span"
        self.sent = bytearray()
        self._in = bytearray()

    def feed(self, data):
        self._in += data

    def recv(self, n):
        if not self._in:
            return b""  # EOF -> _read_exact raises -> loop breaks cleanly
        chunk = self._in[:n]
        del self._in[:n]
        return bytes(chunk)

    read = recv

    def _write(self, data):
        self.sent += data
        return len(data)

    send = sendall = write = _write

    def settimeout(self, seconds):
        pass


class _FakeMux:
    """Opens sub-links with sequential ids 2, 3, 4, ... (main link holds 1)."""

    def __init__(self):
        self._next = 2

    def open_link(self, params, trace_id="", span_id=""):
        link = _FakeLink(self._next)
        self._next += 1
        return link


class _FakeParams:
    key = b"\x00" * 32
    vm_id = 1


# Convenience helpers -------------------------------------------------------

def _ping_msg(serial=1):
    """A raw SPICE ping (msgType 0x04, empty payload) wrapped in a ZTE prefix."""
    return zte_raw_spice.rawMessageWithPrefix(serial, b"\x04\x00\x00\x00\x00\x00")


def _pong_msg(serial=1):
    """The pong (msgType 0x03) that AutoReply writes back for a ping."""
    return zte_raw_spice.rawMessageWithPrefix(serial, b"\x03\x00\x00\x00\x00\x00")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestE2EZteKeepalive(unittest.TestCase):
    """End-to-end ZTE keepalive integration tests (L12 + L13)."""

    # -- L12: setup_zte_subchannels ----------------------------------------

    def test_full_zte_keepalive_flow(self):
        """L12: full setup flow opens 7 sub-channels, auths all, and writes
        DISPLAY_INIT to links 5 & 7 and INPUT_INIT to link 6."""
        mux = _FakeMux()
        main_link = _FakeLink(1)
        params = _FakeParams()

        with mock.patch(
            "cmcc_cloud_alive.zte_route.RawSubChannelHandshake", return_value=True
        ):
            links, authed = zte_route.setup_zte_subchannels(
                mux, params, main_link, 0x1234
            )

        # seven sub-channels opened with ids 2..8, all authenticated
        self.assertEqual(set(links.keys()), {2, 3, 4, 5, 6, 7, 8})
        self.assertEqual(authed, {2, 3, 4, 5, 6, 7, 8})

        disp = zte_raw_spice.BuildZTERawDisplayInit()
        expected_disp = zte_raw_spice.rawMessageWithPrefix(1, disp)
        # DISPLAY_INIT written to link 5 and link 7
        self.assertEqual(bytes(links[5].sent), expected_disp)
        self.assertEqual(bytes(links[7].sent), expected_disp)

        inp = zte_raw_spice.BuildZTERawInputInit()
        expected_inp = zte_raw_spice.rawMessageWithPrefix(1, inp)
        # INPUT_INIT written to link 6
        self.assertEqual(bytes(links[6].sent), expected_inp)

        # the remaining sub-channels (2, 3, 4, 8) receive no init message
        for lid in (2, 3, 4, 8):
            self.assertEqual(bytes(links[lid].sent), b"")

    def test_display_init_exact_bytes(self):
        """L12: the bytes written to link 5 are exactly the raw DISPLAY_INIT
        payload produced by BuildZTERawDisplayInit, framed with serial 1."""
        mux = _FakeMux()
        main_link = _FakeLink(1)
        params = _FakeParams()

        with mock.patch(
            "cmcc_cloud_alive.zte_route.RawSubChannelHandshake", return_value=True
        ):
            links, _ = zte_route.setup_zte_subchannels(
                mux, params, main_link, 0x1234
            )

        disp = zte_raw_spice.BuildZTERawDisplayInit()
        # the builder must be non-empty (a real SPICE init message)
        self.assertGreater(len(disp), 0)
        # link 5 carries exactly the framed DISPLAY_INIT
        self.assertEqual(bytes(links[5].sent), zte_raw_spice.rawMessageWithPrefix(1, disp))
        # link 7 carries the identical DISPLAY_INIT
        self.assertEqual(bytes(links[7].sent), bytes(links[5].sent))
        # link 6 must NOT carry the DISPLAY_INIT (it carries INPUT_INIT instead)
        self.assertNotEqual(bytes(links[6].sent), bytes(links[5].sent))

    def test_subchannel_auth_failure(self):
        """L12: when a sub-channel fails to authenticate it is skipped
        gracefully — no init written, no exception, others still succeed."""
        mux = _FakeMux()
        main_link = _FakeLink(1)
        params = _FakeParams()

        # link 6 (INPUT_INIT channel) fails auth; every other link succeeds
        def fake_handshake(link, *args, **kwargs):
            return link.link_id != 6

        with mock.patch(
            "cmcc_cloud_alive.zte_route.RawSubChannelHandshake",
            side_effect=fake_handshake,
        ):
            links, authed = zte_route.setup_zte_subchannels(
                mux, params, main_link, 0x1234
            )

        # link 6 is not authenticated and received no init message
        self.assertNotIn(6, authed)
        self.assertEqual(bytes(links[6].sent), b"")
        # the other six links authenticated normally
        self.assertEqual(authed, {2, 3, 4, 5, 7, 8})
        # DISPLAY_INIT still written to links 5 & 7
        disp = zte_raw_spice.BuildZTERawDisplayInit()
        expected_disp = zte_raw_spice.rawMessageWithPrefix(1, disp)
        self.assertEqual(bytes(links[5].sent), expected_disp)
        self.assertEqual(bytes(links[7].sent), expected_disp)

    # -- L13: keep_zte_subchannel_alive ------------------------------------

    def test_keepalive_loop_runs(self):
        """L13: the keepalive loop processes multiple ping cycles without
        interruption (time-compressed: 5 pings fed, loop exits cleanly on EOF
        and returns the link id)."""
        link = _FakeLink(6)
        # feed 5 ping messages — simulates several keepalive cycles
        for _ in range(5):
            link.feed(_ping_msg(1))

        lid = zte_route.keep_zte_subchannel_alive(link, link_id=6, read_timeout=0.5)

        # loop terminated cleanly (no uncaught exception) and returned the id
        self.assertEqual(lid, 6)
        # exactly 5 pongs were written back — the loop ran 5 cycles uninterrupted
        self.assertEqual(bytes(link.sent), _pong_msg(1) * 5)

    def test_keepalive_ping_autoreply(self):
        """L13: a single ping (msgType 0x04) is auto-replied with a pong
        (msgType 0x03) carrying the matching serial."""
        link = _FakeLink(6)
        link.feed(_ping_msg(1))

        lid = zte_route.keep_zte_subchannel_alive(link, link_id=6, read_timeout=0.5)

        self.assertEqual(lid, 6)
        sent = bytes(link.sent)
        # the pong frame: [serial u32le=1][4 zero][type 0x03 u16le][size 0 u32le]
        self.assertEqual(sent, _pong_msg(1))
        # type field at offset 8 is 0x0003 (little-endian)
        self.assertEqual(sent[8:10], struct.pack("<H", 0x03))
        # serial echoed back at offset 0
        self.assertEqual(sent[0:4], struct.pack("<I", 1))

    def test_keepalive_stop_event(self):
        """L13: a pre-set stop_event terminates the loop immediately without
        reading or writing anything."""
        link = _FakeLink(6)
        stop = threading.Event()
        stop.set()

        lid = zte_route.keep_zte_subchannel_alive(
            link, link_id=6, read_timeout=0.5, stop_event=stop
        )

        self.assertEqual(lid, 6)
        self.assertEqual(bytes(link.sent), b"")


if __name__ == "__main__":
    unittest.main()
