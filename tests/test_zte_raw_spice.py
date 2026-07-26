"""Unit tests for cmcc_cloud_alive.zte_raw_spice (P10 raw SPICE port).

Covers the byte layout of the REDQ/init builders, the RawSubChannelHandshake
auth flow (success / no-marker / non-zero result), and the keepalive loop
counters.  All socket I/O is mocked — no real network.
"""

import os
import socket
import struct
import sys
import threading

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from cmcc_cloud_alive.zte_raw_spice import (  # noqa: E402
    BuildZTERawChannelREDQ,
    BuildZTERawDisplayInit,
    BuildZTERawInputInit,
    RawState,
    RawSubChannelHandshake,
    keepaliveRawSpiceLoop,
    rawMessageWithPrefix,
)


# ---------------------------------------------------------------------------
# Mock socket
# ---------------------------------------------------------------------------
class MockConn:
    """A minimal socket double: feeds a fixed recv buffer, records sends."""

    def __init__(self, recv_data: bytes = b""):
        self._rbuf = bytearray(recv_data)
        self.sent = bytearray()
        self._closed = False

    # recv semantics: raise socket.timeout when the buffer is drained so the
    # keepalive loop's idle path is exercised.
    def recv(self, n: int) -> bytes:
        if not self._rbuf:
            raise socket.timeout("mock recv drained")
        chunk = bytes(self._rbuf[:n])
        del self._rbuf[:n]
        return chunk

    def send(self, data: bytes) -> int:
        self.sent.extend(data)
        return len(data)

    def sendall(self, data: bytes) -> None:
        self.sent.extend(data)

    def settimeout(self, _t):
        pass

    def close(self):
        self._closed = True


def _u32le(v: int) -> bytes:
    return struct.pack("<I", v)


def _u16le(v: int) -> bytes:
    return struct.pack("<H", v)


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------
class TestBuildZTERawChannelREDQ:
    def _common(self, redq, length, size, conn_id, ctype, cid, link_uuid):
        assert len(redq) == length
        assert redq[0:4] == b"REDQ"
        assert struct.unpack_from("<I", redq, 4)[0] == 2
        assert struct.unpack_from("<I", redq, 8)[0] == 2
        assert struct.unpack_from("<I", redq, 12)[0] == size
        assert struct.unpack_from("<I", redq, 16)[0] == conn_id
        assert redq[20] == ctype & 0xFF
        assert redq[21] == cid & 0xFF
        assert struct.unpack_from("<I", redq, 22)[0] == 1
        assert struct.unpack_from("<I", redq, 30)[0] == 705
        assert struct.unpack_from("<I", redq, 42)[0] == 0x1400
        assert struct.unpack_from("<I", redq, 46)[0] == 0x10000
        # linkUUID echoed at [95:111]
        assert redq[95:111] == link_uuid[:16]

    def test_default_channel_type4(self):
        lu = os.urandom(16)
        redq = BuildZTERawChannelREDQ("k", "v", lu, "tid", "sid", 0x1234, 4, 1)
        self._common(redq, 725, 709, 0x1234, 4, 1, lu)
        # single cap 0x800 at tail
        assert struct.unpack_from("<I", redq, 721)[0] == 0x800
        assert struct.unpack_from("<I", redq, 26)[0] == 0  # cap_count

    def test_channel_type2(self):
        lu = os.urandom(16)
        redq = BuildZTERawChannelREDQ("k", "v", lu, "tid", "sid", 7, 2, 0)
        self._common(redq, 733, 717, 7, 2, 0, lu)
        assert struct.unpack_from("<I", redq, 26)[0] == 2  # cap_count
        caps = [struct.unpack_from("<I", redq, 721 + i * 4)[0] for i in range(3)]
        assert caps == [0xA00, 0xFFC30DEC, 0x48]

    def test_channel_type5(self):
        lu = os.urandom(16)
        redq = BuildZTERawChannelREDQ("k", "v", lu, "tid", "sid", 1, 5, 0)
        self._common(redq, 729, 713, 1, 5, 0, lu)
        assert struct.unpack_from("<I", redq, 26)[0] == 1
        caps = [struct.unpack_from("<I", redq, 721 + i * 4)[0] for i in range(2)]
        assert caps == [0x800, 0x0E]

    def test_channel_type6(self):
        lu = os.urandom(16)
        redq = BuildZTERawChannelREDQ("k", "v", lu, "tid", "sid", 9, 6, 0)
        self._common(redq, 729, 713, 9, 6, 0, lu)
        assert struct.unpack_from("<I", redq, 26)[0] == 1
        caps = [struct.unpack_from("<I", redq, 721 + i * 4)[0] for i in range(2)]
        assert caps == [0x800, 0x07]

    def test_random_link_uuid_when_missing(self):
        redq = BuildZTERawChannelREDQ("k", "v", None, "tid", "sid", 1, 4, 0)
        assert redq[95:111] != b"\x00" * 16  # auto-filled random uuid

    def test_key_vmid_embedded(self):
        redq = BuildZTERawChannelREDQ("KEY", "VMID", os.urandom(16), "tid", "sid", 1, 4, 0)
        # copy_c_string writes a NUL-terminated C string into [50:95]
        blob = bytes(redq[50:95])
        assert blob.startswith(b"KEYVMID\x00")


class TestInitBuilders:
    def test_display_init_exact(self):
        assert BuildZTERawDisplayInit() == bytes.fromhex(
            "65001300000000000000000100004001000000000100fc5f000000000003"
        )

    def test_input_init_exact(self):
        assert BuildZTERawInputInit() == bytes.fromhex("67000200000000000000000200")

    def test_raw_message_prefix(self):
        msg = b"\xab\xcd"
        out = rawMessageWithPrefix(7, msg)
        assert len(out) == 8 + len(msg)
        assert struct.unpack_from("<I", out, 0)[0] == 7
        assert out[4:8] == b"\x00\x00\x00\x00"
        assert out[8:] == msg


# ---------------------------------------------------------------------------
# RawSubChannelHandshake
# ---------------------------------------------------------------------------
RSA_MARKER = b"\x30\x81\x9F\x30\x0D"


def _redq_reply(body: bytes) -> bytes:
    """Build a valid REDQ reply frame: 16-byte head + body."""
    head = b"REDQ" + _u32le(2) + _u32le(2) + _u32le(len(body))
    return head + body


class TestRawSubChannelHandshake:
    def test_success(self):
        body = b"\x00" * 27 + RSA_MARKER  # 32 bytes, marker present
        conn = MockConn(_redq_reply(body) + b"\x00\x00\x00\x00")
        ok = RawSubChannelHandshake(conn, "k", "v", os.urandom(16), "tid", "sid", 1, 4, 0)
        assert ok is True
        # REDQ (725 bytes) + 128-byte zero ticket were sent
        assert conn.sent[:4] == b"REDQ"
        assert len(conn.sent) == 725 + 128
        assert conn.sent[725:] == b"\x00" * 128

    def test_no_marker_returns_false(self):
        body = b"\x00" * 32  # no RSA marker
        conn = MockConn(_redq_reply(body))
        ok = RawSubChannelHandshake(conn, "k", "v", os.urandom(16), "tid", "sid", 1, 4, 0)
        assert ok is False
        # only the REDQ was sent; no ticket
        assert conn.sent[:4] == b"REDQ"
        assert len(conn.sent) == 725

    def test_nonzero_result_returns_false(self):
        body = b"\x00" * 27 + RSA_MARKER
        conn = MockConn(_redq_reply(body) + _u32le(1))  # result == 1
        ok = RawSubChannelHandshake(conn, "k", "v", os.urandom(16), "tid", "sid", 1, 4, 0)
        assert ok is False
        # REDQ + ticket sent, but result non-zero
        assert len(conn.sent) == 725 + 128

    def test_invalid_magic_returns_false(self):
        # reply head without REDQ magic -> readRawLinkReply raises -> False
        bad = b"XXXX" + _u32le(2) + _u32le(2) + _u32le(0)
        conn = MockConn(bad)
        ok = RawSubChannelHandshake(conn, "k", "v", os.urandom(16), "tid", "sid", 1, 4, 0)
        assert ok is False


# ---------------------------------------------------------------------------
# keepaliveRawSpiceLoop
# ---------------------------------------------------------------------------
class TestKeepaliveRawSpiceLoop:
    def test_ping_autoreply_and_tick(self):
        # one SPICE ping: type=0x04, size=4, payload=4 bytes
        ping = _u16le(0x04) + _u32le(4) + b"\x00\x00\x00\x00"
        conn = MockConn(ping)
        counters = keepaliveRawSpiceLoop(conn, interval=0.05, stop_after=0.35)
        assert counters["messages"] == 1
        assert counters["autoReplies"] == 1
        assert counters["ticks"] >= 1
        assert counters["errors"] == 0
        # an auto-reply pong (type 0x03) was written after the 8-byte prefix
        assert conn.sent[8:10] == _u16le(0x03)

    def test_error_breaks_loop(self):
        # header with absurd size -> ReadMessage raises ValueError
        bad = _u16le(0x01) + _u32le(0x200000)
        conn = MockConn(bad)
        counters = keepaliveRawSpiceLoop(conn, interval=0.05, stop_after=0.35)
        assert counters["errors"] == 1
        assert counters["messages"] == 0

    def test_idle_no_errors(self):
        # empty buffer: every ReadMessage times out, ticks still fire
        conn = MockConn(b"")
        counters = keepaliveRawSpiceLoop(conn, interval=0.05, stop_after=0.2)
        assert counters["errors"] == 0
        assert counters["messages"] == 0
        assert counters["ticks"] >= 1


# ---------------------------------------------------------------------------
# RawState AutoReply
# ---------------------------------------------------------------------------
class TestRawStateAutoReply:
    def test_ping_pong(self):
        state = RawState()
        conn = MockConn(b"")
        replied = state.AutoReply(conn, 0x04, b"\x01\x02")
        assert replied is True
        # pong: 8-byte prefix (serial + zeros) + type 0x03 + size 2 + payload
        assert conn.sent[8:10] == _u16le(0x03)
        assert struct.unpack_from("<I", conn.sent, 10)[0] == 2
        assert conn.sent[14:16] == b"\x01\x02"

    def test_no_reply_for_unknown(self):
        state = RawState()
        conn = MockConn(b"")
        assert state.AutoReply(conn, 0x99, b"") is False
        assert len(conn.sent) == 0

    def test_next_serial_sequence(self):
        state = RawState()
        assert state.nextSerial() == 4
        assert state.nextSerial() == 5
        assert state.nextSerial() == 6


# ---------------------------------------------------------------------------
# Integration: setup_zte_subchannels / keep_zte_subchannel_alive
# (orchestration only — RawSubChannelHandshake is stubbed)
# ---------------------------------------------------------------------------
import cmcc_cloud_alive.zte_route as _route  # noqa: E402


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
            return b""  # EOF -> _read_exact raises EOFError
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
    def __init__(self):
        self._next = 2  # main link holds id 1

    def open_link(self, params, trace_id="", span_id=""):
        link = _FakeLink(self._next)
        self._next += 1
        return link


class _FakeParams:
    key = "deadbeef"
    vm_id = "vm-1"


class TestSetupZTESubchannels:
    def test_opens_seven_links_and_auths_all(self, monkeypatch):
        calls = []

        def fake_handshake(conn, key, vmid, link_uuid, trace_id,
                           span_id, spice_sid, chan_type, chan_id):
            calls.append((conn.link_id, chan_type, chan_id))
            return True

        monkeypatch.setattr(_route, "RawSubChannelHandshake", fake_handshake)
        mux = _FakeMux()
        main_link = _FakeLink(1)
        links, authed = _route.setup_zte_subchannels(
            mux, _FakeParams(), main_link, 0x1234)
        # 7 sub-links opened with ids 2..8
        assert sorted(links) == [2, 3, 4, 5, 6, 7, 8]
        assert authed == {2, 3, 4, 5, 6, 7, 8}
        # REDQ table driven: each (link_id, channel_type, channel_id) visited once
        assert sorted(calls) == sorted(_route._ZTE_SUBCHANNEL_REDQS)
        # init message written only for links 5, 6, 7 (DisplayInit/InputInit)
        inited = {lid for lid, lk in links.items() if len(lk.sent) > 0}
        assert inited == set(_route._ZTE_SUBCHANNEL_INIT)

    def test_unauthed_link_gets_no_init(self, monkeypatch):
        # link 6 fails auth -> no init, excluded from authed set
        def fake_handshake(conn, *a, **kw):
            return conn.link_id != 6

        monkeypatch.setattr(_route, "RawSubChannelHandshake", fake_handshake)
        mux = _FakeMux()
        links, authed = _route.setup_zte_subchannels(
            mux, _FakeParams(), _FakeLink(1), 0x1234)
        assert 6 not in authed
        assert len(links[6].sent) == 0
        # link 5 & 7 still authed -> init written
        assert len(links[5].sent) > 0
        assert len(links[7].sent) > 0


class TestKeepZTESubchannelAlive:
    def test_replies_ping_then_stops_on_eof(self):
        from cmcc_cloud_alive.zte_raw_spice import rawMessageWithPrefix
        link = _FakeLink(6)
        # one ping (type 0x04, empty payload) then EOF
        link.feed(rawMessageWithPrefix(1, b"\x04\x00\x00\x00\x00\x00"))
        lid = _route.keep_zte_subchannel_alive(link, link_id=6, read_timeout=0.5)
        assert lid == 6
        # a pong (type 0x03, little-endian) must have been written back
        assert link.sent[8:10] == b"\x03\x00"


if __name__ == "__main__":
    import pytest

    sys.exit(pytest.main([__file__, "-v"]))
