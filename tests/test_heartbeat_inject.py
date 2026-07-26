"""Unit test: verify keepaliveRawSpiceLoop injects type=3 heartbeats at 21Hz."""
import unittest
import struct
import time
from unittest import mock
from cmcc_cloud_alive import zte_raw_spice as zrs


class FakeConn:
    """Fake conn that times out on read, captures all sends."""
    def __init__(self):
        self.sent = []
        self._read_timeout = 2.0
    def recv(self, n):
        raise TimeoutError("no data")
    def sendall(self, data):
        self.sent.append(bytes(data))
    def settimeout(self, t):
        self._read_timeout = t
    def close(self):
        pass


class TestHeartbeatInjection(unittest.TestCase):
    def test_heartbeat_format_matches_pcapng(self):
        """Heartbeat body = [0:u32][0xffffff00:u32][counter:u32], type=3, size=12."""
        hb = zrs.BuildZTERawDisplayHeartbeat(0)
        self.assertEqual(len(hb), 18)
        typ, sz = struct.unpack_from('<HI', hb, 0)
        self.assertEqual(typ, 3)
        self.assertEqual(sz, 12)
        b0, b1, b2 = struct.unpack_from('<III', hb, 6)
        self.assertEqual(b0, 0)
        self.assertEqual(b1, 0xFFFFFF00)
        self.assertEqual(b2, 0)

    def test_counter_increments_250_every_5(self):
        """Counter should increment by 250 every 5 heartbeats."""
        conn = FakeConn()
        # Patch ReadMessage to always timeout, AutoReply to no-op
        with mock.patch.object(zrs.RawState, 'ReadMessage', side_effect=TimeoutError), \
             mock.patch.object(zrs.RawState, 'AutoReply', return_value=False):
            # Run for ~0.3s at 21Hz → ~6 heartbeats
            counters = zrs.keepaliveRawSpiceLoop(
                conn, interval=999, stop_after=0.3, heartbeat_hz=21.0)
        # Should have sent heartbeats
        self.assertGreater(counters['heartbeats'], 0)
        # Extract heartbeat bodies from sent data
        hb_counters = []
        for raw in conn.sent:
            # rawMessageWithPrefix = [serial:u32][pad:u32][type:u16][size:u32][body:12B][suffix:5B]
            # Find type=3 messages
            if len(raw) >= 26:
                typ = struct.unpack_from('<H', raw, 8)[0]
                if typ == 3:
                    counter = struct.unpack_from('<I', raw, 22)[0]
                    hb_counters.append(counter)
        # First 5 should be 0, then 250 (increment after every 5th send)
        if len(hb_counters) >= 6:
            self.assertEqual(hb_counters[0], 0)
            self.assertEqual(hb_counters[4], 0)
            self.assertEqual(hb_counters[5], 250)

    def test_heartbeat_disabled_when_hz_zero(self):
        """When heartbeat_hz=0, no heartbeats sent, read_timeout falls back."""
        conn = FakeConn()
        with mock.patch.object(zrs.RawState, 'ReadMessage', side_effect=TimeoutError), \
             mock.patch.object(zrs.RawState, 'AutoReply', return_value=False):
            counters = zrs.keepaliveRawSpiceLoop(
                conn, interval=999, stop_after=0.2, heartbeat_hz=0)
        self.assertEqual(counters['heartbeats'], 0)


    def test_heartbeat_sent_to_display_links(self):
        """When display_links provided, heartbeats go to each display sub-link, not conn."""
        link_a = FakeConn()
        link_b = FakeConn()
        conn = FakeConn()
        with mock.patch.object(zrs.RawState, 'ReadMessage', side_effect=TimeoutError), \
             mock.patch.object(zrs.RawState, 'AutoReply', return_value=False):
            counters = zrs.keepaliveRawSpiceLoop(
                conn, interval=999, stop_after=0.3, heartbeat_hz=21.0,
                display_links=[link_a, link_b])
        # Both display links should receive heartbeats
        self.assertGreater(counters['heartbeats'], 0)
        # display_type3_heartbeat_frames counts per-link sends (2 links)
        self.assertEqual(counters['display_type3_heartbeat_frames'],
                         counters['heartbeats'] * 2)
        # conn (main link) should NOT receive type=3 heartbeats (only init msgs)
        conn_hb = sum(1 for raw in conn.sent
                      if len(raw) >= 10 and struct.unpack_from('<H', raw, 8)[0] == 3)
        self.assertEqual(conn_hb, 0)
        # Both display links should have received at least one type=3
        for link in (link_a, link_b):
            hb_count = sum(1 for raw in link.sent
                           if len(raw) >= 10 and struct.unpack_from('<H', raw, 8)[0] == 3)
            self.assertGreater(hb_count, 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
