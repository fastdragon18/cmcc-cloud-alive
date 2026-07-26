#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Offline smoke tests for the MQTT keepalive module (T3-MQTT, C-line).

These tests exercise the MQTT 3.1.1 codec, broker-URL parsing, config
redaction, and the ``smoke()`` lifecycle against an in-memory fake socket —
no network and no real credentials are touched. A live smoke run is gated
behind an explicit environment variable and is NOT executed by default.
"""

import io
import contextlib
import json
import os
import socket
import ssl
import unittest
from unittest import mock

from cmcc_cloud_alive import mqtt_keepalive


# ---------------------------------------------------------------------------
# MQTT 3.1.1 codec tests.
# ---------------------------------------------------------------------------

class MqttCodecTests(unittest.TestCase):
    def test_remaining_length_roundtrip(self):
        for value in (0, 1, 127, 128, 16383, 16384, 2097151):
            encoded = mqtt_keepalive._encode_remaining_length(value)
            fake = _FakeSock([encoded])
            self.assertEqual(mqtt_keepalive._decode_remaining_length(fake), value)

    def test_connect_packet_has_username_password_flags(self):
        pkt = mqtt_keepalive.build_connect_packet(
            client_id="cid", username="user", password="jwt", keep_alive=60
        )
        self.assertEqual(pkt[0] >> 4, 0x01)  # CONNECT packet type
        # Connect flags byte is the 10th byte of the variable header start:
        # fixed header (1 + remaining-length) then "MQTT"(2+4) + level(1) + flags(1).
        flags_byte = pkt[1 + 1 + 2 + 4 + 1]
        self.assertTrue(flags_byte & 0x80)  # username flag
        self.assertTrue(flags_byte & 0x40)  # password flag
        self.assertTrue(flags_byte & 0x02)  # clean session

    def test_subscribe_packet_includes_topics(self):
        pkt = mqtt_keepalive.build_subscribe_packet(1, ["a/b", "c/d"])
        self.assertEqual(pkt[0] >> 4, 0x08)  # SUBSCRIBE
        self.assertIn(b"a/b", pkt)
        self.assertIn(b"c/d", pkt)

    def test_pingreq_and_disconnect_are_two_bytes(self):
        self.assertEqual(mqtt_keepalive.build_pingreq_packet(), bytes([0xC0, 0x00]))
        self.assertEqual(mqtt_keepalive.build_disconnect_packet(), bytes([0xE0, 0x00]))


# ---------------------------------------------------------------------------
# Config / redaction / URL parsing tests.
# ---------------------------------------------------------------------------

class ConfigRedactionTests(unittest.TestCase):
    def test_redact_config_omits_raw_secrets(self):
        data = {
            "url": "ssl://alive.soho.komect.com",
            "clientId": "super-secret-client-id",
            "userName": "18747184",
            "jwt": "very-long-jwt-string",
            "subTopics": ["sc/s-notify/x", "sc/s-client/y"],
            "jwtExp": 1783484897,
            "mqttKeepAlive": 30,
        }
        redacted = mqtt_keepalive.redact_config(data)
        dumped = json.dumps(redacted)
        # No raw secret may appear in the redacted form.
        self.assertNotIn("super-secret-client-id", dumped)
        self.assertNotIn("very-long-jwt-string", dumped)
        self.assertNotIn("18747184", dumped)
        # Fingerprints + lengths are present instead.
        self.assertIn("clientIdFingerprint", redacted)
        self.assertEqual(redacted["clientIdLength"], len("super-secret-client-id"))
        self.assertEqual(redacted["subTopics"], ["sc/s-notify/x", "sc/s-client/y"])
        self.assertEqual(redacted["url"], "ssl://alive.soho.komect.com")
        self.assertIn("jwtExp", redacted["extraKeys"])

    def test_parse_broker_url_ssl_default_port(self):
        scheme, host, port = mqtt_keepalive.parse_broker_url("ssl://alive.soho.komect.com")
        self.assertEqual((scheme, host, port), ("ssl", "alive.soho.komect.com", 8883))

    def test_parse_broker_url_explicit_port(self):
        scheme, host, port = mqtt_keepalive.parse_broker_url("tcp://broker.example.com:1883")
        self.assertEqual((scheme, host, port), ("tcp", "broker.example.com", 1883))

    def test_parse_broker_url_rejects_bad_scheme(self):
        with self.assertRaises(mqtt_keepalive.MqttKeepaliveError):
            mqtt_keepalive.parse_broker_url("not-a-url")


# ---------------------------------------------------------------------------
# smoke() lifecycle against a fake socket (no network).
# ---------------------------------------------------------------------------

class SmokeLifecycleTests(unittest.TestCase):
    SAMPLE_CONFIG = {
        "url": "ssl://alive.soho.komect.com",
        "clientId": "cid-secret",
        "userName": "user-secret",
        "jwt": "jwt-secret",
        "subTopics": ["sc/s-notify/a"],
    }

    def _fake_config_fetch(self):
        return mock.patch(
            "cmcc_cloud_alive.mqtt_keepalive.fetch_mqtt_config",
            return_value=dict(self.SAMPLE_CONFIG),
        )

    def _fake_tls_socket(self, server_replies):
        """Patch socket/ssl so smoke() talks to an in-memory fake socket.

        Only the two callables actually used (``socket.create_connection`` and
        ``ssl.create_default_context``) are patched, so the module's
        ``except socket.timeout`` still refers to the *real* exception type
        that ``_FakeSock.recv`` raises.
        """
        fake = _FakeSock(server_replies)
        ctx = mock.MagicMock(
            wrap_socket=mock.Mock(return_value=fake),
            check_hostname=False,
            verify_mode=ssl.CERT_NONE,
        )
        stack = contextlib.ExitStack()
        stack.enter_context(
            mock.patch("cmcc_cloud_alive.mqtt_keepalive.socket.create_connection", mock.Mock(return_value=fake))
        )
        stack.enter_context(
            mock.patch("cmcc_cloud_alive.mqtt_keepalive.ssl.create_default_context", mock.Mock(return_value=ctx))
        )
        return stack

    def test_smoke_rejects_overlong_duration(self):
        with self._fake_config_fetch():
            with self.assertRaises(mqtt_keepalive.MqttKeepaliveError):
                mqtt_keepalive.smoke(duration_seconds=121)

    def test_smoke_full_lifecycle_accepted_and_proven(self):
        # CONNACK(rc=0), SUBACK, PINGRESP, PINGRESP
        connack = bytes([0x20, 0x02, 0x00, 0x00])
        suback = bytes([0x90, 0x03, 0x00, 0x01, 0x00])
        pingresp = bytes([0xD0, 0x00])
        replies = [connack, suback, pingresp, pingresp]
        with self._fake_config_fetch(), self._fake_tls_socket(replies):
            report = mqtt_keepalive.smoke(duration_seconds=1)
        self.assertTrue(report["accepted"])
        self.assertTrue(report["mqttKeepaliveProven"])
        self.assertEqual(report["connect"]["connack"], 0)
        self.assertEqual(report["subscribe"]["packetType"], 0x09)
        self.assertGreater(report["pings"], 0)
        self.assertGreater(report["pingResps"], 0)
        # No raw secrets leak into the report.
        dumped = json.dumps(report)
        self.assertNotIn("jwt-secret", dumped)
        self.assertNotIn("cid-secret", dumped)

    def test_smoke_reports_connect_rejection(self):
        # CONNACK with rc=5 (not authorized).
        connack = bytes([0x20, 0x02, 0x00, 0x05])
        with self._fake_config_fetch(), self._fake_tls_socket([connack]):
            report = mqtt_keepalive.smoke(duration_seconds=1)
        self.assertFalse(report["accepted"])
        self.assertIsNotNone(report["error"])
        # The rejection error must not embed the raw response body.
        self.assertNotIn("jwt-secret", json.dumps(report))


# ---------------------------------------------------------------------------
# Live smoke (opt-in, NOT run by default).
# ---------------------------------------------------------------------------

class LiveSmokeTests(unittest.TestCase):
    def test_live_smoke_is_opt_in_only(self):
        # Guard: never run a live MQTT connection unless explicitly requested.
        if not os.environ.get("CMCC_MQTT_LIVE_SMOKE"):
            self.skipTest("live smoke is opt-in via CMCC_MQTT_LIVE_SMOKE=1")
        report = mqtt_keepalive.smoke(duration_seconds=90)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        self.assertIn(report["stage"], ("done", "error"))


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------

class _FakeSock:
    """Minimal socket double backed by a continuous byte buffer.

    Mirrors real socket semantics: ``recv(n)`` returns *up to* ``n`` bytes
    drained from the front of the buffer, blocking-style until exhausted.
    """

    def __init__(self, replies):
        self._buf = bytearray()
        for chunk in replies:
            self._buf.extend(chunk)
        self._sent = bytearray()
        self.timeout = None

    def sendall(self, data):
        self._sent.extend(data)

    def recv(self, n):
        if not self._buf:
            raise socket.timeout
        chunk = bytes(self._buf[:n])
        del self._buf[:n]
        return chunk

    def settimeout(self, t):
        self.timeout = t

    def close(self):
        pass


if __name__ == "__main__":
    unittest.main()
