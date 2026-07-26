#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the experimental MQTT keepalive module."""

import unittest

from cmcc_cloud_alive import main as cli_main
from cmcc_cloud_alive import mqtt_keepalive


class MqttKeepaliveTests(unittest.TestCase):

    def test_parse_broker_url_defaults_tls_port(self):
        self.assertEqual(
            mqtt_keepalive.parse_broker_url("ssl://alive.soho.komect.com"),
            ("ssl", "alive.soho.komect.com", 8883),
        )

    def test_redact_config_does_not_leak_jwt(self):
        config = {
            "url": "ssl://alive.soho.komect.com",
            "clientId": "client-secret-ish",
            "userName": "phone-or-user",
            "jwt": "header.payload.signature",
            "subTopics": ["/private/topic/a"],
        }
        report = mqtt_keepalive.redact_config(config)
        rendered = repr(report)
        self.assertNotIn("header.payload.signature", rendered)
        self.assertNotIn("phone-or-user", rendered)
        self.assertEqual(report["url"], "ssl://alive.soho.komect.com")
        self.assertEqual(report["subTopics"], ["/private/topic/a"])
        self.assertIn("jwtFingerprint", report)
        self.assertIn("userNameFingerprint", report)

    def test_build_connect_packet_uses_mqtt_311(self):
        packet = mqtt_keepalive.build_connect_packet(
            client_id="client-1",
            username="user-1",
            password="jwt-1",
            keep_alive=30,
        )
        self.assertEqual(packet[0], 0x10)
        self.assertIn(b"MQTT", packet)
        self.assertIn(b"client-1", packet)
        self.assertIn(b"user-1", packet)
        self.assertIn(b"jwt-1", packet)

    def test_subscribe_packet_has_qos1_header(self):
        packet = mqtt_keepalive.build_subscribe_packet(7, ["/topic/a", "/topic/b"])
        self.assertEqual(packet[0], 0x82)
        self.assertIn(b"/topic/a", packet)
        self.assertIn(b"/topic/b", packet)

    def test_cli_registers_mqtt_keepalive(self):
        parser = cli_main.build_parser()
        args = parser.parse_args(["mqtt-keepalive", "2663816", "--duration", "10"])
        self.assertEqual(args.func.__name__, "cmd_mqtt_keepalive")
        self.assertEqual(args.user_service_id, "2663816")
        self.assertEqual(args.duration, 10)


if __name__ == "__main__":
    unittest.main()
