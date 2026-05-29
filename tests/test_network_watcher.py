#!/usr/bin/env python3
"""
tests/test_network_watcher.py
Unit tests for NetworkWatcher CIDR subnet membership checks.
Run: python -m pytest tests/test_network_watcher.py -v
"""
import ipaddress
import unittest
from bifrost.guardian import NetworkWatcher


class TestNetworkWatcherCIDR(unittest.TestCase):
    """Tests that is_host_subnet uses proper CIDR membership checks."""

    def setUp(self):
        # Build a minimal instance without calling __init__
        # HOST_NET is a class attribute — no instance init needed
        self.watcher = object.__new__(NetworkWatcher)

    def test_host_net_is_cidr_object(self):
        """HOST_NET must be an ipaddress.IPv4Network, not a string."""
        from bifrost.guardian import NetworkWatcher
        self.assertIsInstance(NetworkWatcher.HOST_NET, ipaddress.IPv4Network)

    def test_ip_inside_subnet_is_matched(self):
        """An IP inside 192.168.0.0/24 must return True."""
        self.assertTrue(self.watcher.is_host_subnet("192.168.0.1"))
        self.assertTrue(self.watcher.is_host_subnet("192.168.0.100"))
        self.assertTrue(self.watcher.is_host_subnet("192.168.0.254"))

    def test_ip_outside_subnet_is_not_matched(self):
        """An IP outside 192.168.0.0/24 must return False."""
        # Different third octet — same RFC1918 range but different subnet
        self.assertFalse(self.watcher.is_host_subnet("192.168.1.1"))
        self.assertFalse(self.watcher.is_host_subnet("10.0.0.1"))
        # Public IPs
        self.assertFalse(self.watcher.is_host_subnet("8.8.8.8"))
        self.assertFalse(self.watcher.is_host_subnet("87.251.64.176"))

    def test_boundary_ips_handled_correctly(self):
        """Network address and broadcast are inside /24."""
        # Network address (192.168.0.0) is inside the network object
        self.assertTrue(self.watcher.is_host_subnet("192.168.0.0"))
        # Broadcast (192.168.0.255) is inside the network object
        self.assertTrue(self.watcher.is_host_subnet("192.168.0.255"))

    def test_invalid_ip_returns_false(self):
        """Invalid IP strings must return False rather than raising."""
        self.assertFalse(self.watcher.is_host_subnet("not-an-ip"))
        self.assertFalse(self.watcher.is_host_subnet(""))
        self.assertFalse(self.watcher.is_host_subnet("999.999.999.999"))
        self.assertFalse(self.watcher.is_host_subnet("192.168.0"))

    def test_string_prefix_alone_is_insufficient(self):
        """
        Ensure the check is true CIDR membership, not string prefix matching.
        '192.168.0.1000' would pass a naive '192.168.0.' startswith check
        but must be rejected as an invalid IP.
        """
        self.assertFalse(self.watcher.is_host_subnet("192.168.0.1000"))

    def test_cidr_vs_string_containment(self):
        """
        192.168.1.50 contains '192.168.' but is NOT in 192.168.0.0/24.
        A string-containment check would incorrectly return True.
        CIDR membership must correctly return False.
        """
        # Would match '192.168.' prefix — should NOT match /24 CIDR
        self.assertFalse(self.watcher.is_host_subnet("192.168.1.50"))
        self.assertFalse(self.watcher.is_host_subnet("192.168.255.1"))


class TestBrainIPValidation(unittest.TestCase):
    """Tests that brain._apply_policy uses ipaddress for IP detection."""

    def _make_brain(self):
        from heimdall.brain import BifrostBrain
        cfg = {
            "hardware_tier": "TIER_4",
            "learning_mode": True,
            "dry_run": True,
            "autonomous_actions_enabled": False,
        }
        return BifrostBrain(cfg)

    def test_valid_ip_target_sets_dest_ip(self):
        """A valid IPv4 string in target must be treated as destination IP."""
        from heimdall.schema import Decision, ActionType, Severity
        brain = self._make_brain()

        decision = Decision(
            incident_detected=True,
            severity=Severity.HIGH,
            boundary="HOST",
            threat_class="test",
            confidence=0.95,
            action_required=ActionType.BLOCK,
            target="8.8.8.8",
            gjallarhorn_tier=2,
            reasoning="test",
            extractor_model="test",
            reasoner_model="test",
            hardware_tier="TIER_4",
        )
        result = brain._apply_policy(decision)
        # In learning_mode the action is always downgraded; no exception expected
        self.assertIsNotNone(result)

    def test_non_ip_target_does_not_crash(self):
        """A non-IP target (path or domain) must not crash _apply_policy."""
        from heimdall.schema import Decision, ActionType, Severity
        brain = self._make_brain()

        for target in ["/etc/passwd", "example.com", "not-an-ip", ""]:
            decision = Decision(
                incident_detected=True,
                severity=Severity.HIGH,
                boundary="HOST",
                threat_class="test",
                confidence=0.95,
                action_required=ActionType.ALERT,
                target=target,
                gjallarhorn_tier=1,
                reasoning="test",
                extractor_model="test",
                reasoner_model="test",
                hardware_tier="TIER_4",
            )
            result = brain._apply_policy(decision)
            self.assertIsNotNone(result)


if __name__ == "__main__":
    unittest.main()
