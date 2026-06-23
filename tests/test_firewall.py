import os
import sys
import unittest
import sqlite3

# Ensure current folder and parent directory are on path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.db import init_db, get_rules, insert_rule, delete_rule, get_db_connection
from backend.threat_detector import ThreatDetector
from backend.firewall_engine import FirewallEngine

class TestFirewallComponents(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        """Initializes database for tests."""
        init_db()

    def setUp(self):
        """Pre-test cleanup of testing database rules."""
        # Ensure we have a clean test state for rules we edit
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM firewall_rules WHERE rule_name LIKE 'Test%'")
        conn.commit()
        conn.close()

    def test_database_connection(self):
        """Verifies DB connects and lists rules successfully."""
        rules = get_rules()
        self.assertIsInstance(rules, list)
        self.assertTrue(len(rules) >= 0)

    def test_rules_insertion_and_deletion(self):
        """Tests inserting, caching, and removing firewall rules."""
        initial_count = len(get_rules())
        
        # Insert a rule
        rule_id = insert_rule(
            rule_name="Test Rule Ban",
            source_ip="8.8.8.8",
            destination_ip=None,
            source_port=None,
            destination_port=None,
            protocol="TCP",
            direction="Both",
            action="Deny",
            enabled=1
        )
        
        rules = get_rules()
        self.assertEqual(len(rules), initial_count + 1)
        self.assertEqual(rules[0]["rule_name"], "Test Rule Ban")
        self.assertEqual(rules[0]["id"], rule_id)
        
        # Delete the rule
        delete_rule(rule_id)
        rules_after = get_rules()
        self.assertEqual(len(rules_after), initial_count)

    def test_rules_matching_logic(self):
        """Tests that packet engine evaluates IP/Port policies accurately."""
        engine = FirewallEngine()
        
        # Mock active rule set in engine cache
        engine.rules = [
            {
                "rule_name": "Test Deny Malicious Port",
                "protocol": "TCP",
                "source_ip": None,
                "destination_ip": None,
                "source_port": None,
                "destination_port": 6666,
                "action": "Deny",
                "enabled": 1
            },
            {
                "rule_name": "Test Allow Trust DNS",
                "protocol": "UDP",
                "source_ip": None,
                "destination_ip": "1.1.1.1",
                "source_port": None,
                "destination_port": 53,
                "action": "Allow",
                "enabled": 1
            }
        ]

        # 1. Packet targeting port 6666 should be BLOCKED
        pkt_blocked = {
            "source_ip": "192.168.1.100",
            "destination_ip": "45.1.1.2",
            "source_port": 12345,
            "destination_port": 6666,
            "protocol": "TCP"
        }
        action, rule = engine.match_rules(pkt_blocked)
        self.assertEqual(action, "Block")
        self.assertEqual(rule, "Test Deny Malicious Port")

        # 2. Packet targeting 1.1.1.1 port 53 should be ALLOWED
        pkt_allowed = {
            "source_ip": "192.168.1.100",
            "destination_ip": "1.1.1.1",
            "source_port": 12345,
            "destination_port": 53,
            "protocol": "UDP"
        }
        action, rule = engine.match_rules(pkt_allowed)
        self.assertEqual(action, "Allow")
        self.assertEqual(rule, "Test Allow Trust DNS")

        # 3. Random packet targeting unconfigured port should fall back to default Allow policy
        pkt_default = {
            "source_ip": "192.168.1.100",
            "destination_ip": "142.250.190.46",
            "source_port": 12345,
            "destination_port": 443,
            "protocol": "TCP"
        }
        action, rule = engine.match_rules(pkt_default)
        self.assertEqual(action, "Allow")
        self.assertEqual(rule, "Default Policy")

    def test_threat_detector_port_scan(self):
        """Verifies Port Scan alert triggers when same IP touches >15 ports."""
        detector = ThreatDetector()
        src_ip = "185.220.101.5"
        
        # Generate 16 packets to 16 different destination ports
        alert = None
        for port in range(1, 18):
            pkt = {
                "source_ip": src_ip,
                "destination_ip": "192.168.1.120",
                "source_port": 5000,
                "destination_port": port,
                "protocol": "TCP",
                "packet_size": 64
            }
            res = detector.process_packet(pkt)
            if res:
                alert = res
            
        self.assertIsNotNone(alert)
        self.assertEqual(alert["threat_type"], "Port Scanning")
        self.assertEqual(alert["source_ip"], src_ip)
        self.assertEqual(alert["severity"], "Medium")

    def test_threat_detector_ddos(self):
        """Verifies DDoS alert triggers when packet frequency >100/sec."""
        detector = ThreatDetector()
        src_ip = "203.0.113.88"
        
        alert = None
        # Send 105 packets in rapid succession
        for _ in range(105):
            pkt = {
                "source_ip": src_ip,
                "destination_ip": "192.168.1.120",
                "source_port": 12345,
                "destination_port": 80,
                "protocol": "TCP",
                "packet_size": 1000
            }
            res = detector.process_packet(pkt)
            if res:
                alert = res
            
        self.assertIsNotNone(alert)
        self.assertEqual(alert["threat_type"], "DDoS Attack")
        self.assertEqual(alert["source_ip"], src_ip)
        self.assertEqual(alert["severity"], "Critical")

    def test_threat_detector_brute_force(self):
        """Verifies brute force attacks are flagged on auth ports."""
        detector = ThreatDetector()
        src_ip = "198.51.100.4"
        
        alert = None
        # Send 6 connection packets to SSH port 22
        for _ in range(6):
            pkt = {
                "source_ip": src_ip,
                "destination_ip": "192.168.1.120",
                "source_port": 54321,
                "destination_port": 22,
                "protocol": "TCP",
                "packet_size": 150
            }
            res = detector.process_packet(pkt)
            if res:
                alert = res

        self.assertIsNotNone(alert)
        self.assertEqual(alert["threat_type"], "Brute Force Attempt")
        self.assertEqual(alert["source_ip"], src_ip)
        self.assertEqual(alert["severity"], "High")

    def test_threat_detector_malware_ports(self):
        """Verifies outbound communication on reverse shells (port 4444) triggers alert."""
        detector = ThreatDetector()
        src_ip = "192.168.1.120"
        
        # Packet to Metasploit payload handler port 4444
        pkt = {
            "source_ip": src_ip,
            "destination_ip": "185.10.10.10",
            "source_port": 12345,
            "destination_port": 4444,
            "protocol": "TCP",
            "packet_size": 250
        }
        alert = detector.process_packet(pkt)
        
        self.assertIsNotNone(alert)
        self.assertEqual(alert["threat_type"], "Malware Communication")
        self.assertEqual(alert["source_ip"], src_ip)
        self.assertEqual(alert["severity"], "Critical")

if __name__ == "__main__":
    unittest.main()
