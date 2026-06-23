import time
from collections import defaultdict
from backend.db import insert_threat

class ThreatDetector:
    def __init__(self):
        # Sliding windows for threat detection
        # source_ip -> list of packet timestamps
        self.ddos_tracker = defaultdict(list)
        
        # source_ip -> list of (timestamp, dest_port)
        self.port_scan_tracker = defaultdict(list)
        
        # source_ip -> list of timestamps for port 22/3389
        self.brute_force_tracker = defaultdict(list)
        
        # Keep track of recently flagged threats to avoid spamming alerts (cooldown of 10s per threat type per IP)
        # (source_ip, threat_type) -> last_flagged_time
        self.alerts_cooldown = {}

    def is_cooldown(self, source_ip, threat_type):
        key = (source_ip, threat_type)
        now = time.time()
        if key in self.alerts_cooldown:
            if now - self.alerts_cooldown[key] < 10:  # 10 second cooldown
                return True
        self.alerts_cooldown[key] = now
        return False

    def process_packet(self, packet_info):
        """
        Analyzes a packet for threats.
        packet_info is a dict: {
            'source_ip': str,
            'destination_ip': str,
            'source_port': int or None,
            'destination_port': int or None,
            'protocol': str,
            'packet_size': int,
            'action': str
        }
        Returns a dict of the threat if detected, otherwise None.
        """
        src_ip = packet_info.get('source_ip')
        dest_ip = packet_info.get('destination_ip')
        src_port = packet_info.get('source_port')
        dest_port = packet_info.get('destination_port')
        protocol = packet_info.get('protocol')
        
        if not src_ip:
            return None

        now = time.time()
        threat_alert = None

        # 1. Malware Communication Detection
        # Check specific ports: 4444 (Meterpreter), 6667 (IRC Botnets)
        if dest_port in [4444, 6667] or src_port in [4444, 6667]:
            threat_type = "Malware Communication"
            if not self.is_cooldown(src_ip, threat_type):
                severity = "Critical"
                risk_score = 95
                rec_action = f"Block IP {src_ip} immediately and run an antivirus scan on the affected host."
                threat_id = insert_threat(src_ip, threat_type, severity, risk_score, rec_action)
                threat_alert = {
                    "id": threat_id,
                    "source_ip": src_ip,
                    "threat_type": threat_type,
                    "severity": severity,
                    "risk_score": risk_score,
                    "recommended_action": rec_action,
                    "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
                }

        # 2. Brute Force Detection
        # Ports 22 (SSH) and 3389 (RDP)
        if dest_port in [22, 3389]:
            # Clean old brute force stamps (> 10 seconds old)
            self.brute_force_tracker[src_ip] = [t for t in self.brute_force_tracker[src_ip] if now - t < 10]
            self.brute_force_tracker[src_ip].append(now)
            
            # If more than 5 attempts within 10 seconds
            if len(self.brute_force_tracker[src_ip]) >= 5:
                threat_type = "Brute Force Attempt"
                if not self.is_cooldown(src_ip, threat_type):
                    severity = "High"
                    risk_score = 80
                    rec_action = f"Add {src_ip} to Blacklist and check authentication logs for service on port {dest_port}."
                    threat_id = insert_threat(src_ip, threat_type, severity, risk_score, rec_action)
                    threat_alert = {
                        "id": threat_id,
                        "source_ip": src_ip,
                        "threat_type": threat_type,
                        "severity": severity,
                        "risk_score": risk_score,
                        "recommended_action": rec_action,
                        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
                    }

        # 3. DDoS Detection
        # More than 100 packets/sec from same source IP
        # Clean older than 1 second
        self.ddos_tracker[src_ip] = [t for t in self.ddos_tracker[src_ip] if now - t < 1.0]
        self.ddos_tracker[src_ip].append(now)
        
        if len(self.ddos_tracker[src_ip]) > 100:
            threat_type = "DDoS Attack"
            if not self.is_cooldown(src_ip, threat_type):
                severity = "Critical"
                risk_score = 99
                rec_action = f"Enable rate limiting, configure network ACLs to block {src_ip}, and scrub traffic."
                threat_id = insert_threat(src_ip, threat_type, severity, risk_score, rec_action)
                threat_alert = {
                    "id": threat_id,
                    "source_ip": src_ip,
                    "threat_type": threat_type,
                    "severity": severity,
                    "risk_score": risk_score,
                    "recommended_action": rec_action,
                    "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
                }

        # 4. Port Scanning Detection
        # More than 15 unique ports within 5 seconds from same source IP
        if dest_port is not None:
            # Clean older than 5 seconds
            self.port_scan_tracker[src_ip] = [(t, p) for (t, p) in self.port_scan_tracker[src_ip] if now - t < 5.0]
            self.port_scan_tracker[src_ip].append((now, dest_port))
            
            # Calculate unique ports
            unique_ports = {p for (_, p) in self.port_scan_tracker[src_ip]}
            if len(unique_ports) > 15:
                threat_type = "Port Scanning"
                if not self.is_cooldown(src_ip, threat_type):
                    severity = "Medium"
                    risk_score = 65
                    rec_action = f"Isolate {src_ip} dynamically. Block inbound requests from this IP across all port ranges."
                    threat_id = insert_threat(src_ip, threat_type, severity, risk_score, rec_action)
                    threat_alert = {
                        "id": threat_id,
                        "source_ip": src_ip,
                        "threat_type": threat_type,
                        "severity": severity,
                        "risk_score": risk_score,
                        "recommended_action": rec_action,
                        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
                    }

        return threat_alert
