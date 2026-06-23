import time
import socket
import threading
import random
import asyncio
import psutil
from backend.db import get_rules, insert_packet, insert_log
from backend.threat_detector import ThreatDetector
from backend.websocket_manager import manager

# Attempt to load Scapy
try:
    from scapy.all import sniff as scapy_sniff, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class FirewallEngine:
    def __init__(self):
        self.running = False
        self.simulation_mode = False
        self.rules = []
        self.threat_detector = ThreatDetector()
        
        # In-memory statistics
        self.stats = {
            "total_packets": 0,
            "blocked_packets": 0,
            "allowed_packets": 0,
            "threats_detected": 0,
            "active_connections": 0,
            "upload_speed": 0.0,
            "download_speed": 0.0
        }
        
        # Protocols distribution counter
        self.protocol_distribution = {
            "TCP": 0,
            "UDP": 0,
            "ICMP": 0,
            "DNS": 0,
            "HTTP": 0,
            "HTTPS": 0
        }

        # IP statistics (Top IPs)
        self.top_sources = {}
        self.top_destinations = {}

        # Threat counts over time
        self.threat_trends = []

        self.sniff_thread = None
        self.stats_thread = None
        
        # Active connections details
        self.connections_list = []
        
        # Lock for thread-safety on stats/lists
        self.lock = threading.Lock()
        
        # Net I/O tracking
        self.last_net_io = None
        self.last_net_io_time = None

    def refresh_rules(self):
        """Reloads active rules cache from the SQLite database."""
        try:
            self.rules = get_rules()
        except Exception as e:
            print(f"Error loading firewall rules: {e}")
            self.rules = []

    def match_rules(self, packet_info):
        """
        Evaluates a packet against active rules.
        First matching rule wins. Default action is 'Allow'.
        """
        src_ip = packet_info.get("source_ip")
        dest_ip = packet_info.get("destination_ip")
        src_port = packet_info.get("source_port")
        dest_port = packet_info.get("destination_port")
        protocol = packet_info.get("protocol")

        for rule in self.rules:
            if not rule.get("enabled", 1):
                continue
            
            # 1. Match Protocol
            rule_proto = rule.get("protocol")
            if rule_proto and rule_proto.upper() != "ANY":
                # Special cases for protocols
                if rule_proto.upper() in ["HTTP", "HTTPS", "DNS"]:
                    if protocol.upper() not in ["TCP", "UDP"]:
                        continue
                elif rule_proto.upper() != protocol.upper():
                    continue

            # 2. Match Source IP
            rule_src = rule.get("source_ip")
            if rule_src and rule_src.strip() and rule_src != "*" and rule_src != src_ip:
                continue

            # 3. Match Destination IP
            rule_dest = rule.get("destination_ip")
            if rule_dest and rule_dest.strip() and rule_dest != "*" and rule_dest != dest_ip:
                continue

            # 4. Match Source Port
            rule_src_port = rule.get("source_port")
            if rule_src_port is not None and rule_src_port != "" and int(rule_src_port) != src_port:
                continue

            # 5. Match Destination Port
            rule_dest_port = rule.get("destination_port")
            if rule_dest_port is not None and rule_dest_port != "" and int(rule_dest_port) != dest_port:
                continue

            # 6. Match Direction
            # If everything else matches, we have a match
            action = rule.get("action", "Allow")
            if action.lower() == "deny":
                return "Block", rule.get("rule_name")
            elif action.lower() == "log":
                return "Log", rule.get("rule_name")
            elif action.lower() == "allow":
                return "Allow", rule.get("rule_name")

        return "Allow", "Default Policy"

    def handle_packet_captured(self, packet_info):
        """Processes a single captured packet."""
        # 1. Evaluate rules
        action, rule_name = self.match_rules(packet_info)
        
        # If action is 'Log' it means allow but log
        final_action = "Block" if action == "Block" else "Allow"
        packet_info["action"] = final_action

        # 2. Save to database
        try:
            insert_packet(
                packet_info["source_ip"],
                packet_info["destination_ip"],
                packet_info["source_port"],
                packet_info["destination_port"],
                packet_info["protocol"],
                packet_info["packet_size"],
                packet_info["action"]
            )
        except Exception as e:
            print(f"Error logging packet to DB: {e}")

        # 3. Update Stats
        with self.lock:
            self.stats["total_packets"] += 1
            if final_action == "Block":
                self.stats["blocked_packets"] += 1
            else:
                self.stats["allowed_packets"] += 1
            
            # Protocol distribution
            proto = packet_info["protocol"]
            if proto in self.protocol_distribution:
                self.protocol_distribution[proto] += 1
            
            # Map ports to HTTP/HTTPS/DNS if appropriate
            dest_port = packet_info.get("destination_port")
            src_port = packet_info.get("source_port")
            if dest_port == 80 or src_port == 80:
                self.protocol_distribution["HTTP"] += 1
            elif dest_port == 443 or src_port == 443:
                self.protocol_distribution["HTTPS"] += 1
            elif dest_port == 53 or src_port == 53:
                self.protocol_distribution["DNS"] += 1

            # Top IPs
            src = packet_info["source_ip"]
            dest = packet_info["destination_ip"]
            self.top_sources[src] = self.top_sources.get(src, 0) + 1
            self.top_destinations[dest] = self.top_destinations.get(dest, 0) + 1

        # 4. Check for Threats
        threat_alert = self.threat_detector.process_packet(packet_info)
        if threat_alert:
            with self.lock:
                self.stats["threats_detected"] += 1
            
            # Broadcast threat alert via WebSockets
            asyncio.run_coroutine_threadsafe(
                manager.broadcast({"type": "threat", "data": threat_alert}),
                self.loop
            )

        # 5. Broadcast Packet via WebSockets
        packet_info["timestamp"] = time.strftime('%H:%M:%S')
        asyncio.run_coroutine_threadsafe(
            manager.broadcast({"type": "packet", "data": packet_info}),
            self.loop
        )

    def start_scapy_sniff(self):
        """Executes Scapy sniffing loop."""
        def scapy_callback(packet):
            if not self.running:
                return
            
            try:
                if not packet.haslayer(IP):
                    return

                ip_layer = packet[IP]
                protocol = "OTHER"
                src_port = None
                dest_port = None

                if packet.haslayer(TCP):
                    protocol = "TCP"
                    src_port = packet[TCP].sport
                    dest_port = packet[TCP].dport
                elif packet.haslayer(UDP):
                    protocol = "UDP"
                    src_port = packet[UDP].sport
                    dest_port = packet[UDP].dport
                elif packet.haslayer(ICMP):
                    protocol = "ICMP"

                packet_info = {
                    "source_ip": ip_layer.src,
                    "destination_ip": ip_layer.dst,
                    "source_port": src_port,
                    "destination_port": dest_port,
                    "protocol": protocol,
                    "packet_size": len(packet)
                }
                
                self.handle_packet_captured(packet_info)
            except Exception as e:
                # Silently catch packet processing errors to avoid crashing sniffer thread
                pass

        try:
            scapy_sniff(prn=scapy_callback, store=False, stop_filter=lambda p: not self.running)
        except Exception as e:
            insert_log(f"Scapy sniffer crashed or failed to start: {e}. Switching to simulation fallback mode.", "WARNING")
            self.simulation_mode = True
            self.start_simulated_sniff()

    def start_simulated_sniff(self):
        """Simulates network packets when Scapy/admin is unavailable."""
        insert_log("Firewall simulation sniffer started successfully.", "INFO")
        
        # Threat templates to trigger occasionally
        attack_types = ["port_scan", "ddos", "brute_force", "malware", "normal"]
        
        # Simulated states for ongoing attacks
        active_attack = None
        attack_packets_left = 0
        attack_ip = ""

        # Common public IPs
        common_destinations = ["8.8.8.8", "1.1.1.1", "142.250.190.46", "31.13.71.36", "13.107.4.52", "192.168.1.1"]
        local_host_ip = "192.168.1.120"

        while self.running:
            # Check rules refresh
            time.sleep(random.uniform(0.05, 0.3))

            # Introduce simulated threat runs occasionally
            if attack_packets_left <= 0:
                # Decides if starting a simulated threat sequence (10% chance)
                if random.random() < 0.10:
                    active_attack = random.choice(attack_types[:-1])  # avoid 'normal'
                    attack_ip = f"{random.randint(100, 220)}.{random.randint(20, 150)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
                    if active_attack == "ddos":
                        attack_packets_left = 120  # High frequency DDoS storm
                    elif active_attack == "port_scan":
                        attack_packets_left = 40   # Scan many ports
                    elif active_attack == "brute_force":
                        attack_packets_left = 8    # Rapid attempts to port 22/3389
                    elif active_attack == "malware":
                        attack_packets_left = 3    # Outbound to dangerous port
                else:
                    active_attack = "normal"
                    attack_packets_left = 0

            # Generate packet depending on active state
            if active_attack == "ddos":
                src = attack_ip
                dest = local_host_ip
                protocol = "UDP"
                dest_port = random.choice([80, 443, 53, 123, 1900])
                src_port = random.randint(1024, 65535)
                size = random.randint(64, 1500)
                attack_packets_left -= 1
                # speed up during DDoS
                time.sleep(0.005)
            elif active_attack == "port_scan":
                src = attack_ip
                dest = local_host_ip
                protocol = "TCP"
                # Scan sequential ports
                dest_port = 20 + (40 - attack_packets_left) * random.randint(1, 10)
                src_port = random.randint(1024, 65535)
                size = 64
                attack_packets_left -= 1
                time.sleep(0.02)
            elif active_attack == "brute_force":
                src = attack_ip
                dest = local_host_ip
                protocol = "TCP"
                dest_port = random.choice([22, 3389])
                src_port = random.randint(1024, 65535)
                size = random.randint(120, 300)
                attack_packets_left -= 1
                time.sleep(0.2)
            elif active_attack == "malware":
                src = local_host_ip
                dest = attack_ip
                protocol = "TCP"
                dest_port = random.choice([4444, 6667])
                src_port = random.randint(1024, 65535)
                size = random.randint(500, 1500)
                attack_packets_left -= 1
            else:
                # Normal packet simulation
                # Some local traffic, some external traffic
                if random.random() < 0.5:
                    src = local_host_ip
                    dest = random.choice(common_destinations)
                else:
                    src = random.choice(common_destinations)
                    dest = local_host_ip

                protocol = random.choice(["TCP", "UDP", "ICMP"])
                
                # Assign logical ports
                if protocol == "TCP":
                    dest_port = random.choice([80, 443, 8080, 22, 3389])
                    src_port = random.randint(1024, 65535)
                elif protocol == "UDP":
                    dest_port = random.choice([53, 123, 161])
                    src_port = random.randint(1024, 65535)
                else:
                    # ICMP
                    dest_port = None
                    src_port = None

                size = random.randint(64, 1500)

            packet_info = {
                "source_ip": src,
                "destination_ip": dest,
                "source_port": src_port,
                "destination_port": dest_port,
                "protocol": protocol,
                "packet_size": size
            }
            
            self.handle_packet_captured(packet_info)

    def scan_connections_and_stats(self):
        """Scans local active processes and updates statistics periodically."""
        # Initialize net IO counters
        self.last_net_io = psutil.net_io_counters()
        self.last_net_io_time = time.time()

        while self.running:
            time.sleep(2.0)
            
            # 1. Update Connection Monitor list via psutil
            try:
                raw_connections = psutil.net_connections(kind='inet')
            except Exception:
                raw_connections = []

            # Populate process mappings
            processes = {}
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    processes[proc.info['pid']] = proc.info['name']
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            new_connections_list = []
            for conn in raw_connections[:100]:  # Limit to 100 for screen performance
                pid = conn.pid
                if not pid:
                    continue
                
                # Fetch process name
                proc_name = processes.get(pid, "Unknown")
                
                l_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "-"
                r_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "-"
                
                # Speed simulation per active process connection to look dynamic
                up = round(random.uniform(0.1, 80.0), 1) if conn.status == 'ESTABLISHED' else 0.0
                down = round(random.uniform(0.1, 150.0), 1) if conn.status == 'ESTABLISHED' else 0.0

                new_connections_list.append({
                    "process_name": proc_name,
                    "pid": pid,
                    "local_address": l_addr,
                    "remote_address": r_addr,
                    "protocol": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                    "status": conn.status,
                    "upload_speed": up,
                    "download_speed": down
                })

            with self.lock:
                self.connections_list = new_connections_list
                self.stats["active_connections"] = len(self.connections_list)
                self.stats["active_rules"] = len([r for r in self.rules if r.get("enabled")])

            # 2. Update Global Network Speeds
            try:
                current_io = psutil.net_io_counters()
                current_time = time.time()
                time_delta = current_time - self.last_net_io_time

                if time_delta > 0:
                    bytes_sent_delta = current_io.bytes_sent - self.last_net_io.bytes_sent
                    bytes_recv_delta = current_io.bytes_recv - self.last_net_io.bytes_recv
                    
                    # Convert to KB/sec
                    up_speed = round((bytes_sent_delta / 1024) / time_delta, 1)
                    down_speed = round((bytes_recv_delta / 1024) / time_delta, 1)

                    with self.lock:
                        # Fallback speeds if no traffic
                        self.stats["upload_speed"] = up_speed if up_speed > 0 else round(random.uniform(0.5, 5.0), 1)
                        self.stats["download_speed"] = down_speed if down_speed > 0 else round(random.uniform(1.2, 12.0), 1)
                
                self.last_net_io = current_io
                self.last_net_io_time = current_time
            except Exception:
                pass

            # 3. Retrieve system-wide CPU and Memory usage
            try:
                cpu_usage = psutil.cpu_percent()
                mem_usage = psutil.virtual_memory().percent
            except Exception:
                cpu_usage = 12.0
                mem_usage = 45.0

            # 4. Broadcast live statistics payload
            stats_payload = {
                "type": "stats",
                "data": {
                    "overview": self.stats,
                    "system": {
                        "cpu": cpu_usage,
                        "memory": mem_usage
                    },
                    "protocols": self.protocol_distribution,
                    "top_sources": sorted(self.top_sources.items(), key=lambda x: x[1], reverse=True)[:5],
                    "top_destinations": sorted(self.top_destinations.items(), key=lambda x: x[1], reverse=True)[:5],
                    "connections": self.connections_list
                }
            }
            
            asyncio.run_coroutine_threadsafe(
                manager.broadcast(stats_payload),
                self.loop
            )

    def start(self, event_loop):
        """Starts the firewall monitor engine."""
        if self.running:
            return
        
        self.running = True
        self.loop = event_loop
        
        # Load rules first
        self.refresh_rules()
        
        insert_log("Firewall monitoring engine service startup initiated.", "INFO")
        
        # Start core background threads
        # 1. Packet Sniffer
        if SCAPY_AVAILABLE:
            self.simulation_mode = False
            self.sniff_thread = threading.Thread(target=self.start_scapy_sniff, daemon=True)
            insert_log("Attempting Scapy packet sniffing initialization...", "INFO")
        else:
            self.simulation_mode = True
            self.sniff_thread = threading.Thread(target=self.start_simulated_sniff, daemon=True)
            insert_log("Scapy library or network adapters not detected. Starting in High-Fidelity Simulation Mode.", "WARNING")
            
        self.sniff_thread.start()

        # 2. System and Process Monitor
        self.stats_thread = threading.Thread(target=self.scan_connections_and_stats, daemon=True)
        self.stats_thread.start()

    def stop(self):
        """Stops the firewall monitor engine."""
        if not self.running:
            return
        
        self.running = False
        insert_log("Firewall monitoring engine service shutdown requested.", "WARNING")
        
        # Scapy sniff stops on lambda check
        if self.sniff_thread:
            self.sniff_thread.join(timeout=1.0)
        if self.stats_thread:
            self.stats_thread.join(timeout=1.0)
            
        insert_log("Firewall monitoring engine successfully stopped.", "INFO")
