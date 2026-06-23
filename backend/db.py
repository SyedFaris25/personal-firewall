import os
import sqlite3
from datetime import datetime

DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "database")
DB_PATH = os.path.join(DB_DIR, "firewall.db")

def init_db():
    """Initializes the database directory and tables."""
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # 1. packets table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            source_ip TEXT,
            destination_ip TEXT,
            source_port INTEGER,
            destination_port INTEGER,
            protocol TEXT,
            packet_size INTEGER,
            action TEXT
        )
    """)

    # 2. firewall_rules table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS firewall_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_name TEXT NOT NULL,
            source_ip TEXT,
            destination_ip TEXT,
            source_port INTEGER,
            destination_port INTEGER,
            protocol TEXT,
            direction TEXT,
            action TEXT,
            enabled INTEGER DEFAULT 1
        )
    """)

    # 3. threats table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip TEXT,
            threat_type TEXT,
            severity TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            risk_score INTEGER,
            recommended_action TEXT
        )
    """)

    # 4. logs table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            event TEXT,
            status TEXT
        )
    """)

    conn.commit()

    # Pre-populate default rules if table is empty
    cursor.execute("SELECT COUNT(*) FROM firewall_rules")
    if cursor.fetchone()[0] == 0:
        default_rules = [
            ("Block Malicious Port 4444", None, None, None, 4444, "TCP", "Both", "Deny", 1),
            ("Block Torrent Traffic DHT", None, None, None, 6881, "UDP", "Both", "Deny", 1),
            ("Log DNS Queries", None, None, None, 53, "UDP", "Both", "Log", 1),
            ("Allow HTTP Traffic", None, None, None, 80, "TCP", "Both", "Allow", 1),
            ("Allow HTTPS Traffic", None, None, None, 443, "TCP", "Both", "Allow", 1),
            ("Log ICMP Traffic", None, None, None, None, "ICMP", "Both", "Log", 1)
        ]
        cursor.executemany("""
            INSERT INTO firewall_rules (rule_name, source_ip, destination_ip, source_port, destination_port, protocol, direction, action, enabled)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, default_rules)
        conn.commit()
        
        # Log default rules initialization
        cursor.execute("INSERT INTO logs (event, status) VALUES (?, ?)", 
                       ("Firewall rules table initialized with default templates.", "INFO"))
        conn.commit()

    conn.close()

def get_db_connection():
    """Returns a connection to the SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# Packets operations
def insert_packet(source_ip, destination_ip, source_port, destination_port, protocol, packet_size, action):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO packets (source_ip, destination_ip, source_port, destination_port, protocol, packet_size, action)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (source_ip, destination_ip, source_port, destination_port, protocol, packet_size, action))
    conn.commit()
    conn.close()

def get_packets(limit=100):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM packets ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

# Rules operations
def get_rules():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM firewall_rules ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def insert_rule(rule_name, source_ip, destination_ip, source_port, destination_port, protocol, direction, action, enabled=1):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO firewall_rules (rule_name, source_ip, destination_ip, source_port, destination_port, protocol, direction, action, enabled)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (rule_name, source_ip, destination_ip, source_port, destination_port, protocol, direction, action, enabled))
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    insert_log(f"Created rule: {rule_name} (ID: {new_id})", "SUCCESS")
    return new_id

def update_rule(rule_id, rule_name, source_ip, destination_ip, source_port, destination_port, protocol, direction, action, enabled):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE firewall_rules
        SET rule_name = ?, source_ip = ?, destination_ip = ?, source_port = ?, destination_port = ?, protocol = ?, direction = ?, action = ?, enabled = ?
        WHERE id = ?
    """, (rule_name, source_ip, destination_ip, source_port, destination_port, protocol, direction, action, enabled, rule_id))
    conn.commit()
    conn.close()
    insert_log(f"Updated rule: {rule_name} (ID: {rule_id})", "INFO")

def toggle_rule(rule_id, enabled):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE firewall_rules SET enabled = ? WHERE id = ?", (1 if enabled else 0, rule_id))
    conn.commit()
    cursor.execute("SELECT rule_name FROM firewall_rules WHERE id = ?", (rule_id,))
    rule = cursor.fetchone()
    conn.close()
    rule_name = rule["rule_name"] if rule else "Unknown"
    insert_log(f"Toggled rule '{rule_name}' (ID: {rule_id}) to {'Enabled' if enabled else 'Disabled'}", "INFO")

def delete_rule(rule_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT rule_name FROM firewall_rules WHERE id = ?", (rule_id,))
    rule = cursor.fetchone()
    rule_name = rule["rule_name"] if rule else "Unknown"
    cursor.execute("DELETE FROM firewall_rules WHERE id = ?", (rule_id,))
    conn.commit()
    conn.close()
    insert_log(f"Deleted rule '{rule_name}' (ID: {rule_id})", "WARNING")

# Threats operations
def insert_threat(source_ip, threat_type, severity, risk_score, recommended_action):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO threats (source_ip, threat_type, severity, risk_score, recommended_action)
        VALUES (?, ?, ?, ?, ?)
    """, (source_ip, threat_type, severity, risk_score, recommended_action))
    conn.commit()
    threat_id = cursor.lastrowid
    conn.close()
    insert_log(f"Threat detected: {threat_type} from {source_ip} (Severity: {severity})", "ALERT")
    return threat_id

def get_threats(limit=50):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM threats ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

# Logs operations
def insert_log(event, status):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO logs (event, status) VALUES (?, ?)", (event, status))
    conn.commit()
    conn.close()

def get_logs(search=None, status=None, limit=1000):
    conn = get_db_connection()
    cursor = conn.cursor()
    query = "SELECT * FROM logs"
    params = []
    conditions = []
    
    if search:
        conditions.append("event LIKE ?")
        params.append(f"%{search}%")
    if status:
        conditions.append("status = ?")
        params.append(status)
        
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
        
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

# Initialize on import
init_db()
