import os
import csv
import json
import asyncio
from datetime import datetime
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from typing import Optional, List

from backend.db import (
    get_rules, insert_rule, update_rule, toggle_rule, delete_rule,
    get_packets, get_logs, get_threats, insert_log, get_db_connection
)
from backend.firewall_engine import FirewallEngine
from backend.websocket_manager import manager

app = FastAPI(title="Personal Firewall Cybersecurity SOC Portal", version="1.0.0")

# Engine instance
engine = FirewallEngine()

# Model schemas
class RuleModel(BaseModel):
    rule_name: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: str = "ANY"
    direction: str = "Both"
    action: str = "Allow"
    enabled: int = 1

class BlockIPModel(BaseModel):
    ip: str
    rule_name: str = "Quick Block IP"

class ProcessKillModel(BaseModel):
    pid: int

# Mount static folder
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "static")
os.makedirs(STATIC_DIR, exist_ok=True)

# Startup and Shutdown events
@app.on_event("startup")
async def startup():
    loop = asyncio.get_event_loop()
    engine.start(loop)

@app.on_event("shutdown")
def shutdown():
    engine.stop()

# API Endpoints

# 1. Firewall Control
@app.post("/api/firewall/start")
def start_firewall():
    if engine.running:
        return {"status": "already_running", "message": "Firewall engine is already running."}
    loop = asyncio.get_event_loop()
    engine.start(loop)
    return {"status": "started", "message": "Firewall engine started."}

@app.post("/api/firewall/stop")
def stop_firewall():
    if not engine.running:
        return {"status": "already_stopped", "message": "Firewall engine is not running."}
    engine.stop()
    return {"status": "stopped", "message": "Firewall engine stopped."}

@app.get("/api/firewall/status")
def get_firewall_status():
    return {
        "running": engine.running,
        "simulation_mode": engine.simulation_mode,
        "stats": engine.stats
    }

# 2. Firewall Rules CRUD
@app.get("/api/rules")
def fetch_rules():
    return get_rules()

@app.post("/api/rules")
def add_rule(rule: RuleModel):
    rule_id = insert_rule(
        rule.rule_name,
        rule.source_ip,
        rule.destination_ip,
        rule.source_port,
        rule.destination_port,
        rule.protocol,
        rule.direction,
        rule.action,
        rule.enabled
    )
    engine.refresh_rules()
    return {"status": "success", "id": rule_id, "message": f"Rule '{rule.rule_name}' created successfully."}

@app.put("/api/rules/{rule_id}")
def edit_rule(rule_id: int, rule: RuleModel):
    update_rule(
        rule_id,
        rule.rule_name,
        rule.source_ip,
        rule.destination_ip,
        rule.source_port,
        rule.destination_port,
        rule.protocol,
        rule.direction,
        rule.action,
        rule.enabled
    )
    engine.refresh_rules()
    return {"status": "success", "message": "Rule updated successfully."}

@app.patch("/api/rules/{rule_id}/toggle")
def patch_toggle_rule(rule_id: int, enabled: bool):
    toggle_rule(rule_id, enabled)
    engine.refresh_rules()
    return {"status": "success", "message": f"Rule toggled to {'enabled' if enabled else 'disabled'}."}

@app.delete("/api/rules/{rule_id}")
def remove_rule(rule_id: int):
    delete_rule(rule_id)
    engine.refresh_rules()
    return {"status": "success", "message": "Rule deleted successfully."}

# 3. Connection termination & quick block
@app.post("/api/connections/terminate")
def terminate_process(payload: ProcessKillModel):
    import psutil
    pid = payload.pid
    try:
        proc = psutil.Process(pid)
        proc_name = proc.name()
        proc.terminate()
        insert_log(f"Terminated process {proc_name} (PID: {pid}) via dashboard request", "WARNING")
        return {"status": "success", "message": f"Terminated process {proc_name} (PID: {pid})."}
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        raise HTTPException(status_code=400, detail=f"Failed to terminate process: {str(e)}")

@app.post("/api/rules/block-ip")
def block_ip_address(payload: BlockIPModel):
    # Inserts a DENY rule for the specific IP
    rule_id = insert_rule(
        rule_name=f"Block {payload.ip}",
        source_ip=payload.ip,
        destination_ip=None,
        source_port=None,
        destination_port=None,
        protocol="ANY",
        direction="Both",
        action="Deny",
        enabled=1
    )
    engine.refresh_rules()
    return {"status": "success", "id": rule_id, "message": f"Successfully blocked IP {payload.ip}."}

# 4. Logs and Packets Queries
@app.get("/api/logs/packets")
def fetch_packet_logs(
    search: Optional[str] = None,
    protocol: Optional[str] = None,
    action: Optional[str] = None,
    limit: int = 250
):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = "SELECT * FROM packets"
    params = []
    conditions = []
    
    if search:
        conditions.append("(source_ip LIKE ? OR destination_ip LIKE ?)")
        params.append(f"%{search}%")
        params.append(f"%{search}%")
    if protocol and protocol != "ALL":
        conditions.append("protocol = ?")
        params.append(protocol)
    if action and action != "ALL":
        conditions.append("action = ?")
        params.append(action)
        
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
        
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

@app.get("/api/logs/events")
def fetch_event_logs(search: Optional[str] = None, limit: int = 200):
    return get_logs(search=search, limit=limit)

@app.get("/api/threats")
def fetch_threat_alerts(limit: int = 50):
    return get_threats(limit=limit)

# 5. Export logs
@app.get("/api/logs/export")
def export_logs(
    format: str = Query("csv", regex="^(csv|json|pdf)$"),
    log_type: str = Query("packets", regex="^(packets|events)$"),
    search: Optional[str] = None,
    protocol: Optional[str] = None,
    action: Optional[str] = None
):
    # Fetch log details
    if log_type == "packets":
        conn = get_db_connection()
        cursor = conn.cursor()
        query = "SELECT * FROM packets"
        params = []
        conditions = []
        if search:
            conditions.append("(source_ip LIKE ? OR destination_ip LIKE ?)")
            params.append(f"%{search}%")
            params.append(f"%{search}%")
        if protocol and protocol != "ALL":
            conditions.append("protocol = ?")
            params.append(protocol)
        if action and action != "ALL":
            conditions.append("action = ?")
            params.append(action)
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY id DESC"
        cursor.execute(query, params)
        data = [dict(row) for row in cursor.fetchall()]
        conn.close()
    else:
        data = get_logs(search=search, limit=5000)

    # 1. Export as JSON
    if format == "json":
        json_str = json.dumps(data, indent=2)
        return StreamingResponse(
            iter([json_str]),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=firewall_{log_type}_export_{int(datetime.now().timestamp())}.json"}
        )

    # 2. Export as CSV
    elif format == "csv":
        if not data:
            # Empty stream
            return StreamingResponse(iter([""]), media_type="text/csv")
        
        keys = data[0].keys()
        
        def generate_csv():
            import io
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=keys)
            writer.writeheader()
            yield output.getvalue()
            
            for row in data:
                output = io.StringIO()
                writer = csv.DictWriter(output, fieldnames=keys)
                writer.writerow(row)
                yield output.getvalue()

        return StreamingResponse(
            generate_csv(),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=firewall_{log_type}_export_{int(datetime.now().timestamp())}.csv"}
        )
    
    # 3. Export as PDF/HTML printable layout (since PDF is specified, we output a print-optimized, extremely structured HTML report layout that renders beautifully and can be saved as PDF natively).
    elif format == "pdf":
        html_report = f"""
        <html>
        <head>
            <title>Personal Firewall Security Incident & Log Audit Report</title>
            <style>
                body {{ font-family: 'Courier New', Courier, monospace; margin: 40px; background-color: #fff; color: #000; }}
                h1 {{ border-bottom: 2px solid #000; padding-bottom: 10px; font-size: 24px; }}
                h2 {{ font-size: 16px; margin-top: 30px; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 11px; }}
                th, td {{ border: 1px solid #ddd; padding: 6px 10px; text-align: left; }}
                th {{ background-color: #f2f2f2; font-weight: bold; }}
                .meta {{ font-size: 12px; margin-bottom: 20px; line-height: 1.5; }}
            </style>
        </head>
        <body onload="window.print()">
            <h1>FIREWALL AUDIT LOG REPORT</h1>
            <div class="meta">
                <strong>Generation Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>
                <strong>Log Source:</strong> Database Table [{log_type}]<br/>
                <strong>Total Records:</strong> {len(data)}<br/>
                <strong>Export Integrity Checksum:</strong> SHA-256 (Simulated Secure)
            </div>
            <table>
                <thead>
                    <tr>
                        {"".join([f"<th>{k.upper()}</th>" for k in data[0].keys()]) if data else "<th>No Records Found</th>"}
                    </tr>
                </thead>
                <tbody>
                    {"".join([f"<tr>{''.join([f'<td>{v}</td>' for v in row.values()])}</tr>" for row in data]) if data else "<tr><td>No data available.</td></tr>"}
                </tbody>
            </table>
        </body>
        </html>
        """
        return StreamingResponse(
            iter([html_report]),
            media_type="text/html",
            headers={"Content-Disposition": f"attachment; filename=firewall_{log_type}_report_{int(datetime.now().timestamp())}.html"}
        )

# 6. WebSocket routing for real-time dashboards
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        # Send initial data dump to speed up UI loading
        initial_rules = get_rules()
        initial_packets = get_packets(limit=50)
        initial_threats = get_threats(limit=20)
        
        await websocket.send_json({
            "type": "init",
            "data": {
                "rules": initial_rules,
                "packets": initial_packets,
                "threats": initial_threats,
                "simulation_mode": engine.simulation_mode,
                "running": engine.running
            }
        })
        
        # Keep connection open and handle client requests (if any)
        while True:
            data = await websocket.receive_text()
            # Handle client-to-server WS messages if needed
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        manager.disconnect(websocket)

# 7. Serve Frontend index
@app.get("/")
def get_index():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))

# Mount static resources (JS, CSS, assets)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=False)
