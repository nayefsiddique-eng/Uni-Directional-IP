"""
FastAPI REST & WebSocket Server.
Connects Passive Capture, Evidence Fusion, DB Storage, and Web SOC Analyst Dashboard.
"""

import os
import sys
import json
import asyncio
import logging
from typing import List, Dict, Any
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse

# Ensure root workspace is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from src.schema.flow_schema import FlowRecord
from src.features.flow_aggregator import FlowAggregator
from src.injector.attack_injector import SyntheticAttackInjector
from src.ml.fusion_engine import EvidenceFusionEngine, Incident
from src.platform.db_connector import DatabaseConnector, Neo4jConnector

logger = logging.getLogger("TrafficPipeline.APIServer")

app = FastAPI(
    title="Aegis Traffic Intelligence Platform",
    version="1.0.0",
    description="Backend API & WebSocket server for Aegis SOC Threat Intelligence Console"
)

db = DatabaseConnector()
neo4j = Neo4jConnector()
fusion = EvidenceFusionEngine()
aggregator = FlowAggregator()
injector = SyntheticAttackInjector()

# WebSocket Connection Manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in list(self.active_connections):
            try:
                await connection.send_text(message)
            except Exception:
                self.disconnect(connection)

manager = ConnectionManager()

# Mount Static Files
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/")
async def get_dashboard():
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return JSONResponse({"status": "API Server Active", "dashboard": "static index.html missing"})

@app.get("/styles.css")
async def get_css_direct():
    return FileResponse(os.path.join(static_dir, "styles.css"))

@app.get("/app.js")
@app.get("/main.js")
async def get_js_direct():
    main_js = os.path.join(static_dir, "main.js")
    if os.path.exists(main_js):
        return FileResponse(main_js, media_type="application/javascript")
    return FileResponse(os.path.join(static_dir, "app.js"), media_type="application/javascript")

@app.get("/favicon.ico")
async def get_favicon():
    return JSONResponse({"status": "ok"}, status_code=204)

@app.get("/api/v1/health")
async def get_health():
    return {
        "status": "healthy",
        "pipeline": "active",
        "fusion_engine": "operational",
        "active_websockets": len(manager.active_connections)
    }

@app.get("/api/v1/stats")
async def get_stats():
    db_stats = db.get_stats()
    return {
        "flows_processed": db_stats["total_flows_stored"],
        "incidents_detected": db_stats["total_incidents_stored"],
        "fusion_incidents": fusion.incidents_generated,
        "suppressed_alerts": fusion.suppressor.suppressed_count
    }

@app.get("/api/v1/incidents")
async def get_incidents(limit: int = 50):
    return db.get_recent_incidents(limit)

@app.get("/api/v1/topology")
async def get_topology():
    return neo4j.get_graph_topology()

@app.post("/api/v1/inject-attack")
async def inject_synthetic_attack(category: str = Query("ddos", description="Attack category to synthesize")):
    """Generates synthetic attack packets, passes them through pipeline & fusion engine, and broadcasts to dashboard."""
    attacks = injector.generate_all_attack_categories()
    if category not in attacks:
        return JSONResponse({"error": f"Invalid category '{category}'. Choose from {list(attacks.keys())}"}, status_code=400)

    packets = attacks[category]
    emitted_flows = []
    
    for pkt in packets:
        flow = aggregator.add_packet(pkt, label=category)
        if flow:
            emitted_flows.append(flow)
            
    flushed = aggregator.flush_all()
    emitted_flows.extend(flushed)

    incidents_created = []
    for flow in emitted_flows:
        db.store_flow(flow)
        
        # Broadcast flow to dashboard
        await manager.broadcast(json.dumps({"type": "flow", "data": flow.to_dict()}))
        
        # Evaluate ML Fusion
        incident = fusion.evaluate_flow(flow)
        if incident:
            db.store_incident(incident)
            neo4j.add_traffic_edge(incident.src_ip, incident.dst_ip, incident.threat_category, incident.confidence)
            incidents_created.append(incident.to_dict())
            
            # Broadcast incident to dashboard
            await manager.broadcast(json.dumps({"type": "incident", "data": incident.to_dict()}))

    return {
        "status": "success",
        "category": category,
        "packets_generated": len(packets),
        "flows_reconstructed": len(emitted_flows),
        "incidents_detected": len(incidents_created)
    }

@app.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
