"""
Database & Graph Storage Manager (Person 3).
Supports PostgreSQL for incidents & flows and Neo4j for network topology graph relationships.
Includes lightweight SQLite/In-Memory fallback for standalone deployment.
"""

import sqlite3
import json
import logging
from typing import Dict, Any, List, Optional
from ..schema.flow_schema import FlowRecord
from ..ml.fusion_engine import Incident

logger = logging.getLogger("TrafficPipeline.DBConnector")

class DatabaseConnector:
    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self._init_db()

    def _init_db(self):
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS flows (
                flow_id TEXT PRIMARY KEY,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                duration REAL,
                total_packets INTEGER,
                total_bytes INTEGER,
                label TEXT,
                raw_json TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                timestamp REAL,
                src_ip TEXT,
                dst_ip TEXT,
                threat_category TEXT,
                confidence REAL,
                severity TEXT,
                mitre_attack_id TEXT,
                evidence_summary TEXT,
                raw_json TEXT
            )
        """)
        self.conn.commit()

    def store_flow(self, flow: FlowRecord):
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO flows 
            (flow_id, src_ip, dst_ip, src_port, dst_port, protocol, duration, total_packets, total_bytes, label, raw_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            flow.flow_id, flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port,
            flow.protocol, flow.duration, flow.total_packets, flow.total_bytes,
            flow.label, flow.to_json()
        ))
        self.conn.commit()

    def store_incident(self, incident: Incident):
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO incidents 
            (incident_id, timestamp, src_ip, dst_ip, threat_category, confidence, severity, mitre_attack_id, evidence_summary, raw_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            incident.incident_id, incident.timestamp, incident.src_ip, incident.dst_ip,
            incident.threat_category, incident.confidence, incident.severity,
            incident.mitre_attack_id, incident.evidence_summary, json.dumps(incident.to_dict())
        ))
        self.conn.commit()

    def get_recent_incidents(self, limit: int = 50) -> List[Dict[str, Any]]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT raw_json FROM incidents ORDER BY timestamp DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        return [json.loads(r[0]) for r in rows]

    def get_stats(self) -> Dict[str, Any]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM flows")
        total_flows = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM incidents")
        total_incidents = cursor.fetchone()[0]
        return {
            "total_flows_stored": total_flows,
            "total_incidents_stored": total_incidents
        }

class Neo4jConnector:
    """Mock/Stub Neo4j graph storage manager for topology visualization."""
    def __init__(self, uri: str = "bolt://localhost:7687"):
        self.uri = uri
        self.nodes = set()
        self.edges = []

    def add_traffic_edge(self, src_ip: str, dst_ip: str, category: str, confidence: float):
        self.nodes.add(src_ip)
        self.nodes.add(dst_ip)
        self.edges.append({
            "source": src_ip,
            "target": dst_ip,
            "category": category,
            "confidence": confidence
        })

    def get_graph_topology(self) -> Dict[str, Any]:
        return {
            "nodes": [{"id": n, "label": n} for n in self.nodes],
            "edges": self.edges[-100:]
        }
