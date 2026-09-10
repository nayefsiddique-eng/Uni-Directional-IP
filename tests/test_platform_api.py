import pytest
from fastapi.testclient import TestClient
from src.platform.api_server import app

client = TestClient(app)

def test_api_health():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"

def test_api_stats():
    response = client.get("/api/v1/stats")
    assert response.status_code == 200
    data = response.json()
    assert "flows_processed" in data

def test_inject_attack_endpoint():
    response = client.post("/api/v1/inject-attack?category=c2_beaconing")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["category"] == "c2_beaconing"
    assert data["packets_generated"] > 0
