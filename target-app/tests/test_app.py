import os
import pytest

os.environ["DB_PATH"] = "/tmp/test_app.db"
os.environ["API_KEY"] = "test-key-123"
os.environ["FLASK_DEBUG"] = "false"

from src.app import app, init_db


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        init_db()
        yield client


def auth_headers():
    return {"X-API-Key": "test-key-123"}


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.get_json()["status"] == "ok"


def test_create_user(client):
    r = client.post(
        "/api/users",
        json={"username": "alice", "password": "s3cur3p@ss"},
        headers=auth_headers(),
    )
    assert r.status_code == 201
    assert r.get_json()["username"] == "alice"


def test_create_user_duplicate(client):
    payload = {"username": "bob", "password": "pass123"}
    client.post("/api/users", json=payload, headers=auth_headers())
    r = client.post("/api/users", json=payload, headers=auth_headers())
    assert r.status_code == 409


def test_get_user(client):
    client.post(
        "/api/users",
        json={"username": "carol", "password": "pass"},
        headers=auth_headers(),
    )
    r = client.get("/api/users/carol", headers=auth_headers())
    assert r.status_code == 200
    assert r.get_json()["username"] == "carol"


def test_get_user_not_found(client):
    r = client.get("/api/users/nobody", headers=auth_headers())
    assert r.status_code == 404


def test_ingest_report(client):
    payload = {
        "commit_sha": "abc123def456",
        "branch": "main",
        "risk_score": 15,
        "gate_passed": True,
        "findings": {"secrets": 0, "cves": 0, "sast": 2, "container": 0},
    }
    r = client.post("/api/reports", json=payload, headers=auth_headers())
    assert r.status_code == 201


def test_list_reports(client):
    r = client.get("/api/reports", headers=auth_headers())
    assert r.status_code == 200
    assert isinstance(r.get_json(), list)


def test_unauthorized(client):
    r = client.get("/api/users/alice")
    assert r.status_code == 401


def test_invalid_role(client):
    r = client.post(
        "/api/users",
        json={"username": "hacker", "password": "pw", "role": "admin"},
        headers=auth_headers(),
    )
    assert r.status_code == 400
