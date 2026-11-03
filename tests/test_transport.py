"""HTTPS enforcement and response headers."""
import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
from app.config import Settings
from app.main import create_app


def secure_client(db, settings, https_origin=True):
    s = Settings(**{**settings.__dict__, "require_https": True, "cors_origins": ("https://console.example.org",) if https_origin else settings.cors_origins})
    return TestClient(create_app(s, db), follow_redirects=False)


def test_plain_http_get_is_redirected(db, settings):
    r = secure_client(db, settings).get("/api/queue?x=1", headers={"host": "api.example.org"})
    assert r.status_code == 308 and r.headers["location"] == "https://api.example.org/api/queue?x=1"


def test_plain_http_login_is_refused_before_it_is_read(db, settings):
    r = secure_client(db, settings).post("/api/staff/login", json={"email": "a@b.co", "password": "x" * 12})
    assert r.status_code == 403 and "HTTPS" in r.json()["detail"]


def test_https_request_works_and_gets_hsts(db, settings):
    c = TestClient(create_app(Settings(**{**settings.__dict__, "require_https": True, "cors_origins": ("https://console.example.org",)}), db), base_url="https://api.example.org")
    r = c.post("/api/staff/login", json={"email": "root@clinic.io", "password": "root-password-1"})
    assert r.status_code == 200
    assert "max-age" in r.headers["strict-transport-security"]
    assert r.headers["cache-control"] == "no-store" and r.headers["x-content-type-options"] == "nosniff"


def test_health_check_exempt(db, settings):
    assert secure_client(db, settings).get("/health").status_code == 200


def test_plain_websocket_refused(db, settings):
    c = secure_client(db, settings)
    with pytest.raises(WebSocketDisconnect) as e:
        with c.websocket_connect("/api/ws/queue") as ws:
            ws.receive_text()
    assert e.value.code == 4403


def test_https_requires_https_origins(db, settings):
    with pytest.raises(RuntimeError, match="non-https"):
        secure_client(db, settings, https_origin=False)


def test_dev_mode_unchanged(client):
    r = client.get("/health")
    assert r.status_code == 200 and "strict-transport-security" not in r.headers and r.headers["x-frame-options"] == "DENY"
