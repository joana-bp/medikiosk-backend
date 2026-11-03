"""Live queue push over WebSocket: who may listen, and that a change reaches them."""
import json, pytest
from fastapi.testclient import TestClient
from app.main import create_app
from starlette.websockets import WebSocketDisconnect
from conftest import H, staff_auth, make_staff, payload
from app.ingest import process_visit

@pytest.fixture
def client(db, settings):
    """Entering the TestClient starts the app's event loop (the lifespan), which the live hub needs."""
    with TestClient(create_app(settings, db)) as c:
        yield c


ORIGIN = {"origin": "http://localhost:5173"}


def token_of(auth):
    return auth["Authorization"].split()[1]


def open_socket(client, token, headers=ORIGIN):
    ws = client.websocket_connect("/api/ws/queue", headers=headers)
    s = ws.__enter__()
    s.send_text(json.dumps({"token": token}))
    return ws, s


def test_clinic_staff_gets_ready_then_pushes(client, db):
    root = staff_auth(client, "root@clinic.io", "root-password-1")
    nina = make_staff(client, root, "nina@clinic.io")
    ws, s = open_socket(client, token_of(nina))
    try:
        assert s.receive_json() == {"type": "ready"}
        process_visit(db, "medikiosk/K-01/vitals/low", payload("a" * 36))
        client.app.state.hub.publish()                        # ingest calls this after a stored visit
        assert s.receive_json() == {"type": "queue_changed"}
    finally:
        ws.__exit__(None, None, None)


def test_override_pushes_to_other_screens(client, db):
    root = staff_auth(client, "root@clinic.io", "root-password-1")
    nina = make_staff(client, root, "nina@clinic.io")
    process_visit(db, "medikiosk/K-01/vitals/low", payload("b" * 36))
    ws, s = open_socket(client, token_of(nina))
    try:
        assert s.receive_json()["type"] == "ready"
        r = client.post("/api/visits/" + "b" * 36 + "/override", json={"tier": "High", "reason": "looks unwell"}, headers=nina)
        assert r.status_code == 200, r.text
        assert s.receive_json() == {"type": "queue_changed"}
    finally:
        ws.__exit__(None, None, None)


@pytest.mark.parametrize("who", ["bad", "admin", "none"])
def test_refused(client, who):
    root = staff_auth(client, "root@clinic.io", "root-password-1")
    token = {"bad": "not-a-token", "admin": token_of(make_staff(client, root, "ada@clinic.io", "admin")), "none": ""}[who]
    ws, s = open_socket(client, token)
    try:
        with pytest.raises(WebSocketDisconnect) as e:
            s.receive_json()
        assert e.value.code == 4401
    finally:
        ws.__exit__(None, None, None)


def test_other_origin_refused(client):
    with pytest.raises(WebSocketDisconnect) as e:
        with client.websocket_connect("/api/ws/queue", headers={"origin": "http://evil.example"}) as s:
            s.receive_json()
    assert e.value.code == 4403


def test_socket_carries_no_patient_data(client, db):
    root = staff_auth(client, "root@clinic.io", "root-password-1")
    nina = make_staff(client, root, "nina@clinic.io")
    ws, s = open_socket(client, token_of(nina))
    try:
        s.receive_json()
        client.app.state.hub.publish()
        assert set(s.receive_json()) == {"type"}
    finally:
        ws.__exit__(None, None, None)
