import json, os, sys
from datetime import datetime, timedelta, timezone
import mongomock, pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from app.config import Settings
from app.main import create_app


@pytest.fixture
def db():
    return mongomock.MongoClient()["t"]


@pytest.fixture
def settings():
    return Settings(mongo_uri="mock", jwt_secret="s" * 40, qr_secret="q" * 40, mqtt_enabled=False,
                    superadmin_email="root@clinic.io", superadmin_password="root-password-1")


@pytest.fixture
def client(db, settings):
    return TestClient(create_app(settings, db))


def payload(mid, tier="Low", kiosk="K-01", minutes_ago=0, patient_ref=None, in_range=True, **kw):
    prio = {"Normal": 0, "Low": 1, "Medium": 2, "High": 3}[tier]
    d = {"schema_version": 2, "message_id": mid, "kiosk_id": kiosk, "session_type": "guest" if not patient_ref else "patient",
         "patient_ref": patient_ref, "external_session_id": "s-" + mid[:4],
         "captured_at": (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat().replace("+00:00", "Z"),
         "vitals": {"spo2": 97, "systolic": 120, "diastolic": 80, "heart_rate": 75, "temperature": 36.8, "respiratory_rate": 16},
         "body": {"height_cm": 165, "weight_kg": 60, "bmi": 22}, "urgency": tier, "priority": prio,
         "probabilities": {"Normal": 0.1, "Low": 0.9, "Medium": 0, "High": 0}, "in_model_range": in_range,
         "critical_flags": [], "model_version": "logreg-squares-v1", "quality": {"rr_level": "CONFIRMED"}}
    d.update(kw)
    return json.dumps(d).encode()


def H(token):
    return {"Authorization": "Bearer " + token}


def staff_login(client, email, pw):
    return client.post("/api/staff/login", json={"email": email, "password": pw})


def staff_auth(client, email, pw):
    r = staff_login(client, email, pw)
    assert r.status_code == 200, r.text
    return H(r.json()["token"])


def make_staff(client, root, email, access="clinic_staff"):
    r = client.post("/api/staff", json={"name": email.split("@")[0].title(), "email": email, "clinic": "Test Clinic", "accessRole": access}, headers=root)
    assert r.status_code == 201, r.text
    return staff_auth(client, email, r.json()["temporaryPassword"])


PATIENT = {"firstName": "Ana", "lastName": "Cruz", "middleName": "L.", "address": "Canitoan", "birthday": "1998-04-02", "sex": "Female",
           "bloodType": "O+", "email": "ana@example.com", "password": "patient-pass-1"}


def make_patient(client, **kw):
    r = client.post("/api/patient/signup", json={**PATIENT, **kw})
    assert r.status_code == 201, r.text
    return r.json()["patient"]["id"], H(r.json()["token"])


@pytest.fixture
def root(client):
    return staff_auth(client, "root@clinic.io", "root-password-1")


@pytest.fixture
def nurse(client, root):
    return make_staff(client, root, "nurse1@clinic.io")


@pytest.fixture
def admin(client, root):
    return make_staff(client, root, "admin1@clinic.io", "admin")
