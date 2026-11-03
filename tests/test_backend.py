import hashlib, re, uuid
import pytest
from conftest import H, PATIENT, make_patient, make_staff, payload, staff_auth, staff_login
from app.ingest import process_visit

ID = lambda: str(uuid.uuid4())
def feed(db, tier, **kw):
    m = ID(); process_visit(db, f"medikiosk/{kw.get('kiosk', 'K-01')}/vitals/{tier.lower()}", payload(m, tier, **kw)); return m


# ---------------- ingest ----------------
def test_store_then_duplicate(db):
    m = ID()
    assert process_visit(db, "medikiosk/K-01/vitals/low", payload(m))[1] == {"message_id": m, "status": "stored"}
    assert process_visit(db, "medikiosk/K-01/vitals/low", payload(m))[1]["status"] == "duplicate"
    assert db.visits.count_documents({}) == 1


def test_priority_comes_from_tier_not_payload(db):
    m = ID(); process_visit(db, "medikiosk/K-01/vitals/high", payload(m, "High", priority=0))
    assert db.visits.find_one({"_id": m})["effective_priority"] == 3


def test_bad_values_rejected_and_acked(db):
    m = ID()
    bad = payload(m, vitals={"spo2": 250, "systolic": 120, "heart_rate": 70, "temperature": 36, "respiratory_rate": 16})
    assert process_visit(db, "medikiosk/K-01/vitals/low", bad)[1]["status"] == "rejected"
    assert db.visits.count_documents({}) == 0 and db.rejected_messages.count_documents({}) == 1


def test_kiosk_cannot_post_as_another_kiosk(db):
    assert process_visit(db, "medikiosk/K-02/vitals/low", payload(ID(), kiosk="K-01"))[1]["status"] == "rejected"


def test_unreadable_messages_dropped_without_ack(db):
    assert process_visit(db, "medikiosk/K-01/vitals/low", b"not json") is None
    assert process_visit(db, "medikiosk/K-01/vitals/low", b'{"kiosk_id":"../x","message_id":"abc"}') is None


def test_review_reasons(db):
    m = feed(db, "Normal", in_range=False, quality={"rr_level": "ESTIMATE"})
    assert db.visits.find_one({"_id": m})["review_reasons"] == ["outside_trained_range", "breathing_rate_is_estimate"]


# ---------------- queue + override (clinic staff) ----------------
def test_queue_is_tier_first_then_arrival(db, client, nurse):
    ids = {n: feed(db, t, minutes_ago=a) for n, t, a in [("a", "Low", 30), ("b", "High", 20), ("c", "Normal", 40), ("d", "High", 10), ("e", "Medium", 5)]}
    items = client.get("/api/queue", headers=nurse).json()["items"]
    assert [i["id"] for i in items] == [ids[n] for n in "bdeac"]
    assert items[0]["wait_minutes"] in (19, 20) and items[0]["patient_name"] == "Guest"


def test_override_reorders_needs_reason_and_is_audited(db, client, nurse, root):
    a = feed(db, "Low", minutes_ago=30); b = feed(db, "Normal", minutes_ago=5)
    assert client.post(f"/api/visits/{b}/override", json={"tier": "High", "reason": "x"}, headers=nurse).status_code == 422
    assert client.post(f"/api/visits/{b}/override", json={"tier": "High", "reason": "looks unwell, pale"}, headers=nurse).status_code == 200
    top = client.get("/api/queue", headers=nurse).json()["items"][0]
    assert top["id"] == b and top["overridden"] and top["model_tier"] == "Normal" and top["tier"] == "High"
    log = [l for l in client.get("/api/audit-logs", headers=root).json() if l["actor"] == "TIER OVERRIDE"][0]
    assert log["role"] == "nurse1@clinic.io" and log["target"] == b and log["severity"] == "Warning"


def test_done_leaves_active_queue(db, client, nurse):
    m = feed(db, "Low")
    client.post(f"/api/visits/{m}/status", json={"status": "done"}, headers=nurse)
    assert client.get("/api/queue", headers=nurse).json()["count"] == 0


# ---------------- who can do what ----------------
def test_patient_cannot_reach_staff_side(client):
    _, p = make_patient(client)
    for path in ("/api/queue", "/api/visits", "/api/patients", "/api/staff", "/api/kiosks", "/api/audit-logs", "/api/dashboard/stats"):
        assert client.get(path, headers=p).status_code == 403, path


def test_clinic_staff_permissions(client, nurse):
    assert client.get("/api/queue", headers=nurse).status_code == 200
    assert client.get("/api/kiosks", headers=nurse).status_code == 200
    assert client.post("/api/patients", json={**PATIENT, "email": "n@x.io"}, headers=nurse).status_code == 201
    for method, path in (("get", "/api/staff"), ("get", "/api/audit-logs"), ("get", "/api/dashboard/recent-activity")):
        assert getattr(client, method)(path, headers=nurse).status_code == 403, path
    assert client.post("/api/kiosks", json={"name": "X"}, headers=nurse).status_code == 403
    pid = client.get("/api/patients", headers=nurse).json()[0]["id"]
    assert client.delete(f"/api/patients/{pid}", headers=nurse).status_code == 403


def test_admin_manages_but_never_sees_clinical_data(db, client, admin, root):
    pid, _ = make_patient(client)
    feed(db, "High", patient_ref=pid)
    for path in ("/api/queue", "/api/visits", f"/api/vitals/history?patientId={pid}"):
        assert client.get(path, headers=admin).status_code == 403, path
    d = client.get(f"/api/patients/{pid}", headers=admin).json()
    assert d["visitCount"] == 1 and d["visitHistory"] == []
    assert client.post("/api/staff", json={"name": "N", "email": "n2@x.io", }, headers=admin).status_code == 201
    assert client.post("/api/staff", json={"name": "A", "email": "a2@x.io", "accessRole": "admin"}, headers=admin).status_code == 403
    assert client.get("/api/audit-logs", headers=admin).status_code == 403
    assert client.post("/api/kiosks", json={"name": "Lobby", "clinic": "C"}, headers=admin).status_code == 201
    assert all(s["accessRole"] == "clinic_staff" for s in client.get("/api/staff", headers=admin).json())   # admin does not see admin accounts
    assert client.delete(f"/api/patients/{pid}", headers=admin).status_code == 403          # only a super admin deletes patients
    assert client.delete(f"/api/patients/{pid}", headers=root).json()["deletedCheckIns"] == 1


def test_super_admin_has_audit_and_admin_accounts_but_no_clinical_data(client, root):
    assert client.get("/api/queue", headers=root).status_code == 403
    assert client.get("/api/audit-logs", headers=root).status_code == 200
    assert client.post("/api/staff", json={"name": "A", "email": "a3@x.io", "accessRole": "admin"}, headers=root).status_code == 201


def test_nurse_can_read_a_patients_clinical_history(db, client, nurse):
    pid, _ = make_patient(client)
    feed(db, "Medium", patient_ref=pid)
    d = client.get(f"/api/patients/{pid}", headers=nurse).json()
    assert d["visitHistory"][0]["status"] == "Medium" and d["lastVisit"]
    assert client.get(f"/api/vitals/history?patientId={pid}", headers=nurse).status_code == 200


# ---------------- accounts ----------------
def test_temporary_password_flow_and_hashing(client, root, db):
    r = client.post("/api/staff", json={"name": "New Nurse", "email": "New@Clinic.io", "clinic": "C"}, headers=root).json()
    assert r["mustChangePassword"] and r["initials"] == "NN" and r["email"] == "new@clinic.io"
    tmp = r["temporaryPassword"]
    assert tmp not in db.users.find_one({"email": "new@clinic.io"})["password_hash"]
    h = staff_auth(client, "new@clinic.io", tmp)
    assert client.post("/api/staff/change-password", json={"currentPassword": "wrong", "newPassword": "brand-new-pass"}, headers=h).status_code == 400
    assert client.post("/api/staff/change-password", json={"currentPassword": tmp, "newPassword": "brand-new-pass"}, headers=h).status_code == 200
    assert staff_login(client, "new@clinic.io", tmp).status_code == 401
    assert staff_login(client, "new@clinic.io", "brand-new-pass").json()["staff"]["mustChangePassword"] is False


def test_lockout_after_five_wrong_passwords(client, root):
    for _ in range(5):
        assert staff_login(client, "root@clinic.io", "nope").status_code == 401
    assert staff_login(client, "root@clinic.io", "root-password-1").status_code == 429       # even the right password is refused for now


def test_suspended_account_locked_out_at_once(client, root, nurse):
    sid = [s for s in client.get("/api/staff", headers=root).json() if s["email"] == "nurse1@clinic.io"][0]["id"]
    assert client.get("/api/queue", headers=nurse).status_code == 200
    assert client.patch(f"/api/staff/{sid}", json={"status": "Suspended"}, headers=root).json()["status"] == "Suspended"
    assert client.get("/api/queue", headers=nurse).status_code == 401
    assert staff_login(client, "nurse1@clinic.io", "x").status_code == 401


def test_protected_accounts(client, root):
    me = client.get("/api/staff", headers=root).json()[0]["id"]
    assert client.delete(f"/api/staff/{me}", headers=root).status_code == 400
    assert client.patch(f"/api/staff/{me}", json={"status": "Suspended"}, headers=root).status_code == 400


def test_bad_token_and_unauthenticated(client):
    assert client.get("/api/queue").status_code == 401
    assert client.get("/api/queue", headers=H("abc.def.ghi")).status_code == 401


# ---------------- patients and the permanent QR ----------------
def test_patient_signup_login_profile(client, db):
    pid, h = make_patient(client)
    assert pid.startswith("P-") and client.get("/api/patient/me", headers=h).json()["age"] >= 27
    assert PATIENT["password"] not in db.patients.find_one({"_id": pid})["password_hash"]
    assert client.post("/api/patient/signup", json=PATIENT).status_code == 409                  # same email again
    assert client.post("/api/patient/login", json={"email": "ANA@example.com", "password": PATIENT["password"]}).status_code == 200
    assert client.post("/api/patient/login", json={"email": "ana@example.com", "password": "wrong-pass"}).status_code == 401


def test_qr_login_regenerate_and_storage(client, db, nurse):
    pid, ph = make_patient(client)
    tok = client.get("/api/patient/me/qr-token", headers=ph).json()["qrToken"]
    assert re.fullmatch(r"[0-9a-f]{36}", tok)
    doc = db.patients.find_one({"_id": pid})
    assert tok not in str(doc) and doc["qr_hash"] == hashlib.sha256(tok.encode()).hexdigest()   # stored only hashed + encrypted
    ok = client.post("/api/patient/login-qr", json={"qrToken": "MEDIKIOSK:" + tok})
    assert ok.status_code == 200 and ok.json()["patient"]["id"] == pid
    assert client.get(f"/api/patients/{pid}/qr-token", headers=nurse).json()["qrToken"] == tok
    new = client.post(f"/api/patients/{pid}/qr-token", headers=nurse).json()["qrToken"]
    assert new != tok
    assert client.post("/api/patient/login-qr", json={"qrToken": "MEDIKIOSK:" + tok}).status_code == 401     # old printed code is dead
    assert client.post("/api/patient/login-qr", json={"qrToken": "MEDIKIOSK:" + new}).status_code == 200
    assert client.post("/api/patient/login-qr", json={"qrToken": "MEDIKIOSK:123"}).status_code == 401


def test_qr_guessing_is_rate_limited(client):
    for _ in range(5):
        assert client.post("/api/patient/login-qr", json={"qrToken": "MEDIKIOSK:" + "0" * 36}).status_code == 401
    assert client.post("/api/patient/login-qr", json={"qrToken": "MEDIKIOSK:" + "0" * 36}).status_code == 429


def test_patient_sees_only_own_history_without_tier(db, client):
    p1, h1 = make_patient(client); p2, h2 = make_patient(client, email="b@example.com")
    feed(db, "High", patient_ref=p1); feed(db, "Low", patient_ref=p2)
    items = client.get(f"/api/vitals/history?patientId={p1}", headers=h1).json()
    assert len(items) == 1 and items[0]["status"] == "Completed" and items[0]["readings"]["bloodPressure"]["systolic"] == 120
    assert "High" not in str(items) and "tier" not in str(items).lower() and "probab" not in str(items).lower()
    assert client.get(f"/api/vitals/history?patientId={p2}", headers=h1).status_code == 403


# ---------------- kiosks and dashboard ----------------
def test_kiosks_lifecycle_and_activity(db, client, admin, nurse):
    feed(db, "Low", kiosk="K-77")
    k = {x["id"]: x for x in client.get("/api/kiosks", headers=nurse).json()}
    assert k["K-77"]["registered"] is False and k["K-77"]["today"] == 1
    new = client.post("/api/kiosks", json={"name": "Lobby", "clinic": "North"}, headers=admin).json()
    assert new["id"].startswith("K-") and new["registered"]
    assert client.patch(f"/api/kiosks/{new['id']}", json={"status": "Maintenance"}, headers=admin).json()["status"] == "Maintenance"
    assert client.delete(f"/api/kiosks/{new['id']}", headers=admin).status_code == 200
    assert new["id"] not in [x["id"] for x in client.get("/api/kiosks", headers=admin).json()]
    assert new["id"] in [x["id"] for x in client.get("/api/kiosks?removed=true", headers=admin).json()]
    assert client.post(f"/api/kiosks/{new['id']}/restore", headers=admin).status_code == 200
    act = client.get("/api/kiosks/activity", headers=admin).json()
    assert act[0]["patient"] == "Guest" and set(act[0]) == {"date", "time", "kioskId", "clinic", "kiosk", "event", "patient"}      # no vitals or tiers in this feed
    d = act[0]["date"]
    assert len(client.get(f"/api/kiosks/activity?day={d}", headers=admin).json()) == len(act)         # same calendar day
    assert client.get("/api/kiosks/activity?day=2000-01-01", headers=admin).json() == []              # another day: nothing
    assert client.get("/api/kiosks/activity?clinic=Nowhere", headers=admin).json() == []
    assert client.get("/api/kiosks/activity?kiosk=K-NOPE", headers=admin).json() == []
    assert client.get("/api/kiosks/activity?day=notadate", headers=admin).status_code == 422


def test_dashboard_numbers_and_recent_activity(db, client, root, admin, nurse):
    make_patient(client); feed(db, "Low")
    s = client.get("/api/dashboard/stats", headers=admin).json()
    assert s["patientRecords"] == 1 and s["clinicalStaff"] == 1 and s["checkInsToday"] == 1
    assert client.get("/api/dashboard/stats", headers=nurse).status_code == 200
    ra = client.get("/api/dashboard/recent-activity", headers=admin).json()
    assert ra and all(set(r) == {"label", "meta", "status"} for r in ra)
    assert client.get("/api/dashboard/recent-activity", headers=nurse).status_code == 403


def test_patient_self_service(client):
    r = client.post("/api/patient/signup", json={"firstName": "Ana", "lastName": "Cruz", "email": "ana@x.io", "password": "password123"})
    h = {"Authorization": "Bearer " + r.json()["token"]}
    assert client.patch("/api/patient/me", json={"address": "Cebu"}, headers=h).json()["address"] == "Cebu"
    assert client.post("/api/patient/change-password", json={"currentPassword": "bad", "newPassword": "newpass1234"}, headers=h).status_code == 400
    assert client.post("/api/patient/change-password", json={"currentPassword": "password123", "newPassword": "newpass1234"}, headers=h).status_code == 200
    assert client.post("/api/patient/login", json={"email": "ana@x.io", "password": "newpass1234"}).status_code == 200


def test_critical_floor_raises_and_lowering_needs_confirmation(client, db, nurse):
    from app.ingest import process_visit
    import json
    d = json.loads(payload("cccccccc-0001", "Normal"))
    d.update(critical_flags=["spo2<=91"], outside_range=["respiratory_rate"], escalation_tier="Medium", critical_rules_version="provisional-test")
    process_visit(db, "medikiosk/K-01/vitals/x", json.dumps(d).encode())
    q = client.get("/api/queue", headers=nurse).json()["items"][0]
    assert q["tier"] == "Medium" and q["model_tier"] == "Normal" and q["escalated"] and q["outside_range"] == ["respiratory_rate"] and q["critical_rules_version"] == "provisional-test"
    low = client.post(f"/api/visits/{q['id']}/override", json={"tier": "Low", "reason": "re-measured, finger was loose"}, headers=nurse)
    assert low.status_code == 409
    ok = client.post(f"/api/visits/{q['id']}/override", json={"tier": "Low", "reason": "re-measured, finger was loose", "confirmLower": True}, headers=nurse)
    assert ok.status_code == 200
    # a floor never lowers a model tier that is already higher
    d2 = json.loads(payload("cccccccc-0002", "High")); d2.update(escalation_tier="Medium")
    process_visit(db, "medikiosk/K-01/vitals/y", json.dumps(d2).encode())
    top = client.get("/api/queue", headers=nurse).json()["items"][0]
    assert top["tier"] == "High" and not top["escalated"]
