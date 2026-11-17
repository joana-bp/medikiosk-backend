"""Patient usernames: set at mobile sign-up or when staff register a patient, and usable (instead of the email) to sign in."""
from conftest import PATIENT, H


def _signup(client, **kw):
    return client.post("/api/patient/signup", json={**PATIENT, **kw})


def test_mobile_signup_with_username_is_stored_lowercase(client):
    r = _signup(client, username="  Ana.Cruz ")
    assert r.status_code == 201, r.text
    assert r.json()["patient"]["username"] == "ana.cruz"


def test_username_is_required_on_signup_and_when_staff_register_a_patient(client, root):
    no_username = {k: v for k, v in PATIENT.items() if k != "username"}
    assert client.post("/api/patient/signup", json=no_username).status_code == 422
    assert client.post("/api/patient/signup", json={**no_username, "username": ""}).status_code == 422
    assert client.post("/api/patients", json=no_username, headers=root).status_code == 422


def test_bad_usernames_are_refused_on_signup(client):
    for i, bad in enumerate(("ab", "has space", "ana@example.com", "-start", "x" * 31)):
        assert _signup(client, email=f"bad{i}@example.com", username=bad).status_code == 422, bad


def test_duplicate_username_on_signup_is_refused(client):
    assert _signup(client, username="ana").status_code == 201
    r = _signup(client, email="other@example.com", username="ANA")
    assert r.status_code == 409 and "username" in r.json()["detail"]


def test_patient_signs_in_with_username_or_email(client):
    _signup(client, username="ana.c")
    for who in ("ana.c", "ANA.C", "ana@example.com", "Ana@Example.com"):
        r = client.post("/api/patient/login", json={"identifier": who, "password": PATIENT["password"]})
        assert r.status_code == 200 and r.json().get("token"), (who, r.text)


def test_old_email_key_still_works_for_patients(client):
    _signup(client, username="ana.c")
    assert client.post("/api/patient/login", json={"email": "ana@example.com", "password": PATIENT["password"]}).status_code == 200


def test_wrong_password_or_unknown_username_for_patients(client):
    _signup(client, username="ana.c")
    assert client.post("/api/patient/login", json={"identifier": "ana.c", "password": "nope-nope"}).status_code == 401
    assert client.post("/api/patient/login", json={"identifier": "ghost", "password": PATIENT["password"]}).status_code == 401


def test_staff_register_a_patient_with_a_username(client, root, nurse):
    for who in (root, nurse):
        body = {**PATIENT, "email": f"{'r' if who is root else 'n'}@example.com", "username": "Reg.Pat" if who is root else "nurse.pat"}
        r = client.post("/api/patients", json=body, headers=who)
        assert r.status_code == 201, r.text
        assert r.json()["username"] == body["username"].lower()
    dup = client.post("/api/patients", json={**PATIENT, "email": "z@example.com", "username": "reg.pat"}, headers=root)
    assert dup.status_code == 409 and "username" in dup.json()["detail"]


def test_staff_can_add_or_change_a_patient_username_and_search_by_it(client, root):
    pid = client.post("/api/patients", json={**PATIENT, "email": "q@example.com", "username": "first.name"}, headers=root).json()["id"]
    r = client.patch(f"/api/patients/{pid}", json={"username": "findme"}, headers=root)
    assert r.status_code == 200 and r.json()["username"] == "findme"
    rows = client.get("/api/patients?search=findme", headers=root).json()
    assert [x["id"] for x in rows] == [pid]


def test_patient_can_set_their_own_username_but_not_take_anothers(client):
    _signup(client, username="taken")
    pid, h = make_second(client)
    assert client.patch("/api/patient/me", json={"username": "taken"}, headers=h).status_code == 409
    r = client.patch("/api/patient/me", json={"username": "mine"}, headers=h)
    assert r.status_code == 200 and r.json()["username"] == "mine"
    assert client.post("/api/patient/login", json={"identifier": "mine", "password": PATIENT["password"]}).status_code == 200


def make_second(client):
    r = _signup(client, email="second@example.com", username="second.pt")
    assert r.status_code == 201, r.text
    return r.json()["patient"]["id"], H(r.json()["token"])
