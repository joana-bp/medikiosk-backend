"""Checks the collection rules in app/db.py against the documents the backend really writes."""
import uuid
from datetime import datetime
from conftest import PATIENT, make_patient, make_staff, payload
from app.db import COLLECTIONS, VALIDATORS, init_database
from app.ingest import process_visit

TYPES = {"string": lambda v: isinstance(v, str), "bool": lambda v: isinstance(v, bool), "date": lambda v: isinstance(v, datetime),
         "object": lambda v: isinstance(v, dict), "null": lambda v: v is None, "int": lambda v: isinstance(v, int) and not isinstance(v, bool),
         "long": lambda v: isinstance(v, int) and not isinstance(v, bool), "array": lambda v: isinstance(v, list)}


def problems(schema, doc):
    """A small stand-in for MongoDB's $jsonSchema check (required fields, types, allowed values)."""
    s, out = schema["$jsonSchema"], []
    out += [f"missing {k}" for k in s["required"] if k not in doc]
    for k, rule in s["properties"].items():
        if k not in doc:
            continue
        v = doc[k]
        if "enum" in rule and v not in rule["enum"]:
            out.append(f"{k}={v!r} not allowed")
        if "bsonType" in rule:
            t = rule["bsonType"] if isinstance(rule["bsonType"], list) else [rule["bsonType"]]
            if not any(TYPES[x](v) for x in t):
                out.append(f"{k}={v!r} is not {t}")
    return out


def test_every_document_the_backend_writes_passes_the_rules(db, client, root):
    pid, _ = make_patient(client)
    make_staff(client, root, "nurse@clinic.io")
    client.post("/api/kiosks", json={"name": "Lobby", "clinic": "North"}, headers=root)
    process_visit(db, "medikiosk/K-01/vitals/low", payload(str(uuid.uuid4()), "Low", patient_ref=pid))
    process_visit(db, "medikiosk/K-09/vitals/high", payload(str(uuid.uuid4()), "High", kiosk="K-09"))        # unregistered kiosk, guest
    client.post("/api/patient/login", json={"email": PATIENT["email"], "password": "wrong-pass-1"})
    checked = 0
    for name, schema in VALIDATORS.items():
        for doc in db[name].find({}):
            assert problems(schema, doc) == [], (name, doc.get("_id"), problems(schema, doc))
            checked += 1
    assert checked >= 8


def test_rules_catch_a_bad_document():
    bad = {"kiosk_id": "K-01", "captured_at": datetime.now(), "received_at": datetime.now(), "vitals": {}, "model_tier": "Urgent",
           "effective_tier": "Low", "effective_priority": "3", "status": "waiting"}
    p = problems(VALIDATORS["visits"], bad)
    assert any("model_tier" in x for x in p) and any("effective_priority" in x for x in p)


def test_init_creates_every_collection_and_can_be_run_twice(db):
    first = init_database(db, validators=False)
    assert sorted(db.list_collection_names()) >= sorted(COLLECTIONS) and all("created" in x for x in first)
    second = init_database(db, validators=False)
    assert all("already there" in x for x in second)
    assert "email_1" in db.users.index_information() and "qr_hash_1" in db.patients.index_information()


def test_staff_have_no_position_and_role_reads_in_words(client, root):
    r = client.post("/api/staff", json={"name": "Dr Who", "email": "who@clinic.io", "role": "Doctor"}, headers=root).json()   # old field is ignored
    assert "position" not in r and r["role"] == "Clinic Staff" and r["accessRole"] == "clinic_staff"
