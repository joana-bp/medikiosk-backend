import pymongo
from pymongo.errors import OperationFailure


def get_database(uri, name):
    if uri == "mock":                       # in-memory fake, for tests only
        import mongomock
        return mongomock.MongoClient()[name]
    import os
    return pymongo.MongoClient(uri, serverSelectionTimeoutMS=int(os.getenv("MONGO_TIMEOUT_MS", "30000")), tz_aware=True)[name]


def ensure_indexes(db):
    # visits._id IS the edge's message_id, so MongoDB itself refuses a second copy of the same message.
    db.visits.create_index([("status", 1), ("effective_priority", -1), ("captured_at", 1)])
    db.visits.create_index([("patient_ref", 1), ("captured_at", -1)])
    db.visits.create_index([("kiosk_id", 1), ("captured_at", -1)])
    db.users.create_index("email", unique=True)               # staff-side accounts (clinic_staff, admin, super_admin)
    db.patients.create_index("email", unique=True)
    db.patients.create_index("qr_hash", unique=True)
    db.kiosks.create_index("kiosk_id", unique=True)
    db.audit_logs.create_index([("at", -1)])
    db.login_attempts.create_index("first_at", expireAfterSeconds=900)   # lockout window forgets itself


# ---------- the "tables": every collection and what each document must contain ----------
DATE, STR, BOOL, INT, OBJ = "date", "string", "bool", ["int", "long"], "object"
TIERS = ["Normal", "Low", "Medium", "High"]


def _schema(required, props):
    return {"$jsonSchema": {"bsonType": "object", "required": required, "properties": props}}


VALIDATORS = {
    "patients": _schema(["first_name", "last_name", "email", "password_hash", "qr_hash", "qr_enc", "active", "created_at"], {
        "first_name": {"bsonType": STR}, "middle_name": {"bsonType": STR}, "last_name": {"bsonType": STR},
        "birthday": {"bsonType": [STR, "null"]}, "sex": {"bsonType": [STR, "null"]}, "blood_type": {"bsonType": [STR, "null"]},
        "address": {"bsonType": STR}, "email": {"bsonType": STR}, "password_hash": {"bsonType": STR},
        "qr_hash": {"bsonType": STR}, "qr_enc": {"bsonType": STR}, "active": {"bsonType": BOOL}, "created_at": {"bsonType": DATE},
        "mfa_enabled": {"bsonType": BOOL}, "mfa_secret_enc": {"bsonType": STR}, "mfa_pending_enc": {"bsonType": STR},
        "mfa_last_step": {"bsonType": INT}, "recovery_hashes": {"bsonType": "array"}, "email_otp": {"bsonType": OBJ},
        "token_version": {"bsonType": INT}}),
    "users": _schema(["name", "email", "access_role", "password_hash", "active"], {
        "name": {"bsonType": STR}, "email": {"bsonType": STR}, "clinic": {"bsonType": STR}, "password_hash": {"bsonType": STR},
        "access_role": {"enum": ["clinic_staff", "admin", "super_admin"]}, "active": {"bsonType": BOOL},
        "must_change_password": {"bsonType": BOOL}, "last_active": {"bsonType": [DATE, "null"]},
        "mfa_enabled": {"bsonType": BOOL}, "mfa_secret_enc": {"bsonType": STR}, "mfa_pending_enc": {"bsonType": STR},
        "mfa_last_step": {"bsonType": INT}, "recovery_hashes": {"bsonType": "array"}, "email_otp": {"bsonType": OBJ},
        "token_version": {"bsonType": INT}}),
    "kiosks": _schema(["kiosk_id"], {
        "kiosk_id": {"bsonType": STR}, "name": {"bsonType": STR}, "clinic": {"bsonType": STR}, "registered": {"bsonType": BOOL},
        "manual_status": {"enum": ["Maintenance", "Deactivated", None]}, "removed_at": {"bsonType": [DATE, "null"]}}),
    "visits": _schema(["kiosk_id", "captured_at", "received_at", "vitals", "model_tier", "effective_tier", "effective_priority", "status"], {
        "kiosk_id": {"bsonType": STR}, "patient_ref": {"bsonType": [STR, "null"]}, "captured_at": {"bsonType": DATE},
        "received_at": {"bsonType": DATE}, "vitals": {"bsonType": OBJ}, "model_tier": {"enum": TIERS}, "effective_tier": {"enum": TIERS},
        "effective_priority": {"bsonType": INT}, "status": {"enum": ["waiting", "in_progress", "done"]}}),
    "audit_logs": _schema(["at", "action", "ip"], {"at": {"bsonType": DATE}, "action": {"bsonType": STR}, "ip": {"bsonType": STR}}),
}
COLLECTIONS = ["patients", "users", "kiosks", "visits", "audit_logs", "rejected_messages", "counters", "login_attempts"]


def init_database(db, validators=True):
    """Creates every collection (with its rules) and every index. Safe to run again: nothing is deleted."""
    have = set(db.list_collection_names())
    done = []
    for name in COLLECTIONS:
        v = VALIDATORS.get(name) if validators else None
        if name not in have:
            db.create_collection(name, **({"validator": v, "validationLevel": "moderate", "validationAction": "error"} if v else {}))
            done.append(f"{name}: created")
        else:
            note = ""
            if v:
                try:
                    db.command("collMod", name, validator=v, validationLevel="moderate", validationAction="error")
                    note = ", rules updated"
                except OperationFailure:             # e.g. the database user may read/write but not change rules
                    note = ", rules left as they were (this database user may not change them)"
            done.append(f"{name}: already there{note}")
    ensure_indexes(db)
    return done
