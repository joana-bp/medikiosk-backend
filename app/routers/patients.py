from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pymongo.errors import DuplicateKeyError
from ..common import (ADMIN, CLINIC_STAFF, STAFF_SIDE, SUPER_ADMIN, audit, db_dep, local, new_qr, next_id, now, patient_dep, read_qr, require)
from ..mfa import reset_account
from ..schemas import PasswordChange, PatientIn, PatientPatch
from ..security import hash_password, verify_password
from ..views import patient_out

router = APIRouter()
OPEN_RECORDS = require(*STAFF_SIDE)          # may register / look up patients


def last_visits(db, ids):
    rows = db.visits.aggregate([{"$match": {"patient_ref": {"$in": list(ids)}}}, {"$group": {"_id": "$patient_ref", "last": {"$max": "$captured_at"}}}])
    return {r["_id"]: r["last"] for r in rows}


def username_taken(db, username, except_id=None):
    return db.patients.find_one({"username": username, "_id": {"$ne": except_id}}) is not None


def get_patient(db, pid):
    p = db.patients.find_one({"_id": pid})
    if not p:
        raise HTTPException(404, "Patient not found")
    return p


@router.get("/patients")
def list_patients(search: str = Query("", max_length=60), a=Depends(OPEN_RECORDS), db=Depends(db_dep)):
    rows = list(db.patients.find({}).sort("last_name", 1))
    t = search.strip().lower()
    if t:
        rows = [p for p in rows if t in p["first_name"].lower() or t in p["last_name"].lower() or t in p["_id"].lower() or t in p["email"] or t in p.get("username", "")]
    lv = last_visits(db, [p["_id"] for p in rows])
    return [patient_out(p, lv.get(p["_id"])) for p in rows]


@router.get("/patients/{pid}")
def patient_detail(pid: str, request: Request, a=Depends(OPEN_RECORDS), db=Depends(db_dep)):
    p = get_patient(db, pid)
    visits = list(db.visits.find({"patient_ref": pid}).sort("captured_at", -1).limit(100))
    out = patient_out(p, visits[0]["captured_at"] if visits else None)
    out["visitCount"] = db.visits.count_documents({"patient_ref": pid})
    # only clinic staff see clinical results; admins and super admins get the profile and a visit count
    out["visitHistory"] = ([{"date": local(v["captured_at"], request.app.state.settings).strftime("%Y-%m-%d"), "notes": "Kiosk check-in",
                             "status": v["effective_tier"]} for v in visits] if a["_role"] == CLINIC_STAFF else [])
    return out


@router.post("/patients", status_code=201)
def create_patient(body: PatientIn, request: Request, a=Depends(OPEN_RECORDS), db=Depends(db_dep)):
    if username_taken(db, body.username):
        raise HTTPException(409, "That username is already taken")
    tok, h, enc = new_qr(request.app.state.settings)
    doc = {"_id": next_id(db, "patient", "P-", 5), "first_name": body.firstName.strip(), "middle_name": body.middleName.strip(),
           "last_name": body.lastName.strip(), "birthday": body.birthday, "sex": body.sex, "blood_type": body.bloodType, "address": body.address,
           "email": body.email.lower(), "password_hash": hash_password(body.password), "qr_hash": h, "qr_enc": enc, "active": True,
           "created_at": now(), "created_by": a["email"]}
    doc["username"] = body.username
    try:
        db.patients.insert_one(doc)
    except DuplicateKeyError as e:
        raise HTTPException(409, "That username is already taken" if "username" in str(e) else "That email is already registered")
    audit(db, request, a, "PATIENT CREATE", doc["_id"])
    return {**patient_out(doc), "qrToken": tok}


@router.patch("/patients/{pid}")
def update_patient(pid: str, body: PatientPatch, request: Request, a=Depends(OPEN_RECORDS), db=Depends(db_dep)):
    get_patient(db, pid)
    m = {"firstName": "first_name", "middleName": "middle_name", "lastName": "last_name", "address": "address", "birthday": "birthday",
         "sex": "sex", "bloodType": "blood_type"}
    sets = {col: getattr(body, f) for f, col in m.items() if getattr(body, f) is not None}
    if body.email:
        sets["email"] = body.email.lower()
    if body.username:
        if username_taken(db, body.username, pid):
            raise HTTPException(409, "That username is already taken")
        sets["username"] = body.username
    if body.password:
        sets["password_hash"] = hash_password(body.password)
    if sets:
        try:
            db.patients.update_one({"_id": pid}, {"$set": sets})
        except DuplicateKeyError as e:
            raise HTTPException(409, "That username is already taken" if "username" in str(e) else "That email belongs to another patient")
    audit(db, request, a, "PATIENT UPDATE", pid, {"fields": sorted(k for k in sets if k != "password_hash"), "password_changed": "password_hash" in sets})
    return patient_out(get_patient(db, pid))


@router.delete("/patients/{pid}")
def delete_patient(pid: str, request: Request, a=Depends(require(SUPER_ADMIN)), db=Depends(db_dep)):
    get_patient(db, pid)
    n = db.visits.delete_many({"patient_ref": pid}).deleted_count
    db.patients.delete_one({"_id": pid})
    audit(db, request, a, "PATIENT DELETE", pid, {"visits_deleted": n})
    return {"deletedCheckIns": n}


@router.get("/patients/{pid}/qr-token")
def show_qr(pid: str, request: Request, a=Depends(OPEN_RECORDS), db=Depends(db_dep)):
    p = get_patient(db, pid)
    audit(db, request, a, "QR VIEW", pid)
    return {"qrToken": read_qr(request.app.state.settings, p["qr_enc"])}


@router.post("/patients/{pid}/qr-token")
def regenerate_qr(pid: str, request: Request, a=Depends(OPEN_RECORDS), db=Depends(db_dep)):
    """New code; every printed copy of the old one stops working immediately."""
    get_patient(db, pid)
    tok, h, enc = new_qr(request.app.state.settings)
    db.patients.update_one({"_id": pid}, {"$set": {"qr_hash": h, "qr_enc": enc}})
    audit(db, request, a, "QR REGENERATE", pid)
    return {"qrToken": tok}


@router.post("/patients/{pid}/reset-mfa")
def reset_patient_mfa(pid: str, request: Request, a=Depends(OPEN_RECORDS), db=Depends(db_dep)):
    """For a patient who lost their phone (check their identity first): turns their 2FA off and signs them out."""
    reset_account(db, "patient", get_patient(db, pid))
    audit(db, request, a, "MFA RESET", pid)
    return {"success": True}


# ---- the patient's own account (mobile app) ----
@router.get("/patient/me")
def my_profile(p=Depends(patient_dep), db=Depends(db_dep)):
    lv = last_visits(db, [p["_id"]])
    return patient_out(p, lv.get(p["_id"]))


@router.patch("/patient/me")
def update_my_profile(body: PatientPatch, request: Request, p=Depends(patient_dep), db=Depends(db_dep)):
    """Patients may fix their own details (not their ID, QR or password here)."""
    m = {"firstName": "first_name", "middleName": "middle_name", "lastName": "last_name", "address": "address", "birthday": "birthday",
         "sex": "sex", "bloodType": "blood_type"}
    sets = {col: getattr(body, f) for f, col in m.items() if getattr(body, f) is not None}
    if body.email:
        sets["email"] = body.email.lower()
    if body.username:
        if username_taken(db, body.username, p["_id"]):
            raise HTTPException(409, "That username is already taken")
        sets["username"] = body.username
    if sets:
        try:
            db.patients.update_one({"_id": p["_id"]}, {"$set": sets})
        except DuplicateKeyError as e:
            raise HTTPException(409, "That username is already taken" if "username" in str(e) else "That email is already used by another account")
    p["_role"] = "patient"
    audit(db, request, p, "PROFILE UPDATE", p["_id"], {"fields": sorted(sets)})
    return patient_out(get_patient(db, p["_id"]))


@router.post("/patient/change-password")
def change_my_password(body: PasswordChange, request: Request, p=Depends(patient_dep), db=Depends(db_dep)):
    if not verify_password(body.currentPassword, p["password_hash"]):
        raise HTTPException(400, "Current password is wrong")
    if body.currentPassword == body.newPassword:
        raise HTTPException(400, "Choose a different password")
    db.patients.update_one({"_id": p["_id"]}, {"$set": {"password_hash": hash_password(body.newPassword)}})
    p["_role"] = "patient"
    audit(db, request, p, "PASSWORD CHANGE", p["_id"])
    return {"success": True}


@router.get("/patient/me/qr-token")
def my_qr(request: Request, p=Depends(patient_dep)):
    return {"qrToken": read_qr(request.app.state.settings, p["qr_enc"])}
