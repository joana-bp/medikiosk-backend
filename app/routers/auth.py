from fastapi import APIRouter, Depends, HTTPException, Request
from ..common import (CLINIC_STAFF, PATIENT, _account, audit, bearer, check_lock, clear_fails, db_dep, make_token, now, parse_qr, qr_hash, record_fail,
                      staff_dep)
from ..schemas import LoginIn, PasswordChange, PatientIn, QrLoginIn
from ..security import hash_password, verify_password
from ..views import patient_out, staff_out
from pymongo.errors import DuplicateKeyError
from ..common import new_qr, next_id

router = APIRouter()


def _patient_session(request, p):
    s = request.app.state.settings
    return {"token": make_token(s.jwt_secret, p["_id"], "patient", PATIENT, s.jwt_minutes), "patient": patient_out(p)}


@router.post("/patient/login")
def patient_login(body: LoginIn, request: Request, db=Depends(db_dep)):
    key = f"patient:{body.email.lower()}"
    check_lock(db, key)
    p = db.patients.find_one({"email": body.email.lower()})
    if not (verify_password(body.password, p and p.get("password_hash")) and p and p.get("active", True)):
        record_fail(db, key); audit(db, request, {"email": body.email.lower(), "_role": PATIENT}, "LOGIN FAILED", "patient app")
        raise HTTPException(401, "Wrong email or password")
    clear_fails(db, key); p["_role"] = PATIENT
    audit(db, request, p, "LOGIN", "patient app")
    return _patient_session(request, p)


@router.post("/patient/signup", status_code=201)
def patient_signup(body: PatientIn, request: Request, db=Depends(db_dep)):
    s = request.app.state.settings
    tok, h, enc = new_qr(s)
    doc = {"_id": next_id(db, "patient", "P-", 5), "first_name": body.firstName.strip(), "middle_name": body.middleName.strip(),
           "last_name": body.lastName.strip(), "birthday": body.birthday, "sex": body.sex, "blood_type": body.bloodType, "address": body.address,
           "email": body.email.lower(), "password_hash": hash_password(body.password), "qr_hash": h, "qr_enc": enc, "active": True, "created_at": now()}
    try:
        db.patients.insert_one(doc)
    except DuplicateKeyError:
        raise HTTPException(409, "That email is already registered")
    doc["_role"] = PATIENT
    audit(db, request, doc, "PATIENT SIGNUP", doc["_id"])
    return _patient_session(request, doc)


@router.post("/patient/login-qr")
def patient_login_qr(body: QrLoginIn, request: Request, db=Depends(db_dep)):
    """Used by the kiosk's 'Scan QR Code'. The QR holds a long random secret, never the patient ID."""
    key = f"qr:{request.client.host if request.client else 'x'}"
    check_lock(db, key)
    tok = parse_qr(body.qrToken)
    p = tok and db.patients.find_one({"qr_hash": qr_hash(tok)})
    if not p or not p.get("active", True):
        record_fail(db, key); audit(db, request, None, "LOGIN FAILED", "kiosk QR")
        raise HTTPException(401, "This QR code is not valid")
    p["_role"] = PATIENT
    audit(db, request, p, "KIOSK QR LOGIN", p["_id"])
    return _patient_session(request, p)


@router.post("/staff/login")
def staff_login(body: LoginIn, request: Request, db=Depends(db_dep)):
    s = request.app.state.settings
    key = f"staff:{body.email.lower()}"
    check_lock(db, key)
    u = db.users.find_one({"email": body.email.lower()})
    if not (verify_password(body.password, u and u.get("password_hash")) and u and u.get("active", True)):
        record_fail(db, key); audit(db, request, {"email": body.email.lower(), "_role": "unknown"}, "LOGIN FAILED", "staff console")
        raise HTTPException(401, "Wrong email or password")
    clear_fails(db, key)
    db.users.update_one({"_id": u["_id"]}, {"$set": {"last_active": now()}})
    u["_role"] = u["access_role"]; u["last_active"] = now()
    audit(db, request, u, "LOGIN", "staff console")
    return {"token": make_token(s.jwt_secret, u["_id"], "staff", u["access_role"], s.jwt_minutes), "staff": staff_out(u)}


@router.post("/staff/change-password")
def change_password(body: PasswordChange, request: Request, u=Depends(staff_dep), db=Depends(db_dep)):
    if not verify_password(body.currentPassword, u["password_hash"]):
        raise HTTPException(400, "Current password is wrong")
    if body.currentPassword == body.newPassword:
        raise HTTPException(400, "Choose a different password")
    db.users.update_one({"_id": u["_id"]}, {"$set": {"password_hash": hash_password(body.newPassword), "must_change_password": False}})
    audit(db, request, u, "PASSWORD CHANGE", u["_id"])
    return {"success": True}


@router.post("/logout")
def logout(request: Request, creds=Depends(bearer), db=Depends(db_dep)):
    """Signing out marks a staff member Offline straight away (their 'last active' time is cleared).
    Anyone else, or an expired token, just gets a harmless OK."""
    try:
        a = _account(request, creds, db, "staff")
    except HTTPException:
        return {"success": True}
    db.users.update_one({"_id": a["_id"]}, {"$set": {"last_active": None}})
    return {"success": True}