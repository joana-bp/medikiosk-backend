from fastapi import APIRouter, Depends, HTTPException, Request
from ..common import (CLINIC_STAFF, PATIENT, _account, audit, bearer, check_lock, clear_fails, db_dep, make_token, now, parse_qr, qr_hash, record_fail,
                      staff_dep)
from ..schemas import PasswordChange, PatientIn, QrLoginIn, SignInIn
from ..security import hash_password, verify_password
from ..views import patient_out
from ..mfa import pending_token, setup_token
from ..sessions import patient_session, staff_session
from pymongo.errors import DuplicateKeyError
from ..common import new_qr, next_id

router = APIRouter()


_patient_session = patient_session


@router.post("/patient/login")
def patient_login(body: SignInIn, request: Request, db=Depends(db_dep)):
    who = body.identifier.strip().lower()                # an email (has an "@") or a username (never has one)
    key = f"patient:{who}"
    check_lock(db, key)
    p = db.patients.find_one({"email": who} if "@" in who else {"username": who})
    if not (verify_password(body.password, p and p.get("password_hash")) and p and p.get("active", True)):
        record_fail(db, key); audit(db, request, {"email": who, "_role": PATIENT}, "LOGIN FAILED", "patient app")
        raise HTTPException(401, "Wrong email, username or password")
    clear_fails(db, key); p["_role"] = PATIENT
    s = request.app.state.settings
    if p.get("mfa_enabled"):                         # patients who turned 2FA on: step 2 of 2
        return {"mfaRequired": True, "mfaToken": pending_token(s, p, "patient")}
    if s.mfa_required_patients:
        return {"mfaSetupRequired": True, "setupToken": setup_token(s, p, "patient")}
    audit(db, request, p, "LOGIN", "patient app")
    return _patient_session(request, p)


@router.post("/patient/signup", status_code=201)
def patient_signup(body: PatientIn, request: Request, db=Depends(db_dep)):
    s = request.app.state.settings
    if db.patients.find_one({"username": body.username}):
        raise HTTPException(409, "That username is already taken")
    tok, h, enc = new_qr(s)
    doc = {"_id": next_id(db, "patient", "P-", 5), "first_name": body.firstName.strip(), "middle_name": body.middleName.strip(),
           "last_name": body.lastName.strip(), "birthday": body.birthday, "sex": body.sex, "blood_type": body.bloodType, "address": body.address,
           "email": body.email.lower(), "password_hash": hash_password(body.password), "qr_hash": h, "qr_enc": enc, "active": True, "created_at": now()}
    doc["username"] = body.username
    try:
        db.patients.insert_one(doc)
    except DuplicateKeyError as e:
        raise HTTPException(409, "That username is already taken" if "username" in str(e) else "That email is already registered")
    doc["_role"] = PATIENT
    audit(db, request, doc, "PATIENT SIGNUP", doc["_id"])
    if s.mfa_required_patients:
        return {"mfaSetupRequired": True, "setupToken": setup_token(s, doc, "patient"), "patient": patient_out(doc)}
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
def staff_login(body: SignInIn, request: Request, db=Depends(db_dep)):
    s = request.app.state.settings
    who = body.identifier.strip().lower()                # an email (has an "@") or a username (never has one)
    key = f"staff:{who}"
    check_lock(db, key)
    u = db.users.find_one({"email": who} if "@" in who else {"username": who})
    if not (verify_password(body.password, u and u.get("password_hash")) and u and u.get("active", True)):
        record_fail(db, key); audit(db, request, {"email": who, "_role": "unknown"}, "LOGIN FAILED", "staff console")
        raise HTTPException(401, "Wrong email, username or password")
    clear_fails(db, key)
    if u.get("mfa_enabled"):                         # step 2 of 2: the code from the authenticator app (or a recovery code)
        return {"mfaRequired": True, "mfaToken": pending_token(s, u)}
    if s.mfa_required_staff:                         # first sign-in: they must set up 2FA before getting a session
        return {"mfaSetupRequired": True, "setupToken": setup_token(s, u)}
    return staff_session(request, db, u)


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