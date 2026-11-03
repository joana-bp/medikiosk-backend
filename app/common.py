"""Shared helpers: roles, audit log, sign-in lockout, tokens and small formatting functions."""
import base64, hashlib, logging, os, re, secrets
from datetime import date, datetime, timedelta, timezone
from typing import Optional

import jwt
from cryptography.fernet import Fernet
from pymongo import ReturnDocument
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

CLINIC_STAFF, ADMIN, SUPER_ADMIN, PATIENT = "clinic_staff", "admin", "super_admin", "patient"
STAFF_SIDE = (CLINIC_STAFF, ADMIN, SUPER_ADMIN)
bearer = HTTPBearer(auto_error=False)
MAX_FAILS = 5


# ---------- formatting ----------
def now():
    return datetime.now(timezone.utc)


def aware(d):
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def iso(d):
    return aware(d).astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if isinstance(d, datetime) else d


def local(d, s):
    return aware(d) + timedelta(hours=s.tz_offset_hours)


def initials(name):
    parts = [p for p in re.split(r"\s+", (name or "").replace(".", " ").strip()) if p]
    return "".join(p[0].upper() for p in parts[:2]) or "?"


def age_of(birthday):
    try:
        b = date.fromisoformat(birthday)
    except (TypeError, ValueError):
        return None
    t = date.today()
    return t.year - b.year - ((t.month, t.day) < (b.month, b.day))


def ago(d):
    if not d:
        return "never"
    m = int((now() - aware(d)).total_seconds() // 60)
    return "just now" if m < 1 else f"{m} min{'s' if m != 1 else ''} ago" if m < 60 else f"{m // 60} hr{'s' if m >= 120 else ''} ago" if m < 1440 else f"{m // 1440} day{'s' if m >= 2880 else ''} ago"


def next_id(db, name, prefix, width):
    r = db.counters.find_one_and_update({"_id": name}, {"$inc": {"n": 1}}, upsert=True, return_document=ReturnDocument.AFTER)
    return f"{prefix}{r['n']:0{width}d}"


def temp_password():
    return secrets.token_urlsafe(9)


# ---------- audit ----------
SEVERITY = {"LOGIN FAILED": "Warning", "ACCOUNT LOCKED": "Critical", "PATIENT DELETE": "Warning", "STAFF DELETE": "Warning",
            "KIOSK REMOVE": "Warning", "TIER OVERRIDE": "Warning", "QR REGENERATE": "Warning", "QR VIEW": "Warning",
            "MFA FAILED": "Warning", "MFA DISABLE": "Warning", "MFA RESET": "Warning", "RECOVERY CODE USED": "Warning"}


def audit(db, request, who, action, target="—", details=None):
    """who = account dict (staff or patient) or None. Append-only: nothing in the API edits or deletes these."""
    db.audit_logs.insert_one({"at": now(), "actor_email": who and who.get("email"), "actor_role": who and who.get("_role", who.get("access_role")),
                              "action": action, "target": target, "ip": request.client.host if request and request.client else "—",
                              "severity": SEVERITY.get(action, "Info"), "details": details or {}})


# ---------- sign-in lockout (5 wrong passwords -> 15 minutes) ----------
def lockout_disabled():
    """TESTING ONLY: DISABLE_LOCKOUT=1 turns off the 'too many failed attempts' block (passwords, QR and 2FA codes).
    Never set it on a real server. Remove the variable and restart to get the lockout back."""
    return os.getenv("DISABLE_LOCKOUT", "0").strip().lower() in ("1", "true", "yes", "on")


def check_lock(db, key):
    if lockout_disabled():
        return
    r = db.login_attempts.find_one({"_id": key})
    if r and r["count"] >= MAX_FAILS:
        raise HTTPException(429, "Too many failed attempts. Try again in 15 minutes.")


def record_fail(db, key):
    db.login_attempts.update_one({"_id": key}, {"$inc": {"count": 1}, "$setOnInsert": {"first_at": now()}}, upsert=True)


def clear_fails(db, key):
    db.login_attempts.delete_one({"_id": key})


# ---------- tokens and QR secrets ----------
def make_token(secret, sub, kind, role, minutes, tv=0):
    """kind: staff / patient (a real session), or mfa_pending / mfa_setup (short-lived, only usable on the 2FA endpoints).
    tv = the account's token_version; bumping it on the account signs out every older session."""
    t = now()
    return jwt.encode({"sub": sub, "kind": kind, "role": role, "tv": tv, "iat": t, "exp": t + timedelta(minutes=minutes)}, secret, "HS256")


def _fernet(s):
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(s.qr_secret.encode()).digest()))


def new_qr(s):
    """Returns (token, sha256 for lookup, encrypted copy so an admin can show the QR again)."""
    tok = secrets.token_hex(18)                                  # 36 hex chars, 144 random bits
    return tok, hashlib.sha256(tok.encode()).hexdigest(), _fernet(s).encrypt(tok.encode()).decode()


def read_qr(s, enc):
    return _fernet(s).decrypt(enc.encode()).decode()


def qr_hash(tok):
    return hashlib.sha256(tok.encode()).hexdigest()


def parse_qr(value):
    t = (value or "").strip()
    if t.upper().startswith("MEDIKIOSK:"):
        t = t[10:].strip()
    t = t.lower()
    return t if re.fullmatch(r"[0-9a-f]{36}", t) else None


# ---------- who is calling ----------
def db_dep(request: Request):
    return request.app.state.db


def _account(request, creds, db, kind):
    if not creds:
        raise HTTPException(401, "Not signed in")
    try:
        p = jwt.decode(creds.credentials, request.app.state.settings.jwt_secret, algorithms=["HS256"], options={"require": ["exp", "sub", "kind"]})
    except jwt.PyJWTError:
        raise HTTPException(401, "Session expired or invalid")
    if p["kind"] != kind:
        raise HTTPException(403, "Your account type cannot do this")
    a = db.users.find_one({"_id": p["sub"]}) if kind == "staff" else db.patients.find_one({"_id": p["sub"]})
    if not a or not a.get("active", True):
        raise HTTPException(401, "Account disabled")
    if p.get("tv", 0) != a.get("token_version", 0):
        raise HTTPException(401, "Session expired or invalid")        # signed out by a 2FA change / reset
    a["_role"] = a["access_role"] if kind == "staff" else PATIENT
    return a


def staff_dep(request: Request, creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer), db=Depends(db_dep)):
    a = _account(request, creds, db, "staff")
    db.users.update_one({"_id": a["_id"]}, {"$set": {"last_active": now()}})
    return a


def patient_dep(request: Request, creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer), db=Depends(db_dep)):
    return _account(request, creds, db, "patient")


def require(*roles):
    def dep(a=Depends(staff_dep)):
        if a["_role"] not in roles:
            raise HTTPException(403, "Your role cannot do this")
        return a
    return dep
