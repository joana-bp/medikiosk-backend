"""Two-factor sign-in: authenticator-app codes (TOTP), one-time recovery codes, and an optional emailed code.

Sign-in is two steps (patients use /patient/... instead of /staff/...):
  1. POST /staff/login           email + password  ->  {mfaRequired, mfaToken}  or  {mfaSetupRequired, setupToken}
  2. POST /staff/login/mfa       mfaToken + code   ->  {token, staff}           (the real session)
First time: the setupToken lets the person call /mfa/setup and /mfa/enable, which finishes by signing them in.
mfaToken / setupToken are short-lived and have their own `kind`, so they can never be used as a session.

Staff: 2FA is required (MFA_REQUIRED_STAFF). Patients: optional, unless MFA_REQUIRED_PATIENTS=1.
Emailed code (MFA_EMAIL_FALLBACK=1, needs SMTP_*): for someone who set up the app but lost the phone. Never used to
turn 2FA on or off.
"""
import hashlib, hmac, secrets, time
from datetime import timedelta

import jwt, pyotp
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel, Field

from .common import PATIENT, _fernet, aware, audit, bearer, check_lock, clear_fails, db_dep, make_token, now, record_fail
from .security import verify_password
from .sessions import patient_session, staff_session

router = APIRouter()
STEP, RECOVERY_COUNT = 30, 10
PENDING_MINUTES, SETUP_MINUTES = 5, 10
EMAIL_CODE_MINUTES, EMAIL_RESEND_SECONDS = 10, 60

# the two sides of the system: which collection, and the token kinds that belong to it
SIDES = {"staff": {"coll": "users", "pending": "mfa_pending", "setup": "mfa_setup", "session": "staff"},
         "patient": {"coll": "patients", "pending": "pmfa_pending", "setup": "pmfa_setup", "session": "patient"}}
KIND_SIDE = {k: side for side, v in SIDES.items() for k in (v["pending"], v["setup"], v["session"])}
MFA_FIELDS = {"mfa_secret_enc": "", "mfa_pending_enc": "", "mfa_last_step": "", "recovery_hashes": "", "email_otp": ""}


# ---------- codes ----------
def new_secret():
    return pyotp.random_base32()


def encrypt(s, text):
    return _fernet(s).encrypt(text.encode()).decode()


def decrypt(s, enc):
    return _fernet(s).decrypt(enc.encode()).decode()


def check_totp(secret, code, last_step=0):
    """Returns the matching 30-second step, or None. Accepts one step either side; a step already used is refused."""
    code = (code or "").strip().replace(" ", "")
    if not (code.isdigit() and len(code) == 6):
        return None
    totp, cur = pyotp.TOTP(secret), int(time.time() // STEP)
    for step in (cur, cur - 1, cur + 1):
        if step > last_step and hmac.compare_digest(totp.at(step * STEP), code):
            return step
    return None


def _norm(code):
    return (code or "").strip().lower().replace("-", "").replace(" ", "")


def recovery_hash(code):
    return hashlib.sha256(_norm(code).encode()).hexdigest()


def new_recovery_codes():
    """Returns (codes to show once, hashes to store)."""
    codes = [f"{secrets.token_hex(3)}-{secrets.token_hex(3)}" for _ in range(RECOVERY_COUNT)]
    return codes, [recovery_hash(c) for c in codes]


def _who(acct, side):
    return {**acct, "_role": acct.get("access_role") or PATIENT}


def verify_second_factor(db, side, acct, code, s, request, allow_email=False):
    """Checks an authenticator code, a recovery code or (sign-in only) an emailed code.
    Wrong tries are rate-limited (5 -> 15 minutes) and audited."""
    coll = db[SIDES[side]["coll"]]
    key = f"mfa:{side}:{acct['_id']}"
    check_lock(db, key)
    step = check_totp(decrypt(s, acct["mfa_secret_enc"]), code, acct.get("mfa_last_step", 0))
    if step and coll.update_one({"_id": acct["_id"], "mfa_last_step": {"$lt": step}}, {"$set": {"mfa_last_step": step}}).modified_count == 1:
        clear_fails(db, key)
        return "authenticator"
    h = recovery_hash(code)
    if len(_norm(code)) == 12 and h in acct.get("recovery_hashes", []) and \
            coll.update_one({"_id": acct["_id"], "recovery_hashes": h}, {"$pull": {"recovery_hashes": h}}).modified_count == 1:
        clear_fails(db, key)
        audit(db, request, _who(acct, side), "RECOVERY CODE USED", acct["_id"], {"left": len(acct["recovery_hashes"]) - 1})
        return "recovery"
    eo = acct.get("email_otp")
    if allow_email and s.mfa_email_fallback and eo and aware(eo["exp"]) > now() and (code or "").strip().isdigit() \
            and hmac.compare_digest(eo["hash"], recovery_hash(code)) \
            and coll.update_one({"_id": acct["_id"], "email_otp.hash": eo["hash"]}, {"$unset": {"email_otp": ""}}).modified_count == 1:
        clear_fails(db, key)
        audit(db, request, _who(acct, side), "EMAIL CODE USED", acct["_id"])
        return "email"
    record_fail(db, key)
    audit(db, request, _who(acct, side), "MFA FAILED", acct["_id"])
    raise HTTPException(401, "That code is not right")


def reset_account(db, side, acct):
    """Turns 2FA off for an account whose owner lost their device, signs out every session, forgets the lockout.
    Used by the admin endpoints and by scripts/reset_mfa.py. The person must set 2FA up again at next sign-in."""
    db[SIDES[side]["coll"]].update_one({"_id": acct["_id"]}, {"$set": {"mfa_enabled": False, "token_version": acct.get("token_version", 0) + 1},
                                                              "$unset": MFA_FIELDS})
    db.login_attempts.delete_one({"_id": f"mfa:{side}:{acct['_id']}"})


# ---------- tokens ----------
def _role(acct):
    return acct.get("access_role") or PATIENT


def pending_token(s, acct, side="staff"):
    return make_token(s.jwt_secret, acct["_id"], SIDES[side]["pending"], _role(acct), PENDING_MINUTES)


def setup_token(s, acct, side="staff"):
    return make_token(s.jwt_secret, acct["_id"], SIDES[side]["setup"], _role(acct), SETUP_MINUTES)


def _decode(request, token, kinds):
    try:
        p = jwt.decode(token, request.app.state.settings.jwt_secret, algorithms=["HS256"], options={"require": ["exp", "sub", "kind"]})
    except jwt.PyJWTError:
        raise HTTPException(401, "Sign-in expired. Start again.")
    if p["kind"] not in kinds:
        raise HTTPException(403, "Your account type cannot do this")
    return p


def _load(db, p, side):
    a = db[SIDES[side]["coll"]].find_one({"_id": p["sub"]})
    if not a or not a.get("active", True):
        raise HTTPException(401, "Account disabled")
    if p["kind"] == SIDES[side]["session"] and p.get("tv", 0) != a.get("token_version", 0):
        raise HTTPException(401, "Session expired or invalid")
    return a


def actor(request: Request, creds: HTTPAuthorizationCredentials = Depends(bearer), db=Depends(db_dep)):
    """Whoever is calling a /mfa endpoint: someone signed in, or someone holding a setup token.
    Returns (account, side, is_session)."""
    if not creds:
        raise HTTPException(401, "Not signed in")
    p = _decode(request, creds.credentials, tuple(k for v in SIDES.values() for k in (v["session"], v["setup"])))
    side = KIND_SIDE[p["kind"]]
    return _load(db, p, side), side, p["kind"] == SIDES[side]["session"]


def issue_session(request, db, side, acct, method):
    if side == "staff":
        return staff_session(request, db, acct, method)
    acct["_role"] = PATIENT
    audit(db, request, acct, "LOGIN", "patient app", {"method": method})
    return patient_session(request, acct)


# ---------- schemas ----------
class MfaLoginIn(BaseModel):
    mfaToken: str = Field(min_length=1, max_length=2000)
    code: str = Field(min_length=1, max_length=32)


class MfaTokenIn(BaseModel):
    mfaToken: str = Field(min_length=1, max_length=2000)


class CodeIn(BaseModel):
    code: str = Field(min_length=1, max_length=32)


class DisableIn(BaseModel):
    password: str = Field(min_length=1, max_length=72)
    code: str = Field(min_length=1, max_length=32)


def _pending_account(request, db, token, side):
    p = _decode(request, token, (SIDES[side]["pending"],))
    a = _load(db, p, side)
    if not a.get("mfa_enabled"):
        raise HTTPException(401, "Sign-in expired. Start again.")
    return a


# ---------- sign-in step 2 ----------
def _login_mfa(side):
    def endpoint(body: MfaLoginIn, request: Request, db=Depends(db_dep)):
        a = _pending_account(request, db, body.mfaToken, side)
        method = verify_second_factor(db, side, a, body.code, request.app.state.settings, request, allow_email=True)
        return issue_session(request, db, side, a, method)
    return endpoint


def _email_code(side):
    def endpoint(body: MfaTokenIn, request: Request, db=Depends(db_dep)):
        s = request.app.state.settings
        if not s.mfa_email_fallback:
            raise HTTPException(404, "Emailed codes are not turned on")
        a = _pending_account(request, db, body.mfaToken, side)
        eo = a.get("email_otp")
        if eo and (now() - aware(eo["sent_at"])).total_seconds() < EMAIL_RESEND_SECONDS:
            raise HTTPException(429, f"Wait {EMAIL_RESEND_SECONDS} seconds before asking for another code")
        code = f"{secrets.randbelow(10 ** 6):06d}"
        db[SIDES[side]["coll"]].update_one({"_id": a["_id"]}, {"$set": {"email_otp": {"hash": recovery_hash(code), "sent_at": now(),
                                                                                          "exp": now() + timedelta(minutes=EMAIL_CODE_MINUTES)}}})
        try:
            request.app.state.mailer(a["email"], f"{s.mfa_issuer} sign-in code",
                                     f"Your {s.mfa_issuer} sign-in code is {code}. It works once and expires in {EMAIL_CODE_MINUTES} minutes.\n"
                                     "If you did not try to sign in, ignore this email and change your password.")
        except Exception:
            raise HTTPException(502, "Could not send the email. Use your authenticator app or a recovery code.")
        audit(db, request, _who(a, side), "MFA EMAIL SENT", a["_id"])
        return {"sent": True}
    return endpoint


for _side in SIDES:
    router.add_api_route(f"/{_side}/login/mfa", _login_mfa(_side), methods=["POST"])
    router.add_api_route(f"/{_side}/login/mfa/email", _email_code(_side), methods=["POST"])


# ---------- turning 2FA on / off ----------
@router.post("/mfa/setup")
def mfa_setup(request: Request, who=Depends(actor), db=Depends(db_dep)):
    """Step 1 of turning 2FA on: a new secret for the authenticator app. Nothing is active until /mfa/enable proves it works."""
    a, side, _session = who
    if a.get("mfa_enabled"):
        raise HTTPException(409, "Two-factor is already on")
    s = request.app.state.settings
    coll = db[SIDES[side]["coll"]]
    # Keep ONE pending secret until it is enabled: calling this again (a page that re-renders, a second tab, a double request)
    # must show the same QR code, otherwise the code the person scanned stops matching what the server stored.
    # The filter makes the first writer win even when two requests arrive together.
    coll.update_one({"_id": a["_id"], "mfa_pending_enc": {"$exists": False}}, {"$set": {"mfa_pending_enc": encrypt(s, new_secret())}})
    secret = decrypt(s, coll.find_one({"_id": a["_id"]})["mfa_pending_enc"])
    return {"secret": secret, "otpauthUri": pyotp.TOTP(secret).provisioning_uri(name=a["email"], issuer_name=s.mfa_issuer)}


@router.post("/mfa/enable")
def mfa_enable(body: CodeIn, request: Request, who=Depends(actor), db=Depends(db_dep)):
    """Step 2: the first code from the app. Returns the recovery codes (shown once) and a fresh session."""
    a, side, _session = who
    s = request.app.state.settings
    if a.get("mfa_enabled"):
        raise HTTPException(409, "Two-factor is already on")
    if not a.get("mfa_pending_enc"):
        raise HTTPException(400, "Call /mfa/setup first")
    key = f"mfa:{side}:{a['_id']}"
    check_lock(db, key)
    step = check_totp(decrypt(s, a["mfa_pending_enc"]), body.code)
    if not step:
        record_fail(db, key)
        audit(db, request, _who(a, side), "MFA FAILED", a["_id"], {"during": "enrol"})
        raise HTTPException(401, "That code is not right")
    clear_fails(db, key)
    codes, hashes = new_recovery_codes()
    tv = a.get("token_version", 0) + 1
    db[SIDES[side]["coll"]].update_one({"_id": a["_id"]}, {"$set": {"mfa_enabled": True, "mfa_secret_enc": a["mfa_pending_enc"], "mfa_last_step": step,
                                                                     "recovery_hashes": hashes, "token_version": tv}, "$unset": {"mfa_pending_enc": ""}})
    audit(db, request, _who(a, side), "MFA ENABLE", a["_id"])
    a["token_version"], a["mfa_enabled"] = tv, True
    return {**issue_session(request, db, side, a, "enrolment"), "recoveryCodes": codes}


@router.post("/mfa/disable")
def mfa_disable(body: DisableIn, request: Request, who=Depends(actor), db=Depends(db_dep)):
    a, side, is_session = who
    s = request.app.state.settings
    if not is_session:
        raise HTTPException(403, "Sign in first")
    if (side == "staff" and s.mfa_required_staff) or (side == "patient" and s.mfa_required_patients):
        raise HTTPException(403, "Two-factor is required for this kind of account")
    if not a.get("mfa_enabled"):
        raise HTTPException(409, "Two-factor is not on")
    if not verify_password(body.password, a["password_hash"]):
        raise HTTPException(400, "Password is wrong")
    verify_second_factor(db, side, a, body.code, s, request)
    tv = a.get("token_version", 0) + 1
    db[SIDES[side]["coll"]].update_one({"_id": a["_id"]}, {"$set": {"mfa_enabled": False, "token_version": tv}, "$unset": MFA_FIELDS})
    audit(db, request, _who(a, side), "MFA DISABLE", a["_id"])
    return {"success": True, "token": make_token(s.jwt_secret, a["_id"], SIDES[side]["session"], _role(a), s.jwt_minutes, tv)}


@router.post("/mfa/recovery-codes/regenerate")
def regenerate_recovery(body: CodeIn, request: Request, who=Depends(actor), db=Depends(db_dep)):
    a, side, is_session = who
    if not is_session or not a.get("mfa_enabled"):
        raise HTTPException(403, "Two-factor is not on")
    verify_second_factor(db, side, a, body.code, request.app.state.settings, request)
    codes, hashes = new_recovery_codes()
    db[SIDES[side]["coll"]].update_one({"_id": a["_id"]}, {"$set": {"recovery_hashes": hashes}})
    audit(db, request, _who(a, side), "MFA RECOVERY REGENERATE", a["_id"])
    return {"recoveryCodes": codes}
