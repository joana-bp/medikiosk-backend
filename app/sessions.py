"""Issuing a real session (shared by the password step, the two-factor step and enrolment)."""
from .common import PATIENT, audit, make_token, now
from .views import patient_out, staff_out


def staff_session(request, db, u, method=None):
    s = request.app.state.settings
    t = now()
    db.users.update_one({"_id": u["_id"]}, {"$set": {"last_active": t}})
    u["_role"], u["last_active"] = u["access_role"], t
    audit(db, request, u, "LOGIN", "staff console", {"method": method} if method else None)
    return {"token": make_token(s.jwt_secret, u["_id"], "staff", u["access_role"], s.jwt_minutes, u.get("token_version", 0)), "staff": staff_out(u)}


def patient_session(request, p):
    s = request.app.state.settings
    return {"token": make_token(s.jwt_secret, p["_id"], "patient", PATIENT, s.jwt_minutes, p.get("token_version", 0)), "patient": patient_out(p)}
