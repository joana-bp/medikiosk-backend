"""Clinical data: the priority queue, urgency tiers and vitals. Clinic staff only."""
from typing import Literal, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from ..common import CLINIC_STAFF, _account, age_of, aware, audit, bearer, db_dep, iso, local, now, require
from ..ingest import PRIORITY
from ..schemas import OverrideIn, StatusIn

router = APIRouter()
CLINICAL = require(CLINIC_STAFF)


def staff_view(v, names, now_=None, profiles=None):
    now_ = now_ or now()
    prof = (profiles or {}).get(v.get("patient_ref")) or {}
    cap = aware(v["captured_at"])
    return {"id": v["_id"], "kiosk_id": v["kiosk_id"], "patient_ref": v.get("patient_ref"), "patient_name": names.get(v.get("patient_ref")) or "Guest",
            "captured_at": iso(cap), "wait_minutes": max(0, int((now_ - cap).total_seconds() // 60)), "status": v["status"],
            "tier": v["effective_tier"], "model_tier": v["model_tier"], "overridden": v.get("override") is not None,
            "override": v.get("override") and {**v["override"], "at": iso(v["override"]["at"])},
            "critical_flags": v.get("critical_flags", []), "escalated": v.get("escalated", False),
            "escalation_tier": v.get("escalation_tier"), "critical_rules_version": v.get("critical_rules_version"), "in_model_range": v.get("in_model_range", True), "outside_range": v.get("outside_range", []),
            "review_reasons": v.get("review_reasons", []), "vitals": v["vitals"], "body": v.get("body", {}),
            "quality": v.get("quality", {}), "model_version": v.get("model_version"),
            # shown on the queue for reference only; the model never uses age or sex
            "probabilities": v.get("probabilities"), "patient_age": prof.get("age"), "patient_sex": prof.get("sex")}


def patient_profiles(db, rows):
    ids = {r.get("patient_ref") for r in rows if r.get("patient_ref")}
    return {p["_id"]: {"age": age_of(p.get("birthday")), "sex": p.get("sex")} for p in db.patients.find({"_id": {"$in": list(ids)}})} if ids else {}


def patient_names(db, rows):
    ids = {r.get("patient_ref") for r in rows if r.get("patient_ref")}
    return {p["_id"]: f"{p['first_name']} {p['last_name']}" for p in db.patients.find({"_id": {"$in": list(ids)}})} if ids else {}


@router.get("/queue")
def queue(status: Literal["waiting", "in_progress", "active"] = "active", a=Depends(CLINICAL), db=Depends(db_dep)):
    q = {"status": {"$in": ["waiting", "in_progress"]}} if status == "active" else {"status": status}
    q["patient_ref"] = {"$nin": [None, ""]}          # guests (no patient record) are not shown on the queue
    # urgency tier first (High at the top), then who arrived first. Model confidence is never used.
    rows = list(db.visits.find(q).sort([("effective_priority", -1), ("captured_at", 1)]).limit(500))
    names, profiles, t = patient_names(db, rows), patient_profiles(db, rows), now()
    rows = [r for r in rows if r["patient_ref"] in names]   # also hide visits whose patient record no longer exists
    return {"count": len(rows), "items": [staff_view(r, names, t, profiles) for r in rows]}


@router.get("/visits")
def history(limit: int = Query(50, ge=1, le=200), skip: int = Query(0, ge=0), patient_ref: Optional[str] = None,
            kiosk_id: Optional[str] = None, a=Depends(CLINICAL), db=Depends(db_dep)):
    q = {k: v for k, v in (("patient_ref", patient_ref), ("kiosk_id", kiosk_id)) if v}
    rows = list(db.visits.find(q).sort("captured_at", -1).skip(skip).limit(limit))
    names, profiles = patient_names(db, rows), patient_profiles(db, rows)
    return {"items": [staff_view(r, names, None, profiles) for r in rows]}


@router.get("/visits/{vid}")
def visit(vid: str, a=Depends(CLINICAL), db=Depends(db_dep)):
    v = db.visits.find_one({"_id": vid})
    if not v:
        raise HTTPException(404, "Not found")
    return staff_view(v, patient_names(db, [v]), None, patient_profiles(db, [v]))


@router.post("/visits/{vid}/status")
def set_status(vid: str, body: StatusIn, request: Request, a=Depends(CLINICAL), db=Depends(db_dep)):
    r = db.visits.find_one_and_update({"_id": vid}, {"$set": {"status": body.status, "status_by": a["email"]}})
    if not r:
        raise HTTPException(404, "Not found")
    request.app.state.hub.publish()
    audit(db, request, a, "VISIT STATUS", vid, {"from": r["status"], "to": body.status})
    return {"ok": True}


@router.post("/visits/{vid}/override")
def override(vid: str, body: OverrideIn, request: Request, a=Depends(CLINICAL), db=Depends(db_dep)):
    v = db.visits.find_one({"_id": vid})
    if not v:
        raise HTTPException(404, "Not found")
    floor = v.get("escalation_tier")
    if floor and PRIORITY[body.tier] < PRIORITY[floor] and not body.confirmLower:
        raise HTTPException(409, f"This patient has critical values (minimum {floor}). Confirm to set a lower tier.")
    ov = {"by": a["email"], "at": now(), "reason": body.reason.strip(), "from": v["effective_tier"], "to": body.tier}
    db.visits.update_one({"_id": vid}, {"$set": {"effective_tier": body.tier, "effective_priority": PRIORITY[body.tier], "override": ov}})
    request.app.state.hub.publish()
    audit(db, request, a, "TIER OVERRIDE", vid, {"model_tier": v["model_tier"], "below_critical_floor": bool(floor and PRIORITY[body.tier] < PRIORITY[floor]), "from": v["effective_tier"], "to": body.tier, "reason": ov["reason"]})
    return {"ok": True, "tier": body.tier}


# ---- history list used by the patient app (no tier, no probabilities) ----
def readings_of(v):
    x, b = v["vitals"], v.get("body", {})
    r = {"heartRate": {"value": x["heart_rate"], "unit": "bpm"}, "temperature": {"value": x["temperature"], "unit": "°C"},
         "bloodPressure": {"systolic": x["systolic"], "diastolic": x.get("diastolic"), "unit": "mmHg"},
         "spo2": {"value": x["spo2"], "unit": "%"}, "respiration": {"value": x["respiratory_rate"], "unit": "br/min"}}
    if b.get("bmi") is not None:
        r["bmi"] = {"value": b["bmi"], "unit": "kg/m²"}
    return r


@router.get("/vitals/history")
def vitals_history(request: Request, patientId: str = Query(...), db=Depends(db_dep), creds=Depends(bearer)):
    """A patient may read only their own history; clinic staff may read anyone's. Admins and super admins may not."""
    kind = "staff"
    try:
        acct = _account(request, creds, db, "patient"); kind = "patient"
    except HTTPException as e:
        if e.status_code != 403:
            raise
        acct = _account(request, creds, db, "staff")
    if kind == "patient" and acct["_id"] != patientId:
        raise HTTPException(403, "You can only see your own history")
    if kind == "staff" and acct["_role"] != CLINIC_STAFF:
        raise HTTPException(403, "Your role cannot see vitals")
    rows = list(db.visits.find({"patient_ref": patientId}).sort("captured_at", -1).limit(100))
    kiosks = {k["kiosk_id"]: k.get("name") or k["kiosk_id"] for k in db.kiosks.find({})}
    s = request.app.state.settings
    return [{"id": v["_id"], "kioskName": kiosks.get(v["kiosk_id"], v["kiosk_id"]), "date": local(v["captured_at"], s).strftime("%Y-%m-%d %I:%M %p"),
             "vital": "Vitals Check-In", "status": "Completed", "readings": readings_of(v)} for v in rows]