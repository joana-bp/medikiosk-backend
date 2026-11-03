from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from ..common import ADMIN, STAFF_SIDE, SUPER_ADMIN, audit, db_dep, iso, local, next_id, now, require
from ..schemas import KioskIn, KioskPatch
from ..views import kiosk_out

router = APIRouter()
VIEW, MANAGE = require(*STAFF_SIDE), require(ADMIN, SUPER_ADMIN)


def today_start(s):
    n = local(now(), s)
    return n.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(hours=s.tz_offset_hours)


def today_counts(db, s):
    rows = db.visits.aggregate([{"$match": {"received_at": {"$gte": today_start(s).replace(tzinfo=None)}}}, {"$group": {"_id": "$kiosk_id", "n": {"$sum": 1}}}])
    return {r["_id"]: r["n"] for r in rows}


def find(db, kid):
    k = db.kiosks.find_one({"kiosk_id": kid})
    if not k:
        raise HTTPException(404, "Kiosk not found")
    return k


@router.get("/kiosks")
def list_kiosks(request: Request, removed: bool = False, a=Depends(VIEW), db=Depends(db_dep)):
    today = today_counts(db, request.app.state.settings)
    rows = [k for k in db.kiosks.find({}).sort("kiosk_id", 1) if bool(k.get("removed_at")) == removed]
    return [kiosk_out(k, today.get(k["kiosk_id"], 0)) for k in rows]


@router.get("/kiosks/activity")
def activity(request: Request, day: str = Query("", max_length=10), kiosk: str = Query("", max_length=40), clinic: str = Query("", max_length=80), a=Depends(VIEW), db=Depends(db_dep)):
    """Check-in feed. `day` (YYYY-MM-DD, clinic local time) limits it to that calendar day; `kiosk` to one unit; `clinic` to a clinic's kiosks."""
    s = request.app.state.settings
    q = {}
    if day:
        try:
            start = datetime.strptime(day, "%Y-%m-%d") - timedelta(hours=s.tz_offset_hours)
        except ValueError:
            raise HTTPException(422, "day must look like 2026-11-03")
        q["received_at"] = {"$gte": start, "$lt": start + timedelta(days=1)}
    if kiosk:
        q["kiosk_id"] = kiosk
    if clinic:   # every kiosk that belongs to that clinic
        ids = [k["kiosk_id"] for k in db.kiosks.find({"clinic": clinic})]
        q["kiosk_id"] = {"$in": [i for i in ids if not kiosk or i == kiosk]}
    rows = list(db.visits.find(q).sort("received_at", -1).limit(500))
    names = {p["_id"]: f"{p['first_name']} {p['last_name']}" for p in db.patients.find({"_id": {"$in": [r["patient_ref"] for r in rows if r.get("patient_ref")]}})}
    kn = {k["kiosk_id"]: k.get("name") or k["kiosk_id"] for k in db.kiosks.find({})}
    clinics = {k["kiosk_id"]: k.get("clinic", "") for k in db.kiosks.find({})}
    # no vitals or tiers here: this feed is visible to admins as well
    out = []
    for r in rows:
        t = local(r["received_at"], s)
        out.append({"date": t.strftime("%Y-%m-%d"), "time": t.strftime("%I:%M %p"), "kioskId": r["kiosk_id"], "clinic": clinics.get(r["kiosk_id"], ""), "kiosk": kn.get(r["kiosk_id"], r["kiosk_id"]),
                    "event": "Check-in completed", "patient": names.get(r.get("patient_ref")) or "Guest"})
    return out


@router.post("/kiosks", status_code=201)
def add_kiosk(body: KioskIn, request: Request, a=Depends(MANAGE), db=Depends(db_dep)):
    kid = body.id
    while not kid:                                          # no ID typed: take the next free one, never one a kiosk already uses
        kid = next_id(db, "kiosk", "K-", 2)
        if db.kiosks.find_one({"kiosk_id": kid}):
            kid = None
    k = db.kiosks.find_one({"kiosk_id": kid})
    if k and k.get("registered") and not k.get("removed_at"):
        raise HTTPException(409, "That kiosk ID is already registered")
    db.kiosks.update_one({"kiosk_id": kid}, {"$set": {"name": body.name, "clinic": body.clinic, "registered": True, "removed_at": None, "manual_status": None},
                                              "$setOnInsert": {"created_at": now()}}, upsert=True)
    audit(db, request, a, "KIOSK REGISTER", kid)
    return kiosk_out(find(db, kid))


@router.patch("/kiosks/{kid}")
def set_status(kid: str, body: KioskPatch, request: Request, a=Depends(MANAGE), db=Depends(db_dep)):
    find(db, kid)
    db.kiosks.update_one({"kiosk_id": kid}, {"$set": {"manual_status": body.status if body.status in ("Maintenance", "Deactivated") else None}})
    audit(db, request, a, "KIOSK STATUS", kid, {"status": body.status})
    return kiosk_out(find(db, kid))


@router.delete("/kiosks/{kid}")
def remove_kiosk(kid: str, request: Request, a=Depends(MANAGE), db=Depends(db_dep)):
    find(db, kid)
    db.kiosks.update_one({"kiosk_id": kid}, {"$set": {"removed_at": now()}})      # soft delete; can be restored
    audit(db, request, a, "KIOSK REMOVE", kid)
    return {"success": True}


@router.post("/kiosks/{kid}/restore")
def restore_kiosk(kid: str, request: Request, a=Depends(MANAGE), db=Depends(db_dep)):
    find(db, kid)
    db.kiosks.update_one({"kiosk_id": kid}, {"$set": {"removed_at": None}})
    audit(db, request, a, "KIOSK RESTORE", kid)
    return kiosk_out(find(db, kid))