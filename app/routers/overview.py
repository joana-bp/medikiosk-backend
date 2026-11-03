from fastapi import APIRouter, Depends, Query, Request
from ..common import ADMIN, CLINIC_STAFF, STAFF_SIDE, SUPER_ADMIN, db_dep, iso, local, require
from ..views import kiosk_status
from .kiosks import today_counts

router = APIRouter()


@router.get("/dashboard/stats")
def stats(request: Request, a=Depends(require(*STAFF_SIDE)), db=Depends(db_dep)):
    """Totals only: no individual patient's results, so admins can see this too."""
    kiosks = [k for k in db.kiosks.find({}) if not k.get("removed_at") and k.get("registered")]
    return {"clinicalStaff": db.users.count_documents({"access_role": CLINIC_STAFF, "active": True}),
            "clinicalStaffDelta": "Active accounts", "patientRecords": db.patients.count_documents({}), "patientRecordsDelta": "Registered patients",
            "kiosksOnline": sum(kiosk_status(k) == "Online" for k in kiosks), "kiosksTotal": len(kiosks), "kiosksAcross": "Registered kiosks",
            "checkInsToday": sum(today_counts(db, request.app.state.settings).values()), "checkInsDelta": "Since midnight"}


@router.get("/dashboard/recent-activity")
def recent(a=Depends(require(ADMIN, SUPER_ADMIN)), db=Depends(db_dep)):
    skip = {"LOGIN", "LOGIN FAILED", "KIOSK QR LOGIN", "QR VIEW"}
    rows = [r for r in db.audit_logs.find({}).sort("at", -1).limit(60) if r["action"] not in skip][:6]
    return [{"label": r["action"].title(), "meta": f"{r['target']} · {r['at'].strftime('%H:%M')}", "status": r["severity"]} for r in rows]


@router.get("/audit-logs")
def audit_logs(request: Request, search: str = Query("", max_length=60), limit: int = Query(200, ge=1, le=1000), a=Depends(require(SUPER_ADMIN)), db=Depends(db_dep)):
    rows = db.audit_logs.find({}).sort("at", -1).limit(limit)
    st = request.app.state.settings
    out = [{"timestamp": local(r["at"], st).strftime("%Y-%m-%d %H:%M:%S"), "role": r.get("actor_email") or "—",
            "actor": r["action"], "target": r["target"], "ip": r["ip"], "severity": r["severity"], "accountRole": r.get("actor_role")} for r in rows]
    t = search.strip().lower()
    return [r for r in out if t in r["role"].lower() or t in r["actor"].lower() or t in str(r["target"]).lower()] if t else out
