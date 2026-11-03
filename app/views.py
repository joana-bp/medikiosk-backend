"""How database records are shown to the frontend (field names match the frontend's mock backend)."""
from datetime import timedelta
from .common import age_of, ago, aware, initials, iso, now


def patient_out(p, last_visit=None):
    full = " ".join(x for x in (p["first_name"], p.get("middle_name", ""), p["last_name"]) if x)
    return {"id": p["_id"], "firstName": p["first_name"], "middleName": p.get("middle_name", ""), "lastName": p["last_name"],
            "fullName": full, "birthday": p.get("birthday"), "age": age_of(p.get("birthday")), "sex": p.get("sex"), "gender": p.get("sex"),
            "bloodType": p.get("blood_type"), "email": p["email"], "address": p.get("address", ""),
            "lastVisit": last_visit.strftime("%Y-%m-%d") if last_visit else None, "createdAt": iso(p.get("created_at")),
            "mfaEnabled": bool(p.get("mfa_enabled"))}


ACCESS_LABEL = {"clinic_staff": "Clinic Staff", "admin": "Admin", "super_admin": "Super Admin"}


def staff_out(u):
    la = u.get("last_active")
    online = la and (now() - aware(la)) < timedelta(minutes=15)
    return {"id": u["_id"], "name": u["name"], "email": u["email"], "role": ACCESS_LABEL[u["access_role"]], "clinic": u.get("clinic", ""),
            "accessRole": u["access_role"], "status": "Suspended" if not u.get("active", True) else "Online" if online else "Offline",
            "lastActive": ago(la), "initials": initials(u["name"]), "mustChangePassword": bool(u.get("must_change_password")),
            "mfaEnabled": bool(u.get("mfa_enabled"))}


def kiosk_status(k):
    if k.get("manual_status") in ("Maintenance", "Deactivated"):
        return k["manual_status"]
    return "Online" if k.get("uplink") == "online" else "Idle"


def kiosk_out(k, today=0):
    return {"id": k["kiosk_id"], "name": k.get("name") or k["kiosk_id"], "clinic": k.get("clinic", ""), "status": kiosk_status(k),
            "uptime": "—", "today": today, "firmware": k.get("firmware", "—"), "registered": k.get("registered", False),
            "lastSeen": iso(k.get("last_seen")), "removedAt": iso(k.get("removed_at"))}
