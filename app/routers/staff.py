from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pymongo.errors import DuplicateKeyError
from ..common import ADMIN, CLINIC_STAFF, SUPER_ADMIN, audit, db_dep, next_id, now, require, temp_password
from ..mfa import reset_account
from ..schemas import StaffIn, StaffPatch
from ..security import hash_password
from ..views import staff_out

router = APIRouter()
MANAGERS = require(ADMIN, SUPER_ADMIN)


def manageable(actor, target_role):
    """An admin manages clinic staff only. Only a super admin touches admin or super admin accounts."""
    return actor["_role"] == SUPER_ADMIN or target_role == CLINIC_STAFF


def get_target(db, actor, sid):
    u = db.users.find_one({"_id": sid})
    if not u or not manageable(actor, u["access_role"]):
        raise HTTPException(404, "Staff member not found")
    return u


@router.get("/staff")
def list_staff(search: str = Query("", max_length=60), a=Depends(MANAGERS), db=Depends(db_dep)):
    rows = [u for u in db.users.find({}).sort("name", 1) if manageable(a, u["access_role"])]
    t = search.strip().lower()
    if t:
        rows = [u for u in rows if t in u["name"].lower() or t in u["email"] or t in u["_id"].lower()]
    return [staff_out(u) for u in rows]


@router.post("/staff", status_code=201)
def create_staff(body: StaffIn, request: Request, a=Depends(MANAGERS), db=Depends(db_dep)):
    if not manageable(a, body.accessRole):
        raise HTTPException(403, "Only a super admin can create admin accounts")
    pw = temp_password()
    doc = {"_id": next_id(db, "staff", "S-", 4), "name": body.name.strip(), "email": body.email.lower(), "clinic": body.clinic,
           "access_role": body.accessRole, "password_hash": hash_password(pw), "active": True, "must_change_password": True,
           "last_active": None, "created_at": now(), "created_by": a["email"]}
    try:
        db.users.insert_one(doc)
    except DuplicateKeyError:
        raise HTTPException(409, "That email is already used by another account")
    audit(db, request, a, "STAFF CREATE", f"{doc['_id']} {doc['name']}", {"access_role": body.accessRole})
    return {**staff_out(doc), "temporaryPassword": pw}          # shown once; the person must change it at first sign-in


@router.patch("/staff/{sid}")
def update_staff(sid: str, body: StaffPatch, request: Request, a=Depends(MANAGERS), db=Depends(db_dep)):
    u = get_target(db, a, sid)
    sets = {}
    for f, col in (("name", "name"), ("clinic", "clinic")):
        if getattr(body, f) is not None:
            sets[col] = getattr(body, f)
    if body.email:
        sets["email"] = body.email.lower()
    if body.status is not None:
        if u["_id"] == a["_id"]:
            raise HTTPException(400, "You cannot change your own status")
        sets["active"] = body.status != "Suspended"
    if sets:
        try:
            db.users.update_one({"_id": sid}, {"$set": sets})
        except DuplicateKeyError:
            raise HTTPException(409, "That email is already used by another account")
    audit(db, request, a, "STAFF UPDATE", sid, {"fields": sorted(sets)})
    return staff_out(db.users.find_one({"_id": sid}))


@router.post("/staff/{sid}/reset-password")
def reset_password(sid: str, request: Request, a=Depends(MANAGERS), db=Depends(db_dep)):
    u = get_target(db, a, sid)
    pw = temp_password()
    db.users.update_one({"_id": sid}, {"$set": {"password_hash": hash_password(pw), "must_change_password": True}})
    audit(db, request, a, "PASSWORD RESET", sid)
    return {"temporaryPassword": pw}


@router.post("/staff/{sid}/reset-mfa")
def reset_staff_mfa(sid: str, request: Request, a=Depends(MANAGERS), db=Depends(db_dep)):
    """For a lost phone: turns their 2FA off and signs them out. They set it up again at next sign-in.
    An admin can do this for clinic staff only; a super admin for anyone else too (never for themselves)."""
    u = get_target(db, a, sid)
    if u["_id"] == a["_id"]:
        raise HTTPException(400, "You cannot reset your own two-factor sign-in")
    reset_account(db, "staff", u)
    audit(db, request, a, "MFA RESET", sid)
    return {"success": True}


@router.delete("/staff/{sid}")
def delete_staff(sid: str, request: Request, a=Depends(MANAGERS), db=Depends(db_dep)):
    u = get_target(db, a, sid)
    if u["_id"] == a["_id"]:
        raise HTTPException(400, "You cannot delete your own account")
    if u["access_role"] == SUPER_ADMIN and db.users.count_documents({"access_role": SUPER_ADMIN, "active": True}) <= 1:
        raise HTTPException(400, "The last super admin cannot be deleted")
    db.users.delete_one({"_id": sid})
    audit(db, request, a, "STAFF DELETE", f"{sid} {u['name']}")
    return {"success": True}
