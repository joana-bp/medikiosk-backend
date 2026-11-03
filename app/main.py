"""MediKiosk backend: REST API for patients, clinic staff, admins and super admins + MQTT ingest from the kiosks.
Run:  uvicorn app.main:create_app --factory --host 0.0.0.0 --port 8000 --env-file .env

Who can do what (enforced here, on every request, whatever the frontend shows):
  patient       own profile, own QR, own check-in history (no urgency tier)
  clinic_staff  queue, urgency tiers, vitals, tier override; register/edit patients; view kiosks
  admin         patients (profile only, may delete), clinic-staff accounts, kiosks, totals - no vitals or tiers
  super_admin   everything an admin does + admin accounts + the audit log - no vitals or tiers
"""
import asyncio, logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .common import now, next_id
from .config import Settings
from .db import ensure_indexes, get_database
from .ingest import Ingest
from .transport import TransportSecurity
from .live import Hub, router as live_router
from .routers import auth, clinical, kiosks, overview, patients, staff
from .security import hash_password

log = logging.getLogger("backend")


def seed_superadmin(db, s):
    if s.superadmin_email and s.superadmin_password and not db.users.find_one({"access_role": "super_admin"}):
        db.users.insert_one({"_id": next_id(db, "staff", "S-", 4), "name": "Super Admin", "email": s.superadmin_email.lower(), "clinic": "", "access_role": "super_admin", "password_hash": hash_password(s.superadmin_password), "active": True,
                             "must_change_password": False, "last_active": None, "created_at": now()})
        log.warning("created first super admin %s - change this password", s.superadmin_email)


def create_app(settings: Settings = None, db=None):
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:     %(name)s: %(message)s")   # so our own messages (MQTT connected, errors) show next to uvicorn's
    s = settings or Settings.from_env()
    s.check()
    db = db if db is not None else get_database(s.mongo_uri, s.mongo_db)
    ensure_indexes(db)
    seed_superadmin(db, s)
    hub = Hub()
    ingest = Ingest(db, s, hub) if s.mqtt_enabled else None

    @asynccontextmanager
    async def lifespan(_app):
        hub.bind(asyncio.get_running_loop())
        if ingest:
            ingest.start()
        yield
        if ingest:
            ingest.stop()

    app = FastAPI(title="MediKiosk backend", version="0.2.0", lifespan=lifespan)
    app.state.db, app.state.settings, app.state.hub = db, s, hub
    app.add_middleware(TransportSecurity, require_https=s.require_https)    # added first = inside CORS, so its replies still carry CORS headers
    app.add_middleware(CORSMiddleware, allow_origins=list(s.cors_origins), allow_methods=["*"], allow_headers=["*"])

    @app.get("/health")
    def health():
        db.command("ping")
        return {"ok": True}

    for r in (auth, patients, staff, kiosks, clinical, overview):
        app.include_router(r.router, prefix="/api")
    app.include_router(live_router, prefix="/api")
    return app