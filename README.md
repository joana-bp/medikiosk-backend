# MediKiosk backend (FastAPI + MongoDB + MQTT)

```
kiosk (edge sync_worker) --MQTT, tier-priority first--> broker --> backend ingest --> MongoDB
                                                         <-- ack ("stored" / "duplicate") --
patient app + staff console --HTTPS REST (login token)--> backend --> MongoDB
```

## The four accounts
| | patient | clinic_staff | admin | super_admin |
|---|---|---|---|---|
| Own profile, QR, check-in history (no tier) | yes | | | |
| Queue, urgency tiers, vitals, tier override | | **yes** | no | no |
| Register / edit patients | self sign-up | yes | yes | yes |
| Delete a patient | | no | no | yes |
| Clinic-staff accounts | | no | yes | yes |
| Admin accounts | | no | no | yes |
| Kiosks: view / manage | | view | manage | manage |
| Dashboard totals | | yes | yes | yes |
| Audit log | | no | no | **yes** |

Admins and super admins never see individual vitals or tiers. This is enforced in `app/routers/*` on every request, whatever the screens show. One login page for the three staff-side roles is fine: the backend decides what each person may do.

## Endpoints (all under `/api`, names match the frontend's mock backend)
- Patient: `POST /patient/signup`, `/patient/login`, `/patient/login-qr` (kiosk), `GET /patient/me`, `/patient/me/qr-token`, `GET /vitals/history?patientId=`
- Staff: `POST /staff/login`, `/staff/change-password`, `/logout`
- Patients (staff side): `GET/POST /patients`, `GET/PATCH/DELETE /patients/{id}`, `GET/POST /patients/{id}/qr-token` (show / regenerate)
- Staff accounts: `GET/POST /staff`, `PATCH/DELETE /staff/{id}`, `POST /staff/{id}/reset-password`
- Kiosks: `GET/POST /kiosks`, `PATCH/DELETE /kiosks/{id}`, `POST /kiosks/{id}/restore`, `GET /kiosks/activity`
- Dashboard: `GET /dashboard/stats`, `/dashboard/recent-activity`; `GET /audit-logs`
- Clinical (clinic staff only): `GET /queue`, `/visits`, `/visits/{id}`, `POST /visits/{id}/status`, `/visits/{id}/override`
- Docs page with every field: `/docs`

## How the important parts work
- **Queue:** urgency tier first (High on top), then who arrived first. Model confidence is stored but never used for ordering.
- **Override:** needs a reason; the model's tier is kept and the change is audited.
- **New staff accounts:** the console never types a password. The server makes a temporary one, returned once as `temporaryPassword`; the person must change it at first sign-in.
- **Patient QR:** permanent, as your advisor wants. The QR holds `MEDIKIOSK:<36 random hex>`, never the patient ID. The server keeps only a hash (for lookup) and an encrypted copy (so staff can show it again). Regenerating kills every old printed copy. Wrong guesses are rate-limited.
- **Sign-in lockout:** 5 wrong passwords lock that email for 15 minutes.
- **Ingest:** each visit is stored once (`_id` = the kiosk's `message_id`) and acknowledged only after saving. Bad messages go to `rejected_messages`; a kiosk can only post as itself.

## Live queue (WebSocket)
`WS /api/ws/queue` pushes a nudge to clinic-staff screens whenever a visit arrives from a kiosk, a status changes or a tier is overridden. The socket carries **no patient data**: the screen then re-reads `/api/queue` through the normal authenticated call. The client sends its token as the first message (not in the URL, which would end up in logs); the server accepts only active clinic staff and only from the origins in `CORS_ORIGINS`. If the socket drops, the screen reconnects (1s, 2s, 4s ... 30s) and polls every 15s meanwhile. Needs `uvicorn[standard]` (already in `requirements.txt`). Behind HTTPS the browser uses `wss://` automatically.

Kiosk data path: Pi SQLite buffer -> sync worker -> MQTT -> `process_visit()` -> MongoDB -> live nudge -> staff screen.

## Turn on HTTPS (web console, mobile app, live queue)
The app speaks plain HTTP; **a front door in front of it does the encryption**. One certificate covers the REST API and the live queue (`https://` and `wss://`).
1. **Get a front door with HTTPS.** Either a host that provides it (Render, Railway, Fly: your API gets an `https://` address), or your own server with Caddy, which fetches and renews the certificate by itself. Caddyfile:
   ```
   api.yourclinic.example {
       reverse_proxy 127.0.0.1:8000
   }
   ```
2. **Run the app only behind it**, listening on the same machine, and let it trust the front door's scheme header:
   `uvicorn app.main:create_app --factory --host 127.0.0.1 --port 8000 --proxy-headers --forwarded-allow-ips=127.0.0.1 --env-file .env`
   (On a managed host the app is only reachable through the host's proxy, so use `--forwarded-allow-ips="*"` there. Never use `*` if the port is also open to the internet.)
3. **In `.env`:** `REQUIRE_HTTPS=1` and `CORS_ORIGINS=https://your-console-address` (the app refuses to start if any origin is not https).
4. **Point the clients at it:** web `VITE_API_BASE_URL=https://api.yourclinic.example`, mobile `EXPO_PUBLIC_API_URL=https://api.yourclinic.example`.

What `REQUIRE_HTTPS=1` does: plain-HTTP GETs are redirected to https; any other plain-HTTP request (a login, say) is refused without being read; a WebSocket must be `wss://`; responses carry `Strict-Transport-Security`, `no-store` caching on `/api`, `nosniff` and `X-Frame-Options: DENY`. `/health` stays open for the host's health check. Check it: `curl -i http://api.yourclinic.example/api/queue` should answer 308, and a plain-HTTP login should answer 403.

## Collections
`patients`, `users` (staff-side logins), `visits`, `kiosks`, `audit_logs`, `rejected_messages`, `counters`, `login_attempts`. `scripts/init_db.py` creates them with their rules; the backend also makes sure the indexes exist on every start.

## Set up
1. **MongoDB Atlas** (inside your organization): create a Project, then a free cluster (M0, region near you, e.g. Singapore).
   - *Database Access* -> add a database user with a password (letters and numbers only keeps the connection string simple).
   - *Network Access* -> add your current IP address.
   - *Connect -> Drivers* -> copy the connection string and put your password in place of `<db_password>`.
2. `python -m venv venv`, activate it, `pip install -r requirements.txt`
3. `copy .env.example .env` and fill in `MONGO_URI`, `JWT_SECRET`, `QR_SECRET`, `SUPERADMIN_*`.
4. **Create the collections:** `python scripts/init_db.py`. It creates every collection with its rules and indexes (safe to run again, deletes nothing). Check them in Atlas under *Browse Collections*.
5. `uvicorn app.main:create_app --factory --reload --port 8000 --env-file .env` (the first start creates the super admin from `SUPERADMIN_*`)
6. Open `http://localhost:8000/docs`.
For the kiosks: set `MQTT_ENABLED=1` and the `MQTT_*` values, point each kiosk's `broker` at the same broker, and enable its `medikiosk-sync` service.

## Tests
`cd tests && python -m pytest -q`   (45 checks, in-memory database; the collection rules are checked against real documents, but only a real MongoDB enforces them)

## Not done yet
- Broker security for the internet (TLS + a login per kiosk). The kiosk's QR login on the Pi must call `/patient/login-qr` online, or hold a synced copy of QR hashes to work offline.
- Password reset by email for patients; HTTPS/WSS in front of the API (a reverse proxy or the host provides it; the app itself speaks plain HTTP).
