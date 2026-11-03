#!/usr/bin/env python3
"""Break-glass: turn off two-factor sign-in for one account whose owner lost their device AND recovery codes.
Meant for a locked-out super admin (nobody else can reset them). Run it on the server, from the backend folder:
    python scripts/reset_mfa.py someone@clinic.io            (a staff-side account)
    python scripts/reset_mfa.py someone@example.com --patient
The person is signed out everywhere and must set two-factor up again at their next sign-in. The reset is written to the audit log."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass
from app.common import now
from app.db import get_database
from app.mfa import reset_account


def run(db, email, patient=False, operator="cli"):
    side = "patient" if patient else "staff"
    acct = db["patients" if patient else "users"].find_one({"email": email.strip().lower()})
    if not acct:
        return None
    reset_account(db, side, acct)
    db.audit_logs.insert_one({"at": now(), "actor_email": operator, "actor_role": "server console", "action": "MFA RESET", "target": acct["_id"],
                              "ip": "—", "severity": "Warning", "details": {"via": "scripts/reset_mfa.py"}})
    return acct["_id"]


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(args) != 1:
        sys.exit(__doc__)
    uri = os.getenv("MONGO_URI")
    if not uri or uri == "mock":
        sys.exit("Set MONGO_URI in your .env file first.")
    who = run(get_database(uri, os.getenv("MONGO_DB", "medikiosk")), args[0], patient="--patient" in sys.argv)
    sys.exit(f"No {'patient' if '--patient' in sys.argv else 'staff'} account with that email." if not who else print(f"Two-factor reset for {who}. They set it up again at next sign-in.") or 0)
