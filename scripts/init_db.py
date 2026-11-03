#!/usr/bin/env python3
"""Creates all MediKiosk collections (the 'tables'), their rules and their indexes in MongoDB.
Run once after you have your Atlas connection string in .env, from the backend folder:
    python scripts/init_db.py                 (add --no-rules to skip the validation rules)
Safe to run again: it never deletes anything."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass
from app.db import get_database, init_database

uri, name = os.getenv("MONGO_URI"), os.getenv("MONGO_DB", "medikiosk")
if not uri or uri == "mock":
    sys.exit("Set MONGO_URI in your .env file first (your MongoDB Atlas connection string).")
db = get_database(uri, name)
db.command("ping")
print(f"Connected. Database: {name}")
for line in init_database(db, validators="--no-rules" not in sys.argv):
    print("  " + line)
print("Indexes created. Next: start the backend; it creates the first super admin from SUPERADMIN_* in .env.")
