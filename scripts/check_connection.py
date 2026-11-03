#!/usr/bin/env python3
"""Finds out WHY the MongoDB connection fails. Run from the backend folder with your venv active:
    python scripts/check_connection.py
It reads MONGO_URI from .env, tests each step separately and never prints your password."""
import os, re, socket, ssl, sys
from urllib.parse import urlparse, unquote
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

uri = os.getenv("MONGO_URI", "")
if not uri or uri == "mock":
    sys.exit("MONGO_URI is not set in your .env file.")
u = urlparse(uri)
print(f"User: {unquote(u.username or '(none)')}   Host: {u.hostname}   Database in .env: {os.getenv('MONGO_DB', '(MONGO_DB not set)')}")
pw = unquote(u.password) if u.password else ""
print(f"Password: {'(MISSING)' if not pw else str(len(pw)) + ' characters'}   Query part: {u.query or '(none)'}")
problems = []
if not pw:
    problems.append("no password was found between ':' and '@'")
if pw.startswith("<") or pw.endswith(">") or "<db_password>" in uri:
    problems.append("the password is still wrapped in < > (or is the placeholder <db_password>) - remove the angle brackets")
elif "<" in uri or ">" in uri:
    problems.append("there is a < or > somewhere in the line - find it and remove it")
if any(c in pw for c in "/?#[]") or re.search(r"[^A-Za-z0-9._~%-]", pw):
    problems.append("the password has special characters; try a password with only letters and numbers, or URL-encode it (e.g. @ becomes %40)")
if " " in uri.strip():
    problems.append("there is a space inside the connection string; make sure nothing follows it on the line")
for pr in problems:
    print("CHECK THIS:", pr)
if not pw or any("angle" in x or "< or >" in x for x in problems):
    sys.exit("Fix the line in .env, save it, and run this again.")

hosts = []
print("\nStep 1: finding the cluster's servers (DNS)")
try:
    if uri.startswith("mongodb+srv://"):
        import dns.resolver
        ans = dns.resolver.resolve(f"_mongodb._tcp.{u.hostname}", "SRV", lifetime=10)
        hosts = [(str(r.target).rstrip("."), r.port) for r in ans]
    else:
        hosts = [(u.hostname, u.port or 27017)]
    print("  OK:", ", ".join(h for h, _ in hosts))
except Exception as e:
    print(f"  FAILED: {type(e).__name__}: {e}\n  -> Your network or DNS is blocking the lookup. Try another network (e.g. phone hotspot) or another DNS (8.8.8.8).")
    sys.exit(1)

print("\nStep 2: reaching each server on port 27017 (network)")
reachable = []
for h, p in hosts:
    try:
        socket.create_connection((h, p), timeout=10).close()
        print(f"  OK      {h}"); reachable.append((h, p))
    except Exception as e:
        print(f"  FAILED  {h}: {type(e).__name__}: {e}")
if not reachable:
    print("  -> Nothing can reach Atlas. A firewall, school/campus network, or ISP is blocking port 27017. Try a phone hotspot.")
    sys.exit(1)

print("\nStep 3: secure handshake (TLS)")
try:
    import certifi
    ctx = ssl.create_default_context(cafile=certifi.where())
    h, p = reachable[0]
    with socket.create_connection((h, p), timeout=10) as raw, ctx.wrap_socket(raw, server_hostname=h) as t:
        print(f"  OK      {t.version()} with {h}")
except Exception as e:
    print(f"  FAILED: {type(e).__name__}: {e}")
    print("  -> If it says INTERNAL_ERROR: your IP is not (yet) on Atlas's list. If it mentions a certificate: antivirus/proxy is\n     intercepting secure traffic. Pause the antivirus's web/HTTPS scanning, turn off VPN/proxy, and try again.")
    sys.exit(1)

print("\nStep 4: logging in and pinging the database (waits up to 30 seconds)")
import pymongo
try:
    c = pymongo.MongoClient(uri, serverSelectionTimeoutMS=30000)
    c.admin.command("ping")
    print("  OK: connected and logged in.")
    db = os.getenv("MONGO_DB")
    if db:
        print(f"  Database '{db}' collections now:", c[db].list_collection_names() or "(none yet)")
except pymongo.errors.OperationFailure as e:
    print(f"  FAILED to log in: {e}\n  -> Wrong username or password in the connection string, or the user lacks permission.")
    sys.exit(1)
except Exception as e:
    print(f"  FAILED: {type(e).__name__}: {str(e)[:600]}")
    sys.exit(1)
print("\nAll good. Now run: python scripts/init_db.py")
