from datetime import datetime, timedelta, timezone
import bcrypt, jwt

_DUMMY = bcrypt.hashpw(b"dummy-password", bcrypt.gensalt()).decode()


def hash_password(p):
    return bcrypt.hashpw(p.encode(), bcrypt.gensalt()).decode()


def verify_password(p, hashed):
    try:
        return bcrypt.checkpw(p.encode(), (hashed or _DUMMY).encode()) and bool(hashed)
    except ValueError:
        return False


def make_token(secret, user_id, role, minutes):
    now = datetime.now(timezone.utc)
    return jwt.encode({"sub": str(user_id), "role": role, "iat": now, "exp": now + timedelta(minutes=minutes)}, secret, "HS256")
