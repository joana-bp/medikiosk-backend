"""Asking for the 2FA setup QR twice (page re-render, double request, second tab) must show the SAME secret."""
import pyotp
from conftest import H


def _fresh_setup_token(client, root):
    made = client.post("/api/staff", json={"name": "New Nurse", "email": "new@clinic.io", "clinic": "C", "accessRole": "clinic_staff"}, headers=root).json()
    r = client.post("/api/staff/login", json={"identifier": "new@clinic.io", "password": made["temporaryPassword"]}).json()
    return r["setupToken"]


def test_setup_called_twice_returns_the_same_secret_and_it_enables(client, root):
    tok = _fresh_setup_token(client, root)
    a = client.post("/api/mfa/setup", headers=H(tok)).json()
    b = client.post("/api/mfa/setup", headers=H(tok)).json()
    assert a["secret"] == b["secret"] and a["otpauthUri"] == b["otpauthUri"]
    r = client.post("/api/mfa/enable", headers=H(tok), json={"code": pyotp.TOTP(a["secret"]).now()})
    assert r.status_code == 200 and r.json()["recoveryCodes"]


def test_a_new_setup_after_enabling_is_refused(client, root):
    tok = _fresh_setup_token(client, root)
    secret = client.post("/api/mfa/setup", headers=H(tok)).json()["secret"]
    session = client.post("/api/mfa/enable", headers=H(tok), json={"code": pyotp.TOTP(secret).now()}).json()["token"]
    assert client.post("/api/mfa/setup", headers=H(session)).status_code == 409
