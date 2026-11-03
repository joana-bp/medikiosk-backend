import os, re, sys
from datetime import datetime, timedelta, timezone
import pytest
from conftest import H, PATIENT, SECRETS, make_patient, make_staff, staff_login, totp_now
from app.config import Settings
from app.main import create_app

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
from reset_mfa import run as reset_cli

PPW = PATIENT["password"]


def plogin(client):
    return client.post("/api/patient/login", json={"email": PATIENT["email"], "password": PPW})


def p_enrol(client, headers):
    secret = client.post("/api/mfa/setup", headers=headers).json()["secret"]
    r = client.post("/api/mfa/enable", json={"code": totp_now(secret)}, headers=headers)
    assert r.status_code == 200, r.text
    return secret, r.json()


def p_second_step(client, secret, offset=30):
    tok = plogin(client).json()["mfaToken"]
    return client.post("/api/patient/login/mfa", json={"mfaToken": tok, "code": totp_now(secret, offset)})


def staff_secret(client, email):
    return SECRETS[(id(client), email)]


# ---------------- Phase 2: patients ----------------
def test_patient_2fa_is_optional_by_default(client):
    make_patient(client)
    assert "token" in plogin(client).json()


def test_patient_enrols_from_the_app_and_older_sessions_end(client):
    _, h = make_patient(client)
    secret, j = p_enrol(client, h)
    assert j["patient"]["mfaEnabled"] and len(j["recoveryCodes"]) == 10
    assert client.get("/api/patient/me", headers=h).status_code == 401                        # old session ended
    assert client.get("/api/patient/me", headers=H(j["token"])).status_code == 200


def test_patient_login_then_needs_the_code(client):
    _, h = make_patient(client)
    secret, _ = p_enrol(client, h)
    j = plogin(client).json()
    assert set(j) == {"mfaRequired", "mfaToken"}
    assert client.get("/api/patient/me", headers=H(j["mfaToken"])).status_code == 403         # a pending token is not a session
    assert client.post("/api/patient/login/mfa", json={"mfaToken": j["mfaToken"], "code": "000000"}).status_code == 401
    ok = p_second_step(client, secret)
    assert ok.status_code == 200 and client.get("/api/patient/me", headers=H(ok.json()["token"])).status_code == 200


def test_patient_and_staff_tokens_do_not_cross(client, root):
    _, h = make_patient(client)
    p_enrol(client, h)
    ptok = plogin(client).json()["mfaToken"]
    stok = client.post("/api/staff/login", json={"email": "root@clinic.io", "password": "root-password-1"}).json()["mfaToken"]
    assert client.post("/api/staff/login/mfa", json={"mfaToken": ptok, "code": "123456"}).status_code == 403   # patient token on the staff step
    assert client.post("/api/patient/login/mfa", json={"mfaToken": stok, "code": "123456"}).status_code == 403   # staff token on the patient step
    assert client.get("/api/staff", headers=H(stok)).status_code == 403


def test_patient_qr_kiosk_login_is_not_asked_for_a_code(client):
    _, h = make_patient(client)
    tok = client.get("/api/patient/me/qr-token", headers=h).json()["qrToken"]
    p_enrol(client, h)
    r = client.post("/api/patient/login-qr", json={"qrToken": "MEDIKIOSK:" + tok})
    assert r.status_code == 200 and client.get("/api/patient/me", headers=H(r.json()["token"])).status_code == 200


def test_patient_can_turn_2fa_off_with_password_and_code(client):
    _, h = make_patient(client)
    secret, j = p_enrol(client, h)
    h2 = H(j["token"])
    assert client.post("/api/mfa/disable", json={"password": "wrong", "code": totp_now(secret, 30)}, headers=h2).status_code == 400
    assert client.post("/api/mfa/disable", json={"password": PPW, "code": totp_now(secret, 30)}, headers=h2).status_code == 200
    assert "token" in plogin(client).json()


def test_patient_2fa_can_be_made_compulsory(client, settings):
    settings.mfa_required_patients = True
    r = client.post("/api/patient/signup", json=PATIENT).json()
    assert r["mfaSetupRequired"] and "token" not in r
    sh = H(r["setupToken"])
    assert client.get("/api/patient/me", headers=sh).status_code == 403                         # a setup token is not a session
    _, j = p_enrol(client, sh)
    assert client.get("/api/patient/me", headers=H(j["token"])).status_code == 200
    h2 = H(j["token"])
    assert client.post("/api/mfa/disable", json={"password": PPW, "code": "123456"}, headers=h2).status_code == 403


# ---------------- Phase 2: reset for a lost device ----------------
def test_admin_resets_clinic_staff_2fa(client, root, admin, nurse, db):
    sid = db.users.find_one({"email": "nurse1@clinic.io"})["_id"]
    assert client.post(f"/api/staff/{sid}/reset-mfa", headers=admin).status_code == 200
    assert client.get("/api/queue", headers=nurse).status_code == 401                         # signed out
    assert client.post("/api/staff/login", json={"email": "nurse1@clinic.io", "password": "x"}).status_code == 401
    u = db.users.find_one({"_id": sid})
    assert not u["mfa_enabled"] and "mfa_secret_enc" not in u and "recovery_hashes" not in u
    assert db.audit_logs.count_documents({"action": "MFA RESET", "target": sid}) == 1


def test_after_reset_the_person_sets_2fa_up_again(client, root, admin, nurse, db):
    sid = db.users.find_one({"email": "nurse1@clinic.io"})["_id"]
    old_pw = db.users.find_one({"_id": sid})["password_hash"]
    pw = client.post(f"/api/staff/{sid}/reset-password", headers=admin).json()["temporaryPassword"]
    client.post(f"/api/staff/{sid}/reset-mfa", headers=admin)
    j = client.post("/api/staff/login", json={"email": "nurse1@clinic.io", "password": pw}).json()
    assert j["mfaSetupRequired"]
    assert staff_login(client, "nurse1@clinic.io", pw).status_code == 200


def test_reset_clears_a_2fa_lockout(client, admin, nurse, db):
    sid = db.users.find_one({"email": "nurse1@clinic.io"})["_id"]
    db.login_attempts.insert_one({"_id": f"mfa:staff:{sid}", "count": 5, "first_at": datetime.now(timezone.utc)})
    client.post(f"/api/staff/{sid}/reset-mfa", headers=admin)
    assert db.login_attempts.find_one({"_id": f"mfa:staff:{sid}"}) is None


def test_reset_permissions(client, root, admin, nurse, db):
    admin_id = db.users.find_one({"email": "admin1@clinic.io"})["_id"]
    root_id = db.users.find_one({"email": "root@clinic.io"})["_id"]
    nurse_id = db.users.find_one({"email": "nurse1@clinic.io"})["_id"]
    assert client.post(f"/api/staff/{nurse_id}/reset-mfa", headers=nurse).status_code == 403   # clinic staff cannot reset anyone
    assert client.post(f"/api/staff/{root_id}/reset-mfa", headers=admin).status_code == 404    # an admin cannot touch super admins
    h_root = root
    assert client.post(f"/api/staff/{root_id}/reset-mfa", headers=h_root).status_code == 400   # nobody resets themselves
    assert client.post(f"/api/staff/{admin_id}/reset-mfa", headers=h_root).status_code == 200  # a super admin can reset an admin


def test_staff_side_resets_a_patients_2fa(client, nurse, db):
    pid, h = make_patient(client)
    secret, j = p_enrol(client, h)
    assert client.post(f"/api/patients/{pid}/reset-mfa", headers=nurse).status_code == 200
    assert client.get("/api/patient/me", headers=H(j["token"])).status_code == 401
    assert "token" in plogin(client).json()
    assert client.post(f"/api/patients/{pid}/reset-mfa", headers=h).status_code in (401, 403)


def test_break_glass_script_resets_a_locked_out_super_admin(client, root, db):
    assert reset_cli(db, "nobody@clinic.io") is None
    staff_login(client, "root@clinic.io", "root-password-1")                                   # enrols root
    assert db.users.find_one({"email": "root@clinic.io"})["mfa_enabled"]
    assert reset_cli(db, "Root@Clinic.io") == "S-0001"
    assert not db.users.find_one({"email": "root@clinic.io"})["mfa_enabled"]
    assert client.post("/api/staff/login", json={"email": "root@clinic.io", "password": "root-password-1"}).json()["mfaSetupRequired"]
    log = db.audit_logs.find_one({"action": "MFA RESET"})
    assert log["actor_email"] == "cli" and log["target"] == "S-0001"


def test_break_glass_script_works_for_patients(client, db):
    pid, h = make_patient(client)
    p_enrol(client, h)
    assert reset_cli(db, PATIENT["email"], patient=True) == pid
    assert "token" in plogin(client).json()


# ---------------- Phase 3: emailed code ----------------
@pytest.fixture
def mail(client, settings, nurse):
    """Turns the emailed-code fallback on with a fake mail sender. Returns the list of sent (to, subject, body)."""
    settings.mfa_email_fallback = True
    sent = []
    client.app.state.mailer = lambda to, subject, body: sent.append((to, subject, body))
    return sent


def pending(client, email="nurse1@clinic.io", pw=None, db=None):
    if pw is None:
        pw = "tmp"
    return client.post("/api/staff/login", json={"email": email, "password": pw})


@pytest.fixture
def nurse_pw(client, root, db):
    """A clinic-staff account that has enrolled, with its (known) password."""
    r = client.post("/api/staff", json={"name": "Neil", "email": "neil@clinic.io", "clinic": "C", "accessRole": "clinic_staff"}, headers=root).json()
    staff_login(client, "neil@clinic.io", r["temporaryPassword"])
    return r["temporaryPassword"]


def ask_mail(client, mail, pw):
    tok = client.post("/api/staff/login", json={"email": "neil@clinic.io", "password": pw}).json()["mfaToken"]
    r = client.post("/api/staff/login/mfa/email", json={"mfaToken": tok})
    return tok, r


def code_from(mail):
    return re.search(r"code is (\d{6})", mail[-1][2]).group(1)


def test_emailed_code_signs_in_once(client, mail, nurse_pw, db):
    tok, r = ask_mail(client, mail, nurse_pw)
    assert r.status_code == 200 and r.json() == {"sent": True} and mail[-1][0] == "neil@clinic.io"
    code = code_from(mail)
    assert code not in str(db.users.find_one({"email": "neil@clinic.io"})["email_otp"])      # stored hashed
    ok = client.post("/api/staff/login/mfa", json={"mfaToken": tok, "code": code})
    assert ok.status_code == 200 and ok.json()["token"]
    assert client.post("/api/staff/login/mfa", json={"mfaToken": tok, "code": code}).status_code == 401      # single use
    assert db.audit_logs.count_documents({"action": "EMAIL CODE USED"}) == 1


def test_emailed_code_can_be_asked_again_only_after_a_minute(client, mail, nurse_pw, db):
    tok, _ = ask_mail(client, mail, nurse_pw)
    assert client.post("/api/staff/login/mfa/email", json={"mfaToken": tok}).status_code == 429
    db.users.update_one({"email": "neil@clinic.io"}, {"$set": {"email_otp.sent_at": datetime.now(timezone.utc) - timedelta(seconds=61)}})
    assert client.post("/api/staff/login/mfa/email", json={"mfaToken": tok}).status_code == 200


def test_expired_emailed_code_is_refused(client, mail, nurse_pw, db):
    tok, _ = ask_mail(client, mail, nurse_pw)
    db.users.update_one({"email": "neil@clinic.io"}, {"$set": {"email_otp.exp": datetime.now(timezone.utc) - timedelta(seconds=1)}})
    assert client.post("/api/staff/login/mfa", json={"mfaToken": tok, "code": code_from(mail)}).status_code == 401


def test_wrong_emailed_codes_hit_the_lockout(client, mail, nurse_pw):
    tok, _ = ask_mail(client, mail, nurse_pw)
    real = code_from(mail)
    wrong = "000000" if real != "000000" else "111111"
    for _ in range(5):
        assert client.post("/api/staff/login/mfa", json={"mfaToken": tok, "code": wrong}).status_code == 401
    assert client.post("/api/staff/login/mfa", json={"mfaToken": tok, "code": real}).status_code == 429


def test_emailed_code_is_off_unless_turned_on(client, nurse_pw):
    tok = client.post("/api/staff/login", json={"email": "neil@clinic.io", "password": nurse_pw}).json()["mfaToken"]
    assert client.post("/api/staff/login/mfa/email", json={"mfaToken": tok}).status_code == 404


def test_emailed_code_never_changes_2fa_settings(client, mail, nurse_pw, settings):
    settings.mfa_required_staff = False
    tok, _ = ask_mail(client, mail, nurse_pw)
    code = code_from(mail)
    h = H(client.post("/api/staff/login/mfa", json={"mfaToken": tok, "code": "000000"}).json().get("token", ""))  # no session from a wrong code
    s = staff_login(client, "neil@clinic.io", nurse_pw)
    assert s.status_code == 200
    h = H(s.json()["token"])
    assert client.post("/api/mfa/recovery-codes/regenerate", json={"code": code}, headers=h).status_code == 401
    assert client.post("/api/mfa/disable", json={"password": nurse_pw, "code": code}, headers=h).status_code == 401


def test_mail_failure_gives_a_clear_error(client, mail, nurse_pw):
    def boom(*a):
        raise OSError("smtp down")
    client.app.state.mailer = boom
    tok = client.post("/api/staff/login", json={"email": "neil@clinic.io", "password": nurse_pw}).json()["mfaToken"]
    assert client.post("/api/staff/login/mfa/email", json={"mfaToken": tok}).status_code == 502


def test_patient_can_use_an_emailed_code_too(client, settings):
    _, h = make_patient(client)
    p_enrol(client, h)
    settings.mfa_email_fallback = True
    sent = []
    client.app.state.mailer = lambda to, subject, body: sent.append((to, subject, body))
    tok = plogin(client).json()["mfaToken"]
    assert client.post("/api/patient/login/mfa/email", json={"mfaToken": tok}).status_code == 200
    code = re.search(r"code is (\d{6})", sent[-1][2]).group(1)
    assert client.post("/api/patient/login/mfa", json={"mfaToken": tok, "code": code}).status_code == 200


def test_email_fallback_needs_smtp_settings(settings):
    bad = Settings(**{**settings.__dict__, "mfa_email_fallback": True})
    with pytest.raises(RuntimeError, match="SMTP_HOST"):
        bad.check()
    Settings(**{**settings.__dict__, "mfa_email_fallback": True, "smtp_host": "smtp.example.org", "smtp_from": "no-reply@example.org"}).check()
