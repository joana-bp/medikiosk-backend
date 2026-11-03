from conftest import H, make_staff, totp_now

PW = "root-password-1"


def first_login(client, email="root@clinic.io", pw=PW):
    return client.post("/api/staff/login", json={"email": email, "password": pw}).json()


def enrol(client, email="root@clinic.io", pw=PW):
    """Returns (secret, enable-response)."""
    sh = H(first_login(client, email, pw)["setupToken"])
    secret = client.post("/api/mfa/setup", headers=sh).json()["secret"]
    return secret, client.post("/api/mfa/enable", json={"code": totp_now(secret)}, headers=sh)


def mfa_step(client, token, code):
    return client.post("/api/staff/login/mfa", json={"mfaToken": token, "code": code})


def test_first_login_gives_setup_token_not_a_session(client):
    j = first_login(client)
    assert j["mfaSetupRequired"] and "token" not in j
    assert client.get("/api/queue", headers=H(j["setupToken"])).status_code == 403          # a setup token is not a session


def test_enrol_signs_in_and_gives_recovery_codes(client, db):
    secret, r = enrol(client)
    j = r.json()
    assert r.status_code == 200 and j["token"] and j["staff"]["mfaEnabled"] and len(j["recoveryCodes"]) == 10
    u = db.users.find_one({"email": "root@clinic.io"})
    assert secret not in u["mfa_secret_enc"] and all(c not in str(u["recovery_hashes"]) for c in j["recoveryCodes"])     # stored encrypted / hashed
    assert client.get("/api/staff", headers=H(j["token"])).status_code == 200


def test_wrong_code_during_enrolment_is_refused(client):
    sh = H(first_login(client)["setupToken"])
    client.post("/api/mfa/setup", headers=sh)
    assert client.post("/api/mfa/enable", json={"code": "000000"}, headers=sh).status_code == 401


def test_enable_without_setup_is_refused(client):
    sh = H(first_login(client)["setupToken"])
    assert client.post("/api/mfa/enable", json={"code": "123456"}, headers=sh).status_code == 400


def test_second_login_needs_the_code(client):
    secret, _ = enrol(client)
    j = first_login(client)
    assert j["mfaRequired"] and "token" not in j
    assert client.get("/api/queue", headers=H(j["mfaToken"])).status_code == 403             # a pending token is not a session
    assert mfa_step(client, j["mfaToken"], "000000").status_code == 401
    ok = mfa_step(client, j["mfaToken"], totp_now(secret, 30))                               # next step: the enrolment step is used up
    assert ok.status_code == 200 and ok.json()["token"]


def test_code_cannot_be_replayed(client):
    secret, _ = enrol(client)
    j = first_login(client)
    assert mfa_step(client, j["mfaToken"], totp_now(secret)).status_code == 401               # same step as enrolment
    nxt = totp_now(secret, 30)
    assert mfa_step(client, j["mfaToken"], nxt).status_code == 200
    assert mfa_step(client, first_login(client)["mfaToken"], nxt).status_code == 401          # used already


def test_recovery_code_works_once(client, db):
    _, r = enrol(client)
    code = r.json()["recoveryCodes"][0]
    assert mfa_step(client, first_login(client)["mfaToken"], code.upper()).status_code == 200
    assert mfa_step(client, first_login(client)["mfaToken"], code).status_code == 401
    assert len(db.users.find_one({"email": "root@clinic.io"})["recovery_hashes"]) == 9
    assert db.audit_logs.count_documents({"action": "RECOVERY CODE USED"}) == 1


def test_code_step_is_rate_limited_and_audited(client, db):
    enrol(client)
    j = first_login(client)
    for _ in range(5):
        assert mfa_step(client, j["mfaToken"], "000000").status_code == 401
    assert mfa_step(client, j["mfaToken"], "000000").status_code == 429
    assert db.audit_logs.count_documents({"action": "MFA FAILED"}) == 5


def test_password_alone_never_gives_a_session(client):
    enrol(client)
    assert set(first_login(client)) == {"mfaRequired", "mfaToken"}


def test_enrolment_signs_out_older_sessions(client, settings):
    settings.mfa_required_staff = False                                                     # 2FA optional: password alone signs in
    old = first_login(client)["token"]
    assert client.get("/api/staff", headers=H(old)).status_code == 200
    secret = client.post("/api/mfa/setup", headers=H(old)).json()["secret"]
    new = client.post("/api/mfa/enable", json={"code": totp_now(secret)}, headers=H(old)).json()["token"]
    assert client.get("/api/staff", headers=H(old)).status_code == 401
    assert client.get("/api/staff", headers=H(new)).status_code == 200


def test_staff_cannot_turn_2fa_off_when_required(client):
    _, r = enrol(client)
    assert client.post("/api/mfa/disable", json={"password": PW, "code": "123456"}, headers=H(r.json()["token"])).status_code == 403


def test_disable_when_allowed_needs_password_and_code(client, settings):
    secret, r = enrol(client)                      # enrol while 2FA is required, then relax the rule
    settings.mfa_required_staff = False
    h = H(r.json()["token"])
    assert client.post("/api/mfa/disable", json={"password": "nope", "code": totp_now(secret, 30)}, headers=h).status_code == 400
    assert client.post("/api/mfa/disable", json={"password": PW, "code": totp_now(secret, 30)}, headers=h).status_code == 200
    assert client.get("/api/staff", headers=h).status_code == 401                            # the old session ended
    assert "token" in first_login(client)                                                    # and 2FA is off again


def test_regenerate_recovery_codes_replaces_old_ones(client):
    secret, r = enrol(client)
    h, old = H(r.json()["token"]), r.json()["recoveryCodes"][0]
    new = client.post("/api/mfa/recovery-codes/regenerate", json={"code": totp_now(secret, 30)}, headers=h).json()["recoveryCodes"]
    assert len(new) == 10
    assert mfa_step(client, first_login(client)["mfaToken"], old).status_code == 401
    assert mfa_step(client, first_login(client)["mfaToken"], new[0]).status_code == 200


def test_new_staff_member_enrols_on_first_login(client, root):
    h = make_staff(client, root, "nurse9@clinic.io")
    assert client.get("/api/queue", headers=h).status_code == 200


def test_garbage_mfa_token(client):
    assert mfa_step(client, "garbage", "123456").status_code == 401


def test_setup_endpoints_need_sign_in(client):
    assert client.post("/api/mfa/setup").status_code == 401
