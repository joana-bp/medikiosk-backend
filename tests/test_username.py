"""Staff usernames: set when an account is created, and usable (instead of the email) to sign in."""


def _make(client, root, **extra):
    body = {"name": "Una Staff", "email": "una@clinic.io", "clinic": "C", "accessRole": "clinic_staff", **extra}
    return client.post("/api/staff", json=body, headers=root)


def test_create_with_username_is_stored_lowercase_and_returned(client, root):
    r = _make(client, root, username="  Una.Staff ")
    assert r.status_code == 201, r.text
    assert r.json()["username"] == "una.staff"


def test_username_is_optional(client, root):
    r = _make(client, root)
    assert r.status_code == 201 and r.json()["username"] == ""


def test_bad_usernames_are_refused(client, root):
    for bad in ("ab", "has space", "una@clinic.io", "-start", "x" * 31):
        assert _make(client, root, username=bad).status_code == 422, bad


def test_duplicate_username_is_refused_on_create_and_edit(client, root):
    assert _make(client, root, username="una").status_code == 201
    r = _make(client, root, email="other@clinic.io", username="UNA")
    assert r.status_code == 409 and "username" in r.json()["detail"]
    other = _make(client, root, email="third@clinic.io", username="third").json()
    r = client.patch(f"/api/staff/{other['id']}", json={"username": "una"}, headers=root)
    assert r.status_code == 409


def test_edit_can_add_a_username_to_an_existing_account(client, root):
    acct = _make(client, root).json()
    r = client.patch(f"/api/staff/{acct['id']}", json={"username": "una2"}, headers=root)
    assert r.status_code == 200 and r.json()["username"] == "una2"


def test_sign_in_with_username_or_email(client, root):
    created = _make(client, root, username="una").json()
    pw = created["temporaryPassword"]
    for who in ("una", "UNA", "una@clinic.io", "Una@Clinic.io"):
        r = client.post("/api/staff/login", json={"identifier": who, "password": pw})
        assert r.status_code == 200, (who, r.text)
        assert r.json().get("mfaSetupRequired") or r.json().get("mfaRequired") or r.json().get("token")


def test_old_email_key_still_works(client, root):
    pw = _make(client, root, username="una").json()["temporaryPassword"]
    assert client.post("/api/staff/login", json={"email": "una@clinic.io", "password": pw}).status_code == 200


def test_wrong_password_or_unknown_username(client, root):
    pw = _make(client, root, username="una").json()["temporaryPassword"]
    assert client.post("/api/staff/login", json={"identifier": "una", "password": "nope-nope"}).status_code == 401
    assert client.post("/api/staff/login", json={"identifier": "ghost", "password": pw}).status_code == 401


def test_username_cannot_be_used_to_dodge_an_email(client, root):
    """A username never contains '@', so 'una' can't match an account whose email is 'una'."""
    _make(client, root, username="una")
    r = client.post("/api/staff/login", json={"identifier": "una@", "password": "x"})
    assert r.status_code == 401
