import os
from dataclasses import dataclass


def _flag(name, default="0"):
    return os.getenv(name, default).strip().lower() in ("1", "true", "yes", "on")


@dataclass
class Settings:
    mongo_uri: str = "mongodb://localhost:27017"
    mongo_db: str = "medikiosk"
    jwt_secret: str = ""
    jwt_minutes: int = 480
    superadmin_email: str = ""
    superadmin_password: str = ""
    mqtt_enabled: bool = True
    mqtt_host: str = "localhost"
    mqtt_port: int = 1883
    mqtt_username: str = ""
    mqtt_password: str = ""
    mqtt_tls: bool = False
    mqtt_ca_file: str = ""
    qr_secret: str = ""
    tz_offset_hours: int = 8
    cors_origins: tuple = ("http://localhost:5173",)
    require_https: bool = False
    mfa_required_staff: bool = True          # staff-side accounts must use two-factor sign-in (set MFA_REQUIRED_STAFF=0 only while rolling out)
    mfa_issuer: str = "MediKiosk"            # the name an authenticator app shows
    mfa_required_patients: bool = False      # patients may turn 2FA on themselves; set MFA_REQUIRED_PATIENTS=1 to make it compulsory
    mfa_disabled: bool = False               # TEMPORARY: MFA_DISABLED=1 skips two-factor at sign-in for everyone (saved 2FA is kept)
    mfa_email_fallback: bool = False         # emailed sign-in code for someone who lost their authenticator phone (needs SMTP_*)
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from: str = ""

    @classmethod
    def from_env(cls):
        e = os.getenv
        s = cls(
            mongo_uri=e("MONGO_URI", cls.mongo_uri), mongo_db=e("MONGO_DB", cls.mongo_db),
            jwt_secret=e("JWT_SECRET", ""), jwt_minutes=int(e("JWT_MINUTES", "480")),
            superadmin_email=e("SUPERADMIN_EMAIL", ""), superadmin_password=e("SUPERADMIN_PASSWORD", ""),
            mqtt_enabled=_flag("MQTT_ENABLED", "1"), mqtt_host=e("MQTT_HOST", "localhost"),
            mqtt_port=int(e("MQTT_PORT", "1883")), mqtt_username=e("MQTT_USERNAME", ""),
            mqtt_password=e("MQTT_PASSWORD", ""), mqtt_tls=_flag("MQTT_TLS"), mqtt_ca_file=e("MQTT_CA_FILE", ""),
            qr_secret=e("QR_SECRET", ""), tz_offset_hours=int(e("TZ_OFFSET_HOURS", "8")),
            require_https=_flag("REQUIRE_HTTPS"), mfa_required_staff=_flag("MFA_REQUIRED_STAFF", "1"), mfa_issuer=e("MFA_ISSUER", "MediKiosk"),
            mfa_required_patients=_flag("MFA_REQUIRED_PATIENTS"), mfa_email_fallback=_flag("MFA_EMAIL_FALLBACK"), mfa_disabled=_flag("MFA_DISABLED"),
            smtp_host=e("SMTP_HOST", ""), smtp_port=int(e("SMTP_PORT", "587")), smtp_username=e("SMTP_USERNAME", ""),
            smtp_password=e("SMTP_PASSWORD", ""), smtp_from=e("SMTP_FROM", ""),
            cors_origins=tuple(o.strip() for o in e("CORS_ORIGINS", "http://localhost:5173").split(",") if o.strip()))
        return s

    def check(self):
        if len(self.jwt_secret) < 24:
            raise RuntimeError("JWT_SECRET must be set to a long random value (at least 24 characters).")
        if len(self.qr_secret) < 24:
            raise RuntimeError("QR_SECRET must be set to a long random value (at least 24 characters).")
        if self.mfa_email_fallback and not (self.smtp_host and self.smtp_from):
            raise RuntimeError("MFA_EMAIL_FALLBACK=1 needs SMTP_HOST and SMTP_FROM so the code can be emailed.")
        if self.require_https:
            bad = [o for o in self.cors_origins if not o.startswith("https://")]
            if bad:
                raise RuntimeError(f"REQUIRE_HTTPS=1 but CORS_ORIGINS has non-https addresses: {', '.join(bad)}")