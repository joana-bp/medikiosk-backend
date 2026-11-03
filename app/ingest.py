"""Receives visits from the kiosks over MQTT, stores each one exactly once, then acknowledges it.

kiosk sync_worker --medikiosk/<kiosk>/vitals/<tier>--> [broker] --> process_visit() --> MongoDB
                  <--medikiosk/<kiosk>/ack {"message_id","status"}--

The ack is sent only AFTER the database write (or after we found the message was already stored), so the
kiosk keeps the visit in its buffer until we really have it. Duplicates are acked too, otherwise the kiosk
would resend them forever.
"""
import json, logging, re, ssl
from datetime import datetime, timezone
from typing import Literal, Optional

import paho.mqtt.client as mqtt
from pydantic import BaseModel, Field, ValidationError
from pymongo.errors import DuplicateKeyError

log = logging.getLogger("ingest")
PRIORITY = {"Normal": 0, "Low": 1, "Medium": 2, "High": 3}
KIOSK_RE = re.compile(r"^[A-Za-z0-9_-]{1,40}$")


class Vitals(BaseModel):
    spo2: float = Field(ge=0, le=100)
    systolic: float = Field(ge=20, le=350)
    diastolic: Optional[float] = Field(default=None, ge=10, le=250)
    heart_rate: float = Field(ge=10, le=300)
    temperature: float = Field(ge=25, le=50)
    respiratory_rate: float = Field(ge=1, le=80)


class Body(BaseModel):
    height_cm: Optional[float] = None
    weight_kg: Optional[float] = None
    bmi: Optional[float] = None


class VisitIn(BaseModel):
    schema_version: int = 2
    message_id: str = Field(min_length=8, max_length=64)
    kiosk_id: str
    session_type: str = "guest"
    patient_ref: Optional[str] = Field(default=None, max_length=64)
    external_session_id: Optional[str] = Field(default=None, max_length=64)
    captured_at: datetime
    vitals: Vitals
    body: Optional[Body] = None
    urgency: Literal["Normal", "Low", "Medium", "High"]
    priority: Optional[int] = None                 # ignored: we derive it from `urgency` ourselves
    probabilities: Optional[dict] = None
    in_model_range: bool = True
    critical_flags: list[str] = []
    outside_range: list[str] = []                      # which vitals are outside the range the model was built on
    critical_rules_version: Optional[str] = Field(default=None, max_length=60)
    escalation_tier: Optional[Literal["Normal", "Low", "Medium", "High"]] = None   # lowest tier the critical values allow
    model_version: str
    quality: dict = {}


def review_reasons(v):
    """Plain-language reasons staff should double-check this visit (shown next to the tier)."""
    out = []
    if not v.get("in_model_range", True):
        out.append("outside_trained_range")
    if (v.get("quality") or {}).get("rr_level") == "ESTIMATE":
        out.append("breathing_rate_is_estimate")
    return out


def process_visit(db, topic, raw):
    """Handle one MQTT message. Returns (ack_topic, ack_payload) or None when it can't be acknowledged."""
    parts = topic.split("/")
    topic_kiosk = parts[1] if len(parts) >= 3 else None
    try:
        data = json.loads(raw)
        mid, kid = data["message_id"], data["kiosk_id"]
        assert isinstance(mid, str) and isinstance(kid, str) and KIOSK_RE.match(kid)
    except Exception:
        log.warning("dropped an unreadable message on %s", topic)
        return None                                          # no usable message_id: nothing to ack

    ack = (f"medikiosk/{kid}/ack", {"message_id": mid})
    now = datetime.now(timezone.utc)
    try:
        if topic_kiosk != kid:
            raise ValueError(f"topic kiosk {topic_kiosk!r} does not match payload kiosk {kid!r}")
        v = VisitIn.model_validate(data)
    except (ValidationError, ValueError) as e:
        db.rejected_messages.insert_one({"message_id": mid, "kiosk_id": kid, "topic": topic, "error": str(e)[:1000],
                                         "raw": raw.decode(errors="replace")[:20000], "received_at": now})
        log.warning("rejected %s from %s: %s", mid[:8], kid, str(e)[:120])
        return ack[0], {**ack[1], "status": "rejected"}      # acked so the kiosk stops retrying a bad message

    # Only kiosks an admin has registered may add visits. An unknown kiosk is NOT acknowledged, so it keeps the visit
    # in its own SQLite buffer and retries; nothing is lost, and it is accepted once the admin registers that kiosk ID.
    k = db.kiosks.find_one({"kiosk_id": kid})
    if not (k and k.get("registered") and not k.get("removed_at")):
        db.kiosks.update_one({"kiosk_id": kid}, {"$set": {"last_seen": now}, "$setOnInsert": {"registered": False, "name": kid}}, upsert=True)
        log.warning("holding %s: kiosk %s is not registered (register it in the console and the kiosk will resend)", mid[:8], kid)
        return None

    prio = PRIORITY[v.urgency]
    # a critical value can only raise a patient, never lower one; the model's own tier is kept as model_tier
    esc = v.escalation_tier if v.escalation_tier and PRIORITY[v.escalation_tier] > prio else None
    eff = esc or v.urgency
    doc = {"_id": v.message_id, "message_id": v.message_id, "kiosk_id": v.kiosk_id, "session_type": v.session_type,
           "patient_ref": v.patient_ref, "external_session_id": v.external_session_id,
           "captured_at": v.captured_at.astimezone(timezone.utc), "received_at": now,
           "vitals": v.vitals.model_dump(), "body": v.body.model_dump() if v.body else {},
           "model_tier": v.urgency, "model_priority": prio, "probabilities": v.probabilities,
           "in_model_range": v.in_model_range, "critical_flags": v.critical_flags, "model_version": v.model_version,
           "quality": v.quality, "review_reasons": review_reasons(v.model_dump()),
           "effective_tier": eff, "effective_priority": PRIORITY[eff], "override": None,
           "outside_range": v.outside_range, "escalation_tier": v.escalation_tier, "escalated": esc is not None, "critical_rules_version": v.critical_rules_version,
           "status": "waiting", "schema_version": v.schema_version}
    try:
        db.visits.insert_one(doc)
        status = "stored"
    except DuplicateKeyError:
        status = "duplicate"
    db.kiosks.update_one({"kiosk_id": kid}, {"$set": {"last_seen": now}, "$setOnInsert": {"registered": False, "name": kid}},
                         upsert=True)
    log.info("%s %s from %s (%s)", status, v.message_id[:8], kid, v.urgency)
    return ack[0], {**ack[1], "status": status}


class Ingest:
    def __init__(self, db, s, hub=None):
        self.db, self.s, self.hub = db, s, hub
        # fixed client id + persistent session: the broker holds messages while the backend restarts
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="medikiosk-backend", clean_session=False)
        if s.mqtt_username:
            self.client.username_pw_set(s.mqtt_username, s.mqtt_password)
        if s.mqtt_tls:
            self.client.tls_set(ca_certs=s.mqtt_ca_file or None, tls_version=ssl.PROTOCOL_TLS_CLIENT)
        self.client.reconnect_delay_set(1, 30)
        self.client.on_connect = self._on_connect
        self.client.on_disconnect = self._on_disconnect
        self.client.on_connect_fail = self._on_connect_fail
        self.client.on_message = self._on_message

    def _on_connect(self, c, _u, _f, rc, _p):
        if rc.is_failure:
            log.error("MQTT connect failed: %s", rc); return
        c.subscribe([("medikiosk/+/vitals/#", 1), ("medikiosk/+/uplink", 1)])
        log.info("ingest connected to %s:%s", self.s.mqtt_host, self.s.mqtt_port)

    def _on_disconnect(self, c, _u, _f, rc, _p):
        log.warning("MQTT disconnected (%s); will keep retrying", rc)

    def _on_connect_fail(self, c, _u):
        log.warning("MQTT cannot reach %s:%s (wrong address, port blocked, or TLS problem); will keep retrying", self.s.mqtt_host, self.s.mqtt_port)

    def _on_message(self, c, _u, msg):
        try:
            if msg.topic.endswith("/uplink"):                 # kiosk's sync worker online/offline (retained)
                kid = msg.topic.split("/")[1]
                if KIOSK_RE.match(kid):
                    self.db.kiosks.update_one({"kiosk_id": kid}, {"$set": {"uplink": msg.payload.decode()[:20],
                        "uplink_at": datetime.now(timezone.utc)}, "$setOnInsert": {"registered": False, "name": kid}}, upsert=True)
                return
            res = process_visit(self.db, msg.topic, msg.payload)
            if res:
                if self.hub and res[1].get("status") == "stored":
                    self.hub.publish()                    # a new patient is in the queue
                c.publish(res[0], json.dumps(res[1]), qos=1)
        except Exception:
            log.exception("failed to process a message; not acknowledged, the kiosk will resend")

    def start(self):
        self.client.connect_async(self.s.mqtt_host, self.s.mqtt_port, keepalive=30)
        self.client.loop_start()

    def stop(self):
        self.client.loop_stop(); self.client.disconnect()