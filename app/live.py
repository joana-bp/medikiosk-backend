"""Live push to the clinic-staff queue screen over a WebSocket.

The socket carries NO patient data, only a nudge ("queue_changed"). The screen then re-reads /api/queue
through the normal authenticated REST call, so the role rules stay in one place.

Sign-in: browsers cannot send an Authorization header on a WebSocket, and a token in the URL ends up in logs.
So the client connects, then sends its token as the first message; the server checks it exactly like REST does.
Use wss:// (TLS) in production, the same way REST uses https://.
"""
import asyncio, json, logging
import jwt
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from .common import CLINIC_STAFF

log = logging.getLogger("live")
AUTH_WAIT_SECONDS = 5
MAX_SOCKETS = 200


class Hub:
    def __init__(self):
        self.sockets: set = set()
        self.loop = None

    def bind(self, loop):
        self.loop = loop

    def publish(self, event="queue_changed"):
        """Safe to call from any thread (MQTT thread, REST worker threads). Never raises."""
        if not self.loop or not self.sockets:
            return
        try:
            asyncio.run_coroutine_threadsafe(self._send_all(json.dumps({"type": event})), self.loop)
        except Exception:
            log.exception("could not publish live event")

    async def _send_all(self, text):
        for ws in list(self.sockets):
            try:
                await ws.send_text(text)
            except Exception:
                self.sockets.discard(ws)


def _staff_from_token(app, token):
    try:
        p = jwt.decode(token, app.state.settings.jwt_secret, algorithms=["HS256"], options={"require": ["exp", "sub", "kind"]})
    except jwt.PyJWTError:
        return None
    if p["kind"] != "staff":
        return None
    u = app.state.db.users.find_one({"_id": p["sub"]})
    return u if u and u.get("active", True) and u.get("access_role") == CLINIC_STAFF else None


router = APIRouter()


@router.websocket("/ws/queue")
async def queue_socket(ws: WebSocket):
    app = ws.app
    allowed = app.state.settings.cors_origins
    origin = ws.headers.get("origin")
    if origin and origin not in allowed:                      # browsers always send Origin; refuse other sites
        await ws.close(code=4403); return
    await ws.accept()
    try:
        first = json.loads(await asyncio.wait_for(ws.receive_text(), AUTH_WAIT_SECONDS))
        user = await asyncio.to_thread(_staff_from_token, app, str(first.get("token", "")))
    except Exception:
        user = None
    hub = app.state.hub
    if not user or len(hub.sockets) >= MAX_SOCKETS:
        await ws.close(code=4401); return
    hub.sockets.add(ws)
    await ws.send_text(json.dumps({"type": "ready"}))
    try:
        while True:
            await ws.receive_text()                            # the client only sends keep-alive pings
    except WebSocketDisconnect:
        pass
    finally:
        hub.sockets.discard(ws)
