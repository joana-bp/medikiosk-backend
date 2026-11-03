"""Transport security: insist on HTTPS / WSS in production and add safe response headers.

The app itself speaks plain HTTP; TLS is done by whatever sits in front of it (Caddy, nginx, or the host's
load balancer). That front door tells us the original scheme with `X-Forwarded-Proto`, and uvicorn turns it
into the request scheme when started with `--proxy-headers --forwarded-allow-ips=<proxy address>`.

With REQUIRE_HTTPS=1:
  - plain-HTTP GET/HEAD is redirected to https (308); any other plain-HTTP request is refused (403) so a
    password or token in a request body is never accepted over an unencrypted link
  - a WebSocket must be wss://, otherwise it is closed before it is accepted
  - responses carry Strict-Transport-Security so browsers stay on https
/health is exempt so the proxy's own health check can use plain HTTP inside the server.
"""
import json

EXEMPT = ("/health",)


def _header(scope, name):
    for k, v in scope.get("headers", []):
        if k == name:
            return v.decode("latin-1")
    return ""


class TransportSecurity:
    def __init__(self, app, require_https=False):
        self.app, self.require_https = app, require_https

    async def __call__(self, scope, receive, send):
        kind = scope["type"]
        if kind == "websocket":
            if self.require_https and scope.get("scheme") != "wss":
                await receive()                                   # the 'connect' event
                await send({"type": "websocket.close", "code": 4403})
                return
            return await self.app(scope, receive, send)
        if kind != "http":
            return await self.app(scope, receive, send)

        secure = scope.get("scheme") == "https"
        path = scope.get("path", "")
        if self.require_https and not secure and path not in EXEMPT:
            if scope["method"] in ("GET", "HEAD"):
                host = _header(scope, b"host")
                qs = scope.get("query_string", b"").decode("latin-1")
                location = f"https://{host}{path}" + (f"?{qs}" if qs else "")
                return await self._reply(send, 308, {"detail": "Use https"}, [(b"location", location.encode())])
            return await self._reply(send, 403, {"detail": "HTTPS required"})

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                h = message.setdefault("headers", [])
                h += [(b"x-content-type-options", b"nosniff"), (b"referrer-policy", b"no-referrer"),
                      (b"x-frame-options", b"DENY")]
                if path.startswith("/api"):
                    h.append((b"cache-control", b"no-store"))     # tokens and patient data must not be cached
                if self.require_https and secure:
                    h.append((b"strict-transport-security", b"max-age=31536000"))
            await send(message)

        await self.app(scope, receive, send_with_headers)

    @staticmethod
    async def _reply(send, status, body, extra=()):
        data = json.dumps(body).encode()
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(data)).encode()), *extra]})
        await send({"type": "http.response.body", "body": data})
