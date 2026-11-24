"""Security and caching headers, added to every response (plain ASGI, no overhead)."""

CSP = "; ".join(
    [
        "default-src 'self'",
        "script-src 'self' https://www.googletagmanager.com",
        "style-src 'self'",
        "font-src 'self'",
        "img-src 'self' data: https://*.google-analytics.com https://*.googletagmanager.com",
        "connect-src 'self' https://*.google-analytics.com https://*.analytics.google.com "
        "https://*.googletagmanager.com",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "object-src 'none'",
    ]
)

COMMON = [
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"strict-origin-when-cross-origin"),
    (b"x-frame-options", b"DENY"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=(), payment=()"),
    (b"cross-origin-opener-policy", b"same-origin"),
]
HTML_ONLY = [(b"content-security-policy", CSP.encode("ascii"))]
STATIC_CACHE = (b"cache-control", b"public, max-age=31536000, immutable")


class SecurityHeadersMiddleware:
    def __init__(self, app, hsts: bool = True):
        self.app = app
        self.hsts = hsts

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        path = scope.get("path", "")

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                present = {name.lower() for name, _ in headers}
                extra = list(COMMON)
                if self.hsts:
                    extra.append((b"strict-transport-security", b"max-age=31536000; includeSubDomains"))
                content_type = next((v for n, v in headers if n.lower() == b"content-type"), b"")
                if content_type.startswith(b"text/html"):
                    extra += HTML_ONLY
                if path.startswith("/static/") and message.get("status") == 200:
                    extra.append(STATIC_CACHE)
                headers += [(n, v) for n, v in extra if n not in present]
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_wrapper)
