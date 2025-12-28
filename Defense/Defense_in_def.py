# defense_in_depth_gui_demo.py
import base64
import hashlib
import hmac
import http.cookies
import http.server
import json
import os
import queue
import secrets
import ssl
import sys
import tempfile
import threading
import time
import tkinter as tk
import urllib.error
import urllib.parse
import urllib.request
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText

HOST = "127.0.0.1"
PORT = 8443

ACCESS_COOKIE = "__Host-access"
REFRESH_COOKIE = "__Secure-refresh"

ACCESS_TTL_SECONDS = 300
REFRESH_TTL_SECONDS = 24 * 3600

KEY_ROTATE_SECONDS = 3600
MAX_BODY_BYTES = 10_000

# Demo-only embedded self-signed TLS key/cert (localhost/127.0.0.1).
_B64_KEY_LINES = [
    "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcEFJQkFBS0NBUUVBN2sxRjdVeUdi",
    "cjhUblVOUFpHSkNhZ0laSnlPNVVkZUFiOEhwaDlhYkRCK2xNYzAyCmpaeXVPeUhNdVZyU3AyOUNy",
    "Z2w0NXFmeW5xQmx4ZnNyOThQWWxJQ3lmallMTkkzNytBdW1DL3k2THliKzl4SlgKTXJPdlJXTlJy",
    "NUFTLzh5T2RiV0Y5V0pvY0FBWGxXaG9RbEo5VlhHZlhoWTdzdVV3UUowdGp3ZjhuOG1kUjc4YwpW",
    "N0NYdDZwdjUxUzhoYVEvQ0N5bnhZOGVmcXMwT3dOSDdaUk1lUW9ZUDZYRnFrWHMvUHBmdXpuOHB3",
    "UjIxK01xCmJaVVROM1FJcGpndVRHa3d5anl0cWNENjFvWjQrVmRCYU1kTVc3ak9iSXlmQUl0VHJY",
    "aHBIY1N4QWR6akFodysKWmd3UnQ3RmNkN1d1UzBRTzJlYzFIa2J3Mk1xMGtNaktpUmFKRXdJREFR",
    "QUJBb0lCQUQ1cUZNK1RSSDZMSTBzRQpUeTMrb21CN2pqVDNJVm16Tk51UWtXYlhxYUppUTNVb3g0",
    "b05xSUNxV0tHUGpTNzNjQ0ovTHFCVENyUExWUHltCnpaeEdPbHFpM3AwNThITmlZTVZWMzdheUNk",
    "M0J1L1BnWk9CTnViRlYweFpGaVFSZ2drdUlNTDdWZUg4bE53Z1YKNFlERmREaEYyelRjWStSMkxN",
    "NHZuTGdpb21NQy9RRlZmMjRXMTNnMkRzNVIyWDVoUS9GTHRyUGY2QnNrYk1Begpxd1laajMrZjl1",
    "NlVyamRlQUsrUEp6NmZYUy95WW9YTm5uRDI3UDdWNmhIWFhHa1FCMFE3UG9ydnJxZnd0NDJ2Cmta",
    "bTBjeDl2QkI2UUg4VEJQdTl4TGR3a1B6TEhnZkIxOHFkUTFVb3JqTzZvUVdYSWxWUGwyTEVZUkhF",
    "bXJ5NTQKcDR0eDhsa0NnWUVBK0NpL1pkeFFrNnlUd05wMTY0NFJmOHZBdEpJNWFLVkR4b0tQdGU1",
    "T0crbDhhM1FSM245YwpxRHVjNTh6SUExWGRod3o0TGlRTG4wMkZ2REhkYlFXOVo5cGx1M0ZZYjFr",
    "RE03cDc2YlFBRFFsNEFZZFBWMGw2CnhJTEhVN1JBb2FxNytvREVJYnpFL0NVVy9CQThZb3Zobm0x",
    "UFN2UmsrSlNHZnpVSHdLNGx5aWNDZ1lFQTlkVEwKTzlXMG5XOEk2dmdvN1ZTSlJaTFd3N3cxQVF1",
    "VStrNWNobEtxT1c2T2ZLak56V3pib3VaRDBiZXI4cDJ1dkxsYwpxQ25IaHBiNjZ0aDNXejRhazUx",
    "OXp1TGZjaWdyUFlPWUM4b2F6R3pRSVpsSFJJS29DOHNiRXN3a0dRVHBZeWkyCktJczM4ODZpY1kx",
    "aDhJd25yUktSeW9nZ0ZESEpPTmlTaFhKWE9UVUNnWUFHY2RoMnBzQVk5YlJvbjhQTU9FWlEKRVZT",
    "UjIvSk51MjBGTE1MYXNMT3FtZWUzU3E1a0h0NmpKOWt0VSs0bDJBY0d5Tmx4S1ZKNzhxRjBmNzhH",
    "WTgzRgpjckNOcTZYbVRtTjg1bXp0WnRWUmdWdHlmcmNheHplKy9yNTZlQVh0ck9kdzNBTTc5UkVR",
    "azA0RGdkQnZwcjVYClJQTjRPTnllY0EwR0pMUnMxcGo0cFFLQmdRQzZiZzlXcUVJYUpzdW5qbDFU",
    "WnduWGhuMXk0WGQ4L0hDVnh2bXEKTUdUQnUxTTV2TGFldEpCNG9KSU1LSE94UWQzelo4dWFDRjAx",
    "ZDZpQWszc282aGN6blh0OGUxZWpkazBja0lDdAphQzhjbXVUWXBpcUREV2N0MG5FTXQxNGt6ekhE",
    "cm1zK29oM2p1dkE4bDFFUUlPb3grZVF3cVQxU3MxTDcxbHAvCjgyK3NoUUtCZ1FDemRFaUJTVmpC",
    "YUZLTnQ1UTVSZk9iUVQxS01tdHNUQklBWkJTc2s1d3FLVDYwS3d2clhHeVUKTDA4djVMVFpqdEtU",
    "S3d4ZWFaY3djRTA5aW5tbXJvYlBXWEtBZjY2M2JFc255VzBqZUVYTnVmdkJMVUx3Z2lsQQplZGx0",
    "R0FFM2FuNGhRR3NwL2ZhcG9zNytnRW4rR2Jva21yRHNZMTVBSXRqejZXa0J1SzBCbmc9PQotLS0t",
    "LUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo=",
]

_B64_CERT_LINES = [
    "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURHakNDQWdLZ0F3SUJBZ0lVVnpnK3RoYkR5",
    "LzNwWjFVZkp6Wlh4TW8rUWNZd0RRWUpLb1pJaHZjTkFRRUwKQlFBd01ERUxNQWtHQTFVRUJoTUNR",
    "MGd4RFRBTEJnTlZCQW9NQkVSbGJXOHhFakFRQmdOVkJBTU1DV3h2WTJGcwphRzl6ZERBZUZ3MHlO",
    "VEV5TWpVeE5USXdORE5hRncwek5URXlNalF4TlRJd05ETmFNREF4Q3pBSkJnTlZCQVlUCkFrTklN",
    "UTB3Q3dZRFZRUUtEQVJFWlcxdk1SSXdFQVlEVlFRRERBbHNiMk5oYkdodmMzUXdnZ0VpTUEwR0NT",
    "cUcKU0liM0RRRUJBUVVBQTRJQkR3QXdnZ0VLQW9JQkFRRHVUVVh0VEladXZ4T2RRMDlrWWtKcUFo",
    "a25JN2xSMTRCdgp3ZW1IMXBzTUg2VXh6VGFObks0N0ljeTVXdEtuYjBLdUNYam1wL0tlb0dYRit5",
    "djN3OWlVZ0xKK05nczBqZnY0CkM2WUwvTG92SnY3M0VsY3lzNjlGWTFHdmtCTC96STUxdFlYMVlt",
    "aHdBQmVWYUdoQ1VuMVZjWjllRmp1eTVUQkEKblMyUEIveWZ5WjFIdnh4WHNKZTNxbS9uVkx5RnBE",
    "OElMS2ZGang1K3F6UTdBMGZ0bEV4NUNoZy9wY1dxUmV6OAorbCs3T2Z5bkJIYlg0eXB0bFJNM2RB",
    "aW1PQzVNYVRES1BLMnB3UHJXaG5qNVYwRm94MHhidU01c2pKOEFpMU90CmVHa2R4TEVCM09NQ0hE",
    "NW1EQkczc1Z4M3RhNUxSQTdaNXpVZVJ2RFl5clNReU1xSkZva1RBZ01CQUFHakxEQXEKTUJvR0Ex",
    "VWRFUVFUTUJHQ0NXeHZZMkZzYUc5emRJY0Vmd0FBQVRBTUJnTlZIUk1CQWY4RUFqQUFNQTBHQ1Nx",
    "RwpTSWIzRFFFQkN3VUFBNElCQVFCYmFDR3BydE56dFF5ZFJvNGV0MjM1b1FOM0lSUmM5cEEzWnFO",
    "dXZzK3ZVVmJoClZXN3B1Tit2bmdyVThBK0hUTnFhQkkvdGZWenpvY2J3UDgySWs5Z0xObHg3M0N2",
    "YXVJVjhmRjhjVDNkeXFtY1QKcEpSenNyeWdDdGJTNFN6UGNrWXB3ZGczaEZhazdmVGRBVlgxeFM4",
    "NWFOWWRyS29wQzU2S1dDUlhIZHQ5OFBITQpHWjhodndjTXFDVDZMak9BZ09HWmlZd2ZQT0gvN3Vz",
    "SmZET0wwTjFGdmt2Wmtkb0NQSFI0Zll3WldpWlRXdklyCmtwNzd0dmVzMk1ubUxISWxJblhhV25i",
    "UzJEL3lVcnBtdENRM2xETFdYWGVVOGxGNzUvZFluazE0bXkwTFFmbkcKM0pscDI2b2xaR3FRSHB2",
    "V2JGdnJGTkVRU0xoVmZUdVhiWEtNZnZycQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==",
]


def _now() -> int:
    return int(time.time())


def _sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


def _make_cookie(name: str, value: str, max_age: int, path: str) -> str:
    parts = [
        "%s=%s" % (name, value),
        "Max-Age=%d" % int(max_age),
        "Path=%s" % path,
        "Secure",
        "HttpOnly",
        "SameSite=Strict",
    ]
    return "; ".join(parts)


def _clear_cookie(name: str, path: str) -> str:
    return _make_cookie(name, "deleted", 0, path)


class EventBus:
    def __init__(self) -> None:
        self.q = queue.Queue()

    def emit(self, source: str, message: str, data: dict = None) -> None:
        if data is None:
            data = {}
        evt = {
            "ts": time.strftime("%H:%M:%S"),
            "source": source,
            "message": message,
            "data": data,
        }
        try:
            self.q.put_nowait(evt)
        except Exception:
            pass


class TokenBucket:
    def __init__(self, capacity: float, refill_per_sec: float) -> None:
        self.capacity = float(capacity)
        self.refill_per_sec = float(refill_per_sec)
        self.tokens = float(capacity)
        self.updated = time.monotonic()

    def allow(self, cost: float = 1.0) -> bool:
        now = time.monotonic()
        elapsed = now - self.updated
        self.updated = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_sec)
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False


class RateLimiter:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._buckets = {}  # (ip, route) -> TokenBucket

    def allow(self, ip: str, route: str, capacity: int, per_seconds: int) -> bool:
        key = (ip, route)
        refill = float(capacity) / float(per_seconds)
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = TokenBucket(capacity=capacity, refill_per_sec=refill)
                self._buckets[key] = bucket
            return bucket.allow(1.0)


class AccessKeyRing:
    def __init__(self, bus: EventBus) -> None:
        self._lock = threading.Lock()
        self._keys = []  # list of (kid, secret, created_epoch)
        self._last_rotate = 0
        self._bus = bus
        self._rotate_locked()

    def _rotate_locked(self) -> None:
        kid = secrets.token_hex(4)
        secret = secrets.token_bytes(32)
        created = _now()
        self._keys.insert(0, (kid, secret, created))
        self._keys = self._keys[:2]  # keep current + previous
        self._last_rotate = created
        self._bus.emit("server", "keyring rotate", {"kid_current": self._keys[0][0], "kids": [k[0] for k in self._keys]})

    def maybe_rotate(self) -> None:
        with self._lock:
            if _now() - self._last_rotate >= KEY_ROTATE_SECONDS:
                self._rotate_locked()

    def sign_access(self, username: str, ttl_seconds: int) -> str:
        self.maybe_rotate()
        with self._lock:
            kid, secret, _created = self._keys[0]

        payload = {
            "u": username,
            "exp": _now() + int(ttl_seconds),
            "kid": kid,
            "n": secrets.token_hex(8),
        }
        payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        payload_b64 = _b64url_encode(payload_json)
        sig = hmac.new(secret, payload_b64.encode("ascii"), hashlib.sha256).digest()
        sig_b64 = _b64url_encode(sig)
        token = payload_b64 + "." + sig_b64
        self._bus.emit("server", "issue access token", {"user": username, "kid": kid, "exp": payload["exp"]})
        return token

    def verify_access(self, token: str) -> (bool, str, dict):
        try:
            payload_b64, sig_b64 = token.split(".", 1)
            payload_raw = _b64url_decode(payload_b64)
            payload = json.loads(payload_raw.decode("utf-8"))
        except Exception:
            return False, "", {}

        if not isinstance(payload, dict):
            return False, "", {}

        username = payload.get("u")
        exp = payload.get("exp")
        kid = payload.get("kid")
        if not isinstance(username, str) or not isinstance(exp, int) or not isinstance(kid, str):
            return False, "", {}
        if _now() > exp:
            return False, "", payload

        with self._lock:
            keys = list(self._keys)

        for (k_kid, secret, _created) in keys:
            if kid != k_kid:
                continue
            expected_sig = hmac.new(secret, payload_b64.encode("ascii"), hashlib.sha256).digest()
            expected_sig_b64 = _b64url_encode(expected_sig)
            if hmac.compare_digest(expected_sig_b64, sig_b64):
                return True, username, payload

        return False, "", payload

    def debug_snapshot(self) -> dict:
        with self._lock:
            keys = [{"kid": k[0], "created": k[2]} for k in self._keys]
        return {"keys": keys, "last_rotate": self._last_rotate, "rotate_seconds": KEY_ROTATE_SECONDS}


class SessionStore:
    def __init__(self, bus: EventBus) -> None:
        self._lock = threading.Lock()
        self._refresh_by_hash = {}  # refresh_hash -> {u, family, exp}
        self._used_refresh_hash_to_family = {}  # refresh_hash -> family
        self._revoked_families = set()
        self._bus = bus

    def issue_refresh(self, username: str) -> str:
        refresh = secrets.token_urlsafe(32)
        rh = _sha256_hex(refresh)
        family = secrets.token_hex(16)
        with self._lock:
            self._refresh_by_hash[rh] = {
                "u": username,
                "family": family,
                "exp": _now() + REFRESH_TTL_SECONDS,
            }
        self._bus.emit("server", "issue refresh token", {"user": username, "family": family})
        return refresh

    def _revoke_family_locked(self, family: str) -> None:
        self._revoked_families.add(family)
        dead = [k for (k, v) in self._refresh_by_hash.items() if v.get("family") == family]
        for k in dead:
            self._refresh_by_hash.pop(k, None)

    def rotate_refresh(self, refresh: str) -> (bool, str, str, str):
        rh = _sha256_hex(refresh)
        with self._lock:
            if rh in self._used_refresh_hash_to_family:
                family = self._used_refresh_hash_to_family.get(rh, "")
                if family:
                    self._revoke_family_locked(family)
                self._bus.emit("server", "refresh reuse detected -> family revoked", {"family": family})
                return False, "", "", "refresh token reuse detected"

            sess = self._refresh_by_hash.pop(rh, None)
            if sess is None:
                self._bus.emit("server", "refresh invalid", {})
                return False, "", "", "invalid refresh token"

            username = sess.get("u")
            family = sess.get("family")
            exp = sess.get("exp")
            if not isinstance(username, str) or not isinstance(family, str) or not isinstance(exp, int):
                self._bus.emit("server", "refresh session invalid data", {})
                return False, "", "", "invalid session data"

            if _now() > exp:
                self._used_refresh_hash_to_family[rh] = family
                self._bus.emit("server", "refresh expired", {"family": family})
                return False, "", "", "refresh token expired"

            if family in self._revoked_families:
                self._bus.emit("server", "refresh family already revoked", {"family": family})
                return False, "", "", "session family revoked"

            self._used_refresh_hash_to_family[rh] = family

            new_refresh = secrets.token_urlsafe(32)
            new_rh = _sha256_hex(new_refresh)
            self._refresh_by_hash[new_rh] = {
                "u": username,
                "family": family,
                "exp": _now() + REFRESH_TTL_SECONDS,
            }
            self._bus.emit("server", "refresh rotated", {"user": username, "family": family})
            return True, username, new_refresh, ""

    def revoke_refresh(self, refresh: str) -> None:
        rh = _sha256_hex(refresh)
        with self._lock:
            sess = self._refresh_by_hash.pop(rh, None)
            if isinstance(sess, dict):
                family = sess.get("family")
                if isinstance(family, str) and family:
                    self._revoke_family_locked(family)
                    self._bus.emit("server", "logout -> family revoked", {"family": family})
            self._used_refresh_hash_to_family[rh] = self._used_refresh_hash_to_family.get(rh, "unknown")

    def debug_snapshot(self) -> dict:
        with self._lock:
            active = len(self._refresh_by_hash)
            used = len(self._used_refresh_hash_to_family)
            revoked = len(self._revoked_families)
            families = sorted(list(self._revoked_families))[:10]
        return {"active_refresh": active, "used_refresh_hashes": used, "revoked_families": revoked, "revoked_sample": families}


class DemoAuth:
    def __init__(self) -> None:
        self._salt = secrets.token_bytes(16)
        self._iters = 120_000
        self._user = "demo"
        self._pw_hash = self._hash_pw("correct-horse-battery-staple")

    def _hash_pw(self, pw: str) -> bytes:
        return hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), self._salt, self._iters)

    def verify(self, username: str, password: str) -> bool:
        if username != self._user:
            return False
        candidate = self._hash_pw(password)
        return hmac.compare_digest(candidate, self._pw_hash)


def _security_headers(handler: http.server.BaseHTTPRequestHandler) -> None:
    handler.send_header("Strict-Transport-Security", "max-age=31536000")
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("X-Frame-Options", "DENY")
    handler.send_header("Referrer-Policy", "no-referrer")
    handler.send_header(
        "Content-Security-Policy",
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    )
    handler.send_header("Cache-Control", "no-store")


def _html_page(title: str, body_html: str) -> str:
    return (
        "<!doctype html>"
        "<html><head><meta charset='utf-8'>"
        "<title>%s</title>"
        "</head><body>%s</body></html>" % (title, body_html)
    )


class DemoState:
    def __init__(self, bus: EventBus) -> None:
        self.bus = bus
        self.ratelimiter = RateLimiter()
        self.sessions = SessionStore(bus)
        self.keyring = AccessKeyRing(bus)
        self.auth = DemoAuth()


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "DefenseInDepthDemoGUI/1.0"

    def _ip(self) -> str:
        try:
            return str(self.client_address[0])
        except Exception:
            return "unknown"

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            return b""
        if length > MAX_BODY_BYTES:
            return b""
        return self.rfile.read(length)

    def _cookies(self) -> http.cookies.SimpleCookie:
        c = http.cookies.SimpleCookie()
        raw = self.headers.get("Cookie")
        if raw:
            c.load(raw)
        return c

    def _cookie_pairs(self) -> dict:
        c = self._cookies()
        out = {}
        for k in c.keys():
            try:
                out[k] = str(c.get(k).value)
            except Exception:
                out[k] = ""
        return out

    def _get_cookie_value(self, name: str) -> str:
        c = self._cookies()
        morsel = c.get(name)
        if morsel is None:
            return ""
        return str(morsel.value)

    def _send_html(self, status: int, html: str, extra_headers=None) -> None:
        raw = html.encode("utf-8")
        self.send_response(status)
        _security_headers(self)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        if extra_headers:
            for k, v in extra_headers:
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def _redirect(self, location: str, set_cookie_headers=None) -> None:
        self.send_response(303)
        _security_headers(self)
        self.send_header("Location", location)
        if set_cookie_headers:
            for sc in set_cookie_headers:
                self.send_header("Set-Cookie", sc)
        self.end_headers()

    def _require_access(self) -> (bool, str, dict):
        token = self._get_cookie_value(ACCESS_COOKIE)
        if not token:
            return False, "", {}
        ok, user, payload = self.server.state.keyring.verify_access(token)
        self.server.state.bus.emit("server", "verify access", {"ok": ok, "user": user, "payload": payload})
        return ok, user, payload

    def do_GET(self) -> None:
        self.server.state.keyring.maybe_rotate()
        path = urllib.parse.urlparse(self.path).path
        self.server.state.bus.emit("server", "request", {"method": "GET", "path": path, "cookies": self._cookie_pairs()})

        if path == "/":
            html = _html_page(
                "Defense in depth demo",
                "<h1>Defense in depth demo</h1>"
                "<ul><li><a href='/login'>Login</a></li><li><a href='/protected'>Protected</a></li></ul>"
                "<p>Demo user: <code>demo</code> / <code>correct-horse-battery-staple</code></p>",
            )
            self._send_html(200, html)
            return

        if path == "/login":
            html = _html_page(
                "Login",
                "<h1>Login</h1>"
                "<form method='POST' action='/login'>"
                "<label>User <input name='u' autocomplete='username'></label><br>"
                "<label>Pass <input name='p' type='password' autocomplete='current-password'></label><br>"
                "<button type='submit'>Login</button>"
                "</form>",
            )
            self._send_html(200, html)
            return

        if path == "/protected":
            ok, username, _payload = self._require_access()
            if not ok:
                html = _html_page(
                    "Unauthorized",
                    "<h1>401</h1><p>Missing/invalid/expired access token.</p>"
                    "<form method='POST' action='/refresh'><button type='submit'>Refresh session</button></form>",
                )
                self._send_html(401, html)
                return

            html = _html_page(
                "Protected",
                "<h1>Protected</h1><p>Hi <b>%s</b>.</p>"
                "<form method='POST' action='/refresh'><button type='submit'>Rotate refresh + get new access</button></form>"
                "<form method='POST' action='/refresh/logout'><button type='submit'>Logout</button></form>" % username,
            )
            self._send_html(200, html)
            return

        self._send_html(404, _html_page("Not found", "<h1>404</h1><p>Not found.</p>"))

    def do_POST(self) -> None:
        self.server.state.keyring.maybe_rotate()
        ip = self._ip()
        path = urllib.parse.urlparse(self.path).path
        self.server.state.bus.emit("server", "request", {"method": "POST", "path": path, "cookies": self._cookie_pairs()})

        if path == "/login":
            allowed = self.server.state.ratelimiter.allow(ip, "login", capacity=5, per_seconds=60)
            self.server.state.bus.emit("server", "rate limit login", {"ip": ip, "allowed": allowed})
            if not allowed:
                self._send_html(429, _html_page("Too many requests", "<h1>429</h1><p>Rate limit.</p>"))
                return

            body = self._read_body()
            params = urllib.parse.parse_qs(body.decode("utf-8", errors="ignore"))
            u = (params.get("u", [""])[0] or "").strip()
            p = (params.get("p", [""])[0] or "").strip()

            ok = self.server.state.auth.verify(u, p)
            self.server.state.bus.emit("server", "auth verify", {"user": u, "ok": ok})
            if not ok:
                html = _html_page("Login failed", "<h1>Login failed</h1><p>Invalid credentials.</p>")
                self._send_html(403, html)
                return

            access = self.server.state.keyring.sign_access(u, ACCESS_TTL_SECONDS)
            refresh = self.server.state.sessions.issue_refresh(u)

            set_cookies = [
                _make_cookie(ACCESS_COOKIE, access, ACCESS_TTL_SECONDS, "/"),
                _make_cookie(REFRESH_COOKIE, refresh, REFRESH_TTL_SECONDS, "/refresh"),
            ]
            self.server.state.bus.emit("server", "set cookies", {"set_cookie": set_cookies})
            self._redirect("/protected", set_cookie_headers=set_cookies)
            return

        if path == "/refresh":
            allowed = self.server.state.ratelimiter.allow(ip, "refresh", capacity=30, per_seconds=60)
            self.server.state.bus.emit("server", "rate limit refresh", {"ip": ip, "allowed": allowed})
            if not allowed:
                self._send_html(429, _html_page("Too many requests", "<h1>429</h1><p>Rate limit.</p>"))
                return

            refresh = self._get_cookie_value(REFRESH_COOKIE)
            if not refresh:
                self._send_html(401, _html_page("Unauthorized", "<h1>401</h1><p>Missing refresh cookie.</p>"))
                return

            ok, username, new_refresh, err = self.server.state.sessions.rotate_refresh(refresh)
            self.server.state.bus.emit("server", "refresh result", {"ok": ok, "user": username, "err": err})
            if not ok:
                set_cookies = [
                    _clear_cookie(ACCESS_COOKIE, "/"),
                    _clear_cookie(REFRESH_COOKIE, "/refresh"),
                ]
                html = _html_page("Refresh failed", "<h1>Refresh failed</h1><p>%s</p>" % err)
                self._send_html(
                    401,
                    html,
                    extra_headers=[("Set-Cookie", set_cookies[0]), ("Set-Cookie", set_cookies[1])],
                )
                return

            access = self.server.state.keyring.sign_access(username, ACCESS_TTL_SECONDS)
            set_cookies = [
                _make_cookie(ACCESS_COOKIE, access, ACCESS_TTL_SECONDS, "/"),
                _make_cookie(REFRESH_COOKIE, new_refresh, REFRESH_TTL_SECONDS, "/refresh"),
            ]
            self.server.state.bus.emit("server", "set cookies", {"set_cookie": set_cookies})
            self._redirect("/protected", set_cookie_headers=set_cookies)
            return

        if path == "/refresh/logout":
            refresh = self._get_cookie_value(REFRESH_COOKIE)
            if refresh:
                self.server.state.sessions.revoke_refresh(refresh)

            set_cookies = [
                _clear_cookie(ACCESS_COOKIE, "/"),
                _clear_cookie(REFRESH_COOKIE, "/refresh"),
            ]
            self.server.state.bus.emit("server", "logout", {"set_cookie": set_cookies})
            self._redirect("/", set_cookie_headers=set_cookies)
            return

        self._send_html(404, _html_page("Not found", "<h1>404</h1><p>Not found.</p>"))

    def log_message(self, fmt: str, *args) -> None:
        msg = "%s %s" % (self._ip(), (fmt % args))
        try:
            self.server.state.bus.emit("server", "http log", {"line": msg})
        except Exception:
            pass


class DemoHTTPSServer:
    def __init__(self, state: DemoState) -> None:
        self.state = state
        self.httpd = None
        self.thread = None
        self._tmpdir = None

    def _write_embedded_tls_files(self) -> (str, str):
        cert_pem = base64.b64decode("".join(_B64_CERT_LINES)).decode("ascii")
        key_pem = base64.b64decode("".join(_B64_KEY_LINES)).decode("ascii")
        self._tmpdir = tempfile.mkdtemp(prefix="defense_in_depth_tls_")
        cert_path = os.path.join(self._tmpdir, "cert.pem")
        key_path = os.path.join(self._tmpdir, "key.pem")
        with open(cert_path, "w", encoding="ascii") as f:
            f.write(cert_pem)
        with open(key_path, "w", encoding="ascii") as f:
            f.write(key_pem)
        return cert_path, key_path

    def start(self) -> None:
        if self.httpd is not None:
            return

        cert_path, key_path = self._write_embedded_tls_files()
        httpd = http.server.ThreadingHTTPServer((HOST, PORT), Handler)
        httpd.state = self.state  # attach shared state

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20")
        except ssl.SSLError:
            pass
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

        self.httpd = httpd

        def _serve() -> None:
            self.state.bus.emit("server", "server started", {"url": "https://%s:%d/" % (HOST, PORT)})
            try:
                httpd.serve_forever()
            except Exception as e:
                self.state.bus.emit("server", "server exception", {"err": str(e)})
            self.state.bus.emit("server", "server stopped", {})

        self.thread = threading.Thread(target=_serve, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        if self.httpd is None:
            return
        try:
            self.httpd.shutdown()
        except Exception:
            pass
        try:
            self.httpd.server_close()
        except Exception:
            pass
        self.httpd = None
        self.thread = None


class SimpleCookieJar:
    def __init__(self) -> None:
        self.cookies = {}
        self.stolen_refresh = ""

    def clear(self) -> None:
        self.cookies = {}
        self.stolen_refresh = ""

    def steal_refresh(self) -> str:
        c = self.cookies.get(REFRESH_COOKIE)
        if not c:
            self.stolen_refresh = ""
            return ""
        self.stolen_refresh = c.get("value", "")
        return self.stolen_refresh

    def force_refresh_value(self, value: str) -> None:
        if not value:
            return
        c = self.cookies.get(REFRESH_COOKIE)
        if not c:
            c = {"name": REFRESH_COOKIE, "attrs": {}, "path": "/refresh", "max_age": REFRESH_TTL_SECONDS}
        c["value"] = value
        self.cookies[REFRESH_COOKIE] = c

    def _parse_set_cookie(self, sc: str) -> dict:
        parts = [p.strip() for p in sc.split(";")]
        if not parts:
            return {}
        nv = parts[0]
        if "=" not in nv:
            return {}
        name, value = nv.split("=", 1)
        attrs = {}
        path = "/"
        max_age = None
        for p in parts[1:]:
            if not p:
                continue
            if "=" in p:
                ak, av = p.split("=", 1)
                ak = ak.strip().lower()
                av = av.strip()
                attrs[ak] = av
                if ak == "path":
                    path = av
                if ak == "max-age":
                    try:
                        max_age = int(av)
                    except Exception:
                        max_age = None
            else:
                attrs[p.strip().lower()] = True
        if max_age is None:
            max_age = 0
        return {"name": name, "value": value, "attrs": attrs, "path": path, "max_age": max_age, "set_ts": _now()}

    def ingest_set_cookie_headers(self, set_cookie_list: list) -> None:
        for sc in set_cookie_list:
            c = self._parse_set_cookie(sc)
            if not c:
                continue
            name = c["name"]
            if c["max_age"] == 0:
                if name in self.cookies:
                    del self.cookies[name]
                continue
            self.cookies[name] = c

    def cookie_header_for_path(self, path: str) -> str:
        items = []
        now = _now()
        for name, c in list(self.cookies.items()):
            max_age = int(c.get("max_age", 0))
            set_ts = int(c.get("set_ts", 0))
            cpath = c.get("path", "/")
            if max_age <= 0:
                continue
            if now > set_ts + max_age:
                try:
                    del self.cookies[name]
                except Exception:
                    pass
                continue
            if not path.startswith(cpath):
                continue
            items.append("%s=%s" % (name, c.get("value", "")))
        return "; ".join(items)

    def debug_dump(self) -> str:
        lines = []
        now = _now()
        for name in sorted(self.cookies.keys()):
            c = self.cookies[name]
            ttl = (int(c.get("set_ts", 0)) + int(c.get("max_age", 0))) - now
            if ttl < 0:
                ttl = 0
            attrs = c.get("attrs", {})
            flags = []
            for k in sorted(attrs.keys()):
                v = attrs[k]
                if v is True:
                    flags.append(k)
                else:
                    flags.append("%s=%s" % (k, v))
            vshort = c.get("value", "")
            if len(vshort) > 48:
                vshort = vshort[:48] + "..."
            lines.append("%s  path=%s  ttl=%ss" % (name, c.get("path", "/"), str(ttl)))
            lines.append("  value=%s" % vshort)
            lines.append("  attrs=%s" % (", ".join(flags) if flags else "(none)"))
        if not lines:
            return "(no cookies)"
        return "\n".join(lines)


class DemoClient:
    def __init__(self, bus: EventBus, jar: SimpleCookieJar) -> None:
        self.bus = bus
        self.jar = jar
        self.ssl_ctx = ssl.create_default_context()
        self.ssl_ctx.check_hostname = False
        self.ssl_ctx.verify_mode = ssl.CERT_NONE

    def _request(self, method: str, path: str, body_bytes: bytes = b"", headers: dict = None) -> dict:
        if headers is None:
            headers = {}

        # Disable urllib auto-redirect so we can ingest Set-Cookie from 303/302 responses first.
        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, hdrs, newurl):
                return None

        opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=self.ssl_ctx))

        def _make_req(m: str, p: str, b: bytes, h: dict):
            url = "https://%s:%d%s" % (HOST, PORT, p)
            req = urllib.request.Request(url, data=(b if m != "GET" else None), method=m)
            for k, v in h.items():
                req.add_header(k, v)
            return req

        redirect_codes = set([301, 302, 303, 307, 308])
        max_redirects = 5

        cur_method = method
        cur_path = path
        cur_body = body_bytes
        cur_headers = dict(headers)

        for _ in range(max_redirects + 1):
            # Add cookies filtered by Path
            cookie_header = self.jar.cookie_header_for_path(cur_path)
            h = dict(cur_headers)
            if cookie_header:
                h["Cookie"] = cookie_header
            if cur_method in ("POST", "PUT"):
                h["Content-Length"] = str(len(cur_body))

            self.bus.emit("client", "request", {"method": cur_method, "path": cur_path, "send_cookie": cookie_header})

            status = 0
            resp_headers = {}
            resp_body = b""
            set_cookies = []
            err = ""

            try:
                resp = opener.open(_make_req(cur_method, cur_path, cur_body, h), timeout=5)
                status = int(resp.getcode())
                resp_headers = dict(resp.headers.items())
                resp_body = resp.read()
                try:
                    set_cookies = resp.headers.get_all("Set-Cookie") or []
                except Exception:
                    set_cookies = []
            except urllib.error.HTTPError as e:
                status = int(getattr(e, "code", 0) or 0)
                try:
                    resp_headers = dict(e.headers.items())
                    try:
                        set_cookies = e.headers.get_all("Set-Cookie") or []
                    except Exception:
                        set_cookies = []
                except Exception:
                    resp_headers = {}
                    set_cookies = []
                try:
                    resp_body = e.read()
                except Exception:
                    resp_body = b""
                err = "HTTPError"
            except Exception as e:
                err = str(e)

            if set_cookies:
                self.jar.ingest_set_cookie_headers(set_cookies)

            # Log this response (including intermediate redirect responses)
            self.bus.emit(
                "client",
                "response",
                {
                    "status": status,
                    "path": cur_path,
                    "set_cookie_count": len(set_cookies),
                    "set_cookie": set_cookies,
                    "err": err,
                },
            )

            # Manual redirect follow (critical for capturing Set-Cookie on 303)
            loc = resp_headers.get("Location", "")
            if status in redirect_codes and loc:
                self.bus.emit("client", "redirect", {"from_path": cur_path, "to_location": loc, "status": status})

                parsed = urllib.parse.urlparse(loc)
                new_path = parsed.path or "/"
                if parsed.query:
                    new_path = new_path + "?" + parsed.query

                # Browser-like behavior: 303 (and commonly 301/302) switches to GET.
                if status in (301, 302, 303):
                    cur_method = "GET"
                    cur_body = b""
                cur_path = new_path
                cur_headers = {}  # keep it simple; cookies will be attached automatically
                continue

            return {
                "status": status,
                "headers": resp_headers,
                "body": resp_body,
                "set_cookie": set_cookies,
                "err": err,
            }

        return {"status": 0, "headers": {}, "body": b"", "set_cookie": [], "err": "too many redirects"}
    def login(self, username: str, password: str) -> dict:
        form = urllib.parse.urlencode({"u": username, "p": password}).encode("utf-8")
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        return self._request("POST", "/login", body_bytes=form, headers=headers)

    def protected(self) -> dict:
        return self._request("GET", "/protected")

    def refresh(self) -> dict:
        return self._request("POST", "/refresh", body_bytes=b"", headers={"Content-Type": "application/x-www-form-urlencoded"})

    def logout(self) -> dict:
        return self._request("POST", "/refresh/logout", body_bytes=b"", headers={"Content-Type": "application/x-www-form-urlencoded"})


def _decode_access_payload(access_token: str) -> dict:
    if not access_token:
        return {}
    try:
        payload_b64 = access_token.split(".", 1)[0]
        raw = _b64url_decode(payload_b64)
        obj = json.loads(raw.decode("utf-8"))
        if isinstance(obj, dict):
            return obj
        return {}
    except Exception:
        return {}


class App:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Defense in depth - GUI demo")
        self.root.geometry("1200x750")

        self.bus = EventBus()
        self.state = DemoState(self.bus)
        self.server = DemoHTTPSServer(self.state)
        self.jar = SimpleCookieJar()
        self.client = DemoClient(self.bus, self.jar)

        self._build_ui()
        self._poll_events()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self) -> None:
        top = ttk.Frame(self.root, padding=8)
        top.pack(fill="x")

        self.server_status = tk.StringVar(value="server: stopped")
        ttk.Label(top, textvariable=self.server_status).pack(side="left")

        ttk.Button(top, text="Start server", command=self._start_server).pack(side="left", padx=6)
        ttk.Button(top, text="Stop server", command=self._stop_server).pack(side="left")

        ttk.Label(top, text="  url: https://%s:%d/" % (HOST, PORT)).pack(side="left", padx=10)

        mid = ttk.Frame(self.root, padding=8)
        mid.pack(fill="x")

        ttk.Label(mid, text="username").grid(row=0, column=0, sticky="w")
        ttk.Label(mid, text="password").grid(row=0, column=2, sticky="w")

        self.user_var = tk.StringVar(value="demo")
        self.pass_var = tk.StringVar(value="correct-horse-battery-staple")

        ttk.Entry(mid, textvariable=self.user_var, width=20).grid(row=0, column=1, padx=6, sticky="w")
        ttk.Entry(mid, textvariable=self.pass_var, width=30, show="*").grid(row=0, column=3, padx=6, sticky="w")

        btns = ttk.Frame(mid)
        btns.grid(row=1, column=0, columnspan=4, sticky="w", pady=6)

        ttk.Button(btns, text="Login (POST /login)", command=self._do_login).pack(side="left", padx=4)
        ttk.Button(btns, text="Protected (GET /protected)", command=self._do_protected).pack(side="left", padx=4)
        ttk.Button(btns, text="Refresh (POST /refresh)", command=self._do_refresh).pack(side="left", padx=4)
        ttk.Button(btns, text="Logout (POST /refresh/logout)", command=self._do_logout).pack(side="left", padx=4)

        ttk.Separator(mid, orient="horizontal").grid(row=2, column=0, columnspan=4, sticky="ew", pady=6)

        btns2 = ttk.Frame(mid)
        btns2.grid(row=3, column=0, columnspan=4, sticky="w")

        ttk.Button(btns2, text="Clear output log", command=self._clear_output).pack(side="left", padx=4)
        ttk.Button(btns2, text="Burst login x10 (rate limit)", command=lambda: self._burst("login", 10)).pack(side="left", padx=4)
        ttk.Button(btns2, text="Burst refresh x40 (rate limit)", command=lambda: self._burst("refresh", 40)).pack(side="left", padx=4)
        ttk.Button(btns2, text="Clear client cookies", command=self._clear_cookies).pack(side="left", padx=4)

        ttk.Button(btns2, text="Steal refresh token (copy)", command=self._steal_refresh).pack(side="left", padx=18)
        ttk.Button(btns2, text="Reuse stolen refresh (should revoke)", command=self._reuse_stolen_refresh).pack(side="left", padx=4)

        main = ttk.Frame(self.root, padding=8)
        main.pack(fill="both", expand=True)

        left = ttk.Frame(main)
        left.pack(side="left", fill="both", expand=True)

        right = ttk.Frame(main)
        right.pack(side="left", fill="both", expand=True, padx=(10, 0))

        ttk.Label(left, text="Event log (server + client)").pack(anchor="w")
        self.log = ScrolledText(left, height=25, wrap="word")
        self.log.pack(fill="both", expand=True)

        ttk.Label(right, text="Client cookies (what will be sent, with Path filtering)").pack(anchor="w")
        self.cookies_view = ScrolledText(right, height=10, wrap="word")
        self.cookies_view.pack(fill="x")

        ttk.Label(right, text="Decoded access token payload").pack(anchor="w", pady=(8, 0))
        self.access_view = ScrolledText(right, height=9, wrap="word")
        self.access_view.pack(fill="x")

        ttk.Label(right, text="Server snapshots (keyring + sessions)").pack(anchor="w", pady=(8, 0))
        self.state_view = ScrolledText(right, height=9, wrap="word")
        self.state_view.pack(fill="both", expand=True)

        self._refresh_side_panels()

    def _append_log(self, line: str) -> None:
        self.log.insert("end", line + "\n")
        self.log.see("end")

    def _emit_ui_plan(self, action_name: str, method: str, path: str, steps: list) -> None:
        send_cookie = self.jar.cookie_header_for_path(path)
        send_cookie_names = []
        if send_cookie:
            for part in send_cookie.split(";"):
                part = part.strip()
                if "=" in part:
                    send_cookie_names.append(part.split("=", 1)[0].strip())
        self.bus.emit(
            "ui",
            "click: %s" % action_name,
            {
                "method": method,
                "path": path,
                "will_send_cookie_names": send_cookie_names,
                "will_send_cookie_header_preview": (send_cookie[:120] + ("..." if len(send_cookie) > 120 else "")) if send_cookie else "",
                "steps": steps,
            },
        )

    def _drain_event_queue(self) -> None:
        drained = 0
        while drained < 10_000:
            try:
                self.bus.q.get_nowait()
            except Exception:
                break
            drained += 1

    def _clear_output(self) -> None:
        self._drain_event_queue()
        self.log.delete("1.0", "end")
        self._append_log("[--:--:--] ui: output cleared (log + pending events)")
        self._refresh_side_panels()

    def _refresh_side_panels(self) -> None:
        self.cookies_view.delete("1.0", "end")
        self.cookies_view.insert("end", self.jar.debug_dump() + "\n")

        access = ""
        c = self.jar.cookies.get(ACCESS_COOKIE)
        if c:
            access = c.get("value", "")
        payload = _decode_access_payload(access)
        self.access_view.delete("1.0", "end")
        if payload:
            self.access_view.insert("end", json.dumps(payload, indent=2, sort_keys=True) + "\n")
        else:
            self.access_view.insert("end", "(no valid access token payload)\n")

        snap = {
            "keyring": self.state.keyring.debug_snapshot(),
            "sessions": self.state.sessions.debug_snapshot(),
        }
        self.state_view.delete("1.0", "end")
        self.state_view.insert("end", json.dumps(snap, indent=2, sort_keys=True) + "\n")

    def _poll_events(self) -> None:
        drained = 0
        while drained < 200:
            try:
                evt = self.bus.q.get_nowait()
            except Exception:
                break
            drained += 1
            ts = evt.get("ts", "??:??:??")
            src = evt.get("source", "?")
            msg = evt.get("message", "")
            data = evt.get("data", {})
            self._append_log("[%s] %s: %s" % (ts, src, msg))
            if data:
                try:
                    self._append_log("  " + json.dumps(data, sort_keys=True))
                except Exception:
                    self._append_log("  " + str(data))

        self._refresh_side_panels()
        self.root.after(200, self._poll_events)

    def _start_server(self) -> None:
        self.bus.emit(
            "ui",
            "click: Start server",
            {
                "what_happens": [
                    "Spawn ThreadingHTTPServer in background thread.",
                    "Wrap socket with TLS (self-signed demo cert).",
                    "Server begins accepting HTTPS requests on 127.0.0.1:8443.",
                ]
            },
        )
        self.server.start()
        self.server_status.set("server: running")

    def _stop_server(self) -> None:
        self.bus.emit(
            "ui",
            "click: Stop server",
            {"what_happens": ["Shutdown server loop.", "Close listening socket."]},
        )
        self.server.stop()
        self.server_status.set("server: stopped")

    def _do_login(self) -> None:
        self._emit_ui_plan(
            "Login",
            "POST",
            "/login",
            [
                "Client sends username/password form body.",
                "Server applies rate limit (5 per 60s per IP).",
                "Server verifies password (PBKDF2-hash compare).",
                "Server issues access token (HMAC signed; short TTL) and refresh token (random; long TTL).",
                "Server returns Set-Cookie for access (Path=/) and refresh (Path=/refresh), then redirects.",
            ],
        )
        self.client.login(self.user_var.get(), self.pass_var.get())

    def _do_protected(self) -> None:
        self._emit_ui_plan(
            "Protected",
            "GET",
            "/protected",
            [
                "Client sends cookies whose Path matches '/protected' (usually access cookie).",
                "Server verifies access token signature (current/previous key) and checks exp.",
                "If valid -> 200; else -> 401 with suggestion to refresh.",
            ],
        )
        self.client.protected()

    def _do_refresh(self) -> None:
        self._emit_ui_plan(
            "Refresh",
            "POST",
            "/refresh",
            [
                "Client sends cookies whose Path matches '/refresh' (refresh cookie + access cookie if present).",
                "Server rate limits refresh (30 per 60s per IP).",
                "Server rotates refresh token: old token becomes invalid; a new one is issued in same family.",
                "If old refresh is seen again -> reuse detection -> revoke entire family.",
                "Server also issues a new access token and returns new Set-Cookie values, then redirects.",
            ],
        )
        self.client.refresh()

    def _do_logout(self) -> None:
        self._emit_ui_plan(
            "Logout",
            "POST",
            "/refresh/logout",
            [
                "Client sends refresh cookie (Path=/refresh).",
                "Server revokes the session family (so refresh tokens stop working).",
                "Server returns Set-Cookie with Max-Age=0 to clear both cookies, then redirects.",
            ],
        )
        self.client.logout()

    def _burst(self, which: str, n: int) -> None:
        if which == "login":
            self._emit_ui_plan(
                "Burst login x%d" % int(n),
                "POST",
                "/login",
                [
                    "Sends many login attempts quickly to trigger the login rate limiter.",
                    "Watch 'server: rate limit login' events; eventually allowed=false and HTTP 429 responses.",
                ],
            )
        elif which == "refresh":
            self._emit_ui_plan(
                "Burst refresh x%d" % int(n),
                "POST",
                "/refresh",
                [
                    "Sends many refresh requests quickly to trigger refresh rate limiter and/or token rotation rules.",
                    "Watch for HTTP 429; also note that refresh rotation invalidates old tokens.",
                ],
            )
        else:
            self._emit_ui_plan(
                "Burst protected x%d" % int(n),
                "GET",
                "/protected",
                [
                    "Sends many protected requests quickly.",
                    "Useful to observe access expiry behavior over time.",
                ],
            )

        def _run() -> None:
            for _ in range(int(n)):
                if which == "login":
                    self.client.login(self.user_var.get(), self.pass_var.get())
                elif which == "refresh":
                    self.client.refresh()
                else:
                    self.client.protected()
                time.sleep(0.05)

        threading.Thread(target=_run, daemon=True).start()

    def _clear_cookies(self) -> None:
        self._emit_ui_plan(
            "Clear client cookies",
            "(local)",
            "(none)",
            [
                "Deletes cookies stored in the GUI client jar (not on the server).",
                "Next request will send no cookies unless server sets them again.",
            ],
        )
        self.jar.clear()
        self.bus.emit("client", "cookies cleared", {})

    def _steal_refresh(self) -> None:
        self._emit_ui_plan(
            "Steal refresh token",
            "(local)",
            "(none)",
            [
                "Copies the current refresh cookie value into a 'stolen' slot (simulates exfiltration).",
                "Does not change server state by itself.",
            ],
        )
        stolen = self.jar.steal_refresh()
        if stolen:
            self.bus.emit("client", "stole refresh token (copied value)", {"len": len(stolen)})
        else:
            self.bus.emit("client", "no refresh token to steal", {})

    def _reuse_stolen_refresh(self) -> None:
        self._emit_ui_plan(
            "Reuse stolen refresh",
            "POST",
            "/refresh",
            [
                "Forces client refresh cookie back to the previously stolen (old) value.",
                "Sends POST /refresh.",
                "Expected outcome: server detects reuse and revokes the entire refresh family.",
                "After that, refresh should fail (401) until you login again.",
            ],
        )
        if not self.jar.stolen_refresh:
            self.bus.emit("client", "no stolen refresh token saved", {})
            return
        self.jar.force_refresh_value(self.jar.stolen_refresh)
        self.bus.emit("client", "forced refresh cookie to stolen value", {})
        self.client.refresh()

    def _on_close(self) -> None:
        try:
            self.server.stop()
        except Exception:
            pass
        self.root.destroy()


def main() -> None:
    root = tk.Tk()
    try:
        style = ttk.Style()
        if sys.platform.startswith("win"):
            style.theme_use("vista")
    except Exception:
        pass
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()