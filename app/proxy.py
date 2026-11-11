"""Модель прокси и разбор ссылок/списков.

Понимает:
  * tg://proxy?server=...&port=...&secret=...
  * https://t.me/proxy?server=...&port=...&secret=...
  * JSON-списки вида [{"host": ..., "port": ..., "secret": ...}, ...]
Секрет приводится к hex (маленькие буквы): обычный, dd... или ee...(Fake TLS).
"""

import base64
import binascii
import ipaddress
import json
import re
import time
from urllib.parse import parse_qs, quote, unquote, urlsplit

# В тестах разрешаем 127.0.0.1. В приложении — нет, чтобы чужой список
# не заставил телефон стучаться в домашнюю сеть.
ALLOW_PRIVATE = False

LINK_RE = re.compile(
    r"(?:tg://proxy|https?://(?:www\.)?(?:t\.me|telegram\.me|telegram\.dog)/proxy)"
    r"\?[^\s\"'<>\\`()\[\]{}|,]+",
    re.IGNORECASE,
)
_HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9\-.]{0,251}[a-z0-9])?$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def _secret_from_bytes(b):
    if len(b) == 16:
        return b.hex()
    if len(b) == 17 and b[0] == 0xDD:
        return b.hex()
    if len(b) > 17 and b[0] == 0xEE:
        domain = b[17:]
        if len(domain) <= 253 and b"." in domain and all(33 <= c < 127 for c in domain):
            return b.hex()
    return None


def normalize_secret(raw):
    """hex/base64 -> нормальный hex или None, если ключ неправильный."""
    if raw is None:
        return None
    s = unquote(str(raw)).strip()
    if not s or len(s) > 600:
        return None
    if _HEX_RE.match(s) and len(s) % 2 == 0:
        res = _secret_from_bytes(bytes.fromhex(s))
        if res:
            return res
    try:
        t = s.replace("+", "-").replace("/", "_").rstrip("=")
        b = base64.urlsafe_b64decode(t + "=" * (-len(t) % 4))
    except (binascii.Error, ValueError):
        return None
    return _secret_from_bytes(b)


def _is_private(host):
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host == "localhost" or host.endswith(".local") or host.endswith(".localhost")
    return (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
            or ip.is_reserved or ip.is_unspecified)


def normalize_server(raw):
    s = unquote(str(raw or "")).strip().strip("[]").rstrip(".").lower()
    if not s or len(s) > 253:
        return None
    if ":" in s:
        try:
            s = str(ipaddress.IPv6Address(s))
        except ValueError:
            return None
        if not ALLOW_PRIVATE and _is_private(s):
            return None
        return s
    if ".." in s or not _HOST_RE.match(s):
        return None
    if not ALLOW_PRIVATE and _is_private(s):
        return None
    return s


class Proxy(object):
    """Один прокси + результат последних проверок."""

    __slots__ = ("server", "port", "secret", "country", "origin", "pinned", "hint_ms",
                 "status", "ping_ms", "checked_at", "ok_at", "fails", "error")

    def __init__(self, server, port, secret, country="", origin=""):
        self.server = server
        self.port = int(port)
        self.secret = secret
        self.country = country or ""
        self.origin = origin or ""
        self.pinned = False
        self.hint_ms = None      # пинг с сервера GitHub (для порядка проверки)
        self.status = "new"     # new | ok | fail
        self.ping_ms = None
        self.checked_at = 0.0
        self.ok_at = 0.0
        self.fails = 0
        self.error = ""

    # --- удобные свойства -------------------------------------------------
    @property
    def key(self):
        return (self.server, self.port, self.secret)

    @property
    def kind(self):
        if self.secret.startswith("ee") and len(self.secret) > 34:
            return "tls"
        if self.secret.startswith("dd") and len(self.secret) == 34:
            return "secure"
        return "classic"

    @property
    def kind_label(self):
        return {"tls": "Fake TLS (маскируется под сайт)",
                "secure": "Защищённый (dd)",
                "classic": "Обычный"}[self.kind]

    @property
    def domain(self):
        if self.kind != "tls":
            return ""
        return bytes.fromhex(self.secret)[17:].decode("ascii", "replace")

    def _query(self):
        return "server=%s&port=%d&secret=%s" % (quote(self.server, safe=":.-"), self.port, self.secret)

    @property
    def tg_link(self):
        return "tg://proxy?" + self._query()

    @property
    def share_link(self):
        return "https://t.me/proxy?" + self._query()

    def apply(self, res, now=None):
        now = now or time.time()
        self.checked_at = now
        if res.ok:
            self.status = "ok"
            self.ping_ms = res.ping_ms
            self.ok_at = now
            self.fails = 0
            self.error = ""
        else:
            self.status = "fail"
            self.fails += 1
            self.error = res.error or "не работает"

    # --- сохранение ---------------------------------------------------------
    def to_dict(self, full=True):
        d = {"server": self.server, "port": self.port, "secret": self.secret}
        if self.country:
            d["country"] = self.country
        if self.pinned:
            d["pinned"] = True
        if full:
            d.update(status=self.status, ping_ms=self.ping_ms, checked_at=round(self.checked_at),
                     ok_at=round(self.ok_at), fails=self.fails, origin=self.origin,
                     hint_ms=self.hint_ms)
        return d

    @classmethod
    def from_dict(cls, d):
        p = make_proxy(d.get("server"), d.get("port"), d.get("secret"),
                       d.get("country", ""), d.get("origin", ""))
        if p is None:
            return None
        p.pinned = bool(d.get("pinned"))
        p.status = d.get("status") if d.get("status") in ("ok", "fail") else "new"
        p.ping_ms = d.get("ping_ms")
        p.checked_at = float(d.get("checked_at") or 0)
        p.ok_at = float(d.get("ok_at") or 0)
        p.fails = int(d.get("fails") or 0)
        p.hint_ms = d.get("hint_ms")
        return p

    def __repr__(self):
        return "Proxy(%s:%d %s %s)" % (self.server, self.port, self.kind, self.status)


def make_proxy(server, port, secret, country="", origin=""):
    server = normalize_server(server)
    if not server:
        return None
    try:
        port = int(str(port).strip())
    except (TypeError, ValueError):
        return None
    if not 0 < port < 65536:
        return None
    secret = normalize_secret(secret)
    if not secret:
        return None
    country = str(country or "").strip()[:2].upper()
    if not country.isalpha():
        country = ""
    return Proxy(server, port, secret, country, origin)


def parse_link(link, origin=""):
    link = link.replace("&amp;", "&").rstrip(".;:!?")
    try:
        q = parse_qs(urlsplit(link).query)
    except ValueError:
        return None

    def g(name):
        v = q.get(name)
        return v[0] if v else None

    return make_proxy(g("server"), g("port"), g("secret"), origin=origin)


_HOST_KEYS = ("server", "host", "ip", "address", "addr", "hostname")
_SECRET_KEYS = ("secret", "secret_key", "key")


def _walk_json(node, out, origin, depth=0):
    if depth > 8:
        return
    if isinstance(node, dict):
        low = dict((str(k).lower(), v) for k, v in node.items())
        host = next((low[k] for k in _HOST_KEYS if k in low), None)
        secret = next((low[k] for k in _SECRET_KEYS if k in low), None)
        port = low.get("port")
        if host is not None and port is not None and secret is not None:
            p = make_proxy(host, port, secret, low.get("country") or "", origin)
            if p is not None:
                p.pinned = bool(low.get("pinned"))
                ping = low.get("ping_ms")
                if isinstance(ping, (int, float)) and ping > 0:
                    p.hint_ms = int(ping)
                out.append(p)
        children = node.values()
    elif isinstance(node, list):
        children = node
    else:
        return
    for v in children:
        if isinstance(v, (dict, list)):
            _walk_json(v, out, origin, depth + 1)


def merge_unique(proxies):
    """Убирает повторы, сохраняя порядок (первый встреченный побеждает)."""
    seen = {}
    out = []
    for p in proxies:
        old = seen.get(p.key)
        if old is None:
            seen[p.key] = p
            out.append(p)
        else:
            if not old.country and p.country:
                old.country = p.country
            if old.hint_ms is None and p.hint_ms is not None:
                old.hint_ms = p.hint_ms
            old.pinned = old.pinned or p.pinned
    return out


def parse_text(text, origin=""):
    """Ищет прокси в любом тексте: ссылки, JSON, HTML."""
    out = []
    if not text:
        return out
    t = text.replace("\\/", "/").replace("&amp;", "&")
    for m in LINK_RE.finditer(t):
        p = parse_link(m.group(0), origin)
        if p is not None:
            out.append(p)
    s = text.lstrip()
    if s[:1] in ("[", "{"):
        try:
            data = json.loads(s)
        except ValueError:
            data = None
        if data is not None:
            _walk_json(data, out, origin)
    return merge_unique(out)
