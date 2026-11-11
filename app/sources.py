"""Откуда брать прокси.

1. Свой список с GitHub (data/proxies.json в вашем репозитории). Его каждые
   3 часа обновляет робот (GitHub Actions): собирает прокси из открытых
   списков и проверяет каждый. Телефон берёт этот файл первым.
2. Открытые списки на GitHub — запасной вариант.
3. Кэш на телефоне и список, вшитый в APK при сборке.
"""

import json
import ssl
import threading
import urllib.request

from .proxy import merge_unique, parse_text

try:
    import certifi
    _CAFILE = certifi.where()
except Exception:
    _CAFILE = None

USER_AGENT = "Mozilla/5.0 (Linux; Android 14; Mobile) FamilyProxy/1.0"

# Открытые списки MTProto-прокси. Ссылки иногда меняются: робот на
# GitHub пишет в отчёте, какие живые. Свои источники — в data/sources.txt.
PUBLIC_SOURCES = [
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/tg/mtproto.json",
    "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/MTProtoProxy/main/mtproto.txt",
    "https://raw.githubusercontent.com/Grim1313/mtproto-for-telegram/master/all_proxies.txt",
    "https://mtpro.xyz/api/?type=mtproto",
]

_ctx_lock = threading.Lock()
_ctx = None


def _ssl_context():
    global _ctx
    with _ctx_lock:
        if _ctx is None:
            try:
                _ctx = ssl.create_default_context(cafile=_CAFILE) if _CAFILE else ssl.create_default_context()
            except Exception:
                _ctx = ssl.create_default_context()
        return _ctx


def mirror_urls(url):
    """raw.githubusercontent.com иногда тормозит — тогда берём зеркало jsDelivr."""
    out = [url]
    prefix = "https://raw.githubusercontent.com/"
    if url.startswith(prefix):
        parts = url[len(prefix):].split("/", 3)
        if len(parts) == 4:
            owner, repo, branch, path = parts
            out.append("https://cdn.jsdelivr.net/gh/%s/%s@%s/%s" % (owner, repo, branch, path))
    return out


def fetch_text(url, timeout=15.0, max_bytes=8 * 1024 * 1024):
    last = None
    for u in mirror_urls(url):
        try:
            req = urllib.request.Request(u, headers={
                "User-Agent": USER_AGENT, "Accept": "*/*", "Cache-Control": "no-cache"})
            with urllib.request.urlopen(req, timeout=timeout, context=_ssl_context()) as r:
                return r.read(max_bytes).decode("utf-8", "replace")
        except Exception as e:  # пробуем следующее зеркало
            last = e
    raise last if last else IOError("no url")


def parse_source(text, origin):
    """-> (прокси, доп. источники из JSON-поля "sources")"""
    proxies = parse_text(text, origin)
    extra = []
    s = text.lstrip()
    if s.startswith("{"):
        try:
            data = json.loads(s)
        except ValueError:
            data = None
        if isinstance(data, dict) and isinstance(data.get("sources"), list):
            extra = [u for u in data["sources"] if isinstance(u, str) and u.startswith("https://")]
    return proxies, extra


def fetch_many(urls, timeout=15.0, workers=6):
    """Скачивает списки параллельно.

    -> (прокси в порядке urls, отчёт по каждому источнику, доп. источники)
    """
    urls = list(dict.fromkeys(u for u in urls if u))
    results = [None] * len(urls)
    lock = threading.Lock()
    pos = [0]

    def worker():
        while True:
            with lock:
                if pos[0] >= len(urls):
                    return
                i = pos[0]
                pos[0] += 1
            url = urls[i]
            try:
                text = fetch_text(url, timeout)
                proxies, extra = parse_source(text, url)
                results[i] = (proxies, extra, {"url": url, "ok": True, "count": len(proxies), "error": ""})
            except Exception as e:
                results[i] = ([], [], {"url": url, "ok": False, "count": 0,
                                       "error": (type(e).__name__ + ": " + str(e))[:160]})

    threads = [threading.Thread(target=worker, daemon=True)
               for _ in range(max(1, min(workers, len(urls))))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    proxies, report, extra = [], [], []
    for r in results:
        if r is None:
            continue
        proxies.extend(r[0])
        extra.extend(r[1])
        report.append(r[2])
    return merge_unique(proxies), report, list(dict.fromkeys(extra))
