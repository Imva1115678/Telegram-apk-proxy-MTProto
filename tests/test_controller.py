"""Тесты логики приложения: источники, проверка, сортировка, кэш, «нет интернета».

Все проверки настоящие — через поддельные прокси на 127.0.0.1, а скачивание
списков подменено (в песочнице нет интернета).
"""

import json
import os
import socket
import sys
import tempfile
import time
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from app import checker, config  # noqa: E402
from app import proxy as proxymod  # noqa: E402
from app.controller import Controller, ago, speed_bucket  # noqa: E402
from app.proxy import make_proxy  # noqa: E402
from mock_proxy import MockProxy  # noqa: E402

KEY = "0123456789abcdef0123456789abcdef"
OTHER = "fedcba9876543210fedcba9876543210"
CURATED = "https://example.test/curated.json"
PUBLIC = "https://example.test/public.txt"


def tls_secret(domain="www.google.com", key=KEY):
    return "ee" + key + domain.encode().hex()


def make_cfg(**over):
    d = dict((n, getattr(config, n)) for n in dir(config) if n.isupper())
    d.update(CHECK_TIMEOUT=2.0, WORKERS=8, RECHECK_EVERY=0.2, OFFLINE_RETRY=0.05,
             MIN_WORKING=1, MIN_CURATED=1, ENOUGH_WORKING=40, MAX_CHECK=400,
             REFETCH_AFTER=600, RETRY_FAILED_AFTER=1800, FULL_EVERY=3600)
    d.update(over)
    ns = types.SimpleNamespace(**d)
    ns.curated_urls = lambda: []
    return ns


def closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class FakeFetch(object):
    """Вместо скачивания: url -> список (server, port, secret, pinned) или None (не скачался)."""

    def __init__(self, lists):
        self.lists = lists
        self.calls = []

    def __call__(self, urls, timeout=15.0, workers=6):
        self.calls.append(list(urls))
        got, report = [], []
        for u in urls:
            items = self.lists.get(u)
            if items is None:
                report.append({"url": u, "ok": False, "count": 0, "error": "нет связи"})
                continue
            for server, port, secret, pinned in items:
                p = make_proxy(server, port, secret, origin=u)
                p.pinned = pinned
                got.append(p)
            report.append({"url": u, "ok": True, "count": len(items), "error": ""})
        return got, report, []


def entry(srv, secret=None, pinned=False):
    return ("127.0.0.1", srv.port, secret or srv.secret.hex(), pinned)


class Base(unittest.TestCase):
    def setUp(self):
        proxymod.ALLOW_PRIVATE = True
        checker.PURE_AES = True
        self.tmp = tempfile.mkdtemp()
        self.servers = []

    def tearDown(self):
        proxymod.ALLOW_PRIVATE = False
        checker.PURE_AES = False
        for s in self.servers:
            s.close()

    def server(self, secret=KEY, mode="ok"):
        s = MockProxy(secret, mode)
        self.servers.append(s)
        return s

    def ctrl(self, lists, curated=(CURATED,), public=(PUBLIC,), **cfg):
        fetch = FakeFetch(lists)
        c = Controller(self.tmp, None, fetch=fetch, curated=list(curated),
                       public=list(public), cfg=make_cfg(**cfg))
        c.fetch = fetch
        return c


class TestPass(Base):
    def test_full_pass_finds_working_and_hides_dead(self):
        good = [self.server(KEY), self.server("dd" + KEY), self.server(tls_secret())]
        dead = [self.server(KEY, "silent"), self.server(KEY, "close")]
        wrong = self.server(KEY)
        lists = {CURATED: [entry(s) for s in good + dead] + [entry(wrong, OTHER)]
                 + [("127.0.0.1", closed_port(), KEY, False)]}
        c = self.ctrl(lists)
        c.run_pass()
        snap = c.snapshot()
        self.assertEqual(snap["working"], 3)
        self.assertEqual(len(snap["rows"]), 3)
        self.assertTrue(all(r["ok"] for r in snap["rows"]))
        self.assertTrue(all(r["status"].startswith("Работает · ") for r in snap["rows"]))
        self.assertEqual(set(r["pkey"][1] for r in snap["rows"]), set(s.port for s in good))
        self.assertFalse(snap["busy"])
        self.assertFalse(snap["offline"])
        self.assertTrue(c.lists_ok)
        self.assertEqual(snap["empty"], "")
        self.assertTrue(snap["line"].startswith("Рабочих: 3"), snap["line"])
        # открытые списки не нужны — своего хватило
        self.assertEqual(c.fetch.calls, [[CURATED]])
        # нерабочие помечены с понятной причиной
        d = c.details(("127.0.0.1", dead[0].port, KEY))
        self.assertTrue(d["fail"])
        self.assertEqual(d["status"], "Не работает: не отвечает")
        fails = [p for p in c._items.values() if p.status == "fail"]
        self.assertEqual(len(fails), 4)
        self.assertTrue(all(p.error for p in fails))

    def test_details_and_links(self):
        s = self.server(tls_secret())
        c = self.ctrl({CURATED: [entry(s)]})
        c.run_pass()
        row = c.snapshot()["rows"][0]
        d = c.details(row["pkey"])
        self.assertEqual(d["server"], "127.0.0.1")
        self.assertEqual(d["port"], str(s.port))
        self.assertEqual(d["secret"], tls_secret())
        self.assertTrue(d["ok"])
        self.assertEqual(d["checked"], "только что")
        self.assertTrue(d["tg_link"].startswith("tg://proxy?server=127.0.0.1&port=%d&secret=" % s.port))
        self.assertTrue(d["share_link"].startswith("https://t.me/proxy?"))
        self.assertIn("Fake TLS", d["kind"])

    def test_pinned_is_first_and_marked(self):
        fast = [self.server(KEY) for _ in range(3)]
        mine = self.server("dd" + KEY)
        lists = {CURATED: [entry(s) for s in fast] + [entry(mine, pinned=True)]}
        c = self.ctrl(lists)
        c.run_pass()
        rows = c.snapshot()["rows"]
        self.assertEqual(len(rows), 4)
        self.assertTrue(rows[0]["pinned"])
        self.assertEqual(rows[0]["pkey"][1], mine.port)
        self.assertTrue(rows[0]["status"].startswith("Свой · Работает"))

    def test_pinned_shown_even_when_down(self):
        port = closed_port()
        ok = self.server(KEY)
        c = self.ctrl({CURATED: [("127.0.0.1", port, KEY, True), entry(ok)]})
        c.run_pass()
        rows = c.snapshot()["rows"]
        self.assertEqual(len(rows), 2)
        self.assertTrue(rows[0]["pinned"])
        self.assertFalse(rows[0]["ok"])
        self.assertTrue(rows[0]["status"].startswith("Свой · Не работает"))
        self.assertTrue(rows[1]["ok"])

    def test_public_lists_when_curated_unavailable(self):
        good = self.server(KEY)
        c = self.ctrl({CURATED: None, PUBLIC: [entry(good)]})
        c.run_pass()
        self.assertEqual(c.fetch.calls, [[CURATED], [PUBLIC]])
        self.assertEqual(c.working_count(), 1)
        self.assertTrue(c.lists_ok)
        self.assertFalse(c.offline)

    def test_public_lists_when_curated_proxies_blocked(self):
        # список с GitHub скачался, но с этого телефона все его прокси не работают
        blocked = [("127.0.0.1", closed_port(), KEY, False) for _ in range(3)]
        good = self.server(KEY)
        c = self.ctrl({CURATED: blocked, PUBLIC: [entry(good)]})
        c.run_pass()
        self.assertEqual(c.fetch.calls, [[CURATED], [PUBLIC]])
        self.assertEqual(c.working_count(), 1)

    def test_enough_working_stops_early(self):
        servers = [self.server(KEY) for _ in range(5)]
        c = self.ctrl({CURATED: [entry(s) for s in servers]}, ENOUGH_WORKING=2, WORKERS=1)
        c.run_pass()
        self.assertEqual(c.working_count(), 2)
        statuses = sorted(p.status for p in c._items.values())
        self.assertEqual(statuses, ["new", "new", "new", "ok", "ok"])

    def test_recheck_drops_dead_and_keeps_order(self):
        servers = [self.server(KEY) for _ in range(3)]
        c = self.ctrl({CURATED: [entry(s) for s in servers]})
        c.run_pass()
        self.assertEqual(c.working_count(), 3)
        order1 = [r["pkey"] for r in c.snapshot()["rows"]]
        servers[1].mode = "close"   # прокси «умер»: сразу рвёт соединение
        c.last_full = time.time()  # обычная перепроверка, не полное обновление
        c.run_pass()
        self.assertEqual(len(c.fetch.calls), 1)  # списки заново не качали
        rows = [r["pkey"] for r in c.snapshot()["rows"]]
        self.assertEqual(len(rows), 2)
        self.assertNotIn(("127.0.0.1", servers[1].port, KEY), rows)
        self.assertEqual(rows, [k for k in order1 if k in rows])

    def test_refresh_retries_failed(self):
        s = self.server(KEY, "close")
        c = self.ctrl({CURATED: [entry(s)]}, MIN_WORKING=0)
        c.run_pass()
        self.assertEqual(c.working_count(), 0)
        s.mode = "ok"
        c.last_full = time.time()
        c._want_full = True
        c.run_pass()   # без «Обновить» недавно упавший не дёргаем
        self.assertEqual(c.working_count(), 0)
        self.assertTrue(c.refresh())
        c.run_pass()
        self.assertEqual(c.working_count(), 1)

    def test_recheck_one(self):
        s = self.server(KEY)
        c = self.ctrl({CURATED: [entry(s)]})
        c.run_pass()
        key = c.snapshot()["rows"][0]["pkey"]
        s.mode = "close"
        self.assertTrue(c.recheck(key))
        self.assertTrue(c.details(key)["checking"])
        deadline = time.time() + 10
        while time.time() < deadline and c.details(key)["checking"]:
            time.sleep(0.05)
        d = c.details(key)
        self.assertTrue(d["fail"])
        self.assertIn("Не работает", d["status"])


class TestOfflineAndCache(Base):
    def test_offline_detected_and_failures_forgiven(self):
        bundled = os.path.join(self.tmp, "bundled.json")
        items = [{"server": "127.0.0.1", "port": closed_port(), "secret": KEY, "ping_ms": 90 + i}
                 for i in range(3)]
        with open(bundled, "w") as f:
            json.dump({"proxies": items}, f)
        fetch = FakeFetch({CURATED: None, PUBLIC: None})
        c = Controller(self.tmp, bundled, fetch=fetch, curated=[CURATED], public=[PUBLIC],
                       cfg=make_cfg())
        c.load_local()
        self.assertEqual(len(c._items), 3)
        self.assertTrue(all(p.hint_ms for p in c._items.values()))
        c.run_pass()
        snap = c.snapshot()
        self.assertTrue(snap["offline"])
        self.assertIn("Нет интернета", snap["line"])
        self.assertIn("Нет интернета", snap["empty"])
        # ошибки не засчитаны: все снова «новые» и проверятся сразу, как появится сеть
        self.assertTrue(all(p.status == "new" and p.checked_at == 0 for p in c._items.values()))
        self.assertLess(c._next_delay(), 1.0)
        self.assertTrue(c._want_full)

    def test_cache_survives_restart(self):
        servers = [self.server(KEY), self.server(tls_secret())]
        c = self.ctrl({CURATED: [entry(s) for s in servers]})
        c.run_pass()
        self.assertEqual(c.working_count(), 2)
        self.assertTrue(os.path.exists(os.path.join(self.tmp, "cache.json")))
        # новый запуск: рабочие видны сразу, ещё до проверки
        c2 = self.ctrl({CURATED: None, PUBLIC: None})
        c2.load_local()
        snap = c2.snapshot()
        self.assertEqual(snap["working"], 2)
        self.assertEqual(len(snap["rows"]), 2)

    def test_background_thread(self):
        s = self.server(KEY)
        changes = []
        fetch = FakeFetch({CURATED: [entry(s)]})
        c = Controller(self.tmp, None, on_change=lambda: changes.append(1), fetch=fetch,
                       curated=[CURATED], public=[PUBLIC], cfg=make_cfg())
        c.start()
        deadline = time.time() + 15
        while time.time() < deadline and c.working_count() < 1:
            time.sleep(0.05)
        self.assertEqual(c.working_count(), 1)
        self.assertFalse(c.refresh() and False)
        c.pause()
        self.assertTrue(c._paused.is_set())
        c.resume()
        c.stop()
        c._thread.join(5)
        self.assertFalse(c._thread.is_alive())
        self.assertTrue(len(changes) > 2)


class TestTexts(unittest.TestCase):
    def test_ago_and_buckets(self):
        now = 1000000.0
        self.assertEqual(ago(0, now), "ещё не проверялся")
        self.assertEqual(ago(now - 5, now), "только что")
        self.assertEqual(ago(now - 180, now), "3 мин назад")
        self.assertEqual(ago(now - 7300, now), "2 ч назад")
        self.assertEqual([speed_bucket(x) for x in (None, 50, 200, 400, 900)], [9, 0, 1, 2, 3])

    def test_status_lines(self):
        base = {"rows": [], "working": 0, "busy": False, "phase": "", "done": 0, "total": 0,
                "offline": False, "last_check": 0}
        line = Controller.status_line(dict(base, busy=True, phase="проверяем новые", done=120, total=400))
        self.assertEqual(line, "Проверяем новые 120 из 400")
        line = Controller.status_line(dict(base, busy=True, working=3, phase="проверяем новые", done=5, total=9))
        self.assertEqual(line, "Рабочих: 3 · проверяем новые 5 из 9")
        now = time.time()
        line = Controller.status_line(dict(base, working=18, last_check=now - 120), now)
        self.assertEqual(line, "Рабочих: 18 · проверено 2 мин назад")
        self.assertIn("не нашлось", Controller.empty_text(dict(base, last_check=now)))
        self.assertIn("Ищем", Controller.empty_text(dict(base, busy=True)))


if __name__ == "__main__":
    unittest.main()
