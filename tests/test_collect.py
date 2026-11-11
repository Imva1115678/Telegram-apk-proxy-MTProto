"""Тесты робота tools/collect.py: скачивание подменено, проверка настоящая (на 127.0.0.1)."""

import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "tools"))

from app import checker  # noqa: E402
from app import proxy as proxymod  # noqa: E402
from app.proxy import make_proxy, parse_text  # noqa: E402
import collect  # noqa: E402
from mock_proxy import MockProxy  # noqa: E402
from test_controller import KEY, FakeFetch, closed_port, tls_secret  # noqa: E402

URL_A = "https://example.test/a.txt"
URL_B = "https://example.test/b.txt"
quiet = lambda *a: None  # noqa: E731


class TestCollect(unittest.TestCase):
    def setUp(self):
        proxymod.ALLOW_PRIVATE = True
        checker.PURE_AES = False
        self.tmp = tempfile.mkdtemp()
        self.servers = []

    def tearDown(self):
        proxymod.ALLOW_PRIVATE = False
        for s in self.servers:
            s.close()

    def server(self, secret=KEY, mode="ok"):
        s = MockProxy(secret, mode)
        self.servers.append(s)
        return s

    def entry(self, s, pinned=False):
        return ("127.0.0.1", s.port, s.secret.hex(), pinned)

    def test_keeps_only_working_pinned_first(self):
        ok1, ok2, dead = self.server(KEY), self.server(tls_secret()), self.server(KEY, "close")
        fetch = FakeFetch({URL_A: [self.entry(ok1), self.entry(dead)], URL_B: None})
        prev_ok = make_proxy("127.0.0.1", ok2.port, ok2.secret.hex())
        prev_ok.hint_ms = 50
        prev_dead = make_proxy("127.0.0.1", closed_port(), KEY)
        mine = make_proxy("127.0.0.1", closed_port(), "dd" + KEY)
        data, stats = collect.collect([URL_A, URL_B], [prev_dead, prev_ok], [mine],
                                      workers=8, timeout=2, fetch=fetch, log=quiet)
        ports = [d["port"] for d in data["proxies"]]
        self.assertEqual(ports[0], mine.port)          # свой — первым, даже если не ответил
        self.assertTrue(data["proxies"][0]["pinned"])
        self.assertEqual(sorted(ports[1:]), sorted([ok1.port, ok2.port]))
        self.assertNotIn(dead.port, ports)
        self.assertNotIn(prev_dead.port, ports)
        self.assertTrue(all(d.get("ping_ms") for d in data["proxies"][1:]))
        self.assertEqual(data["working"], 2)
        self.assertEqual(data["sources"], [URL_A])
        self.assertEqual(len(stats["report"]), 2)
        self.assertEqual(stats["pinned_down"], 1)
        # робот проверил рабочие дважды (отсев нестабильных)
        self.assertGreaterEqual(len([x for x in ok1.seen if x[0] == "tag"]), 2)

    def test_glitch_keeps_previous_list(self):
        ok = self.server(KEY)
        fetch = FakeFetch({URL_A: [self.entry(ok)]})
        prev = []
        for i in range(8):
            p = make_proxy("127.0.0.1", closed_port(), KEY)
            p.hint_ms = 100 + i
            prev.append(p)
        data, stats = collect.collect([URL_A], prev, [], workers=8, timeout=2, fetch=fetch, log=quiet)
        self.assertEqual(stats["kept_prev"], 8)
        self.assertEqual(data["proxies"][0]["port"], ok.port)
        self.assertEqual(len(data["proxies"]), 9)
        self.assertTrue(all(d["ping_ms"] >= 1100 for d in data["proxies"][1:]))

    def test_main_writes_files_app_can_read(self):
        ok, mine = self.server(KEY), self.server("dd" + KEY)
        fetch = FakeFetch({URL_A: [self.entry(ok)]})
        src = os.path.join(self.tmp, "sources.txt")
        pinned = os.path.join(self.tmp, "pinned.txt")
        out = os.path.join(self.tmp, "out", "proxies.json")
        rep = os.path.join(self.tmp, "out", "README.md")
        with open(src, "w") as f:
            f.write("# комментарий\n\n%s\n" % URL_A)
        with open(pinned, "w") as f:
            f.write("# свой\ntg://proxy?server=127.0.0.1&port=%d&secret=dd%s\n" % (mine.port, KEY))
        code = collect.main(["--out", out, "--report", rep, "--sources", src, "--pinned", pinned,
                             "--no-builtin", "--workers", "8", "--timeout", "2"], fetch=fetch)
        self.assertEqual(code, 0)
        self.assertEqual(fetch.calls, [[URL_A]])
        with open(out, encoding="utf-8") as f:
            text = f.read()
        data = json.loads(text)
        self.assertEqual(data["version"], 1)
        got = parse_text(text, "curated")     # так же, как читает телефон
        self.assertEqual([p.port for p in got], [mine.port, ok.port])
        self.assertTrue(got[0].pinned)
        self.assertIsNotNone(got[1].hint_ms)
        with open(rep, encoding="utf-8") as f:
            report = f.read()
        self.assertIn("работают 2", report)
        self.assertIn("example.test/a.txt", report)

    def test_nothing_works_keeps_old_file(self):
        dead = self.server(KEY, "close")
        fetch = FakeFetch({URL_A: [self.entry(dead)]})
        src = os.path.join(self.tmp, "sources.txt")
        out = os.path.join(self.tmp, "proxies.json")
        rep = os.path.join(self.tmp, "README.md")
        with open(src, "w") as f:
            f.write(URL_A + "\n")
        with open(out, "w") as f:
            f.write('{"version": 1, "proxies": ["old"]}')
        collect.main(["--out", out, "--report", rep, "--sources", src, "--pinned", "",
                      "--no-builtin", "--workers", "8", "--timeout", "2"], fetch=fetch)
        with open(out) as f:
            self.assertIn("old", f.read())
        with open(rep, encoding="utf-8") as f:
            self.assertIn("не обновлён", f.read())

    def test_pinned_comments_are_not_proxies(self):
        path = os.path.join(self.tmp, "pinned.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write("# пример: tg://proxy?server=1.2.3.4&port=443&secret=" + tls_secret() + "\n"
                    "tg://proxy?server=5.6.7.8&port=8443&secret=" + KEY + "\n")
        got = collect.read_proxies(path, "pinned")
        self.assertEqual([(p.server, p.port) for p in got], [("5.6.7.8", 8443)])
        # шаблон из проекта — только комментарии, своих прокси в нём нет
        self.assertEqual(collect.read_proxies(os.path.join(ROOT, "data", "pinned.txt"), "pinned"), [])


if __name__ == "__main__":
    unittest.main()
