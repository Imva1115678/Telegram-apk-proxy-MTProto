"""Тесты ядра: шифрование, разбор ссылок, настоящая проверка через поддельный прокси.

Запуск из корня проекта:  python -m unittest discover -s tests -v
"""

import base64
import os
import random
import socket
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from app import aes, checker, x25519  # noqa: E402
from app import proxy as proxymod  # noqa: E402
from app import sources  # noqa: E402
from app.proxy import make_proxy, normalize_secret, parse_text  # noqa: E402
from app.storage import Store  # noqa: E402
from mock_proxy import MockProxy  # noqa: E402

KEY = "0123456789abcdef0123456789abcdef"


def tls_secret(domain="www.google.com", key=KEY):
    return "ee" + key + domain.encode().hex()


class TestAes(unittest.TestCase):
    def test_sbox(self):
        self.assertEqual(aes.SBOX[0x00], 0x63)
        self.assertEqual(aes.SBOX[0x01], 0x7C)
        self.assertEqual(aes.SBOX[0x53], 0xED)
        self.assertEqual(len(set(aes.SBOX)), 256)

    def test_fips197_aes256(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        pt = bytes.fromhex("00112233445566778899aabbccddeeff")
        self.assertEqual(aes.AES(key).encrypt_block(pt).hex(), "8ea2b7ca516745bfeafc49904b496089")

    def test_ctr_matches_cryptography(self):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        rnd = random.Random(1)
        for _ in range(40):
            key, iv = os.urandom(32), os.urandom(16)
            data = os.urandom(rnd.randrange(1, 400))
            ref = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor().update(data)
            c = aes.AesCtr(key, iv, pure=True)
            out, i = b"", 0
            while i < len(data):
                step = rnd.randrange(1, 70)
                out += c.update(data[i:i + step])
                i += step
            self.assertEqual(out, ref)

    def test_ctr_counter_wraps(self):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        key, iv = os.urandom(32), b"\xff" * 16
        data = os.urandom(80)
        ref = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor().update(data)
        self.assertEqual(aes.AesCtr(key, iv, pure=True).update(data), ref)


class TestX25519(unittest.TestCase):
    def test_rfc7748_vector(self):
        a = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        self.assertEqual(x25519.public_key(a).hex(),
                         "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")

    def test_matches_cryptography(self):
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        for _ in range(5):
            k = os.urandom(32)
            ref = X25519PrivateKey.from_private_bytes(k).public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            self.assertEqual(x25519.public_key(k), ref)


class TestParse(unittest.TestCase):
    def test_secrets(self):
        self.assertEqual(normalize_secret(KEY.upper()), KEY)
        self.assertEqual(normalize_secret("dd" + KEY), "dd" + KEY)
        self.assertEqual(normalize_secret(tls_secret()), tls_secret())
        raw = b"\xee" + os.urandom(16) + b"www.cloudflare.com"
        self.assertEqual(normalize_secret(base64.urlsafe_b64encode(raw).decode().rstrip("=")), raw.hex())
        self.assertEqual(normalize_secret(base64.b64encode(raw).decode()), raw.hex())
        for bad in ("", "xyz", "00" * 15, "ee" + KEY, "dd" + KEY + "00", "ee" + KEY + "0a0b"):
            self.assertIsNone(normalize_secret(bad), bad)

    def test_links_in_text(self):
        text = ("Рабочий: tg://proxy?server=1.2.3.4&port=443&secret=dd%s канал\n"
                "<a href=\"https://t.me/proxy?server=Example.com&amp;port=8443&amp;secret=%s\">x</a>\n"
                "[ссылка](tg://proxy?port=80&secret=%s&server=5.6.7.8)."
                % (KEY, tls_secret(), KEY))
        ps = parse_text(text, "t")
        self.assertEqual([p.key for p in ps], [
            ("1.2.3.4", 443, "dd" + KEY),
            ("example.com", 8443, tls_secret()),
            ("5.6.7.8", 80, KEY),
        ])
        self.assertEqual(ps[1].kind, "tls")
        self.assertEqual(ps[1].domain, "www.google.com")

    def test_json_lists(self):
        text = '[{"host": "9.9.9.9", "port": 443, "secret": "%s", "country": "DE", "ping": 3}]' % KEY
        ps = parse_text(text)
        self.assertEqual(len(ps), 1)
        self.assertEqual(ps[0].country, "DE")
        curated = ('{"updated": 1, "sources": ["https://example.org/list.txt"], "proxies": ['
                   '{"server": "8.8.4.4", "port": 443, "secret": "%s", "ping_ms": 120, "pinned": true}]}'
                   % tls_secret())
        ps, extra = sources.parse_source(curated, "c")
        self.assertEqual(ps[0].hint_ms, 120)
        self.assertTrue(ps[0].pinned)
        self.assertEqual(extra, ["https://example.org/list.txt"])

    def test_private_rejected_and_dedupe(self):
        bad = "tg://proxy?server=192.168.1.1&port=443&secret=%s tg://proxy?server=localhost&port=1&secret=%s"
        self.assertEqual(parse_text(bad % (KEY, KEY)), [])
        dup = "tg://proxy?server=1.1.1.1&port=443&secret=%s" % KEY
        self.assertEqual(len(parse_text(dup + " " + dup.replace("1.1.1.1", "1.1.1.1."))), 1)

    def test_link_roundtrip(self):
        p = make_proxy("proxy.example.net", 443, tls_secret())
        for link in (p.tg_link, p.share_link):
            self.assertEqual(parse_text(link)[0].key, p.key)

    def test_store_roundtrip(self):
        p = make_proxy("proxy.example.net", 443, tls_secret())
        p.apply(checker.Result(True, 77))
        with tempfile.TemporaryDirectory() as d:
            st = Store(os.path.join(d, "sub", "c.json"))
            st.save([p])
            q = st.load()[0]
        self.assertEqual((q.key, q.status, q.ping_ms), (p.key, "ok", 77))

    def test_mirror(self):
        self.assertEqual(sources.mirror_urls("https://raw.githubusercontent.com/a/b/main/data/p.json")[1],
                         "https://cdn.jsdelivr.net/gh/a/b@main/data/p.json")


class TestChecker(unittest.TestCase):
    def setUp(self):
        proxymod.ALLOW_PRIVATE = True
        checker.PURE_AES = True   # тот же AES, что на телефоне

    def tearDown(self):
        proxymod.ALLOW_PRIVATE = False
        checker.PURE_AES = False

    def run_check(self, server_secret, client_secret=None, mode="ok", timeout=5.0):
        srv = MockProxy(server_secret, mode)
        try:
            p = make_proxy("127.0.0.1", srv.port, client_secret or server_secret)
            self.assertIsNotNone(p)
            t0 = time.monotonic()
            res = checker.check(p, timeout=timeout)
            return res, srv, time.monotonic() - t0
        finally:
            time.sleep(0.05)
            srv.close()

    def test_classic_ok(self):
        res, srv, _ = self.run_check(KEY)
        self.assertTrue(res.ok, (res, srv.errors))
        self.assertIn(("tag", "eeeeeeee"), srv.seen)
        self.assertIn(("dc", 2), srv.seen)

    def test_dd_ok(self):
        for _ in range(5):
            res, srv, _ = self.run_check("dd" + KEY)
            self.assertTrue(res.ok, (res, srv.errors))
            self.assertIn(("tag", "dddddddd"), srv.seen)

    def test_faketls_ok(self):
        for domain in ("www.google.com", "s3.amazonaws.com", "a" * 60 + ".example.com"):
            res, srv, _ = self.run_check(tls_secret(domain))
            self.assertTrue(res.ok, (domain, res, srv.errors))
            self.assertIn(("hello_len", 517), srv.seen)
            self.assertIn(("sni", domain), srv.seen)
            self.assertGreaterEqual(res.ping_ms, 1)

    def test_wrong_keys_fail(self):
        other = "fedcba9876543210fedcba9876543210"
        res, _, _ = self.run_check(KEY, other)
        self.assertFalse(res.ok)
        res, _, _ = self.run_check("dd" + KEY, "dd" + other)
        self.assertFalse(res.ok)
        res, _, _ = self.run_check(tls_secret(), tls_secret(key=other))
        self.assertFalse(res.ok)
        self.assertEqual(res.error, "ключ не подошёл")

    def test_real_site_fails(self):
        res, _, _ = self.run_check(tls_secret(), mode="real_site")
        self.assertFalse(res.ok)

    def test_silent_times_out(self):
        res, _, took = self.run_check(KEY, mode="silent", timeout=1.5)
        self.assertFalse(res.ok)
        self.assertEqual(res.error, "не отвечает")
        self.assertLess(took, 3.0)

    def test_closed_connection_fails(self):
        res, _, _ = self.run_check(KEY, mode="close")
        self.assertFalse(res.ok)

    def test_closed_port_fails(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        res = checker.check(make_proxy("127.0.0.1", port, KEY), timeout=2)
        self.assertFalse(res.ok)

    def test_check_many(self):
        servers = [MockProxy(KEY), MockProxy(tls_secret()), MockProxy("dd" + KEY, "close")]
        try:
            ps = [make_proxy("127.0.0.1", s.port, s.secret.hex()) for s in servers]
            got = {}
            lock = threading.Lock()

            def on_result(p, r):
                with lock:
                    got[p.port] = r.ok
            checker.check_many(ps, on_result, workers=3, timeout=4)
            self.assertEqual(got, {servers[0].port: True, servers[1].port: True, servers[2].port: False})
        finally:
            for s in servers:
                s.close()

    def test_client_hello_shape(self):
        rec, digest = checker.build_client_hello(os.urandom(16), b"example.com")
        self.assertEqual(len(rec), 517)
        self.assertEqual(rec[:11], b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03")
        self.assertEqual(rec[11:43], digest)
        self.assertIn(b"example.com", rec)


if __name__ == "__main__":
    unittest.main()
