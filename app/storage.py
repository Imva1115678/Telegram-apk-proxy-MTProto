"""Кэш на телефоне: последние известные прокси и их статусы.

Благодаря кэшу приложение сразу показывает работавшие раньше прокси
и перепроверяет их первыми — даже если GitHub сейчас недоступен.
"""

import json
import os
import threading

from .proxy import Proxy, parse_text


class Store(object):
    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()

    def load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return []
        items = data.get("proxies", []) if isinstance(data, dict) else []
        out = []
        for d in items:
            if isinstance(d, dict):
                p = Proxy.from_dict(d)
                if p is not None:
                    out.append(p)
        return out

    def save(self, proxies):
        data = {"version": 1, "proxies": [p.to_dict() for p in proxies]}
        tmp = self.path + ".tmp"
        with self._lock:
            try:
                folder = os.path.dirname(self.path)
                if folder:
                    os.makedirs(folder, exist_ok=True)
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(data, f, ensure_ascii=False, separators=(",", ":"))
                os.replace(tmp, self.path)
            except OSError:
                pass


def load_bundled(path):
    """Список, вшитый в APK при сборке (data/proxies.json)."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return []
    return parse_text(text, "bundled")
