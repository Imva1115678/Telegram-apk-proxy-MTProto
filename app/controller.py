"""Логика приложения без интерфейса: откуда брать прокси, когда проверять,
как сортировать. Интерфейс (main.py) только показывает то, что здесь.

Всё тяжёлое (скачивание списков и проверки) идёт в фоновом потоке.
on_change() вызывается из фоновых потоков — в Kivy его нужно переносить
в главный поток (Clock.schedule_once).

Порядок одного прохода:
  1. перепроверяем те, что уже работали, и свои (закреплённые);
  2. качаем свежий список с вашего GitHub (его уже проверил робот);
  3. проверяем новых кандидатов, пока не наберётся ENOUGH_WORKING;
  4. если рабочих всё равно мало — берём открытые списки с GitHub и проверяем их.
"""

import os
import threading
import time

from . import checker, config, sources
from .storage import Store, load_bundled

KIND_RANK = {"tls": 0, "secure": 1, "classic": 2}
NET_ERRORS = ("нет соединения", "адрес не найден")
FAR = 10 ** 9


def speed_bucket(ms):
    """Грубая группа по скорости, чтобы список не прыгал от каждого замера."""
    if ms is None:
        return 9
    if ms < 150:
        return 0
    if ms < 300:
        return 1
    if ms < 600:
        return 2
    return 3


def ago(ts, now=None):
    if not ts:
        return "ещё не проверялся"
    now = time.time() if now is None else now
    sec = max(0, int(now - ts))
    if sec < 60:
        return "только что"
    if sec < 3600:
        return "%d мин назад" % (sec // 60)
    if sec < 86400:
        return "%d ч назад" % (sec // 3600)
    return "%d дн назад" % (sec // 86400)


def status_text(p, checking=False):
    if p.status == "ok":
        text = "Работает"
        if p.ping_ms:
            text += " · %d мс" % p.ping_ms
        return text
    if checking:
        return "Проверяется…"
    if p.status == "fail":
        return "Не работает" + (": " + p.error if p.error else "")
    return "Ещё не проверен"


class _AnyEvent(object):
    """«Пора остановиться», если сработало любое из событий."""

    def __init__(self, *events):
        self.events = events

    def is_set(self):
        for e in self.events:
            if e.is_set():
                return True
        return False


class Controller(object):
    def __init__(self, data_dir=None, bundled_path=None, on_change=None,
                 fetch=None, check_many=None, curated=None, public=None,
                 cfg=config, clock=time.time):
        self.cfg = cfg
        self.store = Store(os.path.join(data_dir, "cache.json")) if data_dir else None
        self.bundled_path = bundled_path
        self.on_change = on_change or (lambda: None)
        self._fetch = fetch or sources.fetch_many
        self._check_many = check_many or checker.check_many
        self._curated = list(curated) if curated is not None else cfg.curated_urls()
        self._public = list(public) if public is not None else list(sources.PUBLIC_SOURCES)
        self._extra = []
        self._clock = clock

        self._lock = threading.RLock()
        self._items = {}        # key -> Proxy
        self._seq = {}          # key -> номер по порядку, когда прокси впервые заработал
        self._next_seq = 0
        self._checking = set()  # ключи, которые проверяются прямо сейчас

        self._stop = threading.Event()
        self._wake = threading.Event()
        self._paused = threading.Event()
        self._thread = None
        self._want_full = True
        self._force_retry = False
        self._offline_streak = 0
        self._public_at = 0.0

        self.busy = False
        self.phase = ""
        self.done = 0
        self.total = 0
        self.last_check = 0.0
        self.last_fetch = 0.0
        self.last_full = 0.0
        self.lists_ok = None
        self.offline = False
        self.report = []

    # ---------- запуск и остановка ----------

    def load_local(self):
        """Кэш с телефона и список из APK — мгновенно, без интернета."""
        cached, bundled = [], []
        try:
            cached = self.store.load() if self.store else []
        except Exception:
            cached = []
        try:
            bundled = load_bundled(self.bundled_path) if self.bundled_path else []
        except Exception:
            bundled = []
        with self._lock:
            self._add(cached)
            self._add(bundled)
            self._trim()
            ok = sorted((p for p in self._items.values() if p.status == "ok"),
                        key=lambda p: p.ping_ms or FAR)
            for p in ok:
                self._mark_seq(p)
        self._notify()

    def start(self):
        if self._thread is not None:
            return
        self.load_local()
        self._thread = threading.Thread(target=self._loop, name="proxy-loop")
        self._thread.daemon = True
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._wake.set()
        self.save()

    def pause(self):
        self._paused.set()
        self.save()

    def resume(self):
        if not self._paused.is_set():
            return
        self._paused.clear()
        self._wake.set()

    def refresh(self):
        """Кнопка «Обновить»: скачать списки заново и проверить всё."""
        if self.busy:
            return False
        self._want_full = True
        self._force_retry = True
        self._wake.set()
        return True

    def recheck(self, key):
        """«Проверить ещё раз» для одного прокси (в отдельном потоке)."""
        with self._lock:
            p = self._items.get(key)
            if p is None or key in self._checking:
                return False
            self._checking.add(key)

        def run():
            self._check_list([p], None, None, track=False)
            self.save()

        t = threading.Thread(target=run, name="recheck-one")
        t.daemon = True
        t.start()
        self._notify()
        return True

    def save(self):
        if not self.store:
            return
        with self._lock:
            items = sorted(self._items.values(), key=self._priority)[: self.cfg.KEEP_MAX]
        try:
            self.store.save(items)
        except Exception:
            pass

    # ---------- данные для экрана ----------

    def working_count(self):
        with self._lock:
            return sum(1 for p in self._items.values() if p.status == "ok")

    def working(self):
        with self._lock:
            ok = [p for p in self._items.values() if p.status == "ok"]
            ok.sort(key=self._display_key)
            return ok

    def get(self, key):
        with self._lock:
            return self._items.get(key)

    def snapshot(self):
        """Всё, что нужно главному экрану, одним словарём (безопасно для потоков)."""
        now = self._clock()
        with self._lock:
            shown = [p for p in self._items.values() if p.status == "ok" or p.pinned]
            shown.sort(key=self._display_key)
            rows = []
            for p in shown[: self.cfg.SHOW_MAX]:
                text = status_text(p, p.key in self._checking)
                if p.pinned:
                    text = "Свой · " + text
                rows.append({
                    "pkey": p.key,
                    "title": p.server,
                    "status": text,
                    "ok": p.status == "ok",
                    "pinned": bool(p.pinned),
                })
            snap = {
                "rows": rows,
                "working": sum(1 for p in self._items.values() if p.status == "ok"),
                "known": len(self._items),
                "busy": self.busy,
                "phase": self.phase,
                "done": self.done,
                "total": self.total,
                "offline": self.offline,
                "lists_ok": self.lists_ok,
                "last_check": self.last_check,
            }
        snap["line"] = self.status_line(snap, now)
        snap["empty"] = self.empty_text(snap)
        return snap

    @staticmethod
    def status_line(snap, now=None):
        if snap["busy"]:
            parts = []
            if snap["working"]:
                parts.append("Рабочих: %d" % snap["working"])
            phase = snap["phase"] or "проверяем…"
            if snap["total"]:
                phase += " %d из %d" % (min(snap["done"], snap["total"]), snap["total"])
            parts.append(phase)
            line = " · ".join(parts)
        elif snap["offline"]:
            line = "Нет интернета — попробуем ещё раз чуть позже"
        elif snap["working"]:
            line = "Рабочих: %d · проверено %s" % (snap["working"], ago(snap["last_check"], now))
        elif snap["last_check"]:
            line = "Рабочих прокси сейчас нет"
        else:
            line = "Готовимся к проверке…"
        return line[:1].upper() + line[1:]

    @staticmethod
    def empty_text(snap):
        if snap["rows"]:
            return ""
        if snap["offline"]:
            return "Нет интернета.\nПроверьте Wi-Fi или мобильный интернет."
        if snap["busy"] or not snap["last_check"]:
            return "Ищем рабочие прокси…\nОбычно это занимает меньше минуты."
        return "Сейчас не нашлось рабочих прокси.\nНажмите «Обновить», чтобы поискать ещё раз."

    def details(self, key):
        """Данные для экрана одного прокси."""
        now = self._clock()
        with self._lock:
            p = self._items.get(key)
            if p is None:
                return None
            checking = key in self._checking
            return {
                "pkey": p.key,
                "server": p.server,
                "port": str(p.port),
                "secret": p.secret,
                "kind": p.kind_label,
                "status": status_text(p, checking),
                "ok": p.status == "ok",
                "fail": p.status == "fail",
                "checking": checking,
                "checked": ago(p.checked_at, now),
                "pinned": bool(p.pinned),
                "tg_link": p.tg_link,
                "share_link": p.share_link,
            }

    # ---------- внутреннее ----------

    def _notify(self):
        try:
            self.on_change()
        except Exception:
            pass

    def _mark_seq(self, p):
        if p.key not in self._seq:
            self._seq[p.key] = self._next_seq
            self._next_seq += 1

    def _display_key(self, p):
        return (0 if p.pinned else 1, speed_bucket(p.ping_ms if p.status == "ok" else None),
                self._seq.get(p.key, FAR))

    @staticmethod
    def _priority(p):
        """Кого проверять и хранить в первую очередь (меньше — важнее)."""
        if p.status == "ok":
            rank, speed = 0, p.ping_ms or FAR
        else:
            rank = 1 if p.status == "new" else 2
            speed = p.hint_ms if p.hint_ms is not None else FAR
        return (0 if p.pinned else 1, rank, min(p.fails or 0, 5), speed, KIND_RANK.get(p.kind, 3))

    def _add(self, proxies):
        added = 0
        for p in proxies:
            old = self._items.get(p.key)
            if old is None:
                self._items[p.key] = p
                added += 1
                continue
            if p.country and not old.country:
                old.country = p.country
            if p.hint_ms is not None:
                old.hint_ms = p.hint_ms
            if p.pinned:
                old.pinned = True
        return added

    def _trim(self):
        limit = self.cfg.KEEP_MAX
        if len(self._items) <= limit:
            return
        keep = sorted(self._items.values(), key=self._priority)[:limit]
        self._items = dict((p.key, p) for p in keep)

    # ---------- фоновая работа ----------

    def _loop(self):
        while not self._stop.is_set():
            if self._paused.is_set():
                self._wake.wait(5.0)
                self._wake.clear()
                continue
            self._wake.clear()
            try:
                self._run_pass()
            except Exception:
                # фоновый поток не должен падать ни при каких ошибках
                self.busy = False
                self.phase = ""
                self._notify()
            self.save()
            if self._stop.is_set():
                break
            self._wake.wait(self._next_delay())

    def run_pass(self):
        """Один проход целиком, без фонового потока (для тестов)."""
        self._run_pass()
        self.save()

    def _next_delay(self):
        if self.offline:
            steps = min(max(0, self._offline_streak - 1), 6)
            return min(self.cfg.RECHECK_EVERY, self.cfg.OFFLINE_RETRY * (2 ** steps))
        return self.cfg.RECHECK_EVERY

    def _interrupted(self):
        return self._stop.is_set() or self._paused.is_set()

    def _set_phase(self, phase, done=0, total=0):
        self.phase = phase
        self.done = done
        self.total = total
        self._notify()

    def _public_urls(self):
        seen, out = set(), []
        for u in self._extra + self._public:
            if u and u not in seen:
                seen.add(u)
                out.append(u)
        return out

    def _run_pass(self):
        now = self._clock()
        full = self._want_full or (now - self.last_full >= self.cfg.FULL_EVERY)
        force = self._force_retry
        self._want_full = False
        self._force_retry = False
        stats = {"ok": 0, "total": 0, "net": 0, "seen": set()}
        state = {"lists_ok": None}
        self.busy = True
        self._notify()
        try:
            self._pass_steps(full, force, stats, state)
            if full and not self._interrupted():
                self.last_full = self._clock()
            elif full:
                self._want_full = True  # свернули приложение посреди прохода — доделаем потом
        finally:
            self._finish_pass(stats, state["lists_ok"])

    def _pass_steps(self, full, force, stats, state):
        cfg = self.cfg
        # 1) те, что уже работали, и свои (закреплённые)
        with self._lock:
            known = [p for p in self._items.values() if p.status == "ok" or p.pinned]
        known.sort(key=self._priority)
        if known:
            self._check_list(known, "перепроверяем", stats)
        if self._interrupted():
            return
        need_more = self.working_count() < cfg.MIN_WORKING
        if not (full or need_more):
            return

        # 2) свежие списки: сначала свой (его уже проверил робот), потом открытые
        fetched = False
        public_done = False
        if full or force or self._clock() - self.last_fetch >= cfg.REFETCH_AFTER:
            got, ok = self._download(self._curated)
            state["lists_ok"] = ok if self._curated else None
            if len(got) < cfg.MIN_CURATED:
                got2, ok2 = self._download(self._public_urls())
                self._public_at = self._clock()
                state["lists_ok"] = bool(state["lists_ok"]) or ok2
                public_done = True
            fetched = True
            self.last_fetch = self._clock()
            self.lists_ok = state["lists_ok"]
        if self._interrupted():
            return

        # 3) новые кандидаты — пока не наберётся достаточно рабочих
        self._check_candidates(force, stats)
        if self._interrupted():
            return

        # 4) своего списка не хватило (например, провайдер их режет) — открытые списки
        if self.working_count() < cfg.MIN_WORKING and not public_done:
            if fetched or self._clock() - self._public_at >= cfg.REFETCH_AFTER:
                got2, ok2 = self._download(self._public_urls())
                self._public_at = self._clock()
                state["lists_ok"] = bool(state["lists_ok"]) or ok2
                self.lists_ok = state["lists_ok"]
                if not self._interrupted():
                    self._check_candidates(force, stats)

    def _download(self, urls):
        urls = [u for u in (urls or []) if u]
        if not urls:
            return [], False
        self._set_phase("скачиваем списки…")
        try:
            proxies, report, extra = self._fetch(urls)
        except Exception:
            return [], False
        ok = any(r.get("ok") for r in (report or []))
        with self._lock:
            self._add(proxies)
            self._trim()
            for u in extra or []:
                if u not in self._extra:
                    self._extra.append(u)
            self.report = list(report or [])
        self._notify()
        return proxies, ok

    def _check_candidates(self, force, stats):
        cfg = self.cfg
        now = self._clock()
        limit = 60 if self.offline else cfg.MAX_CHECK
        with self._lock:
            cands = []
            for p in self._items.values():
                if p.status == "ok" or p.key in self._checking or p.key in stats["seen"]:
                    continue
                if (p.status == "fail" and not force
                        and now - (p.checked_at or 0) < cfg.RETRY_FAILED_AFTER):
                    continue
                cands.append(p)
        cands.sort(key=self._priority)
        if cands:
            self._check_list(cands[:limit], "проверяем новые", stats, enough=cfg.ENOUGH_WORKING)

    def _check_list(self, targets, phase, stats=None, enough=None, track=True):
        cfg = self.cfg
        targets = list(targets)
        if not targets:
            return
        if enough is not None and self.working_count() >= enough:
            return
        enough_ev = threading.Event()
        stop = _AnyEvent(self._stop, self._paused, enough_ev)
        with self._lock:
            for p in targets:
                self._checking.add(p.key)
        if track:
            self._set_phase(phase, 0, len(targets))

        def on_result(p, res):
            with self._lock:
                self._checking.discard(p.key)
                p.apply(res, self._clock())
                if res.ok:
                    self._mark_seq(p)
                if stats is not None:
                    stats["total"] += 1
                    stats["seen"].add(p.key)
                    if res.ok:
                        stats["ok"] += 1
                    elif res.error in NET_ERRORS:
                        stats["net"] += 1
                if track:
                    self.done += 1
                if enough is not None and res.ok and not enough_ev.is_set():
                    if sum(1 for q in self._items.values() if q.status == "ok") >= enough:
                        enough_ev.set()
            self._notify()

        try:
            self._check_many(targets, on_result, workers=cfg.WORKERS,
                             timeout=cfg.CHECK_TIMEOUT, stop_event=stop)
        finally:
            with self._lock:
                for p in targets:
                    self._checking.discard(p.key)
            self.last_check = self._clock()
            self._notify()

    def _finish_pass(self, stats, lists_ok):
        no_answers = stats["total"] > 0 and stats["ok"] == 0
        if lists_ok is False and (no_answers or stats["total"] == 0):
            offline = True
        elif lists_ok is None and no_answers and stats["net"] * 10 >= stats["total"] * 8:
            offline = True
        else:
            offline = False
        if offline:
            # Ошибки из-за пропавшего интернета не считаем: когда сеть вернётся,
            # первыми проверим те, что работали до этого.
            with self._lock:
                for k in stats["seen"]:
                    p = self._items.get(k)
                    if p is None or p.status != "fail":
                        continue
                    if p.ok_at and p.ping_ms:
                        p.hint_ms = p.ping_ms
                    p.status = "new"
                    p.checked_at = 0
                    p.fails = max(0, (p.fails or 0) - 1)
                    p.error = ""
            self._want_full = True
            self._offline_streak += 1
        else:
            self._offline_streak = 0
        self.offline = offline
        self.busy = False
        self.phase = ""
        self.done = 0
        self.total = 0
        self._notify()
