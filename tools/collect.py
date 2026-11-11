"""Робот для GitHub Actions: собирает MTProto-прокси из открытых списков,
проверяет каждый настоящим рукопожатием с Telegram и сохраняет рабочие.

    python tools/collect.py --out out/proxies.json --report out/README.md --prev prev.json

Если не заработал ни один прокси (например, у GitHub сбой сети), файл со списком
не записывается — в приложении остаётся предыдущий.
"""

import argparse
import json
import os
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from app import checker, sources  # noqa: E402
from app.proxy import merge_unique, parse_text  # noqa: E402

KIND_RANK = {"tls": 0, "secure": 1, "classic": 2}
KIND_NAME = {"tls": "Fake TLS", "secure": "dd", "classic": "обычный"}
FAR = 10 ** 6


def read_lines(path):
    """Строки файла без пустых и комментариев (#)."""
    if not path:
        return []
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError:
        return []
    return [s.strip() for s in lines if s.strip() and not s.strip().startswith("#")]


def read_proxies(path, origin):
    """Прокси из файла: ссылки, host:port:secret или JSON. Строки с # пропускаются,
    поэтому пример в комментарии data/pinned.txt не станет «своим» прокси."""
    if not path:
        return []
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return []
    if text.lstrip().startswith(("{", "[")):
        return parse_text(text, origin)     # JSON (прошлый список) — как есть
    return parse_text("\n".join(read_lines(path)), origin)


def collect(urls, prev=(), pinned=(), max_check=1500, workers=64, timeout=6.0, keep=300,
            fetch=None, check_many=None, log=print):
    """Возвращает (data для proxies.json или None, статистика для отчёта)."""
    fetch = fetch or sources.fetch_many
    check_many = check_many or checker.check_many
    t0 = time.time()
    fetched, report, extra = fetch(list(urls)) if urls else ([], [], [])
    log("Скачано кандидатов: %d из %d списков" % (len(fetched), len(report)))

    pinned = list(pinned)
    for p in pinned:
        p.pinned = True
    prev = sorted(prev, key=lambda p: p.hint_ms if p.hint_ms is not None else FAR)
    prev_keys = set(p.key for p in prev)
    fresh = sorted(fetched, key=lambda p: KIND_RANK.get(p.kind, 3))
    candidates = merge_unique(pinned + prev + fresh)[:max_check]
    log("Проверяем: %d" % len(candidates))

    passes = {}
    lock = threading.Lock()

    def on_result(p, res):
        with lock:
            p.apply(res)
            if res.ok:
                passes[p.key] = passes.get(p.key, 0) + 1

    check_many(candidates, on_result, workers=workers, timeout=timeout, retry_ok=False)
    # вторая проверка: рабочие — чтобы отсеять нестабильные; упавшие свои и
    # вчерашние — чтобы не выкинуть из-за одной потерянной попытки
    again = [p for p in candidates
             if p.status == "ok" or p.pinned or p.key in prev_keys]
    check_many(again, on_result, workers=workers, timeout=timeout, retry_ok=False)

    working = [p for p in candidates if passes.get(p.key)]
    for p in working:
        if p.status != "ok":       # один раз из двух — всё же берём, но в конец
            p.status = "ok"
    working.sort(key=lambda p: (0 if p.pinned else 1, -passes[p.key], p.ping_ms or FAR))
    pinned_down = [p for p in candidates if p.pinned and not passes.get(p.key)]

    stats = {
        "took": time.time() - t0,
        "checked": len(candidates),
        "working": len(working),
        "report": report,
        "top": working[:15],
        "kept_prev": 0,
        "pinned_down": len(pinned_down),
    }
    if not working and not pinned_down:
        log("Ни один прокси не ответил — старый список не трогаем")
        return None, stats

    out = pinned_down + working[:keep]
    # Сбой сети у GitHub не должен резко урезать список: если рабочих стало в разы
    # меньше, чем было, добавляем в конец вчерашние (телефон всё равно перепроверит).
    if prev and len(working) < min(20, len(prev) // 4):
        have = set(p.key for p in out)
        for p in prev:
            if len(out) >= keep:
                break
            if p.key not in have:
                out.append(p)
                stats["kept_prev"] += 1

    good_sources = [r["url"] for r in report if r.get("ok") and r.get("count")]
    for u in extra or []:
        if u not in good_sources:
            good_sources.append(u)
    items = []
    for p in out:
        d = {"server": p.server, "port": p.port, "secret": p.secret}
        if passes.get(p.key) and p.ping_ms:
            d["ping_ms"] = p.ping_ms
        elif p.hint_ms is not None:
            d["ping_ms"] = p.hint_ms + 1000   # не проверен сейчас — ставим позже других
        if p.country:
            d["country"] = p.country
        if p.pinned:
            d["pinned"] = True
        items.append(d)
    data = {
        "version": 1,
        "updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "updated_ts": int(time.time()),
        "checked": len(candidates),
        "working": len(working),
        "sources": good_sources,
        "proxies": items,
    }
    log("Рабочих: %d, в списке: %d, за %.0f с" % (len(working), len(items), stats["took"]))
    return data, stats


def short_url(url):
    for prefix in ("https://raw.githubusercontent.com/", "https://", "http://"):
        if url.startswith(prefix):
            return url[len(prefix):]
    return url


def render_report(stats, wrote):
    msk = time.gmtime(time.time() + 3 * 3600)
    lines = [
        "# Список прокси для приложения",
        "",
        "Обновлено: %s (МСК) · проверено %d · работают %d · заняло %.0f с"
        % (time.strftime("%d.%m.%Y %H:%M", msk), stats["checked"], stats["working"], stats["took"]),
        "",
    ]
    if not wrote:
        lines += ["> Ни один прокси не ответил, поэтому список не обновлён.", ""]
    if stats.get("kept_prev"):
        lines += ["> Рабочих стало намного меньше — оставлено %d из прошлого списка."
                  % stats["kept_prev"], ""]
    if stats.get("pinned_down"):
        lines += ["> Своих прокси не ответило: %d (они всё равно в списке)."
                  % stats["pinned_down"], ""]
    lines += ["## Источники", "", "| Список | Скачался | Прокси |", "|---|---|---|"]
    for r in stats["report"]:
        state = "да" if r.get("ok") else "нет (%s)" % (r.get("error") or "ошибка")
        lines.append("| %s | %s | %d |" % (short_url(r["url"]), state, r.get("count") or 0))
    if stats["top"]:
        lines += ["", "## Самые быстрые (со сервера GitHub; с телефона может отличаться)", "",
                  "| Сервер | Порт | Тип | Пинг |", "|---|---|---|---|"]
        for p in stats["top"]:
            lines.append("| %s | %d | %s | %s мс |" % (p.server, p.port, KIND_NAME.get(p.kind, p.kind),
                                                     p.ping_ms or "?"))
    lines += ["", "Файл для приложения: `proxies.json`. Обновляется автоматически раз в 3 часа.", ""]
    return "\n".join(lines)


def main(argv=None, fetch=None, check_many=None):
    ap = argparse.ArgumentParser(description="Собрать и проверить MTProto-прокси")
    ap.add_argument("--out", default=os.path.join(ROOT, "data", "proxies.json"))
    ap.add_argument("--report", default="")
    ap.add_argument("--prev", default="", help="прошлый proxies.json (его рабочие проверяются первыми)")
    ap.add_argument("--sources", default=os.path.join(ROOT, "data", "sources.txt"))
    ap.add_argument("--pinned", default=os.path.join(ROOT, "data", "pinned.txt"))
    ap.add_argument("--no-builtin", action="store_true", help="не брать встроенные списки")
    ap.add_argument("--max", type=int, default=1500)
    ap.add_argument("--workers", type=int, default=64)
    ap.add_argument("--timeout", type=float, default=6.0)
    ap.add_argument("--keep", type=int, default=300)
    args = ap.parse_args(argv)

    urls = [] if args.no_builtin else list(sources.PUBLIC_SOURCES)
    for u in read_lines(args.sources):
        if u not in urls:
            urls.append(u)
    prev = read_proxies(args.prev, "prev")
    pinned = read_proxies(args.pinned, "pinned")
    data, stats = collect(urls, prev, pinned, max_check=args.max, workers=args.workers,
                          timeout=args.timeout, keep=args.keep, fetch=fetch, check_many=check_many)
    if data is not None:
        folder = os.path.dirname(os.path.abspath(args.out))
        os.makedirs(folder, exist_ok=True)
        tmp = args.out + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=1)
            f.write("\n")
        os.replace(tmp, args.out)
    if args.report:
        os.makedirs(os.path.dirname(os.path.abspath(args.report)), exist_ok=True)
        with open(args.report, "w", encoding="utf-8") as f:
            f.write(render_report(stats, data is not None))
    return 0


if __name__ == "__main__":
    sys.exit(main())
