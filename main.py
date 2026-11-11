"""ТГ Прокси — рабочие MTProto-прокси для Telegram (Android, Kivy).

Проверка, списки и кэш — в app/controller.py, внешний вид — в ui.kv.
На компьютере запускается так: pip install kivy==2.3.0 && python main.py
"""

import os
import time

from kivy.config import Config
from kivy.utils import platform

Config.set("kivy", "exit_on_escape", "0")
if platform not in ("android", "ios"):
    # окно размером с телефон, чтобы удобно проверять на компьютере
    Config.set("graphics", "width", "400")
    Config.set("graphics", "height", "780")

from kivy.animation import Animation  # noqa: E402
from kivy.app import App  # noqa: E402
from kivy.clock import Clock  # noqa: E402
from kivy.core.clipboard import Clipboard  # noqa: E402
from kivy.core.window import Window  # noqa: E402
from kivy.lang import Builder  # noqa: E402
from kivy.properties import (BooleanProperty, ColorProperty, NumericProperty,  # noqa: E402
                             ObjectProperty, StringProperty)
from kivy.resources import resource_find  # noqa: E402
from kivy.uix.behaviors import ButtonBehavior  # noqa: E402
from kivy.uix.boxlayout import BoxLayout  # noqa: E402
from kivy.uix.floatlayout import FloatLayout  # noqa: E402
from kivy.uix.label import Label  # noqa: E402
from kivy.uix.recycleview import RecycleView  # noqa: E402
from kivy.uix.recycleview.views import RecycleDataViewBehavior  # noqa: E402
from kivy.uix.screenmanager import Screen  # noqa: E402
from kivy.uix.widget import Widget  # noqa: E402

from app import theme  # noqa: E402
from app.controller import Controller  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


# ---------- мелкие помощники ----------

def row_tone(ok, status):
    """ok — работает, fail — не отвечает, wait — ещё не проверен или проверяется."""
    if ok:
        return "ok"
    return "fail" if "Не работает" in (status or "") else "wait"


def group_key(secret, size=8):
    """Ключ блоками по 8 знаков: так он переносится по строкам и легче читается.
    Копируется всегда весь ключ целиком, без пробелов."""
    return " ".join(secret[i:i + size] for i in range(0, len(secret), size))


def _activity():
    from jnius import autoclass
    return autoclass("org.kivy.android.PythonActivity").mActivity


def open_link(url):
    """Открывает ссылку: tg:// сразу попадает в Telegram. True — получилось."""
    if not url:
        return False
    if platform == "android":
        try:
            from jnius import autoclass
            Intent = autoclass("android.content.Intent")
            Uri = autoclass("android.net.Uri")
            intent = Intent(Intent.ACTION_VIEW, Uri.parse(url))
            _activity().startActivity(intent)
            return True
        except Exception:
            return False
    try:
        import webbrowser
        return bool(webbrowser.open(url))
    except Exception:
        return False


def share_text(text, title):
    """Системное окно «Поделиться» (Telegram, WhatsApp и т. д.). True — открылось."""
    if platform != "android":
        return False
    try:
        from jnius import autoclass, cast
        Intent = autoclass("android.content.Intent")
        String = autoclass("java.lang.String")
        intent = Intent()
        intent.setAction(Intent.ACTION_SEND)
        intent.setType("text/plain")
        intent.putExtra(Intent.EXTRA_TEXT, cast("java.lang.CharSequence", String(text)))
        chooser = Intent.createChooser(intent, cast("java.lang.CharSequence", String(title)))
        _activity().startActivity(chooser)
        return True
    except Exception:
        return False


def move_to_background():
    """«Назад» на главном экране сворачивает приложение, а не закрывает его."""
    if platform != "android":
        return
    try:
        _activity().moveTaskToBack(True)
    except Exception:
        pass


def style_status_bar():
    """Красит системную строку состояния в цвет верхней панели (белые значки на синем)."""
    if platform != "android":
        return
    try:
        from android.runnable import run_on_ui_thread
    except Exception:
        return

    @run_on_ui_thread
    def apply():
        try:
            from jnius import autoclass
            Color = autoclass("android.graphics.Color")
            LayoutParams = autoclass("android.view.WindowManager$LayoutParams")
            window = _activity().getWindow()
            window.clearFlags(LayoutParams.FLAG_TRANSLUCENT_STATUS)
            window.addFlags(LayoutParams.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS)
            window.setStatusBarColor(Color.parseColor(theme.BAR_HEX))
        except Exception:
            pass

    apply()


# ---------- виджеты (внешний вид — в ui.kv) ----------

class StatusDot(Widget):
    color = ColorProperty(theme.GRAY_DOT)


class BlueButton(ButtonBehavior, Label):
    radius = NumericProperty(0)


class OutlineButton(ButtonBehavior, Label):
    radius = NumericProperty(0)


class TextButton(ButtonBehavior, Label):
    pass


class BackButton(ButtonBehavior, Widget):
    pass


class ProgressLine(Widget):
    """Тонкая полоска прогресса под строкой статуса."""

    active = BooleanProperty(False)
    value = NumericProperty(0.0)     # 0..1; меньше нуля — «бегущая» полоска
    shift = NumericProperty(0.0)

    def __init__(self, **kwargs):
        self._ev = None
        super(ProgressLine, self).__init__(**kwargs)
        self.bind(active=self._update, value=self._update)

    def _update(self, *_):
        run = self.active and self.value < 0
        if run and self._ev is None:
            self._ev = Clock.schedule_interval(self._tick, 1 / 30.0)
        elif not run and self._ev is not None:
            self._ev.cancel()
            self._ev = None

    def _tick(self, dt):
        self.shift = (self.shift + dt / 1.3) % 1.0


class ProxyRow(RecycleDataViewBehavior, ButtonBehavior, BoxLayout):
    """Строка списка: название, статус и кнопка «Подключить»."""

    pkey = ObjectProperty(None, allownone=True)
    title = StringProperty("")
    status = StringProperty("")
    tone = StringProperty("wait")


class ProxyList(RecycleView):
    """Список. Помнит, когда палец на экране, чтобы строки не прыгали под ним."""

    def __init__(self, **kwargs):
        self._touches = {}
        super(ProxyList, self).__init__(**kwargs)

    def on_touch_down(self, touch):
        if self.collide_point(*touch.pos):
            self._touches[touch.uid] = time.time()
        return super(ProxyList, self).on_touch_down(touch)

    def on_touch_up(self, touch):
        self._touches.pop(touch.uid, None)
        return super(ProxyList, self).on_touch_up(touch)

    def touching(self):
        now = time.time()
        for uid, started in list(self._touches.items()):
            if now - started > 6:
                self._touches.pop(uid, None)
        return bool(self._touches)


class CopyField(ButtonBehavior, BoxLayout):
    """Поле в рамке: нажали — значение скопировано, рамка подсвечивается."""

    caption = StringProperty("")
    value = StringProperty("")
    display = StringProperty("")
    copied = BooleanProperty(False)

    def on_value(self, *_):
        self.copied = False

    def on_release(self):
        if not self.value:
            return
        Clipboard.copy(self.value)
        self.copied = True
        Clock.unschedule(self._reset)
        Clock.schedule_once(self._reset, 1.8)

    def _reset(self, *_):
        self.copied = False


class Toast(Label):
    """Короткое сообщение внизу экрана."""

    def show(self, text, seconds=2.2):
        self.text = text
        Animation.cancel_all(self, "opacity")
        Animation(opacity=1, d=0.15).start(self)
        Clock.unschedule(self._hide)
        Clock.schedule_once(self._hide, seconds)

    def _hide(self, *_):
        Animation.cancel_all(self, "opacity")
        Animation(opacity=0, d=0.3).start(self)


class ListScreen(Screen):
    line = StringProperty("Загружаем…")
    empty = StringProperty("")
    busy = BooleanProperty(False)
    progress = NumericProperty(0.0)


class DetailScreen(Screen):
    pkey = ObjectProperty(None, allownone=True)
    title = StringProperty("")
    status = StringProperty("")
    tone = StringProperty("wait")
    meta = StringProperty("")
    server = StringProperty("")
    port = StringProperty("")
    secret = StringProperty("")
    secret_display = StringProperty("")
    checking = BooleanProperty(False)


class RootView(FloatLayout):
    pass


# ---------- приложение ----------

class FamilyProxyApp(App):
    mono_font = StringProperty("Roboto")

    def build(self):
        self.title = "ТГ Прокси"
        Window.clearcolor = theme.BG
        mono = resource_find("data/fonts/RobotoMono-Regular.ttf")
        if mono:
            self.mono_font = mono
        self.ctrl = Controller(data_dir=self.user_data_dir,
                               bundled_path=os.path.join(HERE, "data", "proxies.json"),
                               on_change=self._changed)
        self.current_key = None
        self._pending = False
        self._postponed = 0
        self._rows = None
        root = Builder.load_file(os.path.join(HERE, "ui.kv"))
        Window.bind(on_keyboard=self._on_key)
        return root

    def on_start(self):
        ids = self.root.ids
        self.sm = ids.sm
        self.list_screen = ids.list_screen
        self.detail_screen = ids.detail_screen
        self.toast = ids.toast
        self.ctrl.load_local()
        self.render()
        self.ctrl.start()
        Clock.schedule_interval(self._tick, 30)   # «проверено N мин назад»
        style_status_bar()

    # --- обновление экрана ---

    def _changed(self):
        """Вызывается из фоновых потоков проверки; рисуем в главном потоке, не чаще 2 раз в секунду."""
        if not self._pending:
            self._pending = True
            Clock.schedule_once(self.render, 0.4)

    def _tick(self, *_):
        self.render()

    def render(self, *_):
        self._pending = False
        ls = self.list_screen
        rv = ls.ids.rv
        if rv.touching() and self._postponed < 5:
            # палец на списке — не двигаем строки под ним, обновим чуть позже
            self._postponed += 1
            self._pending = True
            Clock.schedule_once(self.render, 0.7)
            return
        self._postponed = 0
        snap = self.ctrl.snapshot()
        rows = [{"pkey": r["pkey"], "title": r["title"], "status": r["status"],
                 "tone": row_tone(r["ok"], r["status"])} for r in snap["rows"]]
        if rows != self._rows:
            self._rows = rows
            rv.data = rows
        ls.line = snap["line"]
        ls.empty = "" if rows else snap["empty"]
        ls.busy = bool(snap["busy"])
        if snap["busy"]:
            total = snap.get("total") or 0
            ls.progress = (float(snap.get("done") or 0) / total) if total else -1.0
        else:
            ls.progress = 0.0
        if self.sm.current == "detail":
            self.fill_detail()

    def fill_detail(self):
        d = self.ctrl.details(self.current_key) if self.current_key else None
        if not d:
            return False
        ds = self.detail_screen
        ds.pkey = d["pkey"]
        ds.title = d["server"]
        ds.status = ("Свой · " if d.get("pinned") else "") + d["status"]
        ds.tone = "wait" if d.get("checking") else row_tone(d["ok"], d["status"])
        checked = d.get("checked") or ""
        if checked and not checked.startswith("ещё"):
            checked = "проверено " + checked
        parts = [p for p in (checked[:1].upper() + checked[1:], d.get("kind") or "") if p]
        ds.meta = " · ".join(parts)
        ds.server = d["server"]
        ds.port = str(d["port"])
        ds.secret = d["secret"]
        ds.secret_display = group_key(d["secret"])
        ds.checking = bool(d.get("checking"))
        return True

    # --- переходы между экранами ---

    def open_detail(self, pkey):
        self.current_key = pkey
        if not self.fill_detail():
            return
        self.detail_screen.ids.scroll.scroll_y = 1
        self.sm.transition.direction = "left"
        self.sm.current = "detail"

    def go_back(self):
        if self.sm.current == "list":
            return False
        self.sm.transition.direction = "right"
        self.sm.current = "list"
        return True

    def _on_key(self, window, key, *args):
        if key == 27:   # «Назад» на Android (и Esc на компьютере)
            if not self.go_back():
                move_to_background()
            return True
        return False

    # --- кнопки ---

    def _details_or_toast(self, pkey):
        d = self.ctrl.details(pkey) if pkey else None
        if not d:
            self.toast.show("Этого прокси уже нет в списке")
        return d

    def connect(self, pkey):
        d = self._details_or_toast(pkey)
        if not d:
            return
        if open_link(d["tg_link"]) or open_link(d["share_link"]):
            return
        self.toast.show("Не получилось открыть Telegram")

    def share(self, pkey):
        d = self._details_or_toast(pkey)
        if not d:
            return
        text = "Прокси для Telegram — нажми, чтобы подключить:\n" + d["share_link"]
        if not share_text(text, "Поделиться прокси"):
            Clipboard.copy(d["share_link"])
            self.toast.show("Ссылка скопирована")

    def copy_link(self, pkey):
        d = self._details_or_toast(pkey)
        if d:
            Clipboard.copy(d["share_link"])
            self.toast.show("Ссылка скопирована")

    def recheck(self, pkey):
        if pkey and self.ctrl.recheck(pkey):
            self.fill_detail()
        else:
            self.toast.show("Уже проверяем")

    def refresh(self):
        if self.ctrl.refresh():
            self.toast.show("Ищем свежие прокси")
        else:
            self.toast.show("Проверка уже идёт")
        self._changed()

    # --- жизненный цикл Android ---

    def on_pause(self):
        self.ctrl.pause()
        try:
            self.ctrl.save()
        except Exception:
            pass
        return True

    def on_resume(self):
        self.ctrl.resume()
        style_status_bar()
        self.render()

    def on_stop(self):
        self.ctrl.stop()
        try:
            self.ctrl.save()
        except Exception:
            pass


if __name__ == "__main__":
    FamilyProxyApp().run()
