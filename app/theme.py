"""Цвета интерфейса: светлая тема, синий как в Telegram, без фиолетового.

Контраст текста подобран по WCAG AA: все надписи не бледнее 4.5:1 к фону,
чтобы всё читалось и на старом телефоне с тусклым экраном.
"""


def rgba(hex_color, alpha=1.0):
    h = hex_color.lstrip("#")
    return (int(h[0:2], 16) / 255.0, int(h[2:4], 16) / 255.0, int(h[4:6], 16) / 255.0, alpha)


BG_HEX = "#FFFFFF"
BAR_HEX = "#2678CC"            # верхняя панель и строка состояния Android

BG = rgba(BG_HEX)
BAR = rgba(BAR_HEX)
BAR_TEXT = rgba("#FFFFFF")
BAR_PRESSED = rgba("#FFFFFF", 0.18)
TEXT = rgba("#1C1C1E")
HINT = rgba("#6D6D72")
DIVIDER = rgba("#E6E6EA")
PRESSED = rgba("#F1F2F4")
STRIP = rgba("#F4F5F7")          # полоса статуса под верхней панелью

BLUE = rgba("#2678CC")
BLUE_DOWN = rgba("#1F63A8")
BLUE_LIGHT = rgba("#E8F1FB")
WHITE = rgba("#FFFFFF")

GREEN = rgba("#2EA44F")          # точка «работает»
GREEN_TEXT = rgba("#1E7B3A")     # текст «работает»
RED = rgba("#E5484D")
RED_TEXT = rgba("#C42B30")
GRAY_DOT = rgba("#B4B4BA")

FIELD_BG = rgba("#F7F8FA")
FIELD_LINE = rgba("#7F94AA")     # заметная рамка: сразу видно, что на поле можно нажать
TOAST_BG = rgba("#2B2B2E", 0.94)
SCROLLBAR = rgba("#000000", 0.22)
SCROLLBAR_IDLE = rgba("#000000", 0.10)
CLEAR = (0, 0, 0, 0)


def tone_dot(tone):
    """Цвет точки статуса: ok / fail / wait."""
    return {"ok": GREEN, "fail": RED}.get(tone, GRAY_DOT)


def tone_text(tone):
    """Цвет текста статуса: ok / fail / wait."""
    return {"ok": GREEN_TEXT, "fail": RED_TEXT}.get(tone, HINT)
