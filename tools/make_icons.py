"""Рисует значок приложения и заставку: assets/icon.png и assets/presplash.png.

Запуск: python3 tools/make_icons.py   (нужен Pillow)
"""

import math
import os
import subprocess

from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ASSETS = os.path.join(ROOT, "assets")

TOP = (52, 138, 226)       # синий сверху
BOTTOM = (31, 99, 178)     # и чуть темнее внизу
GREEN = (46, 164, 79)
TEXT = (28, 28, 30)


def plane_points(scale, angle_deg):
    """Бумажный самолётик (как значок «отправить»), повёрнут носом вверх-вправо."""
    pts = [(2.0, 21.0), (23.0, 12.0), (2.0, 3.0), (2.0, 10.0), (17.0, 12.0), (2.0, 14.0)]
    a = math.radians(angle_deg)
    out = []
    for x, y in pts:
        dx, dy = (x - 12.5) * scale, (y - 12.0) * scale
        out.append((dx * math.cos(a) - dy * math.sin(a), dx * math.sin(a) + dy * math.cos(a)))
    return out


def make_icon(size=512, ss=4):
    s = size * ss
    grad = Image.new("RGBA", (s, s))
    g = ImageDraw.Draw(grad)
    for y in range(s):
        t = y / float(s - 1)
        g.line([(0, y), (s, y)], fill=tuple(int(TOP[i] + (BOTTOM[i] - TOP[i]) * t) for i in range(3)) + (255,))
    mask = Image.new("L", (s, s), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, s - 1, s - 1], radius=int(s * 0.225), fill=255)
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    img.paste(grad, (0, 0), mask)

    d = ImageDraw.Draw(img)
    pts = plane_points(s * 0.026, -24)
    xs, ys = [p[0] for p in pts], [p[1] for p in pts]
    cx = s * 0.5 - (min(xs) + max(xs)) / 2 - s * 0.01
    cy = s * 0.5 - (min(ys) + max(ys)) / 2 + s * 0.01
    d.polygon([(x + cx, y + cy) for x, y in pts], fill=(255, 255, 255, 255))

    # зелёная точка «работает» в белой обводке — чтобы не путать с самим Telegram
    r_out, r_in = s * 0.115, s * 0.085
    dx, dy = s * 0.74, s * 0.74
    d.ellipse([dx - r_out, dy - r_out, dx + r_out, dy + r_out], fill=(255, 255, 255, 255))
    d.ellipse([dx - r_in, dy - r_in, dx + r_in, dy + r_in], fill=GREEN + (255,))
    return img.resize((size, size), Image.LANCZOS)


def bold_font(px):
    for query in ("Liberation Sans:bold", "Arial:bold", "Noto Sans:bold", "DejaVu Sans:bold"):
        try:
            path = subprocess.check_output(["fc-match", "-f", "%{file}", query]).decode().strip()
            if path and os.path.exists(path):
                return ImageFont.truetype(path, px)
        except Exception:
            pass
    return ImageFont.load_default()


def make_presplash(icon, size=1024):
    img = Image.new("RGBA", (size, size), (255, 255, 255, 255))
    ic = icon.resize((280, 280), Image.LANCZOS)
    top = int(size * 0.5 - 200)
    img.paste(ic, ((size - 280) // 2, top), ic)
    d = ImageDraw.Draw(img)
    font = bold_font(64)
    text = "ТГ Прокси"
    w = d.textbbox((0, 0), text, font=font)[2]
    d.text(((size - w) // 2, top + 280 + 56), text, font=font, fill=TEXT + (255,))
    return img.convert("RGB")


def main():
    os.makedirs(ASSETS, exist_ok=True)
    icon = make_icon()
    icon.save(os.path.join(ASSETS, "icon.png"))
    make_presplash(icon).save(os.path.join(ASSETS, "presplash.png"))
    print("Готово:", os.path.join(ASSETS, "icon.png"), os.path.join(ASSETS, "presplash.png"))


if __name__ == "__main__":
    main()
