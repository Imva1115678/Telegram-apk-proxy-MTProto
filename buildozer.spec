[app]

# Название под значком на телефоне
title = ТГ Прокси
package.name = familyproxy
package.domain = org.family

source.dir = .
source.include_exts = py,kv,json,png
source.exclude_dirs = tests, tools, bin, out, .github, .buildozer, __pycache__
source.exclude_patterns = prev.json

# Сборка на GitHub сама ставит номер 1.0.<номер сборки>
version = 1.0.0

requirements = python3,kivy==2.3.0,pyjnius,android,certifi

orientation = portrait
fullscreen = 0

icon.filename = %(source.dir)s/assets/icon.png
presplash.filename = %(source.dir)s/assets/presplash.png
android.presplash_color = #FFFFFF

android.permissions = INTERNET, ACCESS_NETWORK_STATE
android.api = 34
android.minapi = 24
android.archs = arm64-v8a, armeabi-v7a
android.accept_sdk_license = True
android.allow_backup = True

[buildozer]
log_level = 2
warn_on_root = 1
