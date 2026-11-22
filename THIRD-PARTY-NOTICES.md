# Сторонние компоненты

В сборку входят сторонние компоненты и локальная производная движка zapret2 с мостом к Rust. У каждого компонента своя лицензия.

Нативное приложение `bin\zapret-rust.exe` использует библиотеки Rust из зафиксированного `native/Cargo.lock`. Перечень версий, лицензионные тексты зависимостей и уведомления стандартной библиотеки собраны в [LICENSE-rust.txt](LICENSE-rust.txt). В стандартной Windows-сборке правила, обработка пакетов, автосмена и инициализация реализованы на Rust. Движок сохраняет Lua API для пользовательских скриптов.

Локальная GNU-сборка также включает уведомления MinGW-w64 runtime — [LICENSE-mingw-w64.txt](LICENSE-mingw-w64.txt).

| Файлы | Проект | Лицензия |
|---|---|---|
| `bin\winws2.exe`, `windivert\quic_initial_ietf.txt` и Lua-библиотеки в сборке совместимости | [zapret2](https://github.com/bol-van/zapret2) v1.0.6 © bol-van | MIT — [LICENSE-zapret2.txt](LICENSE-zapret2.txt) |
| `bin\WinDivert.dll`, `bin\WinDivert64.sys` | [WinDivert](https://github.com/basil00/WinDivert) 2.2.2 © basil00, из релиза zapret2 v1.0.6 | [LGPL-3.0 или GPL-2.0](LICENSE-WinDivert.txt) |
| `bin\cygwin1.dll` | [Cygwin](https://cygwin.com) 3.6.12-1, из официального зеркала Cygwin | LGPL-3.0-or-later с исключением связывания — [LICENSE-cygwin.txt](LICENSE-cygwin.txt); [точные исходники](https://mirrors.kernel.org/sourceware/cygwin/src/release/cygwin/cygwin-3.6.12-1-src.tar.xz) |
| `fake\*.bin`, `lists\list-general.txt`, `lists\list-google.txt`, `lists\list-exclude.txt`, `lists\ipset-all.txt`, `lists\ipset-exclude.txt`, `lists\hosts-flowseal.txt` | [zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube) 1.10.4 © Flowseal | MIT — [LICENSE-flowseal.txt](LICENSE-flowseal.txt) |
| Интерпретатор Lua в стандартной Windows-сборке `bin\winws2.exe` | [Luna Core 4.0.2](https://crates.io/crates/luna-core/4.0.2) © GOLIA K.K. | MIT — [LICENSE-Luna.txt](LICENSE-Luna.txt) |
| LuaJIT в сборке совместимости и эталонных тестах | [OpenResty LuaJIT v2.1-20250826](https://github.com/openresty/luajit2/tree/v2.1-20250826) © Mike Pall, OpenResty | MIT — [LICENSE-LuaJIT.txt](LICENSE-LuaJIT.txt) |
| `tools\dpi-suite.json` | [dpi-checkers](https://github.com/hyperion-cs/dpi-checkers) © hyperion-cs | [Apache-2.0](LICENSE-dpi-checkers.txt) |

`strategies\*.txt` — стратегии Flowseal и примеры из документации zapret2, переведённые в формат этой сборки.

`lua\autoring.lua` написан для этой сборки по идеям [Zapret GUI](https://github.com/zapret-discordyoutube/zapretgui) © censorliber: память автосмены по сайту и подсети, быстрая смена непроверенной стратегии. Лицензия MIT — [LICENSE-zapretgui.txt](LICENSE-zapretgui.txt).

`lua\host-cache.lua` добавляет ограниченный индекс поверх `automate_host_record` из zapret2 (© bol-van, MIT): правила выбора ключа и аварийное создание записи повторяют upstream; после сбоя последующие запросы вызывают неизменённую штатную функцию. MIT — [LICENSE-zapret2.txt](LICENSE-zapret2.txt).

`hostfakesplit_alt` в `lua\fooling.lua` — это `hostfakesplit` из zapret2 (© bol-van, MIT) с порядком частей `altorder=1` из zapret1; так же поступили [z2k](https://github.com/necronicle/z2k) © necronicle (MIT) и [zapret2-next](https://github.com/Dunterbabochka/zapret2-next) © Dunterbabochka (MIT). Из z2k взяты идеи для `lua\autoring.lua` (два повтора для непроверенной стратегии, неудача при закрытии TLS-соединения без ответа) и стратегия 72. Проверка `dev\tests\lintstrat.ps1` написана по идее [zapret-gui](https://github.com/avatarDD/zapret-gui) © avatarDD (MIT). Код этих проектов не копировался.

`native/telegram-core` — перенос транспортного ядра [tg-ws-proxy v1.11.4](https://github.com/Flowseal/tg-ws-proxy/tree/v1.11.4) © Flowseal на Rust: аутентификация MTProxy, маршрутизация Telegram, WebSocket, CF/HTTP2 и резервный TCP. Лицензия MIT — [LICENSE-tg-ws-proxy.txt](LICENSE-tg-ws-proxy.txt). Ядро включено в `bin\zapret-rust.exe`; отдельный Python/tray executable в нативную сборку не входит. Старые `tools\tgbridge.cs`, `tools\tgws.ps1` и скачанный upstream binary остаются только источниками совместимости старых разработческих проверок.

SHA-256 комплекта — в [CHECKSUMS.txt](CHECKSUMS.txt). `tools/upstream.txt` сохраняет происхождение базового релиза и закрепляет фактические файлы; `tools/rust-ring.json` отмечает локально собранные движок, Rust DLL и адаптеры. WinDivert и три upstream Lua-библиотеки не изменены. Исходники моста и воспроизводимый процесс сборки находятся в `native/zapret-ring-ffi`; сведения о них есть в репозитории, они не включаются в пользовательский runtime.

WinDivert распространяется по LGPL-3.0. [Соответствующие исходники WinDivert 2.2.2](https://github.com/basil00/WinDivert/tree/v2.2.2). Файл драйвера совпадает с официальным WinDivert-2.2.2-A. В DLL [сборка zapret2 v1.0.6](https://github.com/bol-van/zapret2/blob/v1.0.6/.github/workflows/build.yml) включает флаг ASLR в заголовке PE через `peflags --dynamicbase=true`. Проект загружает DLL динамически.

Linux-установщик получает [официальный архив zapret2 v1.0.7](https://github.com/bol-van/zapret2/releases/tag/v1.0.7), который распространяется upstream вместе с лицензиями его компонентов.

Внешние сервисы, к которым обращаются скрипты, все по HTTPS:
- **ipwho.is**, запасной **ipinfo.io** — провайдер и страна при проверке подключения, где находятся серверы в трекере;
- **GitHub** — свежие списки Flowseal и номера новых версий;
- **web.telegram.org** — веб-вход Telegram, если включён мост Telegram;
- **hyperion-cs.github.io** — актуальный набор хостингов для проверки 16–20 КБ.

Нативная Windows-сборка движка включает Rust-библиотеку zapret-wincompat и статические библиотеки MinGW-w64/LLVM. Уведомления winpthreads, compiler runtime и BSD-заголовков включены в LICENSE-mingw-w64.txt. Зависимости Rust, включая glob и zlib-rs, перечислены в LICENSE-rust.txt. Нативный движок связывается с Windows UCRT. Строка про Cygwin в таблице относится к сборкам и переходным архивам, которые содержат эту DLL.
