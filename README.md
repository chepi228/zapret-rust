# zapret rust 1.0

Обход DPI для YouTube и Discord с автоподбором стратегии под провайдера и встроенным локальным прокси для Telegram. Windows-сборка основана на [zapret2](https://github.com/bol-van/zapret2), стратегиях [Flowseal](https://github.com/Flowseal/zapret-discord-youtube) и [TG WS Proxy](https://github.com/Flowseal/tg-ws-proxy).

[Скачать релиз](https://github.com/chepi228/zapret-rust/releases/latest) · [Что нового](CHANGELOG.md) · [Связь](#связь) · [English](README.en.md)

## Скачать

| Система | Файлы |
| --- | --- |
| Windows 10/11 x64 | [ZIP](https://github.com/chepi228/zapret-rust/releases/download/v1.0/zapret-rust-native-v1.0.zip) · [RAR](https://github.com/chepi228/zapret-rust/releases/download/v1.0/zapret-rust-v1.0-windows-x64.rar) · [7z](https://github.com/chepi228/zapret-rust/releases/download/v1.0/zapret-rust-v1.0-windows-x64.7z) |
| Linux | [Установщик](https://github.com/chepi228/zapret-rust/releases/download/v1.0/zapret-rust-v1.0-linux-install.sh) на базе upstream zapret2 |

Все три архива Windows содержат одинаковые файлы. [Контрольные суммы SHA-256](https://github.com/chepi228/zapret-rust/releases/download/v1.0/SHA256SUMS.txt).

## Windows

1. Распакуйте архив и запустите `zapret-rust.bat`. Для управления обходом Windows запросит права администратора.
2. Выберите **6** для проверки подключения и **1** для запуска обхода.
3. Пункт **3** подбирает стратегию под провайдера. Пункт **5** позволяет выбрать её вручную.
4. Пункт **4** включает локальный прокси для Telegram. Автозапуск Windows настраивается через **7 → 6**, обновление доступно через **7 → 9**.

Автосмена запоминает рабочие варианты для разных сервисов. Результат зависит от провайдера и выбранной стратегии. Остальные пункты меню, диагностику и удаление описывает [руководство для Windows](https://github.com/chepi228/zapret-rust/blob/v1.0/docs/windows.md).

## Linux

Установщик с SHA-256 проверяет и распаковывает официальный [zapret2 v1.0.7](https://github.com/bol-van/zapret2/releases/tag/v1.0.7) и открывает его интерактивную настройку. Пункты меню и Rust-движок этой версии относятся к Windows.

Скачайте установщик, откройте терминал в папке с файлом и выполните:

```sh
sh zapret-rust-v1.0-linux-install.sh
```

Для подготовки файлов без запуска системной настройки добавьте `--prepare-only`. Требования и удаление описаны в [руководстве для Linux](https://github.com/chepi228/zapret-rust/blob/v1.0/docs/linux.md).

## Что дал переход на Rust

- Меню, диагностика, управление службами и Telegram работают из нативного приложения. Для запуска стандартной Windows-сборки достаточно распаковать архив.
- Стандартные стратегии встроены в пакетный движок. Пользовательские Lua-скрипты поддерживает Luna Core, интерпретатор на Rust.
- Проверка границ буферов и владения ресурсами помогает предотвращать ошибки при обработке пакетов и освобождении системных ресурсов.
- Автоподбор, откат обновления и обработку пакетов можно проверять офлайн на тестовых данных.

Собственный движок, контроллер, фоновый процесс, Telegram и ring штатной сборки Windows x64 написаны на Rust. Для работы она использует сторонний WinDivert и системные библиотеки Windows. [Сборка движка и варианты поставки](native/zapret-ring-ffi/README.md#native-windows-engine).

В репозитории также хранятся C-эталоны, тестовые скрипты и старые компоненты совместимости. Правила `.gitattributes` исключают эти файлы из диаграммы языков GitHub.

## Связь

Telegram [@chepi1](https://t.me/chepi1).

## Поддержать разработку

USDT в сети TRC-20  
`TM9NUBAggxULA56T4wYrTyxfQX4bPMjDM9`

## Исходники и лицензии

Код проекта распространяется по [MIT](LICENSE). У WinDivert, zapret2, компонентов Flowseal и остальных зависимостей свои условия. Они перечислены в [уведомлениях о сторонних компонентах](THIRD-PARTY-NOTICES.md).
