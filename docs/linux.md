# Установка на Linux

Установщик релиза zapret rust 1.1 подготавливает upstream zapret2 v1.0.7 с Linux-движком `nfqws2`. В комплекте upstream есть сборки для нескольких архитектур. Конкретную сборку выбирает `install_bin.sh`. Нативный Rust-движок и меню этого проекта поставляются для Windows x64.

Нужны `sh`, `curl`, `tar`, `sha256sum` и доступ к GitHub. Интерактивная системная установка upstream требует прав администратора и настраивает службу и правила фильтрации. Поддерживаемые системы и способы запуска приведены в [документации zapret2](https://github.com/bol-van/zapret2/tree/v1.0.7#english).

1. Скачайте `zapret-rust-v1.1-linux-install.sh` и `SHA256SUMS.txt` из [релиза 1.1](https://github.com/chepi228/zapret-rust/releases/tag/v1.1).
2. В папке загрузок проверьте установщик.

   ```sh
   grep ' zapret-rust-v1.1-linux-install.sh$' SHA256SUMS.txt | sha256sum -c -
   ```

3. Запустите скрипт без `sudo`. Он сверит хеш upstream-архива и передаст управление штатному `install_easy.sh`. Ввод прав администратора, если потребуется, запросит сам upstream.

   ```sh
   sh zapret-rust-v1.1-linux-install.sh
   ```

Для подготовки Linux-бинарников без системной настройки используйте `sh zapret-rust-v1.1-linux-install.sh --prepare-only`. Скрипт создаст `zapret2-v1.0.7` в текущем каталоге. Системную настройку затем можно запустить через `sh zapret2-v1.0.7/install_easy.sh`.

Для удаления системной установки запустите `sh /opt/zapret2/uninstall_easy.sh` из стандартного каталога upstream. Если вы указали другой каталог при настройке, используйте `uninstall_easy.sh` оттуда.
