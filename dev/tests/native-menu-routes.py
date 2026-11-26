"""Exercise every numbered native menu route with isolated platform effects."""

import argparse
import codecs
import json
import os
from pathlib import Path
from queue import Empty, Queue
import subprocess
from tempfile import TemporaryDirectory, gettempdir
from threading import Thread
from time import monotonic
from zipfile import ZipFile

CHOICE = "Выбор:"
PAUSE = "Enter — продолжить:"
CONFIRM = "[y/n]"
STRATEGY = "Номер или код стратегии:"


class Menu:
    def __init__(self, command, root):
        self.process = subprocess.Popen(
            command, cwd=root, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, creationflags=subprocess.CREATE_NO_WINDOW,
        )
        self.chunks = Queue()
        self.transcript = ""
        self.cursor = 0
        Thread(target=self.read, daemon=True).start()

    def read(self):
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        try:
            while data := os.read(self.process.stdout.fileno(), 8192):
                self.chunks.put(decoder.decode(data))
            self.chunks.put(decoder.decode(b"", final=True))
        finally:
            self.chunks.put(None)

    def expect(self, prompt, required="", timeout=15):
        deadline = monotonic() + timeout
        while (index := self.transcript.find(prompt, self.cursor)) < 0:
            try:
                chunk = self.chunks.get(timeout=max(0, deadline - monotonic()))
            except Empty:
                raise AssertionError(f"Missing prompt {prompt!r}") from None
            if chunk is None:
                raise AssertionError(f"Menu closed before {prompt!r}")
            self.transcript += chunk
        segment = self.transcript[self.cursor:index + len(prompt)]
        self.cursor = index + len(prompt)
        assert required.casefold() in segment.casefold(), (prompt, required)
        return segment

    def send(self, key, prompt=CHOICE, required=""):
        self.process.stdin.write((key + "\n").encode())
        self.process.stdin.flush()
        if prompt:
            return self.expect(prompt, required)
        return ""

    def events(self, start):
        return [
            json.loads(line.split("FIXTURE ", 1)[1])
            for line in self.transcript[start:self.cursor].splitlines()
            if "FIXTURE " in line
        ]

    def finish(self):
        self.send("0", None)
        assert self.process.wait(timeout=10) == 0

    def close(self):
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait(timeout=10)


def expected(action, **arguments):
    return {"action": action, "arguments": arguments}


def setting(*changes):
    return {"action": "settings", "arguments": [list(change) for change in changes]}


def test_selection(**options):
    return expected("test", **{
        "apply": False, "full": False, "webcheck": False, "last": False,
        "compare_a": None, "compare_b": None,
    } | options)


def network(action):
    return expected(action, urls=[], timeout_ms=5000, args=None)


def exercise(menu, root, results):
    def confirm_events(name, start, *events):
        actual = menu.events(start)
        assert actual == list(events), (name, actual, events)
        results.append(name)

    def leaf(name, key, event, required="", next_screen=""):
        start = menu.cursor
        menu.send(key, PAUSE, required)
        confirm_events(name, start, event)
        menu.send("", CHOICE, next_screen)

    menu.expect(CHOICE, "ГЛАВНАЯ")
    assert expected("first-run") in menu.events(0)
    results.append("Первый запуск · подготовка до ввода")
    leaf("Главная T · запись входа в NBA City", "T", expected("track", process="NBA2K*", seconds=120), required="Файл для передачи")
    leaf("Главная 1 · запуск", "1", expected("start"), next_screen="Обход запущен")
    leaf("Главная 1 · перезапуск", "1", expected("restart"), next_screen="Обход запущен")
    leaf("Главная 2 · остановка", "2", expected("stop-all"), next_screen="Обход остановлен")
    menu.send("?", PAUSE, "Нет такого пункта меню")
    menu.send("", CHOICE, "ГЛАВНАЯ")
    results.append("Главная · ошибочный ввод и возврат")

    for key, label, options in [
        ("1", "быстрый подбор", {"apply": True}),
        ("2", "все стратегии", {"apply": True, "full": True}),
        ("3", "подбор с браузером", {"apply": True, "webcheck": True}),
        ("5", "история", {"last": True}),
    ]:
        menu.send("3", CHOICE, "Автоподбор стратегии")
        leaf(f"Автоподбор {key} · {label}", key, test_selection(**options), next_screen="ГЛАВНАЯ")
    menu.send("3", CHOICE)
    start = menu.cursor
    menu.send("4", STRATEGY, "ПЕРВАЯ")
    menu.send("1", STRATEGY, "ВТОРАЯ")
    menu.send("2", PAUSE)
    events = menu.events(start)
    assert len(events) == 1
    options = events[0]["arguments"]
    assert isinstance(options["compare_a"], str) and isinstance(options["compare_b"], str)
    assert options["compare_a"] != options["compare_b"]
    confirm_events("Автоподбор 4 · сравнение", start,
                   test_selection(compare_a=options["compare_a"], compare_b=options["compare_b"]))
    menu.send("", CHOICE, "ГЛАВНАЯ")
    menu.send("3", CHOICE)
    menu.send("0", CHOICE, "ГЛАВНАЯ")
    results.append("Автоподбор 0 · возврат")

    menu.send("4", CHOICE, "МОСТ TELEGRAM")
    leaf("Telegram 1 · старт", "1", expected("telegram-start", port=None), next_screen="ГЛАВНАЯ")
    menu.send("4", CHOICE)
    start = menu.cursor
    menu.send("3", "Новый порт")
    menu.send("24443", CONFIRM, "перезапустив мост")
    menu.send("y", PAUSE)
    confirm_events("Telegram 3 · порт и подтверждение перезапуска", start,
                   expected("telegram-config", port=24443), expected("telegram-start", port=None))
    menu.send("", CHOICE)
    menu.send("4", CHOICE)
    leaf("Telegram 2 · остановка", "2", expected("telegram-stop", port=None), next_screen="ГЛАВНАЯ")
    menu.send("4", CHOICE)
    menu.send("0", CHOICE, "ГЛАВНАЯ")
    results.append("Telegram 0 · возврат")

    start = menu.cursor
    menu.send("5", STRATEGY)
    menu.send("N", STRATEGY, "Страница 2 ")
    menu.send("P", STRATEGY, "Страница 1 ")
    menu.send("1", PAUSE)
    selected = menu.events(start)[0]["arguments"][0][1]
    confirm_events("Главная 5 · страницы и выбор стратегии", start, setting(("alt", selected)))
    menu.send("", CHOICE)
    start = menu.cursor
    menu.send("5", STRATEGY, "MIX-SPLIT")
    menu.send("white-03", PAUSE)
    confirm_events("Главная 5 · выбор по коду", start, setting(("alt", "52")))
    menu.send("", CHOICE, "WHITE-03")
    start = menu.cursor
    menu.send("6", CONFIRM, "hosts")
    menu.send("y", CONFIRM, "IPv4")
    menu.send("y", PAUSE)
    confirm_events("Главная 6 · диагностика и обе правки", start,
                   expected("pc-check"), expected("hosts-set", enabled=True), expected("prefer-ipv4", enabled=True))
    menu.send("", CHOICE)
    leaf("Главная 9 · уведомления", "9", expected("notices"), "Тестовое уведомление", "ГЛАВНАЯ")

    menu.send("7", CHOICE, "НАСТРОЙКИ")
    start = menu.cursor
    menu.send("1", STRATEGY)
    menu.send("alt11 БЕЛЫЙ 1", PAUSE)
    confirm_events("Настройки 1 · прежнее имя стратегии", start, setting(("alt", "50")))
    menu.send("", CHOICE, "WHITE-01")
    leaf("Настройки 2 · автосмена", "2", setting(("auto", "off")))
    for key, changes in [
        ("1", (("game", "all"), ("gametcp", "1024-65535"), ("gameudp", "1024-65535"))),
        ("2", (("game", "all"), ("gametcp", "20000-27200"), ("gameudp", "27000-27200,30000-30100"))),
        ("3", (("game", "tcp"),)), ("4", (("game", "udp"),)), ("6", (("game", "off"),)),
    ]:
        menu.send("3", CHOICE, "ФИЛЬТР ИГРЫ")
        leaf(f"Настройки 3 → {key} · фильтр игры", key, setting(*changes))
    menu.send("3", CHOICE)
    start = menu.cursor
    menu.send("5", "TCP-порты")
    menu.send("20001-20010", "UDP-порты")
    menu.send("30001-30010", PAUSE)
    confirm_events("Настройки 3 → 5 · свои порты", start, setting(
        ("game", "all"), ("gametcp", "20001-20010"), ("gameudp", "30001-30010")))
    menu.send("", CHOICE)
    for key, mode in [("1","loaded"),("2","any"),("3","none")]:
        menu.send("4", CHOICE, "IP-списки")
        leaf(f"Настройки 4 → {key} · IPSet", key, setting(("ipset", mode)))
    for key, mode in [("1","on"),("2","off")]:
        menu.send("5", CHOICE, "АВТОСПИСОК")
        leaf(f"Настройки 5 → {key} · автосписок", key, setting(("autolist", mode)))
    menu.send("5", CHOICE)
    menu.send("3", CONFIRM, "Очистить")
    menu.send("y", PAUSE, "Автосписок очищен")
    assert "fixture.example" not in (root / "lists/autohostlist.txt").read_text(encoding="utf-8")
    results.append("Настройки 5 → 3 · очистка автосписка")
    menu.send("", CHOICE)
    leaf("Настройки 6 · автозапуск", "6", expected("service-autostart"))
    leaf("Настройки 7 · расписание", "7", expected("task-configure", kind="autotune"))
    leaf("Настройки 8 · списки", "8", expected("lists", update=True))
    start = menu.cursor
    menu.send("9", CONFIRM, "Установить доступное обновление")
    menu.send("y", PAUSE)
    confirm_events("Настройки 9 · проверка и установка обновления", start,
                   expected("update", install=False, sha256=None, recover=False, **{"from": None}),
                   expected("update", install=True, sha256=None, recover=False, **{"from": None}))
    menu.send("", CHOICE)
    leaf("Настройки 10 · уведомления Windows", "10", expected("task-configure", kind="notify"))
    start = menu.cursor
    menu.send("11", CONFIRM, "Удалить")
    menu.send("y", PAUSE)
    confirm_events("Настройки 11 · удаление", start, expected("uninstall"))
    menu.send("", CHOICE)
    menu.send("0", CHOICE, "ГЛАВНАЯ")
    results.append("Настройки 0 · возврат")

    menu.send("8", CHOICE, "ИНСТРУМЕНТЫ")
    start = menu.cursor
    menu.send("1", "Имя EXE (")
    menu.send("fixture.exe", PAUSE)
    confirm_events("Инструменты 1 · трекер", start, expected("track", process="fixture.exe", seconds=60))
    menu.send("", CHOICE)
    start = menu.cursor
    menu.send("2", "Имя EXE (")
    menu.send("fixture.exe", CONFIRM)
    menu.send("y", PAUSE)
    confirm_events("Инструменты 2 · сканер", start, expected("scan", process="fixture.exe", seconds=60, apply=True))
    menu.send("", CHOICE)
    leaf("Инструменты 3 · провайдер", "3", network("provider-check"))
    leaf("Инструменты 4 · отчёт", "4", expected("report", output=None))
    for key, question, action in [
        ("5", "диагностический обход", expected("diag", run=True, seconds=60)),
        ("6", "исключения", expected("exclude", apply=True)),
        ("8", "Discord", expected("discord-cache", args=None)),
    ]:
        start = menu.cursor
        menu.send(key, CONFIRM, question)
        menu.send("y", PAUSE)
        confirm_events(f"Инструменты {key} · подтверждение", start, action)
        menu.send("", CHOICE)
    leaf("Инструменты 7 · правила Happ", "7", expected("direct-rules", output=None))
    for key, action in [("9", "latency"), ("10", "webcheck"), ("11", "connection-check")]:
        leaf(f"Инструменты {key} · диагностика {action}", key, network(action))
    for key, audio in [("1","Both"),("2","OnlyReceive"),("3","OnlySend"),("4","None"),("","Unknown")]:
        start = menu.cursor
        menu.send("12", "Enter — начать")
        menu.send("", "Как работал звук во время наблюдения")
        menu.send(key, PAUSE)
        confirm_events(f"Инструменты 12 · звук {audio}", start,
                       network("voicecheck"), expected("publish", kind="voice", audio=audio))
        menu.send("", CHOICE)
    menu.send("0", CHOICE, "ГЛАВНАЯ")
    results.append("Инструменты 0 · возврат")
    menu.send("8", CHOICE, "ИНСТРУМЕНТЫ")
    (root / "runtime/settings.ini").write_text("alt=12\nauto=off\nnotify=off\n", encoding="utf-8")
    (root / "runtime/menu-status-fixture.json").write_text(
        json.dumps({"known": False, "ownership_known": False, "service": {"known": False}}),
        encoding="utf-8",
    )
    returned = menu.send("0", CHOICE, "Состояние обхода не подтверждено")
    assert "автосмена выкл" in returned
    results.append("Возврат на главную после изменения настроек и статуса из другого процесса")
    menu.finish()
    results.append("Главная 0 · выход")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    results = []
    report = {"cases": results, "windows_operations": "fixture"}
    temporary_parent = Path(gettempdir()).resolve()
    with TemporaryDirectory(prefix="zapret-menu-fixture-", dir=temporary_parent) as temporary:
        stage = Path(temporary)
        assert stage.resolve().parent == temporary_parent
        with ZipFile(args.archive.resolve()) as archive:
            archive.extractall(stage)
        root = stage / "zapret-rust"
        (root / "runtime/menu-fixture").touch()
        (root / "runtime/settings.ini").write_text("alt=12\nauto=on\nnotify=off\n", encoding="utf-8")
        (root / "lists/autohostlist.txt").write_text("fixture.example\n", encoding="utf-8")
        menu = Menu([args.fixture.resolve(), root], root)
        try:
            exercise(menu, root, results)
            report["status"] = "Passed"
        except Exception as error:
            report.update(status="Failed", error=str(error))
        finally:
            menu.close()
            args.output.with_suffix(".log").write_text(menu.transcript, encoding="utf-8")
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"{report['status']}: {len(results)} menu scenarios")
    return report["status"] != "Passed"


if __name__ == "__main__":
    raise SystemExit(main())
