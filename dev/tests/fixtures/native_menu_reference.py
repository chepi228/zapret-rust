"""Read-only menu presentation checks through the real BAT launcher.

Only menu-preview, --version and test --last are executed. The interactive
menu has startup side effects and is deliberately never launched here.
Navigation/pause replay belongs to the interactive menu harness or the
explicitly authorized live-navigation check, not to a duplicate state machine.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import zipfile


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    archive = args.archive.resolve()
    passed = []

    def check(condition, label):
        if not condition:
            raise AssertionError(label)
        passed.append(label)
        print("ok", label, flush=True)

    with tempfile.TemporaryDirectory(prefix="zapret-rust-menu-") as temporary:
        # Copy only the launcher and native controller. There is deliberately
        # no engine, driver, Telegram payload or source runtime in this fixture.
        root = Path(temporary) / "пакет с пробелами"
        with zipfile.ZipFile(archive) as package:
            for relative in ("zapret-rust.bat", "bin/zapret-rust.exe", "bin/zapret-rust-recovery.exe"):
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(package.read("zapret-rust/" + relative))
        launcher = root / "zapret-rust.bat"
        launcher_text = launcher.read_text(encoding="utf-8-sig")
        launch_lines = [line.strip() for line in launcher_text.splitlines()
                        if line.lstrip().startswith('"%~dp0bin\\')]
        check(len(launch_lines) == 2 and all(
            re.fullmatch(r'"%~dp0bin\\zapret-rust(?:-recovery)?\.exe" --root "%~dp0\." %\*', line)
            for line in launch_lines
        ), "fixture launcher forwards the fixed read-only command arguments")

        system = Path(os.environ["SystemRoot"])

        def run(command, *, architecture="System32", expected=0):
            # Reject an accidental interactive/action command before it can
            # reach cmd.exe. Callers below use only this small read-only set.
            valid = (command == ["--version"]
                     or command[:1] == ["menu-preview"]
                     or command == ["test", "--last"]
                     or command == ["--json", "test", "--last"]
                     or command in (["status"], ["service", "status"], ["task", "status", "notify"],
                                    ["task", "status", "autotune"], ["telegram", "status"]))
            if not valid:
                raise AssertionError("interactive or mutating command in read-only menu test")
            result = subprocess.run(
                [str(system / architecture / "cmd.exe"), "/d", "/c", str(launcher), *command],
                cwd=root, capture_output=True, timeout=15,
            )
            if result.returncode != expected:
                raise AssertionError(
                    f"{command}: exit {result.returncode}\n"
                    + result.stderr.decode("utf-8", errors="replace")[:2000]
                )
            return result

        for architecture in ("System32", "SysWOW64"):
            version = run(["--version"], architecture=architecture)
            check(version.stdout.decode("utf-8").strip().startswith("zapret-rust "),
                  architecture + " BAT route starts the native application")

        for screen, last_key in (("main", 9), ("settings", 11), ("tools", 12), ("test", 5)):
            for width in (55, 80):
                result = run(["menu-preview", "--screen", screen, "--width", str(width), "--height", "16"])
                text = result.stdout.decode("utf-8")
                expected_width = min(max(width - 4, 1), 74) + 2
                check(text.startswith("╭") and "\x1b" not in text
                      and all(len(line) == expected_width for line in text.splitlines())
                      and all(f" {key:>2}  " in text for key in range(last_key + 1)),
                      f"{screen} preview at {width} columns keeps all actions and aligned plain borders")
        check(not (root / "runtime").exists(), "all menu previews leave runtime uninitialized")

        runtime = root / "runtime"
        runtime.mkdir()
        settings_path = runtime / "settings.ini"
        settings_path.write_bytes(b"alt=12\r\nauto=off\r\nnotify=off\r\nFutureSetting=keep\r\n")
        settings_before = settings_path.read_bytes()
        binary_before = digest(root / "bin/zapret-rust.exe")
        saved_path = runtime / "test-native-last.json"

        def fixture():
            # Current settings deliberately differ from the historical primary.
            # A cached result must not imply that strategy 50 is still active.
            return {
                "schema": 1, "run_id": "cached-result-fixture", "best": {"id": "52", "score": 48.5, "total": 54},
                "rows": [{"id": "52", "score": 48.5, "total": 54}, {"id": "50", "score": 46, "total": 54}],
                "availability": {"52": {"ok": 49, "total": 54}, "50": {"ok": 48, "total": 54}},
                "strategy_names": {"52": "ALT11 белый 3", "50": "ALT11 белый 1"},
                "primary": "50", "primary_changed": False, "accepted": False, "quality_eligible": True,
                "startup": {"running": True, "restored": False},
                "native_identity": "must-not-be-shown", "journal": "C:/internal/fixture.jsonl",
            }

        def cached(report):
            encoded = json.dumps(report, ensure_ascii=False).encode("utf-8")
            saved_path.write_bytes(encoded)
            structured = json.loads(run(["--json", "test", "--last"]).stdout)
            check(structured == report, "cached JSON preserves the exact measured record")
            text = run(["test", "--last"]).stdout.decode("utf-8")
            check(text.startswith("╭") and "ALT11 белый 3" in text
                  and not any(key in text for key in ("must-not-be-shown", "C:/internal/", '"quality_eligible"', '"native_identity"')),
                  "cached human result shows names and hides internal fields")
            check(settings_path.read_bytes() == settings_before and saved_path.read_bytes() == encoded,
                  "viewing cached results preserves settings and immutable measurements")
            return text

        text = cached(fixture())
        check("49/54" in text and "48,5" in text, "real responses remain separate from localized ranking score")
        check(re.search(r"последн|сохранённ|предыдущ|прошл", text, re.IGNORECASE) is not None,
              "cached result is explicitly identified as historical")
        check("Основная изменена" not in text,
              "viewing a different historical primary never claims a current setting change")

        unstable = fixture()
        unstable["quality_eligible"] = False
        text = cached(unstable)
        check("нестабил" in text.lower() and "не примен" in text.lower()
              and "Основная изменена" not in text,
              "unstable measurements are not presented as an applied recommendation")

        restored = fixture()
        restored["startup"]["restored"] = True
        text = cached(restored)
        check("восстановлен" in text.lower() and "Основная изменена" not in text,
              "restored fallback is distinct from applying the highest scoring strategy")

        failed = fixture()
        failed["validation_error"] = "Hetzner: TLS reset"
        text = cached(failed)
        check("Лидер отдельного теста" in text and "Рекомендация:" not in text
              and "Hetzner: TLS reset" in text,
              "a rejected historical trial leader is never advertised as a working recommendation")

        fallback = fixture()
        fallback.update(trial_best={"id": "52"}, best={"id": "50", "score": 46},
                        recommendation_status="confirmed", choice="kept",
                        final_checks={"52": {"confirmed": False, "error": "Hetzner: TLS reset"},
                                      "50": {"confirmed": True, "error": None}})
        text = cached(fallback)
        check("Рекомендация: ALT11 белый 1" in text and "ФИНАЛ НЕ ПРОЙДЕН" in text
              and "Лидер отдельного теста: ALT11 белый 3" in text
              and "Основная изменена" not in text,
              "a verified fallback is distinct from a rejected leader and preserves the recorded primary")

        compact = fixture()
        compact.update(presentation="compact",accepted=True,primary_changed=True,primary="52",
                       elapsed_ms=95000,recommendation_status="confirmed",
                       final_checks={"52":{"confirmed":True}},
                       startup={"requested":False,"reason":"BypassWasStopped"})
        text=cached(compact)
        check("ПРИМЕНЕНО: ALT11 белый 3" in text and "1 мин 35 с" in text
              and "Обход выключен" in text and len(text.splitlines())<=20,
              "compact saved outcome names the strategy and distinguishes it from a stopped bypass")

        compact["accepted"]=False
        compact["primary_changed"]=False
        compact["primary"]="50"
        compact["validation_error"]="Финальная комбинация не подтвердила DPI/Hetzner: FAIL, TCP 30 мс, TLS 0 мс"
        compact["final_checks"]={"52":{"confirmed":False}}
        text=cached(compact)
        check("НЕ ПРИМЕНЕНО: ALT11 белый 1" in text and "Hetzner" in text and "TLS 0 мс" not in text,
              "compact rejection exposes one reason and the retained primary without raw failure spam")

        balanced = fixture()
        balanced.update(presentation="compact",selection_policy="availability-then-paired-connections-v1",
                        accepted=True,primary_changed=True,best={"id":"50"},primary="50",
                        connection_selection={"reference":"52","candidate":"50","confirmed":True,
                            "working":{"scope":"GameServices","targets":4,"gain_ms":30,
                                       "reference_tcp_ms":60,"candidate_tcp_ms":40,
                                       "reference_tls_ms":80,"candidate_tls_ms":60}})
        text=cached(balanced)
        check("быстрее на ~30 мс" in text and "TCP 40 / TLS 60 мс" in text
              and "игровой пинг не измерялся" in text,
              "confirmed connection advantage displays comparable game-service timings without claiming game ping")
        balanced["connection_selection"]["confirmed"]=False
        text=cached(balanced)
        check("быстрее на ~30 мс" not in text,
              "an unconfirmed timing advantage is never presented as a faster game connection")

        balanced.update(selection_policy="availability-then-full-request-latency-v2",
                        connection_selection={"reference":"52","candidate":"50","confirmed":True,
                            "working":{"scope":"AllTargets","targets":50,"gain_ms":40,
                                       "reference_tcp_ms":60,"candidate_tcp_ms":40,
                                       "reference_tls_ms":80,"candidate_tls_ms":60,
                                       "reference_total_ms":240,"candidate_total_ms":200,
                                       "reference_p95_ms":450,"candidate_p95_ms":400}})
        text=cached(balanced)
        check("полный запрос быстрее на ~40 мс" in text and "адресов: 50" in text
              and "всего 200 мс" in text and "400 мс" in text and "к 2K/EAC" not in text,
              "full request latency includes every target group and shows totals and P95")
        balanced["connection_selection"]["confirmed"]=False
        text=cached(balanced)
        check("полный запрос быстрее" not in text,
              "an unconfirmed full request advantage is not presented as measured improvement")

        for command in (["status"], ["service", "status"], ["task", "status", "notify"],
                        ["task", "status", "autotune"], ["telegram", "status"]):
            response = run(command)
            output = response.stdout.decode("utf-8").strip()
            check(output and not output.startswith(("{", "["))
                  and not any(key in output for key in ('"xml":', '"arguments":', '"processes":', '"config_hash":')),
                  "read-only " + " ".join(command) + " has human output without machine fields")
        saved_path.unlink()
        missing = run(["test", "--last"], expected=1)
        check("Результатов ещё нет" in missing.stderr.decode("utf-8"),
              "missing history has a readable error and does not start a selection")
        invalid = fixture()
        invalid["schema"] = 999
        saved_path.write_text(json.dumps(invalid), encoding="utf-8")
        malformed = run(["test", "--last"], expected=1)
        check("повреждён" in malformed.stderr.decode("utf-8").lower(),
              "unsupported cached schema has a readable error")
        saved_path.write_bytes(b"{broken")
        malformed = run(["test", "--last"], expected=1)
        check("повреждён" in malformed.stderr.decode("utf-8").lower(),
              "malformed cached JSON has a readable error")
        check(settings_path.read_bytes() == settings_before
              and digest(root / "bin/zapret-rust.exe") == binary_before
              and not any((runtime / name).exists() for name in (
                  "native-engine.json", "manual-stop.txt", "test-restore-pending.txt")),
              "read-only BAT routes leave engine intent and controller unchanged")

    report = {"passed": passed, "count": len(passed), "archive_sha256": digest(archive),
              "live_changes": False, "interactive_navigation": "NotExecuted"}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"PASS {len(passed)} read-only BAT menu checks", flush=True)


if __name__ == "__main__":
    main()
