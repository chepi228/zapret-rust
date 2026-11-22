use serde_json::json;
use zapret_platform::command;

#[test]
fn read_only_status_does_not_create_runtime() {
    let d = tempfile::tempdir().unwrap();
    let before = std::fs::read_dir(d.path()).unwrap().count();
    let s = command(d.path(), "status", &json!({})).unwrap();
    assert!(s["running"].is_boolean());
    assert!(s["processes"].is_array());
    assert_eq!(before, std::fs::read_dir(d.path()).unwrap().count());
}
#[test]
fn network_context_has_stable_hash_and_no_passwords() {
    let d = tempfile::tempdir().unwrap();
    let a = command(d.path(), "network", &json!({})).unwrap();
    let b = command(d.path(), "network", &json!({})).unwrap();
    assert_eq!(a["known"], true);
    assert_eq!(a["key"], b["key"]);
    assert_eq!(a["key"].as_str().unwrap().len(), 64);
    assert!(!d.path().join("runtime").exists());
}
#[test]
fn hosts_edit_preserves_bom_newlines_unrelated_and_gamepins_and_has_backup() {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir(d.path().join("lists")).unwrap();
    std::fs::write(
        d.path().join("lists/hosts-flowseal.txt"),
        "140.82.112.3 github.com\n149.154.167.99 telegram.org\n",
    )
    .unwrap();
    let h = d.path().join("hosts");
    let old = "\u{feff}# keep me\r\n127.0.0.1 localhost\r\n# zapret: серверы игр - начало (меню: Проверка обходов)\r\n1.2.3.4 api.quago.io\r\n# zapret: серверы игр - конец\r\n9.9.9.9 github.com\r\n";
    std::fs::write(&h, old).unwrap();
    let result = command(
        d.path(),
        "hosts-set",
        &json!({"path":h,"groups":["GitHub"],"flush_dns":false}),
    )
    .unwrap();
    let after = std::fs::read_to_string(&h).unwrap();
    assert!(after.starts_with('\u{feff}'));
    assert!(after.contains("\r\n"));
    assert!(after.contains("1.2.3.4 api.quago.io"));
    assert!(after.contains("# keep me"));
    assert!(after.contains("140.82.112.3 github.com"));
    assert!(!after.contains("9.9.9.9 github.com"));
    assert!(!after.contains("telegram.org"));
    assert_eq!(
        std::fs::read_to_string(result["backup"].as_str().unwrap()).unwrap(),
        old
    );
}
#[test]
fn hosts_rejects_unknown_group_before_any_write() {
    let d = tempfile::tempdir().unwrap();
    let h = d.path().join("hosts");
    std::fs::write(&h, "127.0.0.1 localhost\n").unwrap();
    assert!(
        command(
            d.path(),
            "hosts-set",
            &json!({"path":h,"groups":["all\nmalicious"],"flush_dns":false})
        )
        .is_err()
    );
    assert_eq!(std::fs::read_to_string(h).unwrap(), "127.0.0.1 localhost\n");
}
#[test]
fn telegram_configuration_preserves_fields_or_defers_during_games() {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(d.path().join("runtime/tgws/TgWsProxy")).unwrap();
    std::fs::write(
        d.path().join("runtime/tgws/TgWsProxy/config.json"),
        r#"{"host":"0.0.0.0","pool_size":17,"custom":{"x":true},"autostart":true}"#,
    )
    .unwrap();
    let path = d.path().join("runtime/tgws/TgWsProxy/config.json");
    let before = std::fs::read(&path).unwrap();
    let result = command(
        d.path(),
        "telegram-config",
        &json!({"port":1443,"secret":"123456789abcdef0123456789abcdef0"}),
    );
    // This public control route deliberately observes the actual game guard.
    // The config transformation is also covered without machine state by the
    // prepare_config unit tests in telegram.rs.
    let s = match result {
        Ok(saved) => saved,
        Err(error) => {
            assert!(
                error
                    .to_string()
                    .starts_with("Действие отложено: запущена игра ("),
                "unexpected configuration failure: {error:#}"
            );
            assert_eq!(std::fs::read(&path).unwrap(), before);
            assert!(!d.path().join("runtime/telegram.txt").exists());
            return;
        }
    };
    assert_eq!(s["port"], 1443);
    let saved: serde_json::Value = serde_json::from_slice(
        &std::fs::read(d.path().join("runtime/tgws/TgWsProxy/config.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(saved["host"], "127.0.0.1");
    assert_eq!(saved["pool_size"], 17);
    assert_eq!(saved["custom"]["x"], true);
    assert_eq!(saved["autostart"], false);
    assert_eq!(saved["check_updates"], false);
}
#[test]
fn process_metrics_rejects_reused_pid_identity() {
    let identity = zapret_platform::process_identity(std::process::id()).unwrap();
    let d = tempfile::tempdir().unwrap();
    let row = command(d.path(), "process-metrics", &json!({"identity":identity})).unwrap();
    assert_eq!(row["ready"], true);
    assert_eq!(row["pid"], std::process::id());
    assert!(row["working_set_bytes"].as_u64().unwrap() > 0);
    let mut wrong = identity;
    wrong.created_filetime += 1;
    assert!(command(d.path(), "process-metrics", &json!({"identity":wrong})).is_err());
}
#[test]
fn generated_task_quotes_unicode_root_and_preserves_native_worker_arguments() {
    let d = tempfile::tempdir().unwrap();
    let root = d.path().join("пакет & пробел");
    std::fs::create_dir_all(root.join("bin")).unwrap();
    std::fs::write(root.join("bin/zapret-rust.exe"), b"fixture: not executed").unwrap();
    std::fs::write(
        root.join("bin/zapret-rust-worker.exe"),
        b"GUI fixture: not executed",
    )
    .unwrap();
    for kind in ["autotune", "notify", "telegram", "watch"] {
        let out = command(&root, "task-spec", &json!({"kind":kind})).unwrap();
        let xml = out["xml"].as_str().unwrap();
        let doc = roxmltree::Document::parse(xml).unwrap();
        let text = doc
            .descendants()
            .find(|n| n.has_tag_name("Arguments"))
            .unwrap()
            .text()
            .unwrap();
        assert!(text.contains("--root"));
        assert!(text.contains("пакет & пробел"));
        assert!(!text.contains("powershell"));
        let executable = doc
            .descendants()
            .find(|n| n.has_tag_name("Command"))
            .unwrap()
            .text()
            .unwrap();
        let binary = if ["notify", "telegram"].contains(&kind) {
            "zapret-rust-worker.exe"
        } else {
            "zapret-rust.exe"
        };
        assert_eq!(
            std::path::Path::new(executable),
            root.join("bin").join(binary)
        );
        assert!(!text.contains("--headless") && !text.contains("conhost"));
        if kind == "watch" {
            assert!(xml.contains("<BootTrigger>"));
            assert!(xml.contains("<UserId>S-1-5-18</UserId>"));
        }
        let logon = doc.descendants().find(|n| n.has_tag_name("LogonType"));
        if ["watch", "autotune"].contains(&kind) {
            // ServiceAccount is an API enum, not a valid Task Scheduler XML value.
            assert!(logon.is_none(), "SYSTEM tasks must omit XML LogonType");
        } else {
            assert_eq!(logon.unwrap().text(), Some("InteractiveToken"));
        }
        assert_eq!(
            doc.descendants()
                .find(|n| n.has_tag_name("AllowHardTerminate"))
                .unwrap()
                .text(),
            Some("true")
        );
    }
}
#[test]
fn malformed_telegram_secret_cannot_change_existing_configuration() {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir(d.path().join("runtime")).unwrap();
    let path = d.path().join("runtime/telegram.txt");
    std::fs::write(
        &path,
        "port=1443\nsecret=123456789abcdef0123456789abcdef0\n",
    )
    .unwrap();
    let old = std::fs::read(&path).unwrap();
    assert!(
        command(
            d.path(),
            "telegram-config",
            &json!({"secret":"bad\nport=1"})
        )
        .is_err()
    );
    assert_eq!(std::fs::read(path).unwrap(), old);
}
#[test]
fn trace_guard_rejects_foreign_output_and_session_names_without_starting_etw() {
    let d = tempfile::tempdir().unwrap();
    let root = d.path();
    let parent = zapret_platform::process_identity(std::process::id()).unwrap();
    assert!(command(root,"trace-guard",&json!({"session":"foreign-session","path":root.join("trace.etl"),"parent":parent,"max_seconds":1})).is_err());
    assert!(command(root,"trace-guard",&json!({"session":"zapretNative-0123456789abcdef0123456789abcdef","path":"C:/Windows/trace.etl","parent":parent,"max_seconds":1})).is_err());
    assert_eq!(std::fs::read_dir(root).unwrap().count(), 0);
}
#[test]
fn wifi_event_empty_scope_and_invalid_id_never_write_state() {
    let directory = tempfile::tempdir().unwrap();
    let result = command(
        directory.path(),
        "wifi-events",
        &json!({"interface_ids":[]}),
    )
    .unwrap();
    assert_eq!(result["known"], true);
    assert_eq!(result["last_disconnect_unix"], serde_json::Value::Null);
    assert_eq!(result["sequence"], 0);
    for ids in [
        json!(["invalid"]),
        json!(["00000000000000000000000000000000"]),
        json!(vec!["11111111111111111111111111111111"; 17]),
    ] {
        assert!(
            command(
                directory.path(),
                "wifi-events",
                &json!({"interface_ids":ids})
            )
            .is_err()
        );
    }
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}
#[test]
fn tcp_connections_attributes_own_loopback_listener_to_exact_process_identity() {
    let directory = tempfile::tempdir().unwrap();
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let expected = zapret_platform::process_identity(std::process::id()).unwrap();
    let result = command(directory.path(), "tcp-connections", &json!({})).unwrap();
    assert_eq!(result["family"], "IPv4");
    let row = result["connections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| {
            row["pid"] == std::process::id()
                && row["local_address"] == "127.0.0.1"
                && row["local_port"] == port
        })
        .unwrap_or_else(|| {
            panic!(
                "owned loopback fixture listener port {port}; own rows: {:?}",
                result["connections"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|row| row["pid"] == std::process::id())
                    .collect::<Vec<_>>()
            )
        });
    assert_eq!(
        serde_json::from_value::<zapret_platform::ProcessIdentity>(row["identity"].clone())
            .unwrap(),
        expected
    );
    assert_eq!(
        row["state_known"],
        json!(
            row["state"]
                .as_u64()
                .is_some_and(|state| (1..=12).contains(&state))
        )
    );
    if row["state_known"] == true {
        assert_eq!(row["state"], 2);
    }
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}
