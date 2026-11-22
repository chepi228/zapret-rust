use std::{collections::BTreeMap, fs};
use zapret_core::*;

#[test]
fn unknown_ini_key_spelling_and_case_insensitive_access_survive_roundtrip() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("runtime")).unwrap();
    fs::write(
        root.path().join("runtime/settings.ini"),
        b"MiXeDCustom=roundtrip\r\n",
    )
    .unwrap();
    let settings = read_settings(root.path()).unwrap();
    assert!(settings.values.contains_key("MiXeDCustom"));
    assert_eq!(settings.get("mixedcustom"), "roundtrip");
    save_settings(root.path(), &settings).unwrap();
    assert!(
        fs::read_to_string(root.path().join("runtime/settings.ini"))
            .unwrap()
            .contains("MiXeDCustom=roundtrip\r\n")
    );
}
#[test]
fn custom_uppercase_profile_filenames_keep_the_legacy_windows_match() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("strategies")).unwrap();
    let mut text = String::from("# NAME: Custom profile\n");
    for name in SECTIONS {
        text.push_str(&format!("[{name}]\n--payload=all\n"));
    }
    fs::write(root.path().join("strategies/ALT901.TXT"), text).unwrap();
    let strategies = list_strategies(root.path()).unwrap();
    assert_eq!(strategies.len(), 1);
    assert_eq!(strategies[0].name, "Custom profile");
    assert_eq!(strategies[0].id, "901");
    fs::write(root.path().join("strategies/alt902.txt"), b"\xff").unwrap();
    assert_eq!(
        find_strategy(root.path(), "901").unwrap().unwrap(),
        strategies[0]
    );
    assert!(find_strategy(root.path(), "903").unwrap().is_none());
    assert!(find_strategy(root.path(), "../901").unwrap().is_none());
}

#[test]
fn installer_sidecars_do_not_invalidate_native_rank_context() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    for dir in [
        "bin",
        "tools",
        "lua",
        "fake",
        "lists",
        "strategies",
        "windivert",
    ] {
        fs::create_dir(root.join(dir)).unwrap();
    }
    for file in score_input_files(root).unwrap() {
        fs::write(root.join(file), b"fixture").unwrap();
    }
    let settings = Settings::default();
    let network = "A".repeat(64);
    let before = test_result_context(root, &settings, &network).unwrap();
    fs::write(
        root.join("bin/.native-build-0123456789abcdef0123456789abcdef.tmp.old"),
        b"retained image",
    )
    .unwrap();
    let with_sidecar = test_result_context(root, &settings, &network).unwrap();
    assert!(before.compatible(&with_sidecar));

    fs::write(root.join("bin/zapret-rust.exe"), b"updated controller").unwrap();
    let after_update = test_result_context(root, &settings, &network).unwrap();
    assert!(!before.compatible(&after_update));
}

#[test]
fn domains_and_ipsets_normalize_without_widening_or_accepting_paths() {
    assert_eq!(
        normalize_domain("  Пример.РФ. ").unwrap(),
        "xn--e1afmkfd.xn--p1ai"
    );
    for bad in [
        "https://example.com/a",
        "a..b",
        "*.example.org",
        "127.0.0.1",
        "[::1]",
        "--new=x",
        "a\nb",
    ] {
        assert!(normalize_domain(bad).is_err(), "{bad}");
    }
    assert_eq!(
        normalize_ip_network("203.0.113.17/24").unwrap(),
        "203.0.113.0/24"
    );
    assert_eq!(
        normalize_ip_network("2001:0db8::8/32").unwrap(),
        "2001:db8::/32"
    );
    assert_eq!(normalize_ip_network("8.8.8.8").unwrap(), "8.8.8.8/32");
    assert!(normalize_ip_network("::/129").is_err());
    for bad in [
        "10.0.0.1",
        "100.64.1.2",
        "127.0.0.1",
        "::1",
        "fc00::1",
        "ff02::1",
    ] {
        assert!(!is_public_ip(bad));
    }
    for good in ["8.8.8.8", "2606:4700:4700::1111"] {
        assert!(is_public_ip(good));
    }
}

#[test]
fn transfer_accepts_only_complete_or_intentionally_bounded_evidence() {
    assert_eq!(
        transfer_state("200", Some(0), 0., 10., false, false),
        ProbeState::Ok
    );
    assert_eq!(
        transfer_state("200", Some(28), 0., 10., false, false),
        ProbeState::Freeze
    );
    assert_eq!(
        transfer_state("200", Some(28), 0., 10., false, true),
        ProbeState::Ok
    );
    assert_eq!(
        transfer_state("000", Some(6), 0., 0., false, false),
        ProbeState::Na
    );
    assert_eq!(
        transfer_state("200", Some(60), 0., 10., false, true),
        ProbeState::Fail
    );
    assert_eq!(
        transfer_state("200", None, 0., 10., false, true),
        ProbeState::Fail
    );
}

#[test]
fn coverage_cannot_mix_runs_and_unscoped_history_stays_readable() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir_all(root.path().join("runtime")).unwrap();
    let context = TestResultContext {
        schema: 2,
        network_key: "A".repeat(64),
        inputs_hash: "B".repeat(64),
        run_id: "a".repeat(32),
    };
    let legacy = "base 0 3 DPI=0/3\r\n12 1.5 1.5 3 0 1 DPI=1.5/3\r\n";
    let mut rank = parse_rank(legacy, &["12".into()]).unwrap().unwrap();
    assert_eq!(rank.rows[0].score, 1.5);
    assert!(rank.context.is_none());
    fs::write(root.path().join("runtime/test-rank.txt"), legacy).unwrap();
    rank.context = Some(context.clone());
    save_rank(root.path(), &rank).unwrap();
    assert_eq!(
        fs::read_to_string(root.path().join("runtime/test-rank.txt.v1.bak")).unwrap(),
        legacy
    );
    let coverage = BTreeMap::from([("0".into(), vec![]), ("12".into(), vec!["DPI|a".into()])]);
    save_cover(root.path(), &coverage, &context).unwrap();
    assert_eq!(
        read_cover(root.path(), &rank, &context).unwrap(),
        Some(coverage.clone())
    );
    let mut another = context.clone();
    another.run_id = "b".repeat(32);
    save_cover(root.path(), &coverage, &another).unwrap();
    assert!(read_cover(root.path(), &rank, &context).unwrap().is_none());
    another.network_key = "C".repeat(64);
    assert!(!context.compatible(&another));
}

#[test]
fn missing_manifest_fails_integrity_instead_of_trusting_an_empty_set() {
    let root = tempfile::tempdir().unwrap();
    assert!(verify_package(root.path()).is_err());
}

#[test]
fn malformed_capture_set_falls_back_as_a_whole() {
    let lines = vec![
        "104.255.104.0/22".into(),
        "198.133.210.7/32 # one host".into(),
    ];
    let c = capture_exclusion(&lines).unwrap();
    assert_eq!(
        c.ip_argument,
        "--ipset-exclude-ip=104.255.104.0/22,198.133.210.7/32"
    );
    for bad in ["0.0.0.0/0", "1.2.3.4/24", "2001:db8::/32", "01.2.3.4/32"] {
        let mut lines = lines.clone();
        lines.push(bad.into());
        assert!(capture_exclusion(&lines).is_none(), "{bad}");
    }
}

#[test]
fn selected_primary_stays_first_when_quality_rank_has_five_other_candidates() {
    let all: Vec<_> = (1..=8)
        .map(|id| Strategy {
            id: id.to_string(),
            ..Default::default()
        })
        .collect();
    let rank = TestRank {
        date: None,
        version: "2.2".into(),
        base_ok: 0.,
        base_total: 54,
        base_groups: Default::default(),
        base_group_totals: Default::default(),
        rows: (1..=8)
            .map(|id| RankRow {
                id: id.to_string(),
                score: if id == 8 { 48.5 } else { 49. },
                ok: 49.,
                total: 54,
                ..Default::default()
            })
            .collect(),
        context: None,
    };
    let ring = rotation_order(&all, "8", "general", Some(&rank), None);
    assert_eq!(ring[0].id, "8");
    assert!(ring.len() <= 5);
}
