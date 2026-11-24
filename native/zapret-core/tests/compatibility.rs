use flate2::read::GzDecoder;
use serde::Deserialize;
use std::{collections::BTreeMap, fs, path::Path};
use zapret_core::{ComposeOptions, Settings, compose, read_settings, save_settings};

#[test]
fn legacy_defaults_and_unknown_settings_survive_atomic_roundtrip() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("runtime")).unwrap();
    fs::write(root.path().join("runtime/settings.ini"),"\u{feff}alt=11\r\ngame=wrong\r\nipset=wrong\r\ngametcp=0\r\nautolist=wrong\r\ncustom=Привет\r\nfuture_option=preserved\r\n").unwrap();
    let mut s = read_settings(root.path()).unwrap();
    assert_eq!(s.get("alt"), "11");
    assert_eq!(s.get("game"), "all");
    assert_eq!(s.get("ipset"), "loaded");
    assert_eq!(s.get("gametcp"), "1024-65535");
    assert_eq!(s.get("autolist"), "on");
    assert_eq!(s.get("future_option"), "preserved");
    assert!(s.set("gametcp", "65536").is_err());
    assert!(s.set("inject", "a\nb=c").is_err());
    s.set("gametcp", "20000-27200").unwrap();
    save_settings(root.path(), &s).unwrap();
    assert_eq!(read_settings(root.path()).unwrap().get("custom"), "Привет");
    let bytes = fs::read(root.path().join("runtime/settings.ini")).unwrap();
    assert!(!bytes.starts_with(&[0xef, 0xbb, 0xbf]));
    assert!(
        String::from_utf8(bytes)
            .unwrap()
            .contains("future_option=preserved\r\n")
    );
}

#[derive(Deserialize)]
struct LegacyComposition {
    files: BTreeMap<String, String>,
    cases: Vec<CompositionCase>,
    rank_context: zapret_core::TestResultContext,
    composition_key: String,
    score_files: Vec<String>,
}

#[derive(Deserialize)]
struct CompositionCase {
    name: String,
    settings: BTreeMap<String, String>,
    options: ComposeOptions,
    files: BTreeMap<String, String>,
    args: Vec<String>,
}

fn composition_fixture() -> LegacyComposition {
    serde_json::from_reader(GzDecoder::new(
        include_bytes!("fixtures/legacy-argv.json.gz").as_slice(),
    ))
    .unwrap()
}

fn write_fixture_files(root: &Path, files: &BTreeMap<String, String>) {
    for (name, contents) in files {
        let path = root.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }
}

#[test]
fn profile_composition_matches_frozen_legacy_arguments() {
    let fixture = composition_fixture();
    let temp = tempfile::tempdir().unwrap();
    assert!(!fixture.cases.is_empty());
    for case in fixture.cases {
        let pkg = temp
            .path()
            .join(case.name.as_str())
            .join("package with spaces");
        write_fixture_files(&pkg, &fixture.files);
        write_fixture_files(&pkg, &case.files);
        let settings = Settings {
            values: case.settings,
        };
        let mut options = case.options;
        options.debug_file = options.debug_file.map(|path| {
            pkg.join(
                path.to_str()
                    .unwrap()
                    .replace('/', std::path::MAIN_SEPARATOR_STR),
            )
        });
        let actual = compose(&pkg, &settings, &options)
            .unwrap_or_else(|error| panic!("{}: {error:#}", case.name));
        let package_prefix = format!("{}{}", pkg.display(), std::path::MAIN_SEPARATOR);
        let actual: Vec<_> = actual
            .into_iter()
            .map(|arg| {
                if arg.contains(&package_prefix) {
                    arg.replace(&package_prefix, "{package}/")
                        .replace('\\', "/")
                } else {
                    arg
                }
            })
            .collect();
        if actual != case.args {
            let mismatch = actual
                .iter()
                .zip(&case.args)
                .position(|(a, b)| a != b)
                .unwrap_or(actual.len().min(case.args.len()));
            panic!(
                "{} differs at argument {} (counts {} / {}): actual {:?}, expected {:?}",
                case.name,
                mismatch,
                actual.len(),
                case.args.len(),
                actual.get(mismatch),
                case.args.get(mismatch)
            );
        }
    }
}

#[test]
fn score_input_order_and_context_match_the_legacy_package() {
    let fixture = composition_fixture();
    let temp = tempfile::tempdir().unwrap();
    let pkg = temp.path();
    write_fixture_files(pkg, &fixture.files);
    assert_eq!(
        zapret_core::score_input_files(pkg).unwrap(),
        fixture.score_files
    );
    let ranked = fixture
        .cases
        .iter()
        .find(|case| case.name == "scoped-rank")
        .unwrap();
    let settings = Settings {
        values: ranked.settings.clone(),
    };
    assert_eq!(
        zapret_core::ring_composition_key(pkg, &settings).unwrap(),
        fixture.composition_key
    );
    write_fixture_files(pkg, &ranked.files);
    let context =
        zapret_core::test_result_context(pkg, &settings, &fixture.rank_context.network_key)
            .unwrap();
    assert!(context.compatible(&fixture.rank_context));
}

#[test]
fn pinned_composition_matches_disk_and_requires_every_digest_it_uses() {
    let fixture = composition_fixture();
    let case = fixture
        .cases
        .iter()
        .find(|c| c.name == "scoped-rank")
        .unwrap();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_fixture_files(root, &fixture.files);
    write_fixture_files(root, &case.files);
    let digests: BTreeMap<_, _> = fixture
        .files
        .keys()
        .chain(case.files.keys())
        .map(|name| {
            let path = root.join(name);
            let hash = zapret_core::sha256_file(&path).unwrap();
            (path, hash)
        })
        .collect();
    let mut pinned = digests
        .iter()
        .map(|(path, hash)| (path.clone(), hash.as_str()))
        .collect();
    let settings = Settings {
        values: case.settings.clone(),
    };
    let options = ComposeOptions {
        persistence: true,
        ..case.options.clone()
    };
    let expected = compose(root, &settings, &options).unwrap();
    assert_eq!(
        zapret_core::compose_with_pinned_hashes(root, &settings, &options, &pinned).unwrap(),
        expected
    );
    let missing = root.join("tools/upstream.txt");
    pinned.remove(&missing).unwrap();
    assert!(zapret_core::compose_with_pinned_hashes(root, &settings, &options, &pinned).is_err());
    let bytes = fs::read(&missing).unwrap();
    let mut changed = bytes;
    changed[0] ^= 1;
    fs::write(missing, changed).unwrap();
    assert_ne!(compose(root, &settings, &options).unwrap(), expected);
}

#[test]
fn selected_games_use_only_their_own_lists_on_game_ports() {
    let fixture = composition_fixture();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_fixture_files(root, &fixture.files);
    let mut settings = Settings {
        values: fixture.cases[0].settings.clone(),
    };
    settings.set("game", "selected").unwrap();
    settings.set("ipset", "any").unwrap();
    settings
        .set("gameapps", "NBA2K27.exe| Игра Test.EXE |nba2k27")
        .unwrap();
    let names = zapret_core::selected_game_names(settings.get("gameapps")).unwrap();
    assert_eq!(names, ["nba2k27", "игра test"]);
    for bad in [
        "game*",
        "../game.exe",
        "a||b",
        "game.exe.exe",
        "foo\\game",
        "foo:bar",
    ] {
        assert!(settings.set("gameapps", bad).is_err(), "{bad}");
    }
    zapret_core::prepare_runtime(root, &settings).unwrap();
    let nba = zapret_core::game_server_list(&names[0]);
    let other = zapret_core::game_server_list(&names[1]);
    let path = root.join("lists").join(&nba);
    assert!(
        fs::read_to_string(&path)
            .unwrap()
            .contains("203.0.113.113/32")
    );
    fs::write(&path, "8.8.8.8/32\n").unwrap();
    zapret_core::prepare_runtime(root, &settings).unwrap();
    assert_eq!(fs::read_to_string(&path).unwrap(), "8.8.8.8/32\n");
    let options = ComposeOptions {
        no_auto: true,
        persistence: false,
        ..Default::default()
    };
    let args = compose(root, &settings, &options).unwrap();
    for game in ["--new=game_tcp", "--new=game_udp"] {
        let at = args.iter().position(|arg| arg == game).unwrap();
        let profile = args[at + 1..]
            .iter()
            .take_while(|arg| !arg.starts_with("--new"))
            .collect::<Vec<_>>();
        for suffix in [&nba, &other] {
            assert!(
                profile
                    .iter()
                    .any(|arg| arg.starts_with("--ipset=") && arg.ends_with(suffix))
            );
        }
        assert!(
            profile
                .iter()
                .any(|arg| arg.as_str() == "--ipset-ip=203.0.113.113/32")
        );
        assert!(
            profile
                .iter()
                .any(|arg| arg.ends_with("ipset-exclude-user.txt"))
        );
        assert!(!profile.iter().any(|arg| arg.ends_with("ipset-any.txt")
            || arg.ends_with("ipset-all.txt")
            || arg.ends_with("ipset-user.txt")));
    }
    settings.set("gameapps", "NBA2K27").unwrap();
    let args = compose(root, &settings, &options).unwrap();
    assert!(!args.iter().any(|arg| arg.ends_with(&other)));
    assert!(root.join("lists").join(other).is_file());
    settings.set("gameapps", "").unwrap();
    let args = compose(root, &settings, &options).unwrap();
    assert_eq!(
        args.iter()
            .filter(|arg| arg.as_str() == "--ipset-ip=203.0.113.113/32")
            .count(),
        2
    );
}

#[test]
fn low_latency_profiles_only_capture_game_ports_for_enabled_transports() {
    let pkg = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut settings = Settings::default();
    settings.set("gametcp", "27015").unwrap();
    settings.set("gameudp", "27016").unwrap();
    for (id, profile_tcp, profile_udp) in [
        ("31", true, true),
        ("75", false, false),
        ("76", true, false),
    ] {
        for (mode, mode_tcp, mode_udp) in [
            ("off", false, false),
            ("all", true, true),
            ("selected", true, true),
            ("tcp", true, false),
            ("udp", false, true),
        ] {
            settings.set("game", mode).unwrap();
            for no_auto in [true, false] {
                let options = ComposeOptions {
                    alt: Some(id.into()),
                    no_auto,
                    persistence: false,
                    ..Default::default()
                };
                let args = compose(&pkg, &settings, &options).unwrap();
                for (proto, port, active) in [
                    ("tcp", 27015, profile_tcp && mode_tcp),
                    ("udp", 27016, profile_udp && mode_udp),
                ] {
                    let key = format!("--wf-{proto}-out=");
                    let ports = args.iter().find_map(|arg| arg.strip_prefix(&key)).unwrap();
                    assert_eq!(
                        zapret_core::port_in_list(port, ports),
                        active,
                        "{id}/{mode}/{no_auto}"
                    );
                    assert_eq!(args.contains(&format!("--new=game_{proto}")), active);
                }
                assert!(args.iter().any(|s| s == "--new=discord_voice"));
                assert!(args.iter().any(|s| s == "--new=quic_ipset"));
                assert!(!args.iter().any(|s| s == "--skip"));
            }
        }
    }
}

#[test]
fn native_rotation_skips_identical_slots_after_family_and_fallback_resolution() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    for dir in ["tools", "strategies", "windivert"] {
        fs::create_dir(root.join(dir)).unwrap();
    }
    let manifest = include_str!("../../../tools/upstream.txt")
        .lines()
        .filter(|line| {
            line.split_once('=').is_none_or(|(key, _)| {
                !zapret_core::omits_engine_file(zapret_core::BUILTIN_RULES_SCHEMA, key)
            })
        })
        .collect::<Vec<_>>()
        .join("\n")
        .replace("schema=1", "schema=3");
    fs::write(root.join("tools/upstream.txt"), manifest).unwrap();
    fs::write(root.join("windivert/quic_initial_ietf.txt"), "udp").unwrap();
    for (id, pos) in [("11", 1), ("12", 1), ("32", 2)] {
        let mut text = String::new();
        for section in zapret_core::SECTIONS {
            text.push_str(&format!("[{section}]\n"));
            match (section, id) {
                ("google", "11") => text.push_str("# match-l3: ipv4\n"),
                ("google", "32") => text.push_str("# match-l3: ipv6\n"),
                ("discord_media", "32") => {
                    text.push_str("--lua-desync=user_hook\n");
                    continue;
                }
                _ => {}
            }
            text.push_str(&format!("--lua-desync=multisplit:pos={pos}\n"));
        }
        if id == "12" {
            text.push_str("[ipset_tcp]\n--lua-desync=multisplit:pos=1\n");
        }
        fs::write(root.join(format!("strategies/alt{id}.txt")), text).unwrap();
    }
    let mut settings = Settings::default();
    settings.set("auto", "on").unwrap();
    let args = compose(
        root,
        &settings,
        &ComposeOptions {
            alt: Some("11".into()),
            persistence: false,
            ..Default::default()
        },
    )
    .unwrap();
    let slots = |start: &str| -> Vec<&str> {
        let i = args.iter().position(|a| a == start).unwrap();
        args[i + 1..]
            .iter()
            .take_while(|a| !a.starts_with("--new") && !a.starts_with("--template="))
            .filter_map(|a| {
                a.strip_prefix("--lua-desync=multisplit:pos=")
                    .or_else(|| a.strip_prefix("--lua-desync=user_hook:"))
            })
            .collect()
    };
    let pair = ["1:strategy=1", "2:strategy=2"];
    assert_eq!(slots("--template=tpl_general"), pair);
    assert_eq!(slots("--new=tcp_ipset"), pair);
    assert_eq!(slots("--new=google_ipv4"), ["1"]);
    assert_eq!(slots("--new=google_ipv6"), pair);
    assert_eq!(
        slots("--new=discord_media"),
        ["1:strategy=1", "1:strategy=2", "strategy=3"]
    );
}

#[test]
fn native_ring_persistence_uses_controller_and_worker_identity() {
    let fixture = composition_fixture();
    let temp = tempfile::tempdir().unwrap();
    let pkg = temp.path();
    let files = fixture
        .files
        .into_iter()
        .filter(|(name, _)| !name.ends_with(".ps1") && !name.ends_with(".cs"))
        .collect();
    write_fixture_files(pkg, &files);
    fs::write(
        pkg.join("bin/zapret-rust.exe"),
        b"native worker identity fixture",
    )
    .unwrap();
    let args = compose(pkg, &Settings::default(), &ComposeOptions::default()).unwrap();
    assert!(
        args.iter()
            .any(|arg| arg.starts_with("--lua-desync=circular:"))
    );
    let before = zapret_core::ring_composition_key(pkg, &Settings::default()).unwrap();
    let identity_options = ComposeOptions {
        native_identity: Some("A".repeat(64)),
        ..Default::default()
    };
    let other_options = ComposeOptions {
        native_identity: Some("B".repeat(64)),
        ..Default::default()
    };
    let first = compose(pkg, &Settings::default(), &identity_options).unwrap();
    let second = compose(pkg, &Settings::default(), &other_options).unwrap();
    assert_ne!(
        first.iter().find(|a| a.contains(":state=ring-general-")),
        second.iter().find(|a| a.contains(":state=ring-general-"))
    );
    fs::write(
        pkg.join("bin/zapret-rust.exe"),
        b"new native worker identity",
    )
    .unwrap();
    assert_ne!(
        before,
        zapret_core::ring_composition_key(pkg, &Settings::default()).unwrap()
    );
}
