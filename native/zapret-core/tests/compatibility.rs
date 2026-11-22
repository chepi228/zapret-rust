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
