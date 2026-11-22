use super::*;
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Deserialize)]
struct Manifest {
    profiles: Vec<Fixture>,
}
#[derive(Deserialize)]
struct Fixture {
    id: String,
    source: String,
    fixture: String,
    sha256: String,
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixtures() -> Result<(PathBuf, Manifest)> {
    let directory = root().join("dev/fixtures/flowseal-1.10.4");
    let manifest = serde_json::from_slice(&fs::read(directory.join("manifest.json"))?)?;
    Ok((directory, manifest))
}

#[test]
fn all_pinned_profiles_keep_every_current_action_and_family_condition() -> Result<()> {
    let (directory, manifest) = fixtures()?;
    let retired = zapret_core::list_lines(&root().join("strategies/retired.txt"))?;
    assert_eq!(manifest.profiles.len(), 22);
    for fixture in manifest.profiles {
        let bytes = fs::read(directory.join(fixture.fixture))?;
        assert_eq!(
            zapret_core::sha256(&bytes).to_ascii_lowercase(),
            fixture.sha256
        );
        let converted = convert(std::str::from_utf8(&bytes)?)?;
        let name = format!("alt{}.txt", fixture.id);
        let directory = if retired.contains(&name) {
            "dev/experimental"
        } else {
            "strategies"
        };
        let current = read_sections(&fs::read_to_string(root().join(directory).join(name))?)?;
        assert_eq!(converted.sections, current, "{}", fixture.source);
        assert_eq!(
            converted.warnings.len(),
            if fixture.id == "41" { 4 } else { 0 }
        );
        let definition = definitions::DEFINITIONS
            .iter()
            .find(|definition| definition.id == fixture.id)
            .unwrap();
        let rendered = render_strategy(&converted, definition)?;
        assert_eq!(read_sections(&rendered)?, current);
    }
    Ok(())
}

#[test]
fn unrepresentable_options_never_silently_change_profile_semantics() -> Result<()> {
    let (directory, _) = fixtures()?;
    let original = fs::read_to_string(directory.join("alt1.bat.txt"))?;
    let replacements = [
        ("--filter-udp=443", "--filter-udp=443 stray-token"),
        ("--filter-udp=443", "--filter-udp=443 --bad_option=1"),
        ("--wf-tcp=", "--wf-unknown="),
        ("--wf-tcp=80,443,", "--wf-tcp=81,443,"),
        ("--filter-udp=443", "--filter-udp=443 --filter-tcp=80"),
        ("--filter-udp=443", "--filter-udp=443,9999 --filter-l7=quic"),
        ("--filter-udp=443", "--filter-udp=443 --filter-l3=ipv4"),
        ("--new", "--new --filter-udp=443 --dpi-desync=fake --new"),
        (
            "--dpi-desync=fake",
            "--dpi-desync=invented --dpi-desync=fake",
        ),
        (
            "--dpi-desync-fooling=ts",
            "--dpi-desync-fooling=notreal --dpi-desync-fooling=ts",
        ),
        (
            "--dpi-desync-repeats=6",
            "--dpi-desync-repeats=100 --dpi-desync-repeats=6",
        ),
        ("--filter-l7=discord,stun ", ""),
        ("--hostlist-exclude=\"%LISTS%list-exclude.txt\" ", ""),
    ];
    for (before, after) in replacements {
        assert!(
            original.contains(before),
            "fixture does not contain {before}"
        );
        let changed = original.replacen(before, after, 1);
        assert!(convert(&changed).is_err(), "accepted {before} -> {after}");
    }
    for option in [
        "--dpi-desync-fooling=notreal",
        "--dpi-desync-fooling=badsum",
        "--ip-id=zero",
        "--dpi-desync-cutoff=n2",
        "--dpi-desync-fake-tls=\"%BIN%tls_clienthello_www_google_com.bin\"",
    ] {
        let changed =
            original.replacen("--filter-udp=443", &format!("--filter-udp=443 {option}"), 1);
        assert!(
            convert(&changed).is_err(),
            "accepted unused UDP action {option}"
        );
    }
    let profile = parse::profiles(&original)?.pop().unwrap();
    let mut unknown = profile.clone();
    unknown.push(("--invented-option".into(), "1".into()));
    assert!(parse::options(&unknown, &mut Vec::new()).is_err());
    for invalid in [
        "%BIN%../quic_initial_www_google_com.bin",
        "quic_initial_www_google_com.bin",
        "C:\\different\\quic_initial_www_google_com.bin",
        "0xGG",
    ] {
        assert!(parse::blob(invalid).is_err(), "accepted {invalid}");
    }
    for invalid in [
        "notreal",
        "rnd,notreal",
        "none,rnd",
        "sni=",
        "sni=x:repeats=99",
    ] {
        let profile = vec![("--dpi-desync-fake-tls-mod".into(), invalid.into())];
        assert!(
            parse::options(&profile, &mut Vec::new()).is_err(),
            "accepted {invalid}"
        );
    }
    for invalid in ["", "invalid", "ipv4,ipv6"] {
        assert!(
            parse::options(
                &vec![("--filter-l3".into(), invalid.into())],
                &mut Vec::new()
            )
            .is_err()
        );
    }
    Ok(())
}

fn source_tree(directory: &Path) -> Result<()> {
    let (fixtures, manifest) = fixtures()?;
    fs::create_dir_all(directory)?;
    for fixture in manifest.profiles {
        fs::copy(
            fixtures.join(fixture.fixture),
            directory.join(fixture.source),
        )?;
    }
    Ok(())
}

#[test]
fn conversion_preflights_all_sources_and_check_covers_all_twenty_two() -> Result<()> {
    let folder = tempfile::tempdir()?;
    let source = folder.path().join("источник & пробел");
    let output = folder.path().join("strategies");
    source_tree(&source)?;
    fs::create_dir_all(&output)?;
    fs::write(output.join("alt1.txt"), b"personal uncommitted strategy\n")?;
    assert!(run(&source, &output, false, false).is_err());
    assert_eq!(
        fs::read(output.join("alt1.txt"))?,
        b"personal uncommitted strategy\n"
    );

    run(&source, &output, false, true)?;
    assert_eq!(fs::read_dir(&output)?.count(), 18);
    for definition in definitions::DEFINITIONS
        .iter()
        .filter(|definition| !definition.managed)
    {
        let name = format!("alt{}.txt", definition.id);
        fs::copy(root().join("strategies").join(&name), output.join(&name))?;
    }
    run(&source, &output, true, true)?;
    fs::remove_file(output.join("alt2.txt"))?;
    fs::write(output.join("retired.txt"), "ALT2.txt\n")?;
    run(&source, &output, false, true)?;
    assert!(!output.join("alt2.txt").exists());
    run(&source, &output, true, true)?;
    fs::write(
        output.join("alt1.txt"),
        "[general]\n--lua-desync=invented\n",
    )?;
    assert!(run(&source, &output, true, true).is_err());

    let late = source.join("general (FAKE TLS AUTO ALT3).bat");
    let text = fs::read_to_string(&late)?;
    fs::write(
        &late,
        text.replacen("--dpi-desync=", "--unrecognized=1 --dpi-desync=", 1),
    )?;
    let before = fs::read(output.join("alt1.txt"))?;
    assert!(run(&source, &output, false, true).is_err());
    assert_eq!(fs::read(output.join("alt1.txt"))?, before);
    Ok(())
}

#[test]
fn section_reader_rejects_duplicates_unknown_sections_and_unscoped_actions() -> Result<()> {
    for text in [
        "[general]\n--a\n[general]\n--b\n",
        "[general]\n--a\n[unexpected]\n--b\n",
        "--a\n[general]\n--b\n",
    ] {
        assert!(read_sections(text).is_err());
    }
    let parsed = read_sections("\u{feff}# name: test\n[general]\n--a\n")?;
    assert_eq!(parsed["general"], ["--a"]);
    Ok(())
}
