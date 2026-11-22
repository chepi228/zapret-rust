use crate::{
    ControlGuard,
    storage::{atomic_write, no_reparse, read_limited},
};
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

const BLOCKS: &[(&str, &str)] = &[
    (
        "# zapret: hosts Flowseal - начало (меню: Проверка обходов)",
        "# zapret: hosts Flowseal - конец",
    ),
    (
        "# NBA2K27-zapret2: hosts Flowseal - начало (пункт H меню)",
        "# NBA2K27-zapret2: hosts Flowseal - конец",
    ),
    (
        "# zapret: hosts Flowseal - начало (меню, пункт 4)",
        "# zapret: hosts Flowseal - конец",
    ),
    (
        "# zapret: серверы игр - начало (меню: Проверка обходов)",
        "# zapret: серверы игр - конец",
    ),
];
fn clean_hosts(bytes: &[u8]) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(bytes)?;
    let mut output = if text.starts_with('\u{feff}') {
        "\u{feff}".into()
    } else {
        String::new()
    };
    let mut block = None;
    for line in text.trim_start_matches('\u{feff}').split_inclusive('\n') {
        let marker = line.trim_end_matches('\n').trim_end_matches('\r');
        if let Some((_, end)) = BLOCKS.iter().find(|(begin, _)| marker == *begin) {
            ensure!(
                block.is_none(),
                "Nested zapret hosts block; cleanup cancelled"
            );
            block = Some(*end);
            continue;
        }
        if BLOCKS.iter().any(|(_, end)| marker == *end) {
            ensure!(
                block == Some(marker),
                "Unmatched zapret hosts block; cleanup cancelled"
            );
            block = None;
            continue;
        }
        if block.is_none() {
            output.push_str(line);
        }
    }
    ensure!(
        block.is_none(),
        "Unclosed zapret hosts block; cleanup cancelled"
    );
    Ok(output.into_bytes())
}
fn disable_settings(bytes: &[u8]) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(bytes)?;
    let newline = if text.contains("\r\n") || text.is_empty() {
        "\r\n"
    } else {
        "\n"
    };
    let mut output = if text.starts_with('\u{feff}') {
        "\u{feff}".into()
    } else {
        String::new()
    };
    let mut pins = false;
    let mut telegram = false;
    for line in text.trim_start_matches('\u{feff}').split_inclusive('\n') {
        let body = line.trim_end_matches('\n').trim_end_matches('\r');
        if let Some((key, _)) = body.split_once('=') {
            if ["gamepins", "telegram"]
                .iter()
                .any(|name| key.trim().eq_ignore_ascii_case(name))
            {
                pins |= key.trim().eq_ignore_ascii_case("gamepins");
                telegram |= key.trim().eq_ignore_ascii_case("telegram");
                output.push_str(key);
                output.push_str("=off");
                if line.ends_with("\r\n") {
                    output.push_str("\r\n");
                } else if line.ends_with('\n') {
                    output.push('\n');
                }
                continue;
            }
        }
        output.push_str(line);
    }
    for (key, found) in [("gamepins", pins), ("telegram", telegram)] {
        if !found {
            if !output.is_empty() && !output.ends_with('\n') {
                output.push_str(newline);
            }
            output.push_str(key);
            output.push_str("=off");
            output.push_str(newline);
        }
    }
    Ok(output.into_bytes())
}
struct FileChange {
    path: PathBuf,
    old: Option<Vec<u8>>,
    new: Vec<u8>,
    label: &'static str,
}
impl FileChange {
    fn current(&self) -> Result<()> {
        no_reparse(&self.path)?;
        let current = if self.path.exists() {
            Some(read_limited(&self.path, 8 * 1024 * 1024)?)
        } else {
            None
        };
        ensure!(
            current == self.old,
            "{} changed during uninstall preflight; cleanup deferred",
            self.label
        );
        Ok(())
    }
    fn apply(&self, root: &Path) -> Result<Value> {
        self.current()?;
        if self.old.as_deref() == Some(self.new.as_slice()) {
            return Ok(json!({"updated":false,"path":self.path}));
        }
        let backup = root.join(format!(
            "runtime/uninstall-{}-{}-{}.bak",
            self.label,
            crate::time_filetime(),
            std::process::id()
        ));
        if let Some(old) = self.old.as_ref() {
            atomic_write(&backup, old)?;
        }
        self.current()?;
        atomic_write(&self.path, &self.new)?;
        Ok(json!({"updated":true,"path":self.path,"backup":self.old.as_ref().map(|_|backup)}))
    }
}
fn file_changes(root: &Path, args: &Value) -> Result<[FileChange; 2]> {
    let host_args = args
        .get("hosts_path")
        .map_or_else(|| json!({}), |path| json!({"path":path}));
    let path = crate::hosts::path(root, &host_args)?;
    let old = read_limited(&path, 8 * 1024 * 1024)?;
    let new = clean_hosts(&old)?;
    let hosts = FileChange {
        path,
        old: Some(old),
        new,
        label: "hosts",
    };
    let path = root.join("runtime/settings.ini");
    no_reparse(&path)?;
    let old = if path.exists() {
        Some(read_limited(&path, 8 * 1024 * 1024)?)
    } else {
        None
    };
    let new = disable_settings(old.as_deref().unwrap_or_default())?;
    let settings = FileChange {
        path,
        old,
        new,
        label: "settings",
    };
    Ok([hosts, settings])
}
fn require_owned_tasks(tasks: &[Value]) -> Result<()> {
    for task in tasks {
        ensure!(
            task["exists"].is_boolean(),
            "Task state is unknown; uninstall deferred: {task}"
        );
        ensure!(
            task["exists"] == false || task["owned"] == true,
            "Task belongs to another installation; uninstall deferred: {task}"
        );
    }
    Ok(())
}
pub(crate) fn run(root: &Path, args: &Value) -> Result<Value> {
    let _guard = ControlGuard::acquire(root, "uninstall")?;
    crate::launch::allowed(root, args)?;
    crate::service::assert_owned(root)?;
    crate::system::owned(root)?;
    let kinds = ["autotune", "notify", "telegram", "watch"];
    let tasks = kinds
        .iter()
        .map(|kind| crate::tasks::status(root, &json!({"kind":kind})))
        .collect::<Result<Vec<_>>>()?;
    require_owned_tasks(&tasks)?;
    let changes = file_changes(root, args)?;
    for change in &changes {
        change.current()?;
    }
    let mut telegram_args = args.clone();
    telegram_args["persist_setting"] = json!(false);
    let telegram = crate::telegram::stop(root, &telegram_args)?;
    let stopped = crate::launch::stop(root, args)?;
    let service = crate::launch::remove_service(root, args)?;
    let mut removed = Vec::new();
    for (kind, state) in kinds.iter().zip(&tasks) {
        if state["exists"] == true {
            crate::tasks::action(root, &json!({"kind":kind}), crate::tasks::Action::Delete)?;
            removed.push(*kind);
        }
    }
    crate::maintenance::priority(
        root,
        &json!({"enabled":false,"game_approved":args["game_approved"]}),
    )?;
    let hosts_cleanup = changes[0].apply(root)?;
    let settings = changes[1].apply(root)?;
    let flush_dns = (hosts_cleanup["updated"] == true && args.get("hosts_path").is_none())
        .then(crate::dns_cache::flush);
    let ipv4_restore = if args["restore_ipv4"] == true {
        Some(crate::maintenance::prefer_ipv4(
            root,
            &json!({"enabled":false,"game_approved":args["game_approved"]}),
        )?)
    } else {
        None
    };
    let permissions = crate::package::dispatch(root, "unprotect-package")
        .unwrap_or_else(|error| json!({"known":false,"error":format!("{error:#}")}));
    Ok(
        json!({"running":stopped["running"],"service":service,"telegram":telegram,"removed_tasks":removed,
        "hosts_cleanup":hosts_cleanup,"settings":settings,"flush_dns":flush_dns,"ipv4_restore":ipv4_restore,"package_permissions":permissions}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn uninstall_removes_only_marked_hosts_blocks_preserving_outside_entries_exactly() {
        let text = format!(
            "\u{feff}# user\r\n8.8.8.8 api.quago.io keep.example # outside\r\n{}\r\n1.1.1.1 api.quago.io\r\n{}\r\n{}\r\n140.82.112.3 github.com\r\n{}\r\n9.9.9.9 github.com\r\n",
            BLOCKS[3].0, BLOCKS[3].1, BLOCKS[0].0, BLOCKS[0].1
        );
        assert_eq!(
            String::from_utf8(clean_hosts(text.as_bytes()).unwrap()).unwrap(),
            "\u{feff}# user\r\n8.8.8.8 api.quago.io keep.example # outside\r\n9.9.9.9 github.com\r\n"
        );
        for text in [
            format!("{}\nkeep", BLOCKS[0].0),
            format!("{}\n", BLOCKS[0].1),
            format!("{}\n{}\n", BLOCKS[0].0, BLOCKS[3].0),
        ] {
            assert!(clean_hosts(text.as_bytes()).is_err());
        }
    }
    #[test]
    fn uninstall_preserves_unknown_settings_and_stages_backups_before_owned_cleanup() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("runtime")).unwrap();
        let hosts = root.path().join("hosts");
        std::fs::write(
            &hosts,
            format!(
                "# keep\n{}\n1.1.1.1 api.quago.io\n{}\n",
                BLOCKS[3].0, BLOCKS[3].1
            ),
        )
        .unwrap();
        let settings =
            b"\xef\xbb\xbf# user note\r\nFuture=keep\r\ngamepins=on\r\nTeLeGrAm=on\r\nalt=12\r\n";
        std::fs::write(root.path().join("runtime/settings.ini"), settings).unwrap();
        let changes = file_changes(root.path(), &json!({"hosts_path":hosts})).unwrap();
        for change in &changes {
            change.current().unwrap();
        }
        let cleanup = changes[0].apply(root.path()).unwrap();
        changes[1].apply(root.path()).unwrap();
        assert_eq!(std::fs::read(&hosts).unwrap(), b"# keep\n");
        assert_eq!(
            std::fs::read(cleanup["backup"].as_str().unwrap()).unwrap(),
            changes[0].old.clone().unwrap()
        );
        assert_eq!(
            std::fs::read(root.path().join("runtime/settings.ini")).unwrap(),
            b"\xef\xbb\xbf# user note\r\nFuture=keep\r\ngamepins=off\r\nTeLeGrAm=off\r\nalt=12\r\n"
        );
    }
    #[test]
    fn foreign_or_unknown_task_aborts_uninstall_preflight() {
        assert!(require_owned_tasks(&[json!({"exists":true,"owned":false})]).is_err());
        assert!(require_owned_tasks(&[json!({"exists":null})]).is_err());
        require_owned_tasks(&[json!({"exists":false}), json!({"exists":true,"owned":true})])
            .unwrap();
    }
}
