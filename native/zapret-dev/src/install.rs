use anyhow::{Context, Result, bail};
use std::{
    fs::{self, File, OpenOptions},
    io,
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
    ptr::{null, null_mut},
};
use tempfile::TempPath;
use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW, ReplaceFileW};

pub(crate) fn publish(root: &Path, target: &Path) -> Result<()> {
    let bin = root
        .join("bin")
        .canonicalize()
        .context("Find package bin")?;
    let backups = target.join("previous-controllers");
    fs::create_dir_all(&backups)?;
    let backups = backups.canonicalize()?;
    let release = target.join("release");
    let images = [
        ("zapret-worker.exe", "zapret-rust-worker.exe"),
        ("zapret.exe", "zapret-rust-recovery.exe"),
        ("zapret.exe", "zapret-rust.exe"),
    ]
    .into_iter()
    .map(|(source, name)| Image::stage(&release.join(source), name, &bin, &backups))
    .collect::<Result<Vec<_>>>()?;

    // Stage the whole set before any publication and replace the entry point last.
    // Keep the old images until the whole set succeeds so a failed swap can roll back.
    for (index, image) in images.iter().enumerate() {
        if let Err(error) = image.publish() {
            let mut rollback_errors = Vec::new();
            let restore_partial = (|| {
                if image.backup.try_exists()? && !image.destination.try_exists()? {
                    image.restore()?;
                }
                Ok::<_, anyhow::Error>(())
            })();
            if let Err(error) = restore_partial {
                rollback_errors.push(format!("{error:#}"));
            }
            for previous in images[..index].iter().rev() {
                if let Err(error) = previous.restore() {
                    rollback_errors.push(format!("{error:#}"));
                }
            }
            if rollback_errors.is_empty() {
                return Err(error);
            }
            bail!(
                "{error:#}\nRollback failed: {}\nPrevious images: {}",
                rollback_errors.join("\n"),
                backups.display()
            );
        }
    }
    for image in &images {
        image.discard_backup();
    }
    println!(
        "Installed the native controller, recovery entry and worker in {}",
        bin.display()
    );
    Ok(())
}

struct Image {
    staged: TempPath,
    destination: PathBuf,
    backup: PathBuf,
    previous: bool,
}

impl Image {
    fn stage(source: &Path, name: &str, bin: &Path, backups: &Path) -> Result<Self> {
        let destination = bin.join(name);
        let previous = destination.try_exists()?;
        let id = installation_id()?;
        let staged = stage_image(source, bin, id)?;
        let backup = backup_path(backups, name, id);
        Ok(Self {
            staged,
            destination,
            backup,
            previous,
        })
    }

    fn publish(&self) -> Result<()> {
        let result = if self.previous {
            replace(&self.destination, &self.staged, Some(&self.backup))
        } else {
            move_new(&self.staged, &self.destination)
        };
        result.with_context(|| format!("Install {}", self.destination.display()))
    }

    fn restore(&self) -> Result<()> {
        self.restore_image()
            .with_context(|| format!("Restore {}", self.destination.display()))
    }

    fn restore_image(&self) -> Result<()> {
        if !self.previous {
            fs::remove_file(&self.destination)?;
        } else if !self.destination.try_exists()? {
            move_new(&self.backup, &self.destination)?;
        } else {
            // The backup may itself be mapped by a running process. Stage its
            // bytes again and keep the mapped file at its recognized backup path.
            let bin = self
                .destination
                .parent()
                .context("Installed image has no parent")?;
            let backups = self.backup.parent().context("Backup has no parent")?;
            let name = self
                .destination
                .file_name()
                .and_then(|name| name.to_str())
                .context("Invalid installed image name")?;
            let id = installation_id()?;
            let staged = stage_image(&self.backup, bin, id)?;
            let retired = backup_path(backups, name, id);
            replace(&self.destination, &staged, Some(&retired))?;
            discard_backup(&retired);
            self.discard_backup();
        }
        Ok(())
    }

    fn discard_backup(&self) {
        discard_backup(&self.backup);
    }
}

fn discard_backup(backup: &Path) {
    if let Err(error) = fs::remove_file(backup) {
        if error.kind() != io::ErrorKind::NotFound {
            eprintln!("Retained previous image {} ({error})", backup.display());
        }
    }
}

pub(crate) fn installation_id() -> Result<u128> {
    let mut random = [0u8; 16];
    getrandom::fill(&mut random)?;
    Ok(u128::from_ne_bytes(random))
}

fn backup_path(directory: &Path, name: &str, id: u128) -> PathBuf {
    directory.join(format!("{name}.{id:032x}.old"))
}

fn stage_image(source: &Path, bin: &Path, id: u128) -> Result<TempPath> {
    let path = bin.join(format!(".native-build-{id:032x}.tmp"));
    let path = TempPath::try_from_path(path)?;
    let mut staged = match OpenOptions::new().write(true).create_new(true).open(&*path) {
        Ok(file) => file,
        Err(error) => {
            let message = format!("Stage {}", path.display());
            let _ = path.keep();
            return Err(error).context(message);
        }
    };
    let mut image = File::open(source).with_context(|| format!("Read {}", source.display()))?;
    io::copy(&mut image, &mut staged)?;
    staged.sync_all()?;
    Ok(path)
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

pub(crate) fn replace(destination: &Path, staged: &Path, backup: Option<&Path>) -> io::Result<()> {
    let destination = wide(destination);
    let staged = wide(staged);
    let backup = backup.map(wide);
    let backup = backup.as_ref().map_or(null(), |path| path.as_ptr());
    // The NUL-terminated paths outlive the call. The reserved pointers are null.
    let ok = unsafe {
        ReplaceFileW(
            destination.as_ptr(),
            staged.as_ptr(),
            backup,
            0,
            null_mut(),
            null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn move_new(staged: &Path, destination: &Path) -> io::Result<()> {
    let staged = wide(staged);
    let destination = wide(destination);
    // Both NUL-terminated paths outlive the call.
    let ok = unsafe {
        MoveFileExW(
            staged.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};

    #[test]
    fn failed_publication_restores_the_previous_images() -> Result<()> {
        let root = tempfile::tempdir()?;
        let target = root.path().join("dist/native");
        let bin = root.path().join("bin");
        fs::create_dir_all(&bin)?;
        fs::create_dir_all(target.join("release"))?;
        fs::write(target.join("release/zapret.exe"), b"new controller")?;
        fs::write(target.join("release/zapret-worker.exe"), b"new worker")?;
        let controller = bin.join("zapret-rust.exe");
        let worker = bin.join("zapret-rust-worker.exe");
        let recovery = bin.join("zapret-rust-recovery.exe");
        fs::write(&controller, b"old controller")?;
        fs::write(&worker, b"old worker")?;
        fs::write(&recovery, b"old recovery")?;
        let pin = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(&controller)?;

        let result = publish(root.path(), &target);
        assert!(result.is_err(), "the last executable denies replacement");
        assert_eq!(fs::read(&controller)?, b"old controller");
        assert_eq!(fs::read(&worker)?, b"old worker");
        assert_eq!(fs::read(&recovery)?, b"old recovery");
        assert_eq!(fs::read_dir(&bin)?.count(), 3);
        assert_eq!(
            fs::read_dir(target.join("previous-controllers"))?.count(),
            0
        );

        drop(pin);
        publish(root.path(), &target)?;
        assert_eq!(fs::read(&controller)?, b"new controller");
        assert_eq!(fs::read(&worker)?, b"new worker");
        assert_eq!(fs::read(&recovery)?, b"new controller");
        Ok(())
    }
}
