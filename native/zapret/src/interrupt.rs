use anyhow::{Result, ensure};
use std::sync::{
    OnceLock,
    atomic::{AtomicBool, Ordering},
};

static INTERRUPTED: AtomicBool = AtomicBool::new(false);
static INSTALLED: OnceLock<std::result::Result<(), String>> = OnceLock::new();

pub fn install() -> Result<()> {
    let result = INSTALLED.get_or_init(|| {
        ctrlc::set_handler(|| INTERRUPTED.store(true, Ordering::SeqCst))
            .map_err(|error| error.to_string())
    });
    ensure!(
        result.is_ok(),
        "Не удалось установить обработчик отмены: {result:?}"
    );
    Ok(())
}

pub fn cancelled() -> bool {
    INTERRUPTED.load(Ordering::SeqCst)
}

pub fn check() -> Result<()> {
    ensure!(!cancelled(), "Операция отменена пользователем");
    Ok(())
}

/// Called after a menu action has returned and its owned work has unwound.
pub(crate) fn action_completed() {
    INTERRUPTED.store(false, Ordering::SeqCst);
}

#[cfg(test)]
pub(crate) fn request_for_test() {
    INTERRUPTED.store(true, Ordering::SeqCst);
}
