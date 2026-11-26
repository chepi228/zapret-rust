use std::{
    env,
    ffi::OsString,
    io::{self, IsTerminal},
    process::Command,
};

fn run() -> io::Result<i32> {
    let image = env::current_exe()?;
    let root = image
        .parent()
        .ok_or_else(|| io::Error::other("Не удалось определить папку zapret-rust"))?;
    let args: Vec<OsString> = env::args_os().skip(1).collect();
    let start = |name: &str| {
        let mut command = Command::new(root.join("bin").join(name));
        if !args
            .iter()
            .any(|a| a == "--root" || a.to_string_lossy().starts_with("--root="))
        {
            command.arg("--root").arg(root);
        }
        command.args(&args).status()
    };
    let primary = "zapret-rust.exe";
    let result = match start(primary) {
        Err(error)
            if error.kind() == io::ErrorKind::NotFound
                && !root.join("bin").join(primary).try_exists()? =>
        {
            start("zapret-rust-recovery.exe")
        }
        result => result,
    }?;
    Ok(result.code().unwrap_or(1))
}

fn main() {
    let code = run().unwrap_or_else(|error| {
        eprintln!("Не удалось открыть zapret-rust. Распакуйте архив целиком. {error}");
        if env::args_os().len() == 1 && io::stdin().is_terminal() {
            eprintln!("Нажмите Enter для выхода.");
            let _ = io::stdin().read_line(&mut String::new());
        }
        1
    });
    std::process::exit(code);
}
