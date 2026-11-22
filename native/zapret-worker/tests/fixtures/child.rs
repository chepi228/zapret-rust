use std::{fs, io::{self, Write}, time::Duration};
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetConsoleWindow() -> *mut std::ffi::c_void;
}
fn main() {
    let console = !unsafe { GetConsoleWindow() }.is_null();
    println!("console={console}");
    for argument in std::env::args().skip(1) { println!("arg={argument}"); }
    eprintln!("fixture stderr");
    io::stdout().flush().unwrap();
    if let Some(path) = std::env::var_os("ZAPRET_GUI_FIXTURE_READY") {
        fs::write(path, std::process::id().to_string()).unwrap();
    }
    if std::env::var("ZAPRET_GUI_FIXTURE_WAIT").is_ok_and(|v| v == "1") {
        std::thread::sleep(Duration::from_secs(30));
    }
    std::process::exit(17);
}
