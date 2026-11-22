use crate::{
    ProcessIdentity,
    process::{Handle, same_path, wide},
    storage::no_reparse,
    system::{processes, reg_dword, reg_set, reg_string},
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    mem::{size_of, zeroed},
    path::{Path, PathBuf},
    ptr::{null, null_mut},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Security::*,
    System::{Registry::*, Threading::*},
    UI::{Shell::*, WindowsAndMessaging::*},
};
const PRIORITY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\winws2.exe\PerfOptions";
pub fn is_admin() -> Result<bool> {
    unsafe {
        let mut raw = null_mut();
        ensure!(
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) != 0,
            "OpenProcessToken: {}",
            std::io::Error::last_os_error()
        );
        let token = Handle(raw);
        let mut elevation: TOKEN_ELEVATION = zeroed();
        let mut bytes = 0;
        ensure!(
            GetTokenInformation(
                token.0,
                TokenElevation,
                (&mut elevation as *mut TOKEN_ELEVATION).cast(),
                size_of::<TOKEN_ELEVATION>() as u32,
                &mut bytes
            ) != 0,
            "Token elevation query: {}",
            std::io::Error::last_os_error()
        );
        Ok(elevation.TokenIsElevated != 0)
    }
}
pub(crate) fn elevate(root: &Path, args: &Value) -> Result<Value> {
    let executable = args["executable"]
        .as_str()
        .map(PathBuf::from)
        .unwrap_or(std::env::current_exe()?);
    ensure!(
        executable.is_absolute(),
        "Elevation requires an absolute executable path"
    );
    no_reparse(&executable)?;
    let parameters = args["parameters"]
        .as_array()
        .context("parameters must be an array")?
        .iter()
        .map(|v| {
            v.as_str()
                .context("Elevation parameter must be a string")
                .map(String::from)
        })
        .collect::<Result<Vec<_>>>()?;
    let parameters = zapret_core::windows_command_line(&parameters);
    let exe = wide(&executable)?;
    let verb = wide("runas")?;
    let parameters = wide(parameters)?;
    let dir = wide(root)?;
    unsafe {
        let mut s: SHELLEXECUTEINFOW = zeroed();
        s.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
        s.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
        s.lpVerb = verb.as_ptr();
        s.lpFile = exe.as_ptr();
        s.lpParameters = parameters.as_ptr();
        s.lpDirectory = dir.as_ptr();
        s.nShow = SW_SHOWNORMAL;
        ensure!(
            ShellExecuteExW(&mut s) != 0,
            "Elevation: {}",
            std::io::Error::last_os_error()
        );
        let identity = if !s.hProcess.is_null() {
            let h = Handle(s.hProcess);
            crate::process_identity(GetProcessId(h.0)).ok()
        } else {
            None
        };
        Ok(json!({"elevated":true,"process":identity}))
    }
}
pub(crate) fn priority(root: &Path, args: &Value) -> Result<Value> {
    let enabled = args["enabled"].as_bool();
    let before = reg_dword(HKEY_LOCAL_MACHINE, PRIORITY, "CpuPriorityClass")?;
    let saved = reg_string(
        HKEY_LOCAL_MACHINE,
        PRIORITY,
        "ZapretPreviousCpuPriorityClass",
    )?;
    if let Some(on) = enabled {
        let _guard = crate::ControlGuard::acquire(root, "priority")?;
        crate::launch::allowed(root, args)?;
        if on {
            if before != Some(3) {
                if saved.is_none() {
                    reg_set(
                        HKEY_LOCAL_MACHINE,
                        PRIORITY,
                        "ZapretPreviousCpuPriorityClass",
                        &json!(before.map_or("absent".into(), |v| v.to_string())),
                    )?;
                }
                reg_set(HKEY_LOCAL_MACHINE, PRIORITY, "CpuPriorityClass", &json!(3))?;
            }
            for p in crate::system::owned(root)? {
                unsafe {
                    let h = Handle::new(OpenProcess(
                        PROCESS_SET_INFORMATION
                            | PROCESS_QUERY_LIMITED_INFORMATION
                            | PROCESS_SYNCHRONIZE,
                        0,
                        p.pid,
                    ))?;
                    if crate::process_identity(p.pid).ok().as_ref() == Some(&p) {
                        ensure!(
                            SetPriorityClass(h.0, HIGH_PRIORITY_CLASS) != 0,
                            "Set owned process priority: {}",
                            std::io::Error::last_os_error()
                        );
                    }
                }
            }
        } else if let Some(saved) = saved {
            if before == Some(3) {
                if saved == "absent" {
                    reg_set(
                        HKEY_LOCAL_MACHINE,
                        PRIORITY,
                        "CpuPriorityClass",
                        &Value::Null,
                    )?;
                } else {
                    let v = saved
                        .parse::<u32>()
                        .context("Invalid saved priority policy")?;
                    reg_set(HKEY_LOCAL_MACHINE, PRIORITY, "CpuPriorityClass", &json!(v))?;
                }
            }
            reg_set(
                HKEY_LOCAL_MACHINE,
                PRIORITY,
                "ZapretPreviousCpuPriorityClass",
                &Value::Null,
            )?;
        }
    }
    Ok(
        json!({"enabled":reg_dword(HKEY_LOCAL_MACHINE,PRIORITY,"CpuPriorityClass")?==Some(3),"value":reg_dword(HKEY_LOCAL_MACHINE,PRIORITY,"CpuPriorityClass")?}),
    )
}
pub(crate) fn prefer_ipv4(root: &Path, args: &Value) -> Result<Value> {
    if let Some(on) = args["enabled"].as_bool() {
        let _guard = crate::ControlGuard::acquire(root, "prefer-ipv4")?;
        crate::launch::allowed(root, args)?;
        return crate::network_settings::set_preference(root, args, on);
    }
    crate::network_settings::prefix_status(root)
}
pub(crate) fn conflicts(root: &Path) -> Result<Value> {
    let rows = processes()?;
    let adapters = crate::system::adapters()?;
    let foreign = rows
        .iter()
        .filter(|r| {
            ["winws", "winws2", "goodbyedpi"].contains(&r.name.to_lowercase().as_str())
                && r.identity
                    .as_ref()
                    .is_none_or(|p| !same_path(&p.executable, &root.join("bin/winws2.exe")))
        })
        .collect::<Vec<_>>();
    let proxy = crate::system::proxy()?;
    let service = crate::service::info(root)?;
    let appdata = std::env::var_os("OneDrive").map(PathBuf::from);
    let adguard = rows
        .iter()
        .any(|r| r.name.eq_ignore_ascii_case("AdguardSvc"));
    Ok(
        json!({"foreign_bypass":foreign,"foreign_service":service.as_ref().is_some_and(|s|!s.owned),"tun_adapters":adapters.as_array().unwrap().iter().filter(|a|a["up"]==true&&a["tun"]==true).collect::<Vec<_>>(),"adguard":adguard,"in_onedrive":appdata.is_some_and(|p|root.starts_with(p)),"proxy":proxy}),
    )
}
fn check_delete_tree(path: &Path, base: &Path) -> Result<()> {
    let target = std::fs::canonicalize(path)?;
    let base = std::fs::canonicalize(base)?;
    ensure!(
        target.starts_with(&base) && target != base,
        "Cache deletion target escapes app data"
    );
    no_reparse(path)?;
    if path.is_dir() {
        for p in std::fs::read_dir(path)? {
            let p = p?.path();
            no_reparse(&p)?;
            if p.is_dir() {
                check_delete_tree(&p, &base)?;
            }
        }
    }
    Ok(())
}
pub(crate) fn discord_cache(root: &Path, args: &Value) -> Result<Value> {
    crate::launch::allowed(root, args)?;
    let base = if let Some(p) = args["app_data"].as_str() {
        let p = PathBuf::from(p);
        ensure!(
            p.starts_with(root),
            "Cache fixture must stay within package root"
        );
        p
    } else {
        PathBuf::from(std::env::var_os("APPDATA").context("APPDATA unavailable")?)
    };
    no_reparse(&base)?;
    let local =
        PathBuf::from(std::env::var_os("LOCALAPPDATA").context("LOCALAPPDATA unavailable")?);
    let mut result = Vec::new();
    for (name, folder) in [
        ("Discord", "discord"),
        ("DiscordPTB", "discordptb"),
        ("DiscordCanary", "discordcanary"),
        ("DiscordDevelopment", "discorddevelopment"),
    ] {
        let dir = base.join(folder);
        if !dir.exists() {
            continue;
        }
        no_reparse(&dir)?;
        let matching = processes()?
            .into_iter()
            .filter(|p| p.name.eq_ignore_ascii_case(name))
            .collect::<Vec<_>>();
        let mut stopped = Vec::<ProcessIdentity>::new();
        for p in &matching {
            let identity = p
                .identity
                .as_ref()
                .context("Discord identity unavailable; cache deletion cancelled")?;
            ensure!(
                identity.executable.starts_with(local.join(name)),
                "Discord process path does not match installed client; cache deletion cancelled"
            );
            if crate::terminate_owned(identity)? {
                stopped.push(identity.clone());
            }
        }
        let mut cleared = Vec::new();
        for sub in ["Cache", "Code Cache", "GPUCache"] {
            let p = dir.join(sub);
            if p.exists() {
                check_delete_tree(&p, &dir)?;
                std::fs::remove_dir_all(&p)?;
                cleared.push(sub);
            }
        }
        result.push(json!({"name":name,"cleared":cleared,"stopped":stopped}));
    }
    Ok(json!(result))
}
fn fixed<const N: usize>(value: &str) -> [u16; N] {
    let mut out = [0u16; N];
    for (i, c) in value.encode_utf16().take(N - 1).enumerate() {
        out[i] = c;
    }
    out
}
pub(crate) fn notify(args: &Value) -> Result<Value> {
    let title = args["title"].as_str().unwrap_or("zapret-rust");
    let text = args["text"]
        .as_str()
        .context("Notification text is required")?;
    let class = wide("STATIC")?;
    let name = wide("zapret-rust notification")?;
    unsafe {
        let window = CreateWindowExW(
            0,
            class.as_ptr(),
            name.as_ptr(),
            0,
            0,
            0,
            0,
            0,
            HWND_MESSAGE,
            null_mut(),
            null_mut(),
            null(),
        );
        ensure!(
            !window.is_null(),
            "Create notification window: {}",
            std::io::Error::last_os_error()
        );
        let mut icon: NOTIFYICONDATAW = zeroed();
        icon.cbSize = size_of::<NOTIFYICONDATAW>() as u32;
        icon.hWnd = window;
        icon.uID = 1;
        icon.uFlags = NIF_INFO | NIF_TIP;
        icon.szTip = fixed("zapret-rust");
        icon.szInfoTitle = fixed(title);
        icon.szInfo = fixed(text);
        icon.dwInfoFlags = NIIF_INFO;
        let sent = Shell_NotifyIconW(NIM_ADD, &icon) != 0;
        if sent {
            let end = Instant::now() + Duration::from_secs(5);
            while Instant::now() < end {
                let mut msg = zeroed();
                while PeekMessageW(&mut msg, window, 0, 0, PM_REMOVE) != 0 {
                    TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Shell_NotifyIconW(NIM_DELETE, &icon);
        }
        DestroyWindow(window);
        ensure!(sent, "Windows notification failed");
        Ok(json!({"sent":true,"kind":"windows_balloon"}))
    }
}
