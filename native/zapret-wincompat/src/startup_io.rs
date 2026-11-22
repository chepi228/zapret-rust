//! Startup PID output and best-effort console icon updates.
use std::{ffi::c_char, ptr};
use windows_sys::Win32::{
    Foundation::{
        ERROR_INVALID_PARAMETER, ERROR_PATH_NOT_FOUND, HANDLE, HINSTANCE, HMODULE, HWND,
        SetLastError,
    },
    System::{
        Console::GetConsoleWindow, LibraryLoader::GetModuleHandleW, Threading::GetCurrentProcessId,
    },
    UI::WindowsAndMessaging::{
        IMAGE_ICON, LR_DEFAULTCOLOR, LR_SHARED, LoadImageW, SMTO_ABORTIFHUNG, SMTO_BLOCK,
        SMTO_ERRORONEXIT, SendMessageTimeoutW, WM_SETICON,
    },
};
#[repr(C)]
struct PidOps {
    process: unsafe extern "system" fn() -> u32,
    save: unsafe extern "C" fn(*const c_char, *const u8, usize) -> u32,
}
const PID: PidOps = PidOps {
    process: GetCurrentProcessId,
    save: crate::file_helpers::zapret_engine_save_file,
};
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_startup_pid(filename: *const c_char, input: *const PidOps) -> u32 {
    if filename.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    if unsafe { filename.read() } == 0 {
        return ERROR_PATH_NOT_FOUND;
    }
    let ops = if input.is_null() {
        &PID
    } else {
        unsafe { &*input }
    };
    let mut digits = [0u8; 10];
    let bytes = crate::text_buffer::decimal(unsafe { (ops.process)() }, &mut digits);
    unsafe { (ops.save)(filename, bytes.as_ptr(), bytes.len()) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_startup_write_pid(
    filename: *const c_char,
    publish_error: unsafe extern "C" fn(u32),
) -> bool {
    let error = unsafe { zapret_startup_pid(filename, ptr::null()) };
    unsafe { SetLastError(error) };
    if error == 0 {
        true
    } else {
        unsafe { publish_error(error) };
        false
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn writepid(filename: *const c_char) -> bool {
    unsafe { zapret_startup_write_pid(filename, crate::file_policy::wf_error) }
}

#[repr(C)]
struct IconOps {
    window: unsafe extern "system" fn() -> HWND,
    module: unsafe extern "system" fn(*const u16) -> HMODULE,
    load: unsafe extern "system" fn(HINSTANCE, *const u16, u32, i32, i32, u32) -> HANDLE,
    send: unsafe extern "system" fn(HWND, u32, usize, isize, u32, u32, *mut usize) -> isize,
}
const ICON: IconOps = IconOps {
    window: GetConsoleWindow,
    module: GetModuleHandleW,
    load: LoadImageW,
    send: SendMessageTimeoutW,
};
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_startup_icon(input: *const IconOps) -> u32 {
    let ops = if input.is_null() {
        &ICON
    } else {
        unsafe { &*input }
    };
    let window = unsafe { (ops.window)() };
    if window.is_null() {
        return 0;
    }
    let module = unsafe { (ops.module)(ptr::null()) };
    if module.is_null() {
        return 0;
    }
    let mut installed = 0;
    for (kind, size) in [(0usize, 32), (1, 0)] {
        let icon = unsafe {
            (ops.load)(
                module,
                // MAKEINTRESOURCEW(1) is an ordinal, never UTF-16 storage.
                ptr::without_provenance(1),
                IMAGE_ICON,
                size,
                size,
                LR_DEFAULTCOLOR | LR_SHARED,
            )
        };
        if !icon.is_null() {
            let mut previous = 0;
            if unsafe {
                (ops.send)(
                    window,
                    WM_SETICON,
                    kind,
                    icon as isize,
                    SMTO_ABORTIFHUNG | SMTO_BLOCK | SMTO_ERRORONEXIT,
                    200,
                    &mut previous,
                )
            } == 0
            {
                break;
            }
            // LR_SHARED and previous foreign icons are never owned here.
            installed += 1;
        }
    }
    installed
}
