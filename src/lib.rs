mod log;

use anyhow::Result;
use ctor::ctor;
use frida_gum::{interceptor::Interceptor, Gum, Module, NativePointer};
use lazy_static::lazy_static;
use libc::{c_char, c_int, c_void};
use log::HookLogger;
use once_cell::sync::OnceCell;
use std::{cell::UnsafeCell, sync::Mutex};

type LibcOpen = unsafe extern "C" fn(*const c_char, flags: c_int) -> c_int;

lazy_static! {
    static ref GUM: Gum = unsafe { Gum::obtain() };
    static ref ORIGINAL_OPEN: Mutex<UnsafeCell<Option<LibcOpen>>> =
        Mutex::new(UnsafeCell::new(None));
}

static LOGGER: OnceCell<HookLogger> = OnceCell::new();

//TODO: set errno for correctness
unsafe extern "C" fn open_hook(name: *const c_char, flags: c_int) -> c_int {
    let now = std::time::SystemTime::now();
    if let Some(logger) = LOGGER.get() {
        logger.append(&now)
    }
    if let Ok(guard) = ORIGINAL_OPEN.lock() {
        if let Some(Some(ptr)) = guard.get().as_ref() {
            ptr(name, flags)
        } else {
            eprintln!("[-] libc open function pointer not saved (check log of set_hook)");
            -1
        }
    } else {
        eprintln!("[-] mutex error");
        -1
    }
}

fn set_hook() -> Result<()> {
    let mut interceptor = Interceptor::obtain(&GUM);
    let libc_open = Module::find_export_by_name(None, "open").ok_or(anyhow::anyhow!(
        "Can'f find open function in export symbols"
    ))?;
    let mut guard = ORIGINAL_OPEN
        .lock()
        .map_err(|e| anyhow::anyhow!("Mutex err: {e}"))?;
    let ptr = interceptor.replace(
        libc_open,
        NativePointer(open_hook as *mut c_void),
        NativePointer(std::ptr::null_mut()),
    )?;
    unsafe {
        *guard.get_mut() = Some(std::mem::transmute(ptr.0));
    }
    eprintln!("[+] Hook successfully installed");
    Ok(())
}

#[ctor]
fn init() {
    match HookLogger::new("./log.txt".to_string()) {
        Ok(logger) => {
            if let Err(_) = LOGGER.set(logger) {
                eprintln!("[-] Can't initialize global hook logger")
            }
            eprintln!("[+] Logger created");
            if let Err(e) = set_hook() {
                eprintln!("[-] Error while hook installation: {e}")
            }
        }
        Err(e) => eprintln!("[-] Hook logger creation error: {e}"),
    }
}
