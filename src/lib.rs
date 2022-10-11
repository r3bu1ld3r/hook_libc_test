mod log;

use anyhow::Result;
use ctor::{ctor, dtor};
use frida_gum::{interceptor::Interceptor, Gum, Module, NativePointer};
use lazy_static::lazy_static;
use libc::{c_char, c_int, c_void};
use log::HookLogger;
use once_cell::sync::OnceCell;

type LibcOpen = unsafe extern "C" fn(*const c_char, flags: c_int) -> c_int;

lazy_static! {
    static ref GUM: Gum = unsafe { Gum::obtain() };
}

static LOGGER: OnceCell<HookLogger> = OnceCell::new();
static mut ORIGINAL_OPEN: OnceCell<LibcOpen> = OnceCell::new();

//TODO: set errno for correctness?
unsafe extern "C" fn open_hook(name: *const c_char, flags: c_int) -> c_int {
    LOGGER.get().map(|v| v.append());
    ORIGINAL_OPEN
        .get()
        .map(|ptr| ptr(name, flags))
        .unwrap_or(-1)
}

fn set_hook() -> Result<()> {
    let mut interceptor = Interceptor::obtain(&GUM);
    let libc_open = Module::find_export_by_name(None, "open").ok_or(anyhow::anyhow!(
        "Can'f find open function in export symbols"
    ))?;
    let ptr = interceptor.replace(
        libc_open,
        NativePointer(open_hook as *mut c_void),
        NativePointer(std::ptr::null_mut()),
    )?;
    unsafe {
        //SAFETY
        // 1. Rust LibcOpen type have the same signature as C open function
        // 2. once cell is initialized here, so unwrap won't panic
        ORIGINAL_OPEN.set(std::mem::transmute(ptr.0)).unwrap()
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

#[dtor]
fn shutdown() {
    let ptr = unsafe { ORIGINAL_OPEN.get().unwrap() };
    let mut interceptor = Interceptor::obtain(&GUM);
    unsafe { interceptor.revert(NativePointer(std::mem::transmute(ptr))) };
}
