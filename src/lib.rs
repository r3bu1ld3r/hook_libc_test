mod hook;
mod log;

use anyhow::Result;
use ctor::{ctor, dtor};
use frida_gum::{interceptor::Interceptor, Gum, Module, NativePointer};
use hook::HookStorage;
use lazy_static::lazy_static;
use libc::{c_char, c_int, c_void};
use log::HookLogger;
use once_cell::sync::OnceCell;

use crate::hook::Hook;

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

fn set_hook(storage: &mut HookStorage) -> Result<()> {
    let hook_list = vec![];
    for (name, fptr) in hook_list {
        storage.add(name, fptr)
    }
    eprintln!("[+] Hook successfully installed");
    Ok(())
}

#[ctor]
fn init() {
    let mut storage = HookStorage::new();
    match HookLogger::new("./log.txt".to_string()) {
        Ok(logger) => {
            if let Err(_) = LOGGER.set(logger) {
                eprintln!("[-] Can't initialize global hook logger")
            }
            eprintln!("[+] Logger created");
            if let Err(e) = set_hook(&mut storage) {
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
