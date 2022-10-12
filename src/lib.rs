mod hook_storage;
mod hooks;
mod log;
mod types;

use anyhow::Result;
use ctor::{ctor, dtor};
use frida_gum::Gum;
use hook_storage::HookStorage;
use lazy_static::lazy_static;
use log::HookLogger;
use once_cell::sync::OnceCell;

use crate::types::HOOK_LIST;

lazy_static! {
    static ref GUM: Gum = unsafe { Gum::obtain() };
}

static LOGGER: OnceCell<HookLogger> = OnceCell::new();
static mut STORAGE: OnceCell<HookStorage> = OnceCell::new();

fn set_hooks(mut storage: HookStorage) -> Result<()> {
    for (name, hook_addr) in &HOOK_LIST {
        storage.add(name, hook_addr.0)?
    }
    unsafe {
        STORAGE
            .set(storage)
            .map_err(|_| anyhow::anyhow!("[-] Can't init hook storage"))?
    }

    eprintln!("[+] Hook successfully installed");
    Ok(())
}

#[ctor]
fn init() {
    let storage = HookStorage::new();
    match HookLogger::new("./log.txt".to_string()) {
        //TODO: move this to env
        Ok(logger) => {
            if let Err(_) = LOGGER.set(logger) {
                eprintln!("[-] Can't initialize global hook logger")
            }
            eprintln!("[+] Logger created");
            if let Err(e) = set_hooks(storage) {
                eprintln!("[-] Error while hook installation: {e}")
            }
        }
        Err(e) => eprintln!("[-] Hook logger creation error: {e}"),
    }
}

#[dtor]
fn shutdown() {
    let storage = unsafe { STORAGE.get_mut().unwrap() };
    for (name, _) in &HOOK_LIST {
        storage.remove(name)
    }
}
