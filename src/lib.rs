mod hook;
mod log;

use anyhow::Result;
use ctor::{ctor, dtor};
use frida_gum::Gum;
use hook::HookStorage;
use lazy_static::lazy_static;
use libc::{c_char, c_int, c_void};
use log::HookLogger;
use once_cell::sync::OnceCell;

pub(crate) trait Intercept {}

type LibcOpen = unsafe extern "C" fn(*const c_char, flags: c_int) -> c_int;

lazy_static! {
    static ref GUM: Gum = unsafe { Gum::obtain() };
}

struct HookWrapper(*mut c_void);

unsafe impl std::marker::Send for HookWrapper {}
unsafe impl std::marker::Sync for HookWrapper {}

static HOOK_LIST: [(&'static str, HookWrapper); 1] =
    [("open", HookWrapper(open_hook as *mut c_void))];

static LOGGER: OnceCell<HookLogger> = OnceCell::new();
static mut STORAGE: OnceCell<HookStorage> = OnceCell::new();

//TODO: set errno for correctness?
unsafe extern "C" fn open_hook(name: *const c_char, flags: c_int) -> c_int {
    LOGGER.get().map(|v| v.append());
    STORAGE
        .get()
        .map(|s| std::mem::transmute::<*mut c_void, LibcOpen>(s.get_ptr("open"))(name, flags))
        .unwrap_or(-1)
}

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
