use ctor::ctor;
use frida_gum::{interceptor::Interceptor, Gum, Module, NativePointer};
use lazy_static::lazy_static;
use libc::{c_char, c_int, c_void};
use std::{cell::UnsafeCell, sync::Mutex};

type LibcOpen = unsafe extern "C" fn(*const c_char, flags: c_int) -> c_int;

lazy_static! {
    static ref GUM: Gum = unsafe { Gum::obtain() };
    static ref ORIGINAL_OPEN: Mutex<UnsafeCell<Option<LibcOpen>>> =
        Mutex::new(UnsafeCell::new(None));
}

//TODO: proper error handling instead of 0 return
unsafe extern "C" fn open_hook(name: *const c_char, flags: c_int) -> c_int {
    let _now = std::time::SystemTime::now();
    if let Ok(guard) = ORIGINAL_OPEN.lock() {
        if let Some(Some(ptr)) = guard.get().as_ref() {
            ptr(name, flags)
        } else {
            0 
        }
    } else {
        0
    }
}

#[ctor]
fn set_hook() {
    let mut interceptor = Interceptor::obtain(&GUM);
    if let Some(libc_open) = Module::find_export_by_name(None, "open") {
        if let Ok(mut guard) = ORIGINAL_OPEN.lock() {
            if let Ok(ptr) = interceptor.replace(
                libc_open,
                NativePointer(open_hook as *mut c_void),
                NativePointer(std::ptr::null_mut()),
            ) {
                unsafe {
                    *guard.get_mut() = Some(std::mem::transmute(ptr.0));
                }
                eprintln!("[+] Hook successfully installed");
            } else {
                eprintln!("[-] interceptor replace error");
            };
        } else {
            eprintln!("[-] mutex error");
        }
    } else {
        eprintln!("[-] libc open not found in exports")
    }
}
