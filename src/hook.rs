use anyhow::Result;
use frida_gum::{interceptor::Interceptor, Module, NativePointer};
use libc::c_void;
use libc::{c_char, c_int};
use once_cell::sync::OnceCell;

use crate::{open_hook, LibcOpen, GUM};

pub(crate) enum LibcArgs {
    Open(*const c_char, c_int),
}

pub(crate) enum LibcRet {
    Open(c_int),
}

pub(crate) trait HookExecute {
    fn execute(&self, args: LibcArgs) -> LibcRet;
}

pub(crate) struct Hook<T> {
    origin: OnceCell<T>,
}

impl<T> Hook<T> {
    pub(crate) fn new() -> Self {
        Self {
            origin: OnceCell::new(),
        }
    }

    pub(crate) fn install(
        &mut self,
        engine: &mut Interceptor,
        func_name: &str,
        hook_addr: *mut T,
    ) -> Result<()> {
        let source = Module::find_export_by_name(None, func_name).ok_or(anyhow::anyhow!(
            "Can'f find open function in export symbols"
        ))?;
        let origin_ptr = engine.replace(
            source,
            NativePointer(hook_addr as *mut c_void),
            NativePointer(std::ptr::null_mut()),
        )?;
        if let Err(_) = unsafe {
            //SAFETY
            // 1. Rust LibcOpen type have the same signature as C open function
            // 2. once cell is initialized here, so unwrap won't panic
            self.origin.set(std::ptr::read(origin_ptr.0 as *const T))
        } {
            eprintln!("[-] hook install error");
        }
        Ok(())
    }

    pub(crate) fn remove(&mut self, engine: &mut Interceptor) {
        let origin_ptr = unsafe {
            let ptr = self.origin.get_unchecked();
            std::mem::transmute::<&T, *mut c_void>(ptr)
        };
        engine.revert(NativePointer(origin_ptr));
    }

    pub(crate) fn get(&self) -> Option<&T> {
        self.origin.get()
    }
}

impl HookExecute for Hook<LibcOpen> {
    fn execute(&self, args: LibcArgs) -> LibcRet {
        let ret = unsafe {
            match args {
                LibcArgs::Open(name, flags) => self.get().map(|ptr| ptr(name, flags)).unwrap_or(-1),
                _ => -1,
            }
        };
        LibcRet::Open(ret)
    }
}

pub(crate) struct HookStorage {
    storage: Vec<Box<dyn HookExecute>>,
}

impl HookStorage {
    pub(crate) fn new() -> Self {
        Self {
            storage: Vec::new(),
        }
    }

    pub(crate) fn add<T: 'static>(&mut self, name: &str, fptr: *mut T)
    where
        Hook<T>: HookExecute,
    {
        let mut interceptor = Interceptor::obtain(&GUM);
        let mut h = Hook::<T>::new();
        h.install(&mut interceptor, name, fptr as *mut T).unwrap();
        self.storage.push(Box::new(h));
    }
}
