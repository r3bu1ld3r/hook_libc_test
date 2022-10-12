use std::collections::HashMap;

use anyhow::Result;
use frida_gum::{interceptor::Interceptor, Module, NativePointer};
use libc::c_void;

use crate::GUM;

pub(crate) struct HookStorage {
    storage: HashMap<&'static str, NativePointer>,
}

impl HookStorage {
    pub fn new() -> Self {
        Self {
            storage: HashMap::new(),
        }
    }

    pub fn add(&mut self, name: &'static str, hook_addr: *mut c_void) -> Result<()> {
        let mut engine = Interceptor::obtain(&GUM);
        let origin_ptr = self.install(&mut engine, name, hook_addr)?;
        self.storage.insert(name, origin_ptr);
        Ok(())
    }

    pub fn get_ptr(&self, name: &str) -> *mut c_void {
        self.storage.get(name).unwrap().0
    }

    fn install(
        &self,
        engine: &mut Interceptor,
        func_name: &str,
        hook_addr: *mut c_void,
    ) -> Result<NativePointer> {
        let source = Module::find_export_by_name(None, func_name).ok_or(anyhow::anyhow!(
            "Can'f find open function in export symbols"
        ))?;
        let origin_ptr = engine.replace(
            source,
            NativePointer(hook_addr),
            NativePointer(std::ptr::null_mut()),
        )?;
        Ok(origin_ptr)
    }

    pub fn remove(&mut self, name: &'static str) {
        let mut interceptor = Interceptor::obtain(&GUM);
        let entry = self.storage.remove(name).unwrap();
        interceptor.revert(entry);
    }
}
