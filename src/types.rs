use crate::hooks::open_hook;
use libc::{c_char, c_int, c_void};

pub(crate) type LibcOpen = unsafe extern "C" fn(*const c_char, flags: c_int) -> c_int;

pub(crate) struct HookWrapper(pub *mut c_void);
unsafe impl std::marker::Send for HookWrapper {}
unsafe impl std::marker::Sync for HookWrapper {}

pub(crate) static HOOK_LIST: [(&'static str, HookWrapper); 1] =
    [("open", HookWrapper(open_hook as *mut c_void))];
