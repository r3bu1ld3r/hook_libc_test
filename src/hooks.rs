use libc::{c_char, c_int, c_void};

use crate::{types::LibcOpen, LOGGER, STORAGE};

//TODO: set errno for correctness?
pub(crate) unsafe extern "C" fn open_hook(name: *const c_char, flags: c_int) -> c_int {
    LOGGER.get().map(|v| v.append());
    STORAGE
        .get()
        .map(|s| std::mem::transmute::<*mut c_void, LibcOpen>(s.get_ptr("open"))(name, flags))
        .unwrap_or(-1)
}
