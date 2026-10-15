//! Process settings that keep a crash from leaving a trace on this machine.
//!
//! What this covers, and what it cannot:
//!
//! * A panic is recorded as one fixed line in the memory buffer; the default
//!   hook (message, source location, optional backtrace on stderr) is replaced.
//! * Windows: the error-reporting dialog is turned off and an unhandled
//!   exception ends the process quietly. Windows Error Reporting may still
//!   keep a record on its own policy (it is configured for the whole machine).
//! * Linux: core dumps are limited to zero bytes and the process is marked
//!   non-dumpable. macOS: the core size limit is set to zero.
//!
//! Dumps that the operating system wrote earlier, `systemd-coredump`, crash
//! reporters configured for the whole machine, hibernation and the page file
//! are outside the program's control.

use std::sync::Arc;

use super::Logger;

/// Replace the panic hook so a panic is noted in the memory buffer only.
pub fn install_panic_hook(logger: Arc<Logger>) {
    std::panic::set_hook(Box::new(move |_info| {
        // The payload and location are left out on purpose: they can carry
        // values and source paths.
        let thread = std::thread::current();
        let name = thread.name().unwrap_or("unnamed");
        let line = format!("PANIC in thread {} (details withheld)", short_thread(name));
        logger.record_raw(&line);
    }));
}

fn short_thread(n: &str) -> String {
    n.chars().take(24).collect()
}

/// Ask the OS not to write crash dumps for this process.
pub fn disable_crash_dumps() {
    #[cfg(windows)]
    windows::apply();
    #[cfg(unix)]
    unix::apply();
}

#[cfg(windows)]
mod windows {
    use std::ffi::c_void;

    const SEM_FAILCRITICALERRORS: u32 = 0x0001;
    const SEM_NOGPFAULTERRORBOX: u32 = 0x0002;
    const SEM_NOOPENFILEERRORBOX: u32 = 0x8000;
    const EXCEPTION_EXECUTE_HANDLER: i32 = 1;

    type Filter = unsafe extern "system" fn(*mut c_void) -> i32;

    #[link(name = "kernel32")]
    extern "system" {
        fn SetErrorMode(mode: u32) -> u32;
        fn SetUnhandledExceptionFilter(filter: Option<Filter>) -> Option<Filter>;
    }

    unsafe extern "system" fn quiet(_info: *mut c_void) -> i32 {
        // Ends the process without invoking Windows Error Reporting's UI.
        EXCEPTION_EXECUTE_HANDLER
    }

    pub fn apply() {
        // SAFETY: plain Win32 calls with valid arguments; no pointers escape.
        unsafe {
            SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
            SetUnhandledExceptionFilter(Some(quiet));
        }
    }
}

#[cfg(unix)]
mod unix {
    pub fn apply() {
        let lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `lim` is a valid rlimit that lives for the call.
        unsafe {
            libc::setrlimit(libc::RLIMIT_CORE, &lim);
            #[cfg(target_os = "linux")]
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        }
    }
}
