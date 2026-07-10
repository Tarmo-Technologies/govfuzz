// SPDX-License-Identifier: Apache-2.0

//! Thread-local "in_hook" flag. If a hook winds up calling another
//! libc function we've also hooked (e.g. open() inside the JSONL
//! writer's open-on-first-use path), the second hook needs to
//! short-circuit and call the real syscall without logging — else
//! we'd recurse forever.

use std::cell::Cell;

thread_local! {
    static IN_HOOK: Cell<bool> = const { Cell::new(false) };
}

/// Returns true if the current thread is already inside a hook. The
/// caller is expected to short-circuit (call the real syscall, skip
/// logging) when this returns true.
pub fn entering_hook() -> bool {
    IN_HOOK.with(|f| {
        if f.get() {
            true
        } else {
            f.set(true);
            false
        }
    })
}

pub fn leaving_hook() {
    IN_HOOK.with(|f| f.set(false));
}

/// RAII guard for the in_hook flag. Constructing this returns Err
/// when we're already inside a hook; the caller short-circuits in
/// that case. Drop clears the flag.
pub struct HookGuard;

impl HookGuard {
    pub fn acquire() -> Option<Self> {
        if entering_hook() {
            None
        } else {
            Some(HookGuard)
        }
    }
}

impl Drop for HookGuard {
    fn drop(&mut self) {
        leaving_hook();
    }
}
