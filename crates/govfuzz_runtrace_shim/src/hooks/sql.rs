// SPDX-License-Identifier: Apache-2.0

//! SQL database-execution audit hooks (SQLite / libpq / MySQL).
//!
//! Unlike the other hooks these interpose LIBRARY symbols rather than libc: the
//! shim exports them so an LD_PRELOAD run intercepts them whenever the target
//! dynamically links the client library, and forwards to the real function via
//! dlsym(RTLD_NEXT). A contiguous run of the SQL *text* argument that came from
//! the fuzz input — rather than from a bound parameter — is SQL injection
//! (GF-441); a parameterized query keeps untrusted values out of the text and so
//! severs the byte-origin match and reports nothing.
//!
//! Safety: every #[no_mangle] extern "C" fn here is invoked by the dynamic
//! linker as a client-library symbol. Caller-supplied pointers must satisfy the
//! matching library function's contract; we forward them unchanged after
//! auditing.

#![allow(clippy::missing_safety_doc)]
#![allow(clippy::missing_transmute_annotations)]
#![allow(clippy::too_many_arguments)]

use crate::dlsym::ResolvedFn;
use crate::jsonl::Builder;
use crate::reentrancy::HookGuard;
use std::ffi::CStr;

static REAL_SQLITE3_EXEC: ResolvedFn = ResolvedFn::new(b"sqlite3_exec\0");
static REAL_SQLITE3_PREPARE: ResolvedFn = ResolvedFn::new(b"sqlite3_prepare\0");
static REAL_SQLITE3_PREPARE_V2: ResolvedFn = ResolvedFn::new(b"sqlite3_prepare_v2\0");
static REAL_SQLITE3_PREPARE_V3: ResolvedFn = ResolvedFn::new(b"sqlite3_prepare_v3\0");
static REAL_PQEXEC: ResolvedFn = ResolvedFn::new(b"PQexec\0");
static REAL_PQEXECPARAMS: ResolvedFn = ResolvedFn::new(b"PQexecParams\0");
static REAL_MYSQL_QUERY: ResolvedFn = ResolvedFn::new(b"mysql_query\0");
static REAL_MYSQL_REAL_QUERY: ResolvedFn = ResolvedFn::new(b"mysql_real_query\0");

/// Minimum run of fuzz-input-derived bytes the SQL text must contain before it
/// is treated as taint (#422). Matches the floor the other sink hooks use.
const TAINT_MIN_LEN: usize = 4;

const SQLITE_ERROR: libc::c_int = 1;

fn save_errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

fn restore_errno(saved: i32) {
    unsafe { *libc::__errno_location() = saved };
}

/// The SQL text bytes for a sink event. `count` distinguishes the two shapes the
/// libc SQL APIs use: `None` = a NUL-terminated C string (bounded by a strlen
/// scan); `Some(n)` = a COUNTED buffer of exactly `n` bytes that may contain
/// embedded NULs and need not be NUL-terminated. Counted APIs (MySQL
/// `mysql_real_query`, sqlite prepare with `nbyte >= 0`) MUST pass `Some(..)`:
/// strlen-scanning a non-terminated counted buffer reads out of bounds.
///
/// # Safety
/// `sql` must be null, a valid NUL-terminated C string (`count == None`), or a
/// readable buffer of at least `n` bytes (`count == Some(n)`).
unsafe fn sql_text<'a>(sql: *const libc::c_char, count: Option<usize>) -> Option<&'a [u8]> {
    if sql.is_null() {
        return None;
    }
    let text: &[u8] = match count {
        Some(0) => return None,
        Some(n) => std::slice::from_raw_parts(sql as *const u8, n),
        None => CStr::from_ptr(sql).to_bytes(),
    };
    (!text.is_empty()).then_some(text)
}

/// Emit a `sql` sink event for SQL text reaching a database-execution API,
/// tagged with byte-origin taint when a contiguous run of the text came from the
/// current fuzz input. Emitted on every call (tainted or not) so the CLI's
/// SQL-injection sink oracle (GF-441) can confirm a fuzz-controlled query and
/// suppress a constant one. See [`sql_text`] for the `count` contract.
unsafe fn emit_sql_bytes(api: &[u8], sql: *const libc::c_char, count: Option<usize>) {
    let Some(text) = sql_text(sql, count) else {
        return;
    };
    let saved_errno = save_errno();
    if let Some(_g) = HookGuard::acquire() {
        let mut b = Builder::new(b"sql");
        b.field_str(b"a", api);
        b.field_str(b"q", text);
        if let Some((offset, _len)) =
            crate::fakes::fuzz_input::input_derived_run(text, TAINT_MIN_LEN)
        {
            b.field_i64(b"u", 1);
            b.field_i64(b"o", offset as i64);
        }
        b.emit();
    }
    restore_errno(saved_errno);
}

/// NUL-terminated convenience wrapper over [`emit_sql_bytes`] for the SQL APIs
/// whose text argument is a genuine C string (`sqlite3_exec`, `PQexec`,
/// `mysql_query`, …).
unsafe fn emit_sql(api: &[u8], sql: *const libc::c_char) {
    emit_sql_bytes(api, sql, None);
}

/// The counted length for an sqlite `prepare` text argument. sqlite's `nbyte`
/// is negative for a NUL-terminated string, else the maximum bytes to read;
/// `strnlen` clamps to the first NUL within that bound, so the emitted text is
/// both in-bounds and matches what sqlite parses.
unsafe fn sqlite_prepare_count(sql: *const libc::c_char, nbyte: libc::c_int) -> Option<usize> {
    if sql.is_null() || nbyte < 0 {
        None
    } else {
        Some(libc::strnlen(sql, nbyte as usize))
    }
}

#[no_mangle]
pub unsafe extern "C" fn sqlite3_exec(
    db: *mut libc::c_void,
    sql: *const libc::c_char,
    callback: *mut libc::c_void,
    arg: *mut libc::c_void,
    errmsg: *mut *mut libc::c_char,
) -> libc::c_int {
    emit_sql(b"sqlite3_exec", sql);
    let real = REAL_SQLITE3_EXEC.ptr() as *const ();
    if real.is_null() {
        return SQLITE_ERROR;
    }
    let real: unsafe extern "C" fn(
        *mut libc::c_void,
        *const libc::c_char,
        *mut libc::c_void,
        *mut libc::c_void,
        *mut *mut libc::c_char,
    ) -> libc::c_int = std::mem::transmute(real);
    real(db, sql, callback, arg, errmsg)
}

/// `sqlite3_prepare` and `sqlite3_prepare_v2` share a signature.
unsafe fn sqlite_prepare_common(
    real_fn: &ResolvedFn,
    api: &[u8],
    db: *mut libc::c_void,
    sql: *const libc::c_char,
    nbyte: libc::c_int,
    stmt: *mut *mut libc::c_void,
    tail: *mut *const libc::c_char,
) -> libc::c_int {
    emit_sql_bytes(api, sql, sqlite_prepare_count(sql, nbyte));
    let real = real_fn.ptr() as *const ();
    if real.is_null() {
        return SQLITE_ERROR;
    }
    let real: unsafe extern "C" fn(
        *mut libc::c_void,
        *const libc::c_char,
        libc::c_int,
        *mut *mut libc::c_void,
        *mut *const libc::c_char,
    ) -> libc::c_int = std::mem::transmute(real);
    real(db, sql, nbyte, stmt, tail)
}

#[no_mangle]
pub unsafe extern "C" fn sqlite3_prepare(
    db: *mut libc::c_void,
    sql: *const libc::c_char,
    nbyte: libc::c_int,
    stmt: *mut *mut libc::c_void,
    tail: *mut *const libc::c_char,
) -> libc::c_int {
    sqlite_prepare_common(
        &REAL_SQLITE3_PREPARE,
        b"sqlite3_prepare",
        db,
        sql,
        nbyte,
        stmt,
        tail,
    )
}

#[no_mangle]
pub unsafe extern "C" fn sqlite3_prepare_v2(
    db: *mut libc::c_void,
    sql: *const libc::c_char,
    nbyte: libc::c_int,
    stmt: *mut *mut libc::c_void,
    tail: *mut *const libc::c_char,
) -> libc::c_int {
    sqlite_prepare_common(
        &REAL_SQLITE3_PREPARE_V2,
        b"sqlite3_prepare_v2",
        db,
        sql,
        nbyte,
        stmt,
        tail,
    )
}

#[no_mangle]
pub unsafe extern "C" fn sqlite3_prepare_v3(
    db: *mut libc::c_void,
    sql: *const libc::c_char,
    nbyte: libc::c_int,
    flags: libc::c_uint,
    stmt: *mut *mut libc::c_void,
    tail: *mut *const libc::c_char,
) -> libc::c_int {
    emit_sql_bytes(b"sqlite3_prepare_v3", sql, sqlite_prepare_count(sql, nbyte));
    let real = REAL_SQLITE3_PREPARE_V3.ptr() as *const ();
    if real.is_null() {
        return SQLITE_ERROR;
    }
    let real: unsafe extern "C" fn(
        *mut libc::c_void,
        *const libc::c_char,
        libc::c_int,
        libc::c_uint,
        *mut *mut libc::c_void,
        *mut *const libc::c_char,
    ) -> libc::c_int = std::mem::transmute(real);
    real(db, sql, nbyte, flags, stmt, tail)
}

#[no_mangle]
pub unsafe extern "C" fn PQexec(
    conn: *mut libc::c_void,
    query: *const libc::c_char,
) -> *mut libc::c_void {
    emit_sql(b"PQexec", query);
    let real = REAL_PQEXEC.ptr() as *const ();
    if real.is_null() {
        return std::ptr::null_mut();
    }
    let real: unsafe extern "C" fn(*mut libc::c_void, *const libc::c_char) -> *mut libc::c_void =
        std::mem::transmute(real);
    real(conn, query)
}

#[no_mangle]
pub unsafe extern "C" fn PQexecParams(
    conn: *mut libc::c_void,
    command: *const libc::c_char,
    n_params: libc::c_int,
    param_types: *const libc::c_uint,
    param_values: *const *const libc::c_char,
    param_lengths: *const libc::c_int,
    param_formats: *const libc::c_int,
    result_format: libc::c_int,
) -> *mut libc::c_void {
    emit_sql(b"PQexecParams", command);
    let real = REAL_PQEXECPARAMS.ptr() as *const ();
    if real.is_null() {
        return std::ptr::null_mut();
    }
    let real: unsafe extern "C" fn(
        *mut libc::c_void,
        *const libc::c_char,
        libc::c_int,
        *const libc::c_uint,
        *const *const libc::c_char,
        *const libc::c_int,
        *const libc::c_int,
        libc::c_int,
    ) -> *mut libc::c_void = std::mem::transmute(real);
    real(
        conn,
        command,
        n_params,
        param_types,
        param_values,
        param_lengths,
        param_formats,
        result_format,
    )
}

#[no_mangle]
pub unsafe extern "C" fn mysql_query(
    mysql: *mut libc::c_void,
    stmt: *const libc::c_char,
) -> libc::c_int {
    emit_sql(b"mysql_query", stmt);
    let real = REAL_MYSQL_QUERY.ptr() as *const ();
    if real.is_null() {
        return 1;
    }
    let real: unsafe extern "C" fn(*mut libc::c_void, *const libc::c_char) -> libc::c_int =
        std::mem::transmute(real);
    real(mysql, stmt)
}

#[no_mangle]
pub unsafe extern "C" fn mysql_real_query(
    mysql: *mut libc::c_void,
    stmt: *const libc::c_char,
    length: libc::c_ulong,
) -> libc::c_int {
    // `mysql_real_query` is the COUNTED query API: `stmt` is exactly `length`
    // bytes, may contain embedded NULs, and need not be NUL-terminated. Bounding
    // by `length` avoids a strlen OOB read on a non-terminated buffer.
    emit_sql_bytes(b"mysql_real_query", stmt, Some(length as usize));
    let real = REAL_MYSQL_REAL_QUERY.ptr() as *const ();
    if real.is_null() {
        return 1;
    }
    let real: unsafe extern "C" fn(
        *mut libc::c_void,
        *const libc::c_char,
        libc::c_ulong,
    ) -> libc::c_int = std::mem::transmute(real);
    real(mysql, stmt, length)
}

pub struct Sql;

impl crate::sdk::FakeResource for Sql {
    fn name(&self) -> &'static str {
        "sql"
    }
    fn intercepts(&self) -> &'static [&'static [u8]] {
        &[
            b"sqlite3_exec\0",
            b"sqlite3_prepare\0",
            b"sqlite3_prepare_v2\0",
            b"sqlite3_prepare_v3\0",
            b"PQexec\0",
            b"PQexecParams\0",
            b"mysql_query\0",
            b"mysql_real_query\0",
        ]
    }
    fn is_enabled(&self) -> bool {
        true
    }
    fn describe(&self) -> &'static str {
        "audit fuzz-controlled SQL text reaching database-execution APIs"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Regression (security review, HIGH): the counted SQL APIs (mysql_real_query,
    // sqlite prepare with nbyte >= 0) must bound the read by the count, never
    // strlen-scan a buffer that need not be NUL-terminated.
    #[test]
    fn counted_sql_text_uses_length_not_strlen() {
        // A counted buffer with an embedded NUL and NO trailing NUL. strlen would
        // stop at the embedded NUL (wrong text) or, with no NUL at all, read out
        // of bounds. The counted path returns exactly the `n` bytes.
        let buf: [u8; 5] = [b'S', b'E', 0, b'L', b'X'];
        let got = unsafe { sql_text(buf.as_ptr() as *const libc::c_char, Some(buf.len())) };
        assert_eq!(got, Some(&buf[..]));

        // NUL-terminated path stops at the first NUL.
        let cstr = b"SEL\0LX";
        let got = unsafe { sql_text(cstr.as_ptr() as *const libc::c_char, None) };
        assert_eq!(got, Some(&b"SEL"[..]));

        // Null / empty / zero-count guards.
        assert_eq!(unsafe { sql_text(std::ptr::null(), None) }, None);
        assert_eq!(
            unsafe { sql_text(buf.as_ptr() as *const libc::c_char, Some(0)) },
            None
        );
    }

    // sqlite `nbyte`: negative => NUL-terminated (None); non-negative => clamp to
    // the first NUL within the bound so the read stays in-bounds.
    #[test]
    fn sqlite_prepare_count_clamps_to_nul_within_bound() {
        let s = b"SELECT 1\0trailing";
        let p = s.as_ptr() as *const libc::c_char;
        assert_eq!(unsafe { sqlite_prepare_count(p, -1) }, None); // NUL-terminated
        assert_eq!(unsafe { sqlite_prepare_count(p, 8) }, Some(8)); // no NUL in first 8
        assert_eq!(unsafe { sqlite_prepare_count(p, 100) }, Some(8)); // clamps to NUL at 8
        assert_eq!(unsafe { sqlite_prepare_count(std::ptr::null(), 5) }, None);
    }
}
