//! Linear-memory growth cap for the classifier (Phase C.3-B).
//!
//! The [`wasmi::core::ResourceLimiter`] trait is the single hook by
//! which a host can bound a module's memory.  Our implementation denies
//! `memory.grow` requests that would exceed [`ClassifierConfig::max_memory_pages`](crate::ClassifierConfig)
//! and records the denial so the runtime can translate the resulting
//! trap into a typed [`ClassifierExecError::MemoryGrowthDenied`](crate::errors::ClassifierExecError)
//! rather than a generic [`ClassifierExecError::ClassifyCallTrap`](crate::errors::ClassifierExecError).
//!
//! # Denial semantics
//!
//! Returning `Ok(false)` from [`ResourceLimiter::memory_growing`] makes
//! `memory.grow` return `-1` to the guest.  Standard LLVM-compiled
//! classifiers (e.g. via Rust's `std::alloc::Allocator` path) interpret
//! `-1` as allocation failure and trap with `unreachable`, surfacing
//! as a [`wasmi::Error`] at the `classify` call-site.  A classifier
//! that gracefully handles `-1` would instead simply fail its own
//! logic and return an error-tier output; either path is acceptable.
//!
//! # Unit conversion
//!
//! The `wasmi` trait reports `current`/`desired`/`maximum` in **bytes**
//! (guaranteed multiples of [`crate::config::WASM_PAGE_SIZE`]
//! per the trait contract).  We convert to pages at the boundary so
//! [`ClassifierMemoryLimiter`] holds and reports everything in pages,
//! matching [`ClassifierConfig::max_memory_pages`](crate::ClassifierConfig).

use wasmi::core::{LimiterError, ResourceLimiter};

use crate::config::WASM_PAGE_SIZE;

/// Maximum number of elements any table in a classifier module may
/// contain after growth.  An LLVM-compiled Rust/wasm32 indirect-call
/// vtable is well under 1 000 entries for any realistic classifier;
/// 4 096 leaves ~4× headroom while preventing unbounded table-growth
/// as a side-channel for host-memory inflation.
pub const MAX_TABLE_ELEMENTS: u32 = 4_096;

/// Fresh per-invocation memory-growth limiter.
///
/// Lives inside the `Store<ClassifierMemoryLimiter>`.  The runtime reads
/// the crate-internal `denial` accessor after execute returns to decide
/// whether a classifier trap should be reported as
/// [`ClassifierExecError::MemoryGrowthDenied`](crate::errors::ClassifierExecError).
#[derive(Debug, Clone, Copy)]
pub struct ClassifierMemoryLimiter {
    cap_pages: u32,
    denial: Option<Denial>,
}

/// Recorded detail of the first denied `memory.grow`.  Subsequent grow
/// requests after the first denial do not overwrite this — the earliest
/// denial is almost always the one the caller wants to see.
///
/// Crate-internal: the public typed error surface for a denied grow is
/// [`crate::ClassifierExecError::MemoryGrowthDenied`], not this struct.
///
/// The shared `_pages` suffix on every field is deliberate: the `wasmi`
/// trait reports amounts in *bytes*, while this struct and the
/// corresponding error variant use *pages* (1 page = 64 KiB).  Naming
/// the unit in the field makes a unit-mismatch impossible to miss at
/// every access site — a memory-safety invariant the shorter names
/// (`current`/`requested`/`cap`) would obscure.
#[derive(Debug, Clone, Copy)]
#[allow(clippy::struct_field_names)]
pub(crate) struct Denial {
    pub(crate) current_pages: u32,
    pub(crate) requested_pages: u32,
    pub(crate) cap_pages: u32,
}

impl ClassifierMemoryLimiter {
    /// Construct a fresh limiter with the given page cap.
    pub fn new(cap_pages: u32) -> Self {
        Self {
            cap_pages,
            denial: None,
        }
    }

    /// Returns the denial record if any `memory.grow` was rejected.
    /// Crate-internal: the runtime reads this after execute returns to
    /// translate a guest trap into
    /// [`crate::ClassifierExecError::MemoryGrowthDenied`].
    pub(crate) fn denial(&self) -> Option<Denial> {
        self.denial
    }
}

impl ResourceLimiter for ClassifierMemoryLimiter {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> Result<bool, LimiterError> {
        // `wasmi` guarantees both amounts are multiples of WASM_PAGE_SIZE;
        // the divisions are exact.  The saturating cast guards against a
        // pathological future wasmi that reports byte counts exceeding
        // `u32::MAX * WASM_PAGE_SIZE` (theoretically impossible under
        // Wasm32, where linear memory is capped at 4 GiB = u32::MAX + 1
        // bytes, i.e. 65536 pages).
        let current_pages = pages_from_bytes(current);
        let desired_pages = pages_from_bytes(desired);

        if desired_pages > self.cap_pages {
            if self.denial.is_none() {
                self.denial = Some(Denial {
                    current_pages,
                    requested_pages: desired_pages,
                    cap_pages: self.cap_pages,
                });
            }
            return Ok(false);
        }
        Ok(true)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> Result<bool, LimiterError> {
        // `reference_types` is disabled at `Config` level, so the only
        // permissible table usage in a valid module is an indirect-call
        // vtable of `funcref`s.  Cap at `MAX_TABLE_ELEMENTS` to prevent
        // a pathological module from inflating host memory through
        // unbounded table growth as a side channel.
        if desired > MAX_TABLE_ELEMENTS as usize {
            return Ok(false);
        }
        Ok(true)
    }

    fn instances(&self) -> usize {
        // We only ever create one instance per `execute_classifier` call;
        // tighten from wasmi's 10,000 default.
        1
    }

    fn tables(&self) -> usize {
        // A well-formed classifier will have 0 or 1 table (the indirect-
        // call table emitted by LLVM's Rust backend).  Cap at 1.
        1
    }

    fn memories(&self) -> usize {
        // `multi_memory` is disabled at Config level; exactly one memory.
        1
    }
}

/// Convert a byte count to Wasm pages, saturating at `u32::MAX` if the
/// input ever exceeds the representable range.  See the call-site
/// comment for why saturation (not truncation) is the safe default.
#[allow(clippy::cast_possible_truncation)]
fn pages_from_bytes(bytes: usize) -> u32 {
    let pages = bytes / WASM_PAGE_SIZE;
    if pages > u32::MAX as usize {
        u32::MAX
    } else {
        pages as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_growth_within_cap() {
        let mut l = ClassifierMemoryLimiter::new(64);
        // 32 pages = 2 MiB
        let ok = l
            .memory_growing(0, 32 * WASM_PAGE_SIZE, None)
            .expect("no error");
        assert!(ok);
        assert!(l.denial().is_none());
    }

    #[test]
    fn allows_growth_at_exact_cap() {
        let mut l = ClassifierMemoryLimiter::new(64);
        let ok = l
            .memory_growing(0, 64 * WASM_PAGE_SIZE, None)
            .expect("no error");
        assert!(ok);
        assert!(l.denial().is_none());
    }

    #[test]
    fn denies_growth_one_page_over_cap() {
        let mut l = ClassifierMemoryLimiter::new(64);
        let ok = l
            .memory_growing(64 * WASM_PAGE_SIZE, 65 * WASM_PAGE_SIZE, None)
            .expect("no error");
        assert!(!ok);
        let d = l.denial().expect("denial recorded");
        assert_eq!(d.current_pages, 64);
        assert_eq!(d.requested_pages, 65);
        assert_eq!(d.cap_pages, 64);
    }

    #[test]
    fn first_denial_wins() {
        let mut l = ClassifierMemoryLimiter::new(64);
        let _ = l.memory_growing(0, 100 * WASM_PAGE_SIZE, None);
        let _ = l.memory_growing(0, 200 * WASM_PAGE_SIZE, None);
        let d = l.denial().expect("denial recorded");
        // Earliest denial is requested=100, not 200.
        assert_eq!(d.requested_pages, 100);
    }

    #[test]
    fn table_growth_allows_within_ceiling() {
        let mut l = ClassifierMemoryLimiter::new(64);
        // Grow within ceiling (4096) — should succeed, not touch memory-denial.
        let ok = l
            .table_growing(0, MAX_TABLE_ELEMENTS as usize, None)
            .expect("no error");
        assert!(ok);
        assert!(l.denial().is_none());
    }

    #[test]
    fn table_growth_denies_over_ceiling() {
        let mut l = ClassifierMemoryLimiter::new(64);
        // One element past the ceiling — denied.
        let ok = l
            .table_growing(0, MAX_TABLE_ELEMENTS as usize + 1, None)
            .expect("no error");
        assert!(!ok);
        // Memory denial state is unaffected by table decisions.
        assert!(l.denial().is_none());
    }

    #[test]
    fn pages_from_bytes_exact_page_multiples() {
        assert_eq!(pages_from_bytes(0), 0);
        assert_eq!(pages_from_bytes(WASM_PAGE_SIZE), 1);
        assert_eq!(pages_from_bytes(64 * WASM_PAGE_SIZE), 64);
        assert_eq!(pages_from_bytes(65_536 * WASM_PAGE_SIZE), 65_536);
    }

    #[test]
    fn pages_from_bytes_saturates_at_u32_max() {
        // Reachable only on 64-bit targets, where `usize::MAX / WASM_PAGE_SIZE`
        // exceeds `u32::MAX`.  The saturation guarantees host-side arithmetic
        // cannot silently truncate a pathological byte count into a small
        // legitimate-looking page value.
        assert_eq!(pages_from_bytes(usize::MAX), u32::MAX);
    }

    #[test]
    fn resource_caps_are_tight() {
        let l = ClassifierMemoryLimiter::new(64);
        assert_eq!(l.instances(), 1);
        assert_eq!(l.tables(), 1);
        assert_eq!(l.memories(), 1);
    }
}
