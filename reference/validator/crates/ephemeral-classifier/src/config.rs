//! Caller-configurable knobs for classifier execution (Phase C.3-B).
//!
//! [`ClassifierConfig`] centralizes all three safety-envelope ceilings —
//! CPU (fuel), host-allocation (output-size cap), and guest memory
//! (linear-memory page cap) — into a single explicit struct, replacing
//! Phase C.3-A's hardcoded crate-level constants.
//!
//! The defaults are tuned for the spec §4 classifier profile:
//! CBOR-parsing + rule-matching, well under 10k instructions per call,
//! output ≤ 64 KiB, linear memory ≤ a few MiB.  Each default carries an
//! order of magnitude of headroom above any realistic legitimate
//! classifier, while still bounding a malicious or buggy module tightly
//! enough to prevent a single call from stalling or OOM-killing the
//! validator process.
//!
//! Callers MAY override any field; the underlying enforcement points
//! (fuel metering, output-size ceiling, `ResourceLimiter`) honor the
//! values exactly with no additional clamping.

/// Default fuel ceiling for one `classify` invocation (100 million wasmi
/// instructions ≈ 1 second on modern `x86_64`).
///
/// See [`ClassifierConfig::fuel_budget`] for rationale.
pub const DEFAULT_FUEL_BUDGET: u64 = 100_000_000;

/// Default host-side ceiling on `output_len` claimed by the packed
/// locator (1 MiB; ~16× any realistic [`crate::ClassifierOutput`]).
///
/// See [`ClassifierConfig::max_output_bytes`] for rationale.
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 1 << 20;

/// Default cap on the classifier's linear-memory growth (64 Wasm pages
/// = 4 MiB).  One Wasm page is 64 KiB.
///
/// See [`ClassifierConfig::max_memory_pages`] for rationale.
pub const DEFAULT_MAX_MEMORY_PAGES: u32 = 64;

/// Bytes per Wasm linear-memory page per the Wasm core spec.
///
/// Re-exported as a crate-public constant so callers configuring
/// [`ClassifierConfig::max_memory_pages`] can reason about the
/// byte-level cap without magic numbers.
pub const WASM_PAGE_SIZE: usize = 65_536;

/// Execution-time configuration for [`crate::execute_classifier`].
///
/// Construct with [`ClassifierConfig::default`] for spec-§4-tuned
/// defaults or with struct-literal syntax for custom bounds.  The type
/// is [`Copy`] so it may be shared across threads and passed into
/// repeated invocations without clone overhead.
///
/// # Example
/// ```
/// use ephemeral_classifier::ClassifierConfig;
///
/// // Tighter defaults for a production-grade validator:
/// let cfg = ClassifierConfig {
///     fuel_budget: 10_000_000,           // 100ms ceiling
///     max_output_bytes: 64 * 1024,       // 64 KiB
///     max_memory_pages: 16,              // 1 MiB
/// };
/// # let _ = cfg;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassifierConfig {
    /// Per-invocation fuel ceiling.  One wasmi instruction consumes one
    /// fuel unit; `classify` traps with
    /// [`crate::ClassifierExecError::ClassifyCallTrap`] on exhaustion.
    ///
    /// Rationale for the default ([`DEFAULT_FUEL_BUDGET`]): spec-§4
    /// classifiers perform simple table lookups + string comparisons
    /// (< 10k instructions per call); 100M instructions is an order of
    /// magnitude safety margin while still bounding any infinite-loop
    /// or quadratic-pathological module to sub-second wall time.
    pub fuel_budget: u64,

    /// Ceiling on the byte length the classifier may claim in its
    /// packed output locator.  Enforced *before* the host allocates
    /// the receiving buffer, so a 4 GiB length field cannot OOM-kill
    /// the validator process.
    ///
    /// Rationale for the default ([`DEFAULT_MAX_OUTPUT_BYTES`]): a
    /// [`crate::ClassifierOutput`] with maximal escalations is under
    /// 64 KiB; 1 MiB gives ~16× headroom while rejecting any
    /// attacker-controlled `u32::MAX`-adjacent claim.
    pub max_output_bytes: usize,

    /// Maximum number of 64 KiB Wasm pages the classifier's linear
    /// memory may grow to.  Enforced via a `ResourceLimiter` installed
    /// on the `Store`; exceeding the cap either causes `memory.grow`
    /// to return -1 to the guest (which typically triggers a
    /// subsequent trap) or surfaces as
    /// [`crate::ClassifierExecError::MemoryGrowthDenied`] with the
    /// exact denial-point recorded.
    ///
    /// Rationale for the default ([`DEFAULT_MAX_MEMORY_PAGES`]):
    /// 64 pages = 4 MiB.  CBOR input + CBOR output + runtime state
    /// of a realistic classifier is under 3 MiB; 4 MiB gives ~33%
    /// headroom without permitting moderate-heap allocation attacks.
    pub max_memory_pages: u32,
}

impl Default for ClassifierConfig {
    fn default() -> Self {
        Self {
            fuel_budget: DEFAULT_FUEL_BUDGET,
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            max_memory_pages: DEFAULT_MAX_MEMORY_PAGES,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_matches_published_constants() {
        let cfg = ClassifierConfig::default();
        assert_eq!(cfg.fuel_budget, DEFAULT_FUEL_BUDGET);
        assert_eq!(cfg.max_output_bytes, DEFAULT_MAX_OUTPUT_BYTES);
        assert_eq!(cfg.max_memory_pages, DEFAULT_MAX_MEMORY_PAGES);
    }

    #[test]
    fn is_copy_and_clone_and_eq() {
        // Compile-time witnesses that the documented trait bounds hold.
        fn assert_copy<T: Copy>() {}
        fn assert_clone<T: Clone>() {}
        fn assert_eq_trait<T: Eq + PartialEq>() {}
        fn assert_debug<T: std::fmt::Debug>() {}
        assert_copy::<ClassifierConfig>();
        assert_clone::<ClassifierConfig>();
        assert_eq_trait::<ClassifierConfig>();
        assert_debug::<ClassifierConfig>();
    }

    #[test]
    fn default_memory_cap_is_realistic() {
        // Guard against an accidental regression to the pre-C.3-B default
        // of 256 pages = 16 MiB (too generous against moderate-heap
        // allocation attacks) or to 1 page = 64 KiB (would break legit
        // classifiers).  64 pages is the deliberate middle ground.
        assert_eq!(DEFAULT_MAX_MEMORY_PAGES, 64);
        assert_eq!(
            DEFAULT_MAX_MEMORY_PAGES as usize * WASM_PAGE_SIZE,
            4 * 1024 * 1024
        );
    }

    #[test]
    fn wasm_page_size_matches_spec() {
        // Guard against accidental off-by-one — the Wasm core spec fixes
        // the page size at 64 KiB.  If this ever changes, the Limiter
        // unit conversion (bytes <-> pages) must be audited.
        assert_eq!(WASM_PAGE_SIZE, 65_536);
    }
}
