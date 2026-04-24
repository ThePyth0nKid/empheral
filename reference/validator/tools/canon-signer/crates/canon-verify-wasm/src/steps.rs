//! Step-by-step instrumentation for the transparency panel.
//!
//! Every verification pass records exactly ten named steps in a fixed
//! order.  When a step fails, all subsequent steps are marked
//! `skipped` and the overall result carries the first step's error.
//! The UI reads this list and renders ✓ / ✗ / — glyphs so the viewer
//! sees *where* a verification breaks, not just *that* it did.

use serde::Serialize;

/// Fixed step names in their execution order.  Indexed 0..10.
pub const STEP_NAMES: [&str; 10] = [
    "Decode envelope hex",
    "Parse CBOR as COSE_Sign1",
    "Extract protected header, payload, signature",
    "Extract kid from protected header",
    "Parse public key",
    "Derive expected kid from public key",
    "Build to-be-signed bytes (TBS)",
    "Verify Ed25519 signature over TBS",
    "Compute event_hash = SHA-256(payload)",
    "Decode payload as 7-field Canon fact array",
];

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    Ok,
    Fail,
    Skipped,
}

#[derive(Debug, Serialize)]
pub struct Step {
    pub name: String,
    pub status: StepStatus,
    pub detail: String,
}

/// Fluent builder that enforces the "all-or-fail, then skip the rest"
/// contract.  Each call to [`Self::record`] appends one [`Step`] and
/// flips the internal `failed` latch on `StepStatus::Fail`.  Once
/// latched, further `record` calls produce `skipped` entries only.
#[derive(Debug)]
pub struct StepsBuilder {
    steps: Vec<Step>,
    failed: bool,
}

impl StepsBuilder {
    pub fn new() -> Self {
        Self {
            steps: Vec::with_capacity(STEP_NAMES.len()),
            failed: false,
        }
    }

    /// Record an `ok` step with a human-readable detail.
    pub fn ok(&mut self, idx: usize, detail: impl Into<String>) {
        self.steps.push(Step {
            name: STEP_NAMES[idx].to_string(),
            status: StepStatus::Ok,
            detail: detail.into(),
        });
    }

    /// Record a `fail` step.  Latches `failed` → all subsequent
    /// [`Self::ok`] calls are upgraded to `skipped`, and
    /// [`Self::fill_skipped`] marks any untouched tail.
    pub fn fail(&mut self, idx: usize, detail: impl Into<String>) {
        self.steps.push(Step {
            name: STEP_NAMES[idx].to_string(),
            status: StepStatus::Fail,
            detail: detail.into(),
        });
        self.failed = true;
    }

    /// Has any prior step failed?  Callers use this to short-circuit
    /// expensive work like signature verification after a cheap
    /// structural check has already failed.
    pub fn has_failed(&self) -> bool {
        self.failed
    }

    /// Mark every step from `next_idx..STEP_NAMES.len()` as skipped.
    /// Called once at the end of a failed verification path so the
    /// returned `steps` array always has exactly 10 entries.
    pub fn fill_skipped(&mut self) {
        for idx in self.steps.len()..STEP_NAMES.len() {
            self.steps.push(Step {
                name: STEP_NAMES[idx].to_string(),
                status: StepStatus::Skipped,
                detail: String::new(),
            });
        }
    }

    pub fn into_vec(self) -> Vec<Step> {
        self.steps
    }
}

impl Default for StepsBuilder {
    fn default() -> Self {
        Self::new()
    }
}
