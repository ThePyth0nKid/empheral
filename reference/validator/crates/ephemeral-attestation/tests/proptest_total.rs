//! Totality tests: [`verify_nitro_attestation`] must never panic on
//! arbitrary byte input — no infinite loops, no stack overflows.

use ephemeral_attestation::{verify_nitro_attestation, NitroRootSet, MAX_NITRO_DOC_BYTES};
use proptest::prelude::*;

proptest! {
    #[test]
    fn verify_nitro_is_total(
        bytes in prop::collection::vec(any::<u8>(), 0..MAX_NITRO_DOC_BYTES)
    ) {
        let roots = NitroRootSet::new();
        // Must return Ok or Err — never panic, never recurse unboundedly.
        // `current_time = 0` is deliberate: totality is about the pipeline
        // never diverging, not about any particular success/failure verdict.
        let _ = verify_nitro_attestation(&bytes, &roots, None, 0);
    }
}

#[cfg(feature = "rekor")]
mod rekor_totality {
    use ephemeral_attestation::rekor::{verify_rekor_inclusion, RekorEntry};
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn verify_rekor_is_total(
            leaf_hash in prop::array::uniform32(any::<u8>()),
            tree_root in prop::array::uniform32(any::<u8>()),
            proof_len in 0usize..=16,
            index in any::<u64>(),
            tree_size in 1u64..=u64::MAX,
        ) {
            // Build a random proof path
            let proof_path: Vec<[u8; 32]> = (0..proof_len)
                .map(|_| [0u8; 32])
                .collect();
            let entry = RekorEntry {
                leaf_hash,
                proof_path,
                index,
                tree_size,
            };
            let payload_hash = leaf_hash;
            let _ = verify_rekor_inclusion(&entry, &payload_hash, &tree_root);
        }
    }
}
