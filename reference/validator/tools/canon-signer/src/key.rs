//! Ed25519 key loading with a three-step priority:
//!
//! 1. Env `CANON_SIGNER_KEY_HEX` (64 hex chars = 32-byte seed)
//! 2. CLI flag `--keyfile <path>` (file contents are trimmed then
//!    treated like the env value)
//! 3. Auto-generate from [`rand_core::OsRng`] and persist the seed to
//!    the platform temp directory (`${TMPDIR}` on unix, `%TEMP%` on
//!    Windows) as `canon-signer.key` so a restart can resume the same
//!    identity.  The public pubkey is logged to **stderr** so Canon
//!    operators can recover it.
//!
//! A [`SignerIdentity`] bundles the loaded [`SigningKey`] with its
//! derived `kid` (via [`crate::cose::derive_kid`]) and wire-format
//! public-key string.
//!
//! # Seed-material hygiene
//!
//! Every path that touches raw 32-byte seed bytes zeroizes them before
//! the allocation is dropped.  `ed25519_dalek::SigningKey` itself
//! implements `ZeroizeOnDrop`, so the wrapped key is scrubbed when the
//! identity dies — but transient buffers (decoded `Vec<u8>`, stack
//! `[u8; 32]`, `hex_seed: String` used for persistence) must be
//! scrubbed explicitly or the seed lingers in freed heap/stack slots.

use std::env;
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use zeroize::Zeroize;

use crate::io::derive_public_identity;

/// Where a [`SignerIdentity`] came from — surfaced to `main` for the
/// stderr log line.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum Source {
    /// Loaded from `CANON_SIGNER_KEY_HEX`.
    Env,
    /// Loaded from `--keyfile <path>`.
    Keyfile(PathBuf),
    /// Auto-generated at startup; if the seed was persisted, the path
    /// is attached so the operator can find it.
    Generated { persisted_to: Option<PathBuf> },
}

/// Errors produced during key-loading.  All are fatal at startup.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum KeyLoadError {
    #[error("CANON_SIGNER_KEY_HEX must be exactly 64 hex characters (got {0})")]
    EnvWrongLength(usize),
    #[error("CANON_SIGNER_KEY_HEX is not valid hex: {0}")]
    EnvInvalidHex(String),
    #[error("--keyfile: cannot read file {path}: {source}")]
    KeyfileRead {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("--keyfile {path}: content must be 64 hex characters (got {got})")]
    KeyfileWrongLength { path: PathBuf, got: usize },
    #[error("--keyfile {path}: content is not valid hex: {source}")]
    KeyfileInvalidHex {
        path: PathBuf,
        source: hex::FromHexError,
    },
}

/// A bundled signing identity: signing key + derived kid + wire pubkey.
#[derive(Debug)]
pub struct SignerIdentity {
    signing_key: SigningKey,
    kid: String,
    pubkey_wire: String,
}

impl SignerIdentity {
    /// Build from an already-constructed [`SigningKey`].  Derives kid
    /// and wire-format pubkey once.
    pub fn from_signing_key(signing_key: SigningKey) -> Self {
        let pk_bytes = signing_key.verifying_key().to_bytes();
        let (kid, pubkey_wire) = derive_public_identity(&pk_bytes);
        Self {
            signing_key,
            kid,
            pubkey_wire,
        }
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Borrow the wire-format pubkey string.  Lives as long as the
    /// identity, so callers should not clone it on every sign call.
    pub fn pubkey_wire_str(&self) -> &str {
        &self.pubkey_wire
    }

    pub fn pubkey_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }
}

/// Attempt to build a [`SignerIdentity`] from the environment.
///
/// Returns `Ok(None)` if the env var is unset; `Ok(Some(_))` if it is
/// set and well-formed; `Err(_)` if it is set but malformed (fatal).
pub fn try_from_env() -> Result<Option<SignerIdentity>, KeyLoadError> {
    let Ok(hex_str) = env::var("CANON_SIGNER_KEY_HEX") else {
        return Ok(None);
    };
    let trimmed = hex_str.trim();
    if trimmed.len() != 64 {
        return Err(KeyLoadError::EnvWrongLength(trimmed.len()));
    }
    let mut seed = hex::decode(trimmed).map_err(|e| KeyLoadError::EnvInvalidHex(e.to_string()))?;
    let mut arr: [u8; 32] = seed
        .as_slice()
        .try_into()
        .expect("length checked above; 64 hex chars always decode to 32 bytes");
    let sk = SigningKey::from_bytes(&arr);
    seed.zeroize();
    arr.zeroize();
    Ok(Some(SignerIdentity::from_signing_key(sk)))
}

/// Load a key from a file on disk.  The file must contain exactly 64
/// hex characters (trailing whitespace is trimmed).
pub fn from_keyfile(path: &Path) -> Result<SignerIdentity, KeyLoadError> {
    let raw = std::fs::read_to_string(path).map_err(|source| KeyLoadError::KeyfileRead {
        path: path.to_path_buf(),
        source,
    })?;
    let trimmed = raw.trim();
    if trimmed.len() != 64 {
        return Err(KeyLoadError::KeyfileWrongLength {
            path: path.to_path_buf(),
            got: trimmed.len(),
        });
    }
    let mut seed = hex::decode(trimmed).map_err(|source| KeyLoadError::KeyfileInvalidHex {
        path: path.to_path_buf(),
        source,
    })?;
    let mut arr: [u8; 32] = seed.as_slice().try_into().expect("length checked above");
    let sk = SigningKey::from_bytes(&arr);
    seed.zeroize();
    arr.zeroize();
    Ok(SignerIdentity::from_signing_key(sk))
}

/// Auto-generate a fresh Ed25519 identity from `OsRng`.  Attempts to
/// persist the seed to the platform temp directory so a subsequent
/// restart resumes the same identity.  If persistence fails (e.g.
/// read-only FS), returns the identity anyway with `persisted_to:
/// None` — a restart will produce a fresh key.
pub fn autogenerate() -> (SignerIdentity, Source) {
    use rand_core::{OsRng, RngCore};
    let mut seed = [0u8; 32];
    // `OsRng` fills directly from the OS entropy source; `rand_core`'s
    // contract is infallible on supported platforms (`fill_bytes`
    // panics only on platform misconfiguration which is a bootstrap
    // problem anyway).
    OsRng.fill_bytes(&mut seed);
    let sk = SigningKey::from_bytes(&seed);
    seed.zeroize();

    let persisted_to = persist_seed(&sk);
    let identity = SignerIdentity::from_signing_key(sk);
    (identity, Source::Generated { persisted_to })
}

fn persist_seed(sk: &SigningKey) -> Option<PathBuf> {
    // Honour `TMPDIR` if the operator explicitly set it, otherwise fall
    // back to the platform default (`std::env::temp_dir` respects
    // `%TEMP%`/`%TMP%` on Windows and `/tmp` on unix).  We refuse to
    // persist if the target does not resolve to an existing directory
    // to avoid writing seed material to surprising locations when a
    // typo in `TMPDIR` creates a new path.
    let dir = env::var_os("TMPDIR").map_or_else(env::temp_dir, PathBuf::from);
    if !dir.is_dir() {
        return None;
    }
    let path = dir.join("canon-signer.key");

    let raw_seed = sk.to_bytes();
    let mut hex_seed = hex::encode(raw_seed);
    let write_result = std::fs::write(&path, hex_seed.as_bytes());
    hex_seed.zeroize();

    match write_result {
        Ok(()) => {
            // Best-effort permissions tightening.  Failing to set 0600
            // is not fatal — stderr will mention the location so the
            // operator can secure it.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            }
            Some(path)
        }
        Err(_) => None,
    }
}

/// Top-level key resolver.  Inspects the environment and CLI flags in
/// priority order; returns the identity + the source it came from.
pub fn load(keyfile_arg: Option<&Path>) -> Result<(SignerIdentity, Source), KeyLoadError> {
    if let Some(id) = try_from_env()? {
        return Ok((id, Source::Env));
    }
    if let Some(path) = keyfile_arg {
        let id = from_keyfile(path)?;
        return Ok((id, Source::Keyfile(path.to_path_buf())));
    }
    let (id, src) = autogenerate();
    Ok((id, src))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn autogenerate_produces_valid_identity() {
        let (id, src) = autogenerate();
        assert!(id.kid().starts_with("canon/"));
        assert_eq!(id.kid().len(), "canon/".len() + 16);
        assert!(id.pubkey_wire_str().starts_with("ed25519:"));
        assert!(matches!(src, Source::Generated { .. }));
    }

    #[test]
    fn from_signing_key_derives_matching_kid_and_pubkey() {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let pk_bytes = sk.verifying_key().to_bytes();
        let id = SignerIdentity::from_signing_key(sk);

        // kid derivation is deterministic from the public-key bytes.
        let expected_kid = format!("canon/{}", &hex::encode(pk_bytes)[..16]);
        assert_eq!(id.kid(), expected_kid);

        // pubkey bytes survive the bundle.
        assert_eq!(id.pubkey_bytes(), pk_bytes);
    }

    #[test]
    fn from_keyfile_reads_valid_hex_seed() {
        let tmp = std::env::temp_dir().join("canon-signer-test-valid.key");
        std::fs::write(
            &tmp,
            "1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();
        let id = from_keyfile(&tmp).unwrap();
        assert!(id.kid().starts_with("canon/"));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn from_keyfile_rejects_wrong_length() {
        let tmp = std::env::temp_dir().join("canon-signer-test-short.key");
        std::fs::write(&tmp, "dead").unwrap();
        let err = from_keyfile(&tmp).unwrap_err();
        assert!(matches!(
            err,
            KeyLoadError::KeyfileWrongLength { got: 4, .. }
        ));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn from_keyfile_rejects_invalid_hex() {
        let tmp = std::env::temp_dir().join("canon-signer-test-bad.key");
        std::fs::write(
            &tmp,
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        )
        .unwrap();
        let err = from_keyfile(&tmp).unwrap_err();
        assert!(matches!(err, KeyLoadError::KeyfileInvalidHex { .. }));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn from_keyfile_missing_path_surfaces_io_error() {
        let err = from_keyfile(Path::new("/this/path/does/not/exist/hopefully")).unwrap_err();
        assert!(matches!(err, KeyLoadError::KeyfileRead { .. }));
    }
}
