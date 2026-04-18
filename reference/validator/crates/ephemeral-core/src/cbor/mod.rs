//! Canonical CBOR encoder / decoder for [`CoreValue`].
//!
//! Implements **RFC 8949 §4.2 Core Deterministic Encoding** directly over
//! [`std::io::Write`] — no dependency on an existing CBOR crate because every
//! surveyed Rust crate (ciborium, minicbor, cbor4ii) violates at least one
//! canonical requirement by default (NaN quieting, lossy float promotion, or
//! stable-but-non-canonical map ordering).
//!
//! # Hard requirements
//!
//! - **Shortest-form integers** (`arg` embedded when `≤ 23`; 1/2/4/8-byte
//!   extension otherwise).
//! - **Shortest-lossless float**: prefer f16 if bit-exact, else f32, else f64.
//! - **Canonical NaN**: `0xf9 0x7e 0x00` (single payload, no signalling NaNs).
//! - **Canonical ±Inf**: `0xf9 0x7c 0x00` / `0xf9 0xfc 0x00`.
//! - **`-0.0` preservation** — unlike JSON, IEEE-754 negative zero survives.
//! - **No indefinite-length items**.
//! - **Map keys sorted by byte-lexicographic order** of their CBOR encoding
//!   ("encoded-bytes sort", RFC 8949 §4.2.1). Duplicate keys rejected.
//! - **32 MiB output cap** ([`MAX_CBOR_BYTES`]).
//! - **Depth cap** ([`MAX_CBOR_DEPTH`] = 64) matches the JSON codec's.
//!
//! # R7.C6 SET ordering
//!
//! The canonicalization and delegation executors (Session 2) apply SET
//! semantics *at the [`CoreValue`] level* via [`canonicalize_set_elements`]
//! before encoding. The encoder itself never has to know which arrays are
//! SET-typed — determinism at the CBOR layer is purely about map-key ordering.
//!
//! # Limitations
//!
//! - CBOR **tags** (Major 6) are not emitted. Our [`CoreValue`] does not carry
//!   tagged values; bignums (Tag 2/3) would be needed only for integers
//!   outside `[-2^64, 2^64-1]`, and JSON cannot express those.
//! - CBOR **simple values** other than `true/false/null` are not emitted.

use crate::codec::CoreValue;

/// Hard cap on total encoded CBOR bytes. Matches [`crate::suite_file::MAX_SUITE_FILE_BYTES`]
/// and defends against adversarial depth-bombs or bytes-explosion inputs.
pub const MAX_CBOR_BYTES: usize = 32 * 1024 * 1024;

/// Maximum nesting depth during encode/decode. Mirrors
/// [`crate::codec::MAX_JSON_DEPTH`] so JSON → CoreValue → CBOR never rejects
/// a document that the JSON codec accepted.
pub const MAX_CBOR_DEPTH: usize = 64;

/// CBOR encoder / decoder errors. Domain reject codes (e.g. `unicode-not-nfc`)
/// are modelled per-suite and never reach this enum.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CborError {
    #[error("encoded output exceeds {MAX_CBOR_BYTES} bytes")]
    Limit,
    #[error("value nesting exceeds {MAX_CBOR_DEPTH}")]
    DepthExceeded,
    #[error("map contains duplicate keys after canonical encoding")]
    DuplicateMapKey,
    #[error("integer {0} is outside representable CBOR range (requires bignum tag)")]
    IntOutOfCborRange(i128),
    #[error("decode: unexpected end of input")]
    UnexpectedEof,
    #[error("decode: indefinite-length item forbidden by deterministic encoding")]
    IndefiniteLength,
    #[error("decode: unsupported major type or simple value: {0:#04x}")]
    Unsupported(u8),
    #[error("decode: trailing bytes after top-level value")]
    TrailingBytes,
    #[error("decode: invalid UTF-8 in text string")]
    InvalidUtf8,
    #[error("decode: tag values are not supported by this validator")]
    TagsNotSupported,
    #[error("decode: reserved additional-information value 28-30")]
    ReservedAdditional,
}

// ---------------- encoder ---------------------------------------------------

/// Encode a [`CoreValue`] as canonical CBOR (RFC 8949 §4.2).
///
/// The encoder is pure: no external state, no dependency on input map
/// ordering. Two calls on structurally equivalent values produce byte-identical
/// outputs — this is the *determinism invariant*. [`canonicalize_set_elements`]
/// must be applied to SET-typed arrays by the caller before encoding.
pub fn encode(v: &CoreValue) -> Result<Vec<u8>, CborError> {
    let mut out = Vec::new();
    write_value(&mut out, v, 0)?;
    Ok(out)
}

/// Decode a canonical CBOR document back into a [`CoreValue`].
///
/// The decoder is intentionally permissive about input *ordering*: it accepts
/// maps that are not byte-lex sorted (returning the structural value). Use
/// [`assert_roundtrip`] to assert canonical-in/canonical-out byte equality.
pub fn decode(bytes: &[u8]) -> Result<CoreValue, CborError> {
    let mut cur = Cursor::new(bytes);
    let v = read_value(&mut cur, 0)?;
    if !cur.is_at_end() {
        return Err(CborError::TrailingBytes);
    }
    Ok(v)
}

/// Encode, decode, re-encode, assert byte-equality.
///
/// The bit-level idempotence property: for any `v`, `encode(decode(encode(v))) == encode(v)`.
/// Non-byte-equal output from a canonical encoder is a bug; this helper returns
/// [`CborError::Unsupported`] with the first diverging byte for diagnostics.
pub fn assert_roundtrip(v: &CoreValue) -> Result<(), CborError> {
    let bytes1 = encode(v)?;
    let decoded = decode(&bytes1)?;
    let bytes2 = encode(&decoded)?;
    if bytes1 == bytes2 {
        Ok(())
    } else {
        let first_diff = bytes1
            .iter()
            .zip(bytes2.iter())
            .position(|(a, b)| a != b)
            .unwrap_or(bytes1.len().min(bytes2.len()));
        Err(CborError::Unsupported(
            u8::try_from(first_diff & 0xff).unwrap_or(0),
        ))
    }
}

/// Canonicalize an array-in-place as a SET: sort by encoded bytes, deduplicate.
///
/// Applied by canonicalization / delegation executors to fields enumerated in
/// **design-final-v2.md §4.2.1** (e.g. `Mandate.cap`, `DelegationScope.integrations`,
/// `Tariff.step_up_allowlist`). Not applied by the encoder itself — typing is
/// caller-specified so positional arrays (SEQUENCE-typed) remain untouched.
pub fn canonicalize_set_elements(arr: &mut Vec<CoreValue>) -> Result<(), CborError> {
    let mut indexed: Vec<(Vec<u8>, CoreValue)> = Vec::with_capacity(arr.len());
    for v in arr.drain(..) {
        let bytes = encode(&v)?;
        indexed.push((bytes, v));
    }
    indexed.sort_by(|a, b| a.0.cmp(&b.0));
    indexed.dedup_by(|a, b| a.0 == b.0);
    *arr = indexed.into_iter().map(|(_, v)| v).collect();
    Ok(())
}

// ---- internal: write -------------------------------------------------------

fn put(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), CborError> {
    if out.len().saturating_add(bytes.len()) > MAX_CBOR_BYTES {
        return Err(CborError::Limit);
    }
    out.extend_from_slice(bytes);
    Ok(())
}

/// Write a major-type header + `arg` in the shortest form.
#[allow(clippy::cast_possible_truncation)]
fn write_head(out: &mut Vec<u8>, major: u8, arg: u64) -> Result<(), CborError> {
    let mt = major << 5;
    if arg <= 23 {
        put(out, &[mt | (arg as u8)])
    } else if let Ok(a) = u8::try_from(arg) {
        put(out, &[mt | 24, a])
    } else if let Ok(a) = u16::try_from(arg) {
        let b = a.to_be_bytes();
        put(out, &[mt | 25, b[0], b[1]])
    } else if let Ok(a) = u32::try_from(arg) {
        let b = a.to_be_bytes();
        put(out, &[mt | 26, b[0], b[1], b[2], b[3]])
    } else {
        let b = arg.to_be_bytes();
        put(
            out,
            &[mt | 27, b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]],
        )
    }
}

fn write_value(out: &mut Vec<u8>, v: &CoreValue, depth: usize) -> Result<(), CborError> {
    if depth > MAX_CBOR_DEPTH {
        return Err(CborError::DepthExceeded);
    }
    match v {
        CoreValue::Null => put(out, &[0xf6]),
        CoreValue::Bool(false) => put(out, &[0xf4]),
        CoreValue::Bool(true) => put(out, &[0xf5]),
        CoreValue::Int(i) => write_int(out, *i),
        CoreValue::Float(f) => write_float(out, *f),
        CoreValue::Text(s) => {
            let bytes = s.as_bytes();
            let len = u64::try_from(bytes.len()).map_err(|_| CborError::Limit)?;
            write_head(out, 3, len)?;
            put(out, bytes)
        }
        CoreValue::Bytes(b) => {
            let len = u64::try_from(b.len()).map_err(|_| CborError::Limit)?;
            write_head(out, 2, len)?;
            put(out, b)
        }
        CoreValue::Array(items) => {
            let len = u64::try_from(items.len()).map_err(|_| CborError::Limit)?;
            write_head(out, 4, len)?;
            for it in items {
                write_value(out, it, depth + 1)?;
            }
            Ok(())
        }
        CoreValue::Map(entries) => write_map(out, entries, depth),
    }
}

fn write_int(out: &mut Vec<u8>, i: i128) -> Result<(), CborError> {
    if i >= 0 {
        let u = u64::try_from(i).map_err(|_| CborError::IntOutOfCborRange(i))?;
        write_head(out, 0, u)
    } else {
        // MT1 argument is the unsigned `-1 - n`. For i in [-(2^64), -1] the
        // argument fits in u64: `-1 - i` is at most 2^64-1.
        let neg_minus_one: i128 = -1 - i;
        let u = u64::try_from(neg_minus_one).map_err(|_| CborError::IntOutOfCborRange(i))?;
        write_head(out, 1, u)
    }
}

fn write_float(out: &mut Vec<u8>, f: f64) -> Result<(), CborError> {
    if f.is_nan() {
        return put(out, &[0xf9, 0x7e, 0x00]);
    }
    if f.is_infinite() {
        let high: u8 = if f.is_sign_negative() { 0xfc } else { 0x7c };
        return put(out, &[0xf9, high, 0x00]);
    }
    if let Some(bits_f16) = f64_to_f16_exact(f) {
        let b = bits_f16.to_be_bytes();
        return put(out, &[0xf9, b[0], b[1]]);
    }
    if let Some(bits_f32) = f64_to_f32_exact(f) {
        let b = bits_f32.to_be_bytes();
        return put(out, &[0xfa, b[0], b[1], b[2], b[3]]);
    }
    let b = f.to_bits().to_be_bytes();
    put(
        out,
        &[0xfb, b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]],
    )
}

/// Returns `Some(f16_bits)` iff `f` is losslessly representable as IEEE 754
/// binary16. Preserves `-0.0` via the sign bit. NaN/Inf are handled upstream.
fn f64_to_f16_exact(f: f64) -> Option<u16> {
    let bits = f.to_bits();
    let sign: u16 = u16::from(((bits >> 63) & 1) as u8);
    let exp_f64 = ((bits >> 52) & 0x7ff) as i32;
    let mantissa_f64 = bits & 0x000f_ffff_ffff_ffff_u64;

    // ±0
    if exp_f64 == 0 && mantissa_f64 == 0 {
        return Some(sign << 15);
    }
    // f64 subnormals are far smaller than any f16 subnormal; never fit losslessly.
    if exp_f64 == 0 {
        return None;
    }

    let unbiased = exp_f64 - 1023;
    // f16 normal range: unbiased exponent in [-14, 15].
    if (-14..=15).contains(&unbiased) {
        // Mantissa must fit in 10 bits: low 42 of f64's 52-bit mantissa must be zero.
        if mantissa_f64 & ((1_u64 << 42) - 1) != 0 {
            return None;
        }
        let mantissa_f16 = ((mantissa_f64 >> 42) & 0x3ff) as u16;
        #[allow(clippy::cast_sign_loss)]
        let exp_f16 = (unbiased + 15) as u16; // 0..=31 inclusive of boundary
        return Some((sign << 15) | (exp_f16 << 10) | mantissa_f16);
    }

    // f16 subnormal range: -24 ≤ unbiased ≤ -15.
    // f16 subnormal value = (-1)^s * 2^-14 * (m/1024).
    // The f64 representation of that exact value has unbiased exponent
    // in [-24, -15] and a specific mantissa pattern. We reconstruct the
    // candidate f16 and verify via bits-compare.
    if (-24..=-15).contains(&unbiased) {
        // Effective shift: the implicit leading 1 of f64 becomes part of the
        // f16 subnormal mantissa. Combined mantissa = (1 << 52) | mantissa_f64.
        let combined = (1_u64 << 52) | mantissa_f64;
        // Position the 10-bit subnormal mantissa. Subnormal f16 has exponent
        // field 0 and represents 2^-14 * (m/1024). For unbiased = -14 - k
        // (k in 1..=10), we shift right by 42 + k.
        let k = (-14 - unbiased) as u32; // k in 1..=10
        let shift = 42_u32 + k;
        // Low `shift` bits of combined must be zero to be lossless.
        if combined & ((1_u64 << shift) - 1) != 0 {
            return None;
        }
        let mantissa_f16 = (combined >> shift) as u16;
        return Some((sign << 15) | mantissa_f16);
    }

    None
}

/// Returns `Some(f32_bits)` iff `f` is losslessly representable as IEEE 754
/// binary32. `.to_bits()` roundtrip preserves sign on zero.
fn f64_to_f32_exact(f: f64) -> Option<u32> {
    #[allow(clippy::cast_possible_truncation)]
    let as_f32 = f as f32;
    if f64::from(as_f32).to_bits() == f.to_bits() {
        Some(as_f32.to_bits())
    } else {
        None
    }
}

fn write_map(
    out: &mut Vec<u8>,
    entries: &[(CoreValue, CoreValue)],
    depth: usize,
) -> Result<(), CborError> {
    if depth > MAX_CBOR_DEPTH {
        return Err(CborError::DepthExceeded);
    }
    let mut encoded: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(entries.len());
    for (k, v) in entries {
        let mut kb = Vec::new();
        write_value(&mut kb, k, depth + 1)?;
        let mut vb = Vec::new();
        write_value(&mut vb, v, depth + 1)?;
        encoded.push((kb, vb));
    }
    encoded.sort_by(|a, b| a.0.cmp(&b.0));
    if encoded.windows(2).any(|w| w[0].0 == w[1].0) {
        return Err(CborError::DuplicateMapKey);
    }
    let len = u64::try_from(encoded.len()).map_err(|_| CborError::Limit)?;
    write_head(out, 5, len)?;
    for (kb, vb) in encoded {
        put(out, &kb)?;
        put(out, &vb)?;
    }
    Ok(())
}

// ---- internal: read --------------------------------------------------------

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    fn is_at_end(&self) -> bool {
        self.pos >= self.data.len()
    }
    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }
    fn read_u8(&mut self) -> Result<u8, CborError> {
        let b = *self.data.get(self.pos).ok_or(CborError::UnexpectedEof)?;
        self.pos += 1;
        Ok(b)
    }
    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], CborError> {
        let end = self.pos.checked_add(n).ok_or(CborError::UnexpectedEof)?;
        if end > self.data.len() {
            return Err(CborError::UnexpectedEof);
        }
        let s = &self.data[self.pos..end];
        self.pos = end;
        Ok(s)
    }
}

fn read_head(cur: &mut Cursor<'_>) -> Result<(u8, u64), CborError> {
    let ib = cur.read_u8()?;
    let major = ib >> 5;
    let ai = ib & 0x1f;
    let arg = match ai {
        0..=23 => u64::from(ai),
        24 => u64::from(cur.read_u8()?),
        25 => {
            let b = cur.read_bytes(2)?;
            u64::from(u16::from_be_bytes([b[0], b[1]]))
        }
        26 => {
            let b = cur.read_bytes(4)?;
            u64::from(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
        }
        27 => {
            let b = cur.read_bytes(8)?;
            u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
        }
        28..=30 => return Err(CborError::ReservedAdditional),
        31 => return Err(CborError::IndefiniteLength),
        _ => unreachable!("5-bit value"),
    };
    Ok((major, arg))
}

fn read_value(cur: &mut Cursor<'_>, depth: usize) -> Result<CoreValue, CborError> {
    if depth > MAX_CBOR_DEPTH {
        return Err(CborError::DepthExceeded);
    }
    // Peek initial byte to handle Major 7 (floats / simple) separately.
    let ib = *cur.data.get(cur.pos).ok_or(CborError::UnexpectedEof)?;
    let major = ib >> 5;
    let ai = ib & 0x1f;

    if major == 7 {
        cur.pos += 1;
        return match ai {
            20 => Ok(CoreValue::Bool(false)),
            21 => Ok(CoreValue::Bool(true)),
            22 => Ok(CoreValue::Null),
            // 23 ("undefined") is handled by the wildcard below.
            25 => {
                let b = cur.read_bytes(2)?;
                let bits = u16::from_be_bytes([b[0], b[1]]);
                Ok(CoreValue::Float(f16_bits_to_f64(bits)))
            }
            26 => {
                let b = cur.read_bytes(4)?;
                let bits = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
                Ok(CoreValue::Float(f64::from(f32::from_bits(bits))))
            }
            27 => {
                let b = cur.read_bytes(8)?;
                let bits = u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
                Ok(CoreValue::Float(f64::from_bits(bits)))
            }
            28..=30 => Err(CborError::ReservedAdditional),
            31 => Err(CborError::IndefiniteLength),
            _ => Err(CborError::Unsupported(ib)),
        };
    }

    let (_, arg) = read_head(cur)?;
    match major {
        0 => Ok(CoreValue::Int(i128::from(arg))),
        1 => Ok(CoreValue::Int(-1_i128 - i128::from(arg))),
        2 => {
            let n = usize::try_from(arg).map_err(|_| CborError::Limit)?;
            let b = cur.read_bytes(n)?;
            Ok(CoreValue::Bytes(b.to_vec()))
        }
        3 => {
            let n = usize::try_from(arg).map_err(|_| CborError::Limit)?;
            let b = cur.read_bytes(n)?;
            let s = std::str::from_utf8(b).map_err(|_| CborError::InvalidUtf8)?;
            Ok(CoreValue::Text(s.to_owned()))
        }
        4 => {
            let n = usize::try_from(arg).map_err(|_| CborError::Limit)?;
            // Cap pre-allocation against attacker-controlled element counts.
            // Each element needs ≥ 1 header byte, so the remaining input is a
            // hard upper bound on realizable elements — an oversized `n` will
            // still hit `UnexpectedEof`, but without an OOM-sized `Vec`.
            let cap = n.min(cur.remaining());
            let mut out = Vec::with_capacity(cap);
            for _ in 0..n {
                out.push(read_value(cur, depth + 1)?);
            }
            Ok(CoreValue::Array(out))
        }
        5 => {
            let n = usize::try_from(arg).map_err(|_| CborError::Limit)?;
            // Cap pre-allocation (see array arm). Map entries consume ≥ 2 bytes.
            let cap = n.min(cur.remaining() / 2);
            let mut out = Vec::with_capacity(cap);
            for _ in 0..n {
                let k = read_value(cur, depth + 1)?;
                let v = read_value(cur, depth + 1)?;
                out.push((k, v));
            }
            Ok(CoreValue::Map(out))
        }
        6 => Err(CborError::TagsNotSupported),
        _ => Err(CborError::Unsupported(major << 5 | ai)),
    }
}

#[allow(clippy::cast_sign_loss, clippy::cast_precision_loss)]
fn f16_bits_to_f64(bits: u16) -> f64 {
    let sign = u64::from((bits >> 15) & 1);
    let exp = u64::from((bits >> 10) & 0x1f);
    let mantissa = u64::from(bits & 0x3ff);
    if exp == 0 {
        if mantissa == 0 {
            return f64::from_bits(sign << 63);
        }
        // Subnormal: value = sign * 2^-14 * (m / 1024). Exact in f64 arithmetic.
        let abs = 2.0_f64.powi(-14) * (mantissa as f64 / 1024.0);
        return if sign == 1 { -abs } else { abs };
    }
    if exp == 0x1f {
        if mantissa == 0 {
            return if sign == 1 {
                f64::NEG_INFINITY
            } else {
                f64::INFINITY
            };
        }
        return f64::NAN;
    }
    // Normal: widen mantissa 10 → 52 bits; rebias exponent (-15 → -1023).
    let unbiased = exp as i64 - 15;
    let exp_f64 = (unbiased + 1023) as u64;
    let mantissa_f64 = mantissa << 42;
    f64::from_bits((sign << 63) | (exp_f64 << 52) | mantissa_f64)
}

// ---- tests -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;

    fn to_hex(b: &[u8]) -> String {
        let mut s = String::with_capacity(b.len() * 2);
        for x in b {
            let _ = write!(s, "{x:02x}");
        }
        s
    }

    // Known-answer vectors from RFC 8949 Appendix A.
    #[test]
    fn kat_integers() {
        let cases: &[(i128, &str)] = &[
            (0, "00"),
            (1, "01"),
            (10, "0a"),
            (23, "17"),
            (24, "1818"),
            (25, "1819"),
            (100, "1864"),
            (1000, "1903e8"),
            (1_000_000, "1a000f4240"),
            (1_000_000_000_000, "1b000000e8d4a51000"),
            (-1, "20"),
            (-10, "29"),
            (-100, "3863"),
            (-1000, "3903e7"),
        ];
        for (i, expected) in cases {
            let bytes = encode(&CoreValue::Int(*i)).unwrap();
            assert_eq!(to_hex(&bytes), *expected, "int {i}");
            // Decode roundtrip
            let back = decode(&bytes).unwrap();
            assert_eq!(back, CoreValue::Int(*i));
        }
    }

    #[test]
    fn kat_floats_zero_and_ones() {
        // +0.0 → f9 0000
        let bytes = encode(&CoreValue::Float(0.0)).unwrap();
        assert_eq!(to_hex(&bytes), "f90000");
        // -0.0 → f9 8000  (preservation — distinguishes from +0.0)
        let bytes = encode(&CoreValue::Float(-0.0_f64)).unwrap();
        assert_eq!(to_hex(&bytes), "f98000");
        // 1.0 → f9 3c00
        let bytes = encode(&CoreValue::Float(1.0)).unwrap();
        assert_eq!(to_hex(&bytes), "f93c00");
        // -1.0 → f9 bc00
        let bytes = encode(&CoreValue::Float(-1.0)).unwrap();
        assert_eq!(to_hex(&bytes), "f9bc00");
    }

    #[test]
    fn kat_float_nan_inf() {
        let bytes = encode(&CoreValue::Float(f64::NAN)).unwrap();
        assert_eq!(to_hex(&bytes), "f97e00");
        let bytes = encode(&CoreValue::Float(f64::INFINITY)).unwrap();
        assert_eq!(to_hex(&bytes), "f97c00");
        let bytes = encode(&CoreValue::Float(f64::NEG_INFINITY)).unwrap();
        assert_eq!(to_hex(&bytes), "f9fc00");
    }

    #[test]
    fn negative_zero_preserved_through_roundtrip() {
        let v = CoreValue::Float(-0.0_f64);
        let bytes = encode(&v).unwrap();
        let back = decode(&bytes).unwrap();
        match back {
            CoreValue::Float(f) => assert!(
                f.to_bits() == (-0.0_f64).to_bits(),
                "bit pattern changed: {:#018x}",
                f.to_bits()
            ),
            _ => panic!("not a float"),
        }
    }

    #[test]
    fn kat_float_promotes_when_f16_lossy() {
        // 1.1 is not exactly representable as f16 or f32.
        let bytes = encode(&CoreValue::Float(1.1_f64)).unwrap();
        assert_eq!(to_hex(&bytes), "fb3ff199999999999a");
    }

    #[test]
    fn kat_float_chooses_f32_when_f16_lossy_but_f32_exact() {
        // 100000.0 fits f32 exactly but needs more than 10 mantissa bits for f16.
        let bytes = encode(&CoreValue::Float(100_000.0_f64)).unwrap();
        assert_eq!(to_hex(&bytes), "fa47c35000");
    }

    #[test]
    fn kat_text_and_bytes() {
        assert_eq!(to_hex(&encode(&CoreValue::Text(String::new())).unwrap()), "60");
        assert_eq!(
            to_hex(&encode(&CoreValue::Text("a".into())).unwrap()),
            "6161"
        );
        assert_eq!(
            to_hex(&encode(&CoreValue::Text("IETF".into())).unwrap()),
            "6449455446"
        );
        assert_eq!(to_hex(&encode(&CoreValue::Bytes(vec![])).unwrap()), "40");
        assert_eq!(
            to_hex(&encode(&CoreValue::Bytes(vec![0x01, 0x02, 0x03, 0x04])).unwrap()),
            "4401020304"
        );
    }

    #[test]
    fn kat_array_and_map() {
        assert_eq!(to_hex(&encode(&CoreValue::Array(vec![])).unwrap()), "80");
        assert_eq!(to_hex(&encode(&CoreValue::Map(vec![])).unwrap()), "a0");

        let arr = CoreValue::Array(vec![
            CoreValue::Int(1),
            CoreValue::Int(2),
            CoreValue::Int(3),
        ]);
        assert_eq!(to_hex(&encode(&arr).unwrap()), "83010203");

        // Map `{"a": 1, "b": [2, 3]}` — keys in byte-lex order.
        let m = CoreValue::Map(vec![
            (
                CoreValue::Text("a".into()),
                CoreValue::Int(1),
            ),
            (
                CoreValue::Text("b".into()),
                CoreValue::Array(vec![CoreValue::Int(2), CoreValue::Int(3)]),
            ),
        ]);
        assert_eq!(to_hex(&encode(&m).unwrap()), "a26161016162820203");
    }

    #[test]
    fn primitives_null_bool() {
        assert_eq!(to_hex(&encode(&CoreValue::Null).unwrap()), "f6");
        assert_eq!(to_hex(&encode(&CoreValue::Bool(false)).unwrap()), "f4");
        assert_eq!(to_hex(&encode(&CoreValue::Bool(true)).unwrap()), "f5");
    }

    #[test]
    fn map_keys_sort_by_encoded_bytes() {
        // Keys of different type sort by their encoded-byte representation.
        // Int(1) encodes as `01`; Text("a") encodes as `6161`. `01` < `61`.
        let m = CoreValue::Map(vec![
            (CoreValue::Text("a".into()), CoreValue::Int(10)),
            (CoreValue::Int(1), CoreValue::Int(20)),
        ]);
        let bytes = encode(&m).unwrap();
        // a2 + [01 + 14] + [6161 + 0a] = a20114616101 0a ... let's compute.
        // a2 = map(2). key 01. val 14 (20). key 6161 (text "a"). val 0a (10).
        assert_eq!(to_hex(&bytes), "a2011461610a");
    }

    #[test]
    fn map_input_ordering_irrelevant() {
        let m1 = CoreValue::Map(vec![
            (CoreValue::Text("z".into()), CoreValue::Int(1)),
            (CoreValue::Text("a".into()), CoreValue::Int(2)),
        ]);
        let m2 = CoreValue::Map(vec![
            (CoreValue::Text("a".into()), CoreValue::Int(2)),
            (CoreValue::Text("z".into()), CoreValue::Int(1)),
        ]);
        assert_eq!(encode(&m1).unwrap(), encode(&m2).unwrap());
    }

    #[test]
    fn map_duplicate_key_rejected() {
        let m = CoreValue::Map(vec![
            (CoreValue::Text("k".into()), CoreValue::Int(1)),
            (CoreValue::Text("k".into()), CoreValue::Int(2)),
        ]);
        assert_eq!(encode(&m).unwrap_err(), CborError::DuplicateMapKey);
    }

    #[test]
    fn canonicalize_set_dedups_and_sorts() {
        let mut arr = vec![
            CoreValue::Text("b".into()),
            CoreValue::Text("a".into()),
            CoreValue::Text("b".into()),
        ];
        canonicalize_set_elements(&mut arr).unwrap();
        assert_eq!(
            arr,
            vec![CoreValue::Text("a".into()), CoreValue::Text("b".into())]
        );
    }

    #[test]
    fn canonicalize_set_stable_across_input_perms() {
        let input_a = vec![
            CoreValue::Int(3),
            CoreValue::Int(1),
            CoreValue::Int(2),
            CoreValue::Int(1),
        ];
        let input_b = vec![
            CoreValue::Int(1),
            CoreValue::Int(2),
            CoreValue::Int(3),
            CoreValue::Int(2),
        ];
        let mut a = input_a;
        let mut b = input_b;
        canonicalize_set_elements(&mut a).unwrap();
        canonicalize_set_elements(&mut b).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn roundtrip_nested() {
        let v = CoreValue::Map(vec![
            (
                CoreValue::Text("verb".into()),
                CoreValue::Text("get".into()),
            ),
            (
                CoreValue::Text("params".into()),
                CoreValue::Map(vec![
                    (CoreValue::Text("x".into()), CoreValue::Int(1)),
                    (CoreValue::Text("y".into()), CoreValue::Array(vec![])),
                ]),
            ),
        ]);
        let bytes = encode(&v).unwrap();
        let back = decode(&bytes).unwrap();
        let bytes2 = encode(&back).unwrap();
        assert_eq!(bytes, bytes2);
    }

    #[test]
    fn depth_limit_on_array() {
        let mut v = CoreValue::Int(0);
        for _ in 0..(MAX_CBOR_DEPTH + 2) {
            v = CoreValue::Array(vec![v]);
        }
        assert_eq!(encode(&v).unwrap_err(), CborError::DepthExceeded);
    }

    #[test]
    fn limit_enforced_on_large_bytes() {
        let oversized = vec![0_u8; MAX_CBOR_BYTES];
        let v = CoreValue::Bytes(oversized);
        assert_eq!(encode(&v).unwrap_err(), CborError::Limit);
    }

    #[test]
    fn trailing_bytes_rejected_on_decode() {
        let mut bytes = encode(&CoreValue::Int(1)).unwrap();
        bytes.push(0x00);
        assert_eq!(decode(&bytes).unwrap_err(), CborError::TrailingBytes);
    }

    #[test]
    fn indefinite_length_rejected() {
        // 0x5f = indefinite-length byte string
        let bytes = vec![0x5f, 0xff];
        assert_eq!(decode(&bytes).unwrap_err(), CborError::IndefiniteLength);
    }

    #[test]
    fn oversized_count_does_not_preallocate() {
        // 0x9b = MT4 array, 8-byte length follows; claim u64::MAX elements.
        // Pre-fix this caused `Vec::with_capacity(u64::MAX)` → OOM.
        // Post-fix capacity is bounded by remaining bytes, so the decoder
        // surfaces `UnexpectedEof` cleanly instead of panicking.
        let bytes = vec![0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(decode(&bytes).unwrap_err(), CborError::UnexpectedEof);
        // Same for MT5 (map).
        let bytes = vec![0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(decode(&bytes).unwrap_err(), CborError::UnexpectedEof);
    }

    #[test]
    fn int_boundary_encodings() {
        // 2^32-1 and 2^32 — forces MT0 size transition.
        assert_eq!(
            to_hex(&encode(&CoreValue::Int(0xFFFF_FFFF)).unwrap()),
            "1affffffff"
        );
        assert_eq!(
            to_hex(&encode(&CoreValue::Int(0x1_0000_0000)).unwrap()),
            "1b0000000100000000"
        );
        // Negative boundary: -1 - x.
        assert_eq!(
            to_hex(&encode(&CoreValue::Int(-0x1_0000_0000_i128)).unwrap()),
            "3affffffff"
        );
    }

    #[test]
    fn int_at_u64_max_boundary() {
        // u64::MAX is the largest MT0 value.
        assert_eq!(
            to_hex(&encode(&CoreValue::Int(i128::from(u64::MAX))).unwrap()),
            "1bffffffffffffffff"
        );
        // u64::MAX + 1 overflows → IntOutOfCborRange.
        let v = CoreValue::Int(i128::from(u64::MAX) + 1);
        assert!(matches!(
            encode(&v).unwrap_err(),
            CborError::IntOutOfCborRange(_)
        ));
    }

    #[test]
    fn map_decodes_unsorted_but_reencodes_canonical() {
        // A hand-crafted CBOR byte sequence with keys out of canonical order.
        // decode accepts it, but re-encoding produces the canonical order.
        let non_canon = hex::decode("a26162016161 02".replace(' ', "")).unwrap();
        let v = decode(&non_canon).unwrap();
        let canon = encode(&v).unwrap();
        assert_eq!(to_hex(&canon), "a2616102616201");
    }
}
