//! Minimal hand-rolled ASN.1 DER encoding helpers.
//!
//! These produce structurally correct DER for X.509 certs without pulling in
//! heavy X.509 builder crates.  Determinism is guaranteed: no random padding,
//! no conditional branches on heap layout.

// Test-only hand-rolled ASN.1 encoder: casts to u8 are intentional (BER
// length encoding, OID base-128 encoding). Single-char variable names
// mirror the Gregorian-date algorithm they implement (Hinnant §3).
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::similar_names)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::needless_borrow)]
#![allow(clippy::doc_markdown)]

pub(crate) fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 128 {
        out.push(len as u8);
    } else if len < 256 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xff) as u8);
    }
    out.extend_from_slice(content);
    out
}

pub(crate) fn der_sequence(items: &[&[u8]]) -> Vec<u8> {
    let mut content = Vec::new();
    for item in items {
        content.extend_from_slice(item);
    }
    der_tlv(0x30, &content)
}

pub(crate) fn der_explicit(tag: u8, content: &[u8]) -> Vec<u8> {
    der_tlv(0xa0 | tag, content)
}

pub(crate) fn der_integer(bytes: &[u8]) -> Vec<u8> {
    der_tlv(0x02, bytes)
}

pub(crate) fn der_boolean(val: bool) -> Vec<u8> {
    der_tlv(0x01, &[if val { 0xff } else { 0x00 }])
}

pub(crate) fn der_octet_string(content: &[u8]) -> Vec<u8> {
    der_tlv(0x04, content)
}

pub(crate) fn der_bit_string(content: &[u8]) -> Vec<u8> {
    let mut v = vec![0x00]; // zero unused bits
    v.extend_from_slice(content);
    der_tlv(0x03, &v)
}

pub(crate) fn der_oid(arcs: &[u64]) -> Vec<u8> {
    let mut content = Vec::new();
    // First two arcs combined: 40*arc0 + arc1
    content.push((40 * arcs[0] + arcs[1]) as u8);
    for &arc in &arcs[2..] {
        // Base-128 big-endian encoding
        let mut tmp = Vec::new();
        let mut v = arc;
        tmp.push((v & 0x7f) as u8);
        v >>= 7;
        while v > 0 {
            tmp.push(0x80 | (v & 0x7f) as u8);
            v >>= 7;
        }
        tmp.reverse();
        content.extend_from_slice(&tmp);
    }
    der_tlv(0x06, &content)
}

pub(crate) fn der_name_from_spki(spki: &[u8]) -> Vec<u8> {
    // Use first 8 bytes of SPKI as a CN UTF8String — minimal but unique
    let cn_bytes = &spki[..spki.len().min(8)];
    let utf8_str = der_tlv(0x0c, cn_bytes); // UTF8String
    let attr = der_sequence(&[&der_oid(&[2, 5, 4, 3]), &utf8_str]); // CN
    let rdn = der_tlv(0x31, &attr); // SET
    der_sequence(&[&rdn]) // SEQUENCE of RDNs
}

pub(crate) fn der_generalized_time(unix_seconds: i64) -> Vec<u8> {
    // GeneralizedTime: YYYYMMDDHHmmssZ
    // Use a simplified but correct Gregorian calendar conversion.
    let secs = unix_seconds.max(0) as u64;
    let sec = secs % 60;
    let mins_total = secs / 60;
    let min = mins_total % 60;
    let hours_total = mins_total / 60;
    let hour = hours_total % 24;
    let days_since_epoch = hours_total / 24;

    // Gregorian calendar: compute year, month, day from days_since_epoch.
    // Algorithm: https://howardhinnant.github.io/date_algorithms.html
    let z = days_since_epoch as i64 + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };

    let s = format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}Z",
        year, m, d, hour, min, sec
    );
    der_tlv(0x18, s.as_bytes())
}
