/* tslint:disable */
/* eslint-disable */

/**
 * JavaScript-facing entry point.  Serializes [`VerifyResult`] via
 * `serde-wasm-bindgen` so the caller receives a plain object.
 *
 * The function is total: any input produces a value and never
 * throws.  Callers should `.verified` on the returned object to
 * branch; the `error` field carries a one-line reason when false.
 */
export function verify_canon_envelope(envelope_hex: string, pubkey_wire: string, kid_override?: string | null): any;
