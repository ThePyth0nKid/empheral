# EPHEMERAL Reference Validator

Rust implementation of the EPHEMERAL Agent-Authority Protocol conformance
validator (Phase B). Validates `conformance/*.json` vector suites against
`conformance/schema.json` and executes the semantic behaviors required by
`design-final-v2.md` §15.

## Status

**Session 1 / 3** — workspace scaffold, structural layer.

- [x] Workspace + crate layout
- [x] Core types (`Vector`, `VectorSuite`, `ExpectedOutcome`, …)
- [x] Error surface (`ValidatorError` via `thiserror`)
- [x] Suite-file loader
- [x] JSON Schema 2020-12 validator (`jsonschema` 0.29)
- [x] Codec scaffold (`CoreValue` + JSON roundtrip)
- [x] CLI (`ephemeral-validator`)
- [x] Integration test: 6 suites × structural validation
- [ ] Canonicalization R7.C1-C10  *(Session 2)*
- [ ] Delegation V3-1  *(Session 2)*
- [ ] Tariff R8.T1-T5  *(Session 2)*
- [ ] Deterministic CBOR encoder  *(Session 2)*
- [ ] PCR attestation §9.3-§9.4  *(Session 3)*
- [ ] Audit replay §3.5, §11  *(Session 3)*
- [ ] Fuzz runner  *(Session 3)*
- [ ] Sensitive-paths matcher (Sec-N5)  *(Session 3)*

## Layout

```
reference/validator/
├── Cargo.toml               # workspace
├── crates/
│   ├── ephemeral-core/      # library
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── error.rs
│   │   │   ├── types.rs
│   │   │   ├── suite_file.rs
│   │   │   ├── schema/      # JSON Schema validation
│   │   │   └── codec/       # JSON <-> CoreValue roundtrip
│   │   └── tests/
│   │       └── integration.rs
│   └── ephemeral-cli/       # binary
│       └── src/main.rs
```

## Build

```bash
cd reference/validator
cargo check
cargo clippy --all-targets -- -D warnings
cargo test
```

## Run

```bash
# Validate every conformance file with the default schema path
cargo run --bin ephemeral-validator

# Pin a specific schema + subset of inputs
cargo run --bin ephemeral-validator -- \
    --schema ../../conformance/schema.json \
    ../../conformance/canonicalization.json \
    ../../conformance/delegation-scope.json

# JSON report
cargo run --bin ephemeral-validator -- --json-report report.json
```

## Exit codes

- `0` — every loaded file validates structurally and every executed vector passes
- `1` — one or more vectors fail or a harness error occurs
- `2` — invalid arguments or unreadable inputs (clap default)

## Design rationale

See `../../design-final-v2.md` §15 (conformance suites) and the per-session
scope documented at the top of this README. The architectural decisions for
this crate live in the companion design report; crate choices were vetted in
the Phase B research pass (2026-04-18).
