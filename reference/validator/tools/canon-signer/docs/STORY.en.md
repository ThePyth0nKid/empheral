# Canon — A Wax Seal for Digital Business

> A story in seven parts.  For juries, customers, and anyone who wants
> to understand it without reading a single line of code.
> For technical depth, see [`TECHNICAL.md`](TECHNICAL.md) and
> [`VALIDATION.md`](VALIDATION.md).

---

## 1. TL;DR

**Canon** reads business email and pulls out structured **facts** —
small, precise claims like *"Customer X reported EUR 127,000 in Q1
revenue."* **canon-signer** cryptographically seals every fact, the way
a notary seals a document with wax.  **The Web Verifier** —
[thepyth0nkid.github.io/empheral](https://thepyth0nkid.github.io/empheral/)
— lets **any human on earth with a browser** check for themselves that
the seal is real.  No server trust.  No blockchain.  No vendor lock-in.

---

## 2. The Metaphor: Wax Seals for the Digital Age

In the 16th century, important letters carried a **wax seal** stamped
with the sender's coat of arms.  Three properties made the system
robust:

1. **Hard to forge** — the stamp couldn't be easily reproduced.
2. **Visibly broken** — any tampered letter was instantly obvious.
3. **Publicly verifiable** — anyone who knew the coat of arms could
   confirm it themselves.  No royal court required.

Canon builds **the same system**, only for digital facts instead of
letters.  Instead of wax, we use an **Ed25519 signature**.  Instead of
a coat of arms, we use a **public key**.  Instead of couriers carrying
the letter, we use a **hex string that fits inside a QR code**.

The user experience is deliberately modelled on the old system: on the
verifier page you see a **stamped wax seal** — green when real, broken
and red when tampered.  No console, no log files.  The seal *is* the
answer.

---

## 3. What is a "fact"?

A fact is a single **structured claim**.  It has nine fields — together
they form an unalterable record:

| Field | Meaning | Example |
|---|---|---|
| **Fact ID** | Unique identifier | `f_q1_acme_0001` |
| **Entity** | Who is this about | `customer:acme` |
| **Claim** | The actual statement | `Q1 revenue was EUR 127,000` |
| **Source** | Where it came from | `gmail:msg_abc123` |
| **Excerpt** | Verbatim quote | `"Our Q1 came in at 127k EUR…"` |
| **Parent** | Hash of the previous fact | `b0f3…` or empty (genesis) |
| **Signed at** | Timestamp | `2026-04-24T09:03:12Z` |
| **Signer (kid)** | Which key sealed it | `canon/8a88e3dd7409f195` |
| **Event hash** | SHA-256 over the payload | `b0f3753095…` |

The critical piece is **Parent**.  Every new fact points to the hash of
the previous one — like a **notary's ledger page** referencing the
one before.  If someone later edits an old fact, the chain no longer
lines up.  The verifier catches it immediately.

This turns a stream of individual email statements into a **gap-free
history** that neither Canon nor the customer can rewrite after the
fact.

---

## 4. How the two systems interact

```
   ┌────────────────────┐           ┌──────────────────────┐
   │  Canon (Node.js)   │           │  canon-signer (Rust) │
   │                    │  JSON     │                      │
   │  AI extractor:     │  stdin    │  COSE_Sign1 +        │
   │  email → claim     ├──────────▶│  Ed25519 seal        │
   │                    │           │                      │
   │                    │  JSON     │                      │
   │  store + chain     │◀──────────┤  hex envelope +      │
   │                    │  stdout   │  public key          │
   └─────────┬──────────┘           └──────────────────────┘
             │
             │ share URL with ?e=<hex>&pk=<key>
             │ (fits inside a QR code)
             ▼
   ┌────────────────────────────────────────────────────┐
   │  Web Verifier (WASM in the browser)                │
   │  thepyth0nkid.github.io/empheral                   │
   │                                                    │
   │  10 steps visible, green seal, done.               │
   └────────────────────────────────────────────────────┘
```

Three clear roles, each with one purpose:

- **Canon** is the **author**.  It knows what a business claim is, how
  to pull one out of an email, how to store it.  But it can't sign
  securely on its own — that would be like letting the author carve
  their own notary stamp.
- **canon-signer** is the **notary**.  It has exactly one job: receive
  a fact, seal it, return it.  It knows nothing about email or AI.  It
  is ~700 lines of Rust and uses a crypto library that has been battle-
  hardened in production for years.
- **The Web Verifier** is the **independent witness**.  It holds *only*
  the verify half of the code — it *cannot* sign.  Which means: even
  if someone took over the verifier URL, they couldn't forge seals.
  The worst they could do is refuse to check.

This **separation between author, notary, and witness** is the whole
game.

---

## 5. The journey of one fact

Let's follow a concrete example.  Friday, 9:03 AM:

**Step 1 — The email arrives.**
Ms. Meyer at customer **Acme** writes to her financial advisor: *"Hi,
Q1 came in at 127k EUR, we're doing well."*

**Step 2 — Canon reads along.**
The Canon AI recognises the business claim and normalises it:
```
entity  = "customer:acme"
claim   = "Q1 revenue was EUR 127,000"
source  = "gmail:msg_abc123"
excerpt = "Our Q1 came in at 127k EUR…"
```

**Step 3 — Canon asks the notary.**
Canon spawns `canon-signer` as a subprocess and sends a JSON line over
stdin.  The signer builds:

- a **seven-field CBOR payload** (the fact in compact binary form),
- a **COSE_Sign1 envelope** with protected header `{alg: Ed25519}`,
- an **Ed25519 signature** over the payload plus a fixed domain
  separator `canon/fact/v1` (so no one can replay a fact in a different
  context),
- replies with the **hex envelope** + the **public key**.

Total latency: under one millisecond.

**Step 4 — Canon stores the fact.**
The envelope lands in Canon's database.  The fact's `event_hash`
becomes the `parent_hash` for the next fact about the same customer.
That's how the chain builds up.

**Step 5 — The advisor needs to prove it.**
The advisor has to show the auditor that Acme *actually* reported
EUR 127,000.  Old answer: *"Here's a screenshot of the email."*
Evidentiary weight: zero.  Editable in seconds.

**New answer:** Canon generates a **share URL**:
```
https://thepyth0nkid.github.io/empheral/?e=84581b…a2d1c0d&pk=ed25519:iojj…
```

That URL fits in a QR code.  You can email it, print it, put it on a
quote, embed it as a link in an invoice PDF.

**Step 6 — The auditor opens the URL.**
On their phone.  In any browser.  No login.  No Canon account.
The page shows:
- **Stamped green wax seal**, with a small stamp-down animation.
- "Signature valid.  Signed by `canon/8a88…` and has not been altered."
- The nine fact fields, cleanly formatted.
- The ten verify steps, all green.
- On demand: the raw bytes that fed into the signature — for the
  auditor who'd rather open Python and recompute it themselves.

**Step 7 — The counter-test.**
The auditor, for fun, changes one character in the URL.  The page
flips instantly: **red, broken wax seal**.  Step 7 ("Ed25519 verify")
lights up red.  No explanation needed, it's self-evident.

Total time for the full audit: **four seconds.**  No account creation.
No trust in Canon.  No blockchain wallet.

---

## 6. Why this wins — three killer points

**(a) Zero trust through role separation.**
The code that seals runs on Canon infrastructure.  The code that
verifies runs in the browser of every person who opens the URL.  The
WASM bundle contains **no** signing primitives — even if someone
compromised the verifier, they couldn't forge seals.  Trust isn't
"we promise to play fair" — it's **architecturally enforced**.

**(b) Portable without infrastructure.**
No blockchain node.  No central timestamp service.  No dependency on
GitHub Pages (the page can live anywhere — S3, self-hosted, a customer
VPN).  A fact is **two strings**: a hex envelope and a public key.
Both fit in a QR code.  You can print them on paper, text them, embed
them in an invoice PDF.

**(c) Radical transparency, demonstrated.**
Most crypto products say "trust us, it's cryptographically secure."
We show **every single step** — by name, with byte dumps, in an order
the jury can follow themselves.  A customer can **convince themselves**
rather than take our word.  That's the differentiator against every
proprietary "blockchain for enterprise" product on the market.

---

## 7. Three-minute stage script

**[00:00 — 00:20] Hook.**
*"Your business today runs on email.  A customer writes 'we did 127k in
Q1', you store it, you book against it.  But six months later, when the
auditor shows up — how do you prove that exact sentence was there?
A screenshot?  Laughable."*

**[00:20 — 00:50] What Canon does.**
*"Canon reads every incoming email, automatically finds the business
claims, and extracts them into structured 'facts'.  Who, what, when,
where from.  That's half the product.  The other half is this:"*
→ Open browser to [thepyth0nkid.github.io/empheral](https://thepyth0nkid.github.io/empheral/)

**[00:50 — 01:20] Live demo.**
*"This is the Canon Verifier.  It runs entirely in your browser — no
sign-in, no account."*
→ Click **Load demo fact**, then **Verify**.
*"Green wax seal.  That's Acme, Q1 revenue one hundred twenty-seven
thousand euros, signed at 9:03.  And here — this is the part that
matters — are the ten steps the browser just performed.  Every single
one shown.  You don't have to take my word for any of it."*

**[01:20 — 02:00] The tamper moment.**
*"Now I change one character in the URL."*
→ Flip a hex digit at the end of the envelope, click **Verify**.
*"Seal broken.  Step seven red.  In four hundred milliseconds the
whole world knows: tampered.  This isn't 'we log it' — this is
cryptographically unrepairable."*

**[02:00 — 02:30] The architecture in one breath.**
*"The code that **makes** the seals runs on our side.  The code that
**checks** them is a Rust-compiled WASM binary — 250 kilobytes, sitting
in your browser cache.  The two codebases share **zero** signing
primitives.  Meaning: even if someone hacks us, they can't forge
anything your browsers don't immediately reject."*

**[02:30 — 03:00] Close.**
*"No blockchain.  No vendor lock-in.  A fact is two strings, fits in a
QR code.  Here's the URL — every one of you can try this yourselves
right now, live, from the audience.  Takes four seconds.  Thank you."*
→ Leave a QR code on screen.

---

## Appendix: Recurring questions

**"If Canon gets compromised, isn't it all over?"**
Only the *new* seals from the moment of compromise onward are suspect.
All older facts remain verifiable, because each one carries its own
public key in its header.  A key-rotation event is visible — the
`kid` changes.  The verifier still stamps green, as long as the
public key matches.

**"Why COSE_Sign1 and not JWT/JWS?"**
JSON bloats payloads and isn't deterministic (field order).  CBOR is
compact and byte-exact.  For QR codes and long-term archiving, every
byte counts.

**"Why Ed25519, not ECDSA-P256?"**
Smaller signatures (64 bytes vs. 72).  Deterministic (no RNG
weaknesses).  Faster to verify.  Better fit for the mobile + QR
scenario.

**"Is this open source?"**
The verifier ships as public WASM; the signer crate is in hackathon
state, with the LICENSE decision pending post-event.  See
[`VALIDATION.md`](VALIDATION.md).
