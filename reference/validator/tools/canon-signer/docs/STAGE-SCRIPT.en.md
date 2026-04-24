# Stage Script (English) — Canon @ Berlin Hack

> **Duration:** 3-minute demo + 2-minute Q&A buffer.
> **Setup:** laptop + projector, browser tab on `thepyth0nkid.github.io/empheral`
> open and ready.  QR code (`canon-verifier-qr-demo.png`) either held up
> as a printout or shown as a secondary slide.

---

## Prep (2 minutes before you go on)

- [ ] Browser tab on the live URL, **in fullscreen / presentation mode** (F11)
- [ ] Fields **empty** (hit Clear if previously used)
- [ ] Wi-Fi tested — run one Verify end-to-end, then Clear
- [ ] QR code visible (A5 printout, or slide ready)
- [ ] Second tab with DevTools Console open (in case someone asks,
      you show "zero requests after load")
- [ ] Voice warm, water within reach

---

## 00:00 – 00:20 · Hook

> *"Your business today runs on email.  A customer writes 'we did one
> hundred twenty-seven thousand in Q1,' you store it, you book against
> it.  But six months later, when the auditor shows up — how do you
> prove **that exact sentence** was there?"*

**Pause.  Make eye contact.**

> *"A screenshot?  Laughable.  Screenshot forgery is a two-second job
> in Photoshop."*

**Pace:** calm, serious.  You're framing the problem.  No solution yet.

---

## 00:20 – 00:50 · What Canon does

> *"We're building Canon.  Canon reads every incoming business email
> and uses AI to extract the actual claims in structured form.  Who
> said what, about whom, when, where from.  We call that a 'fact'.
> That's the first half of the product."*

**[Gesture towards the projector.]**

> *"The second half is this."*

**Bring the browser tab forward.**

---

## 00:50 – 01:30 · Live demo

> *"This is the Canon Verifier.  Runs a hundred percent in your
> browser.  No login, no account, no Canon infrastructure required.
> Plain HTML plus two hundred and fifty kilobytes of WebAssembly."*

**Click [Load demo fact]**.  Both text fields fill in.

> *"I'm loading a sample fact.  Acme GmbH, Q1 revenue one hundred
> twenty-seven thousand euros, signed on April twenty-fourth.  And
> now the money shot."*

**Click [Verify]**.

**Short pause — let the wax seal stamp in.**

> *"Green wax seal.  That's our metaphor — a digital wax seal, just
> like the sixteenth century: hard to forge, visibly broken when
> tampered, publicly verifiable."*

**Scroll to the steps panel.**

> *"And here is what Canon does **differently** from every other
> product on the market: the ten steps the browser just performed.
> Every single one shown, byte dump included.  You don't have to
> take my word for **anything** — you see it yourself."*

---

## 01:30 – 02:10 · The tamper moment (highlight)

> *"Now I change one single character in the signature."*

**Edit one hex digit at the end of the envelope field.**
For example `…a2d1c0d` → `…a2d1c0e`.

**Click [Verify]**.

**The seal breaks red.  Step 7 turns red.**

> *"Seal broken.  Step seven — the Ed25519 verification — red.
> Four hundred milliseconds.  This isn't 'we'll log it and hope
> someone notices' — this is **cryptographically unrepairable**."*

**Pause.  Let it land.**

---

## 02:10 – 02:40 · The architecture in one breath

> *"The code that **makes** the seals runs on our side, on Canon
> servers.  The code that **checks** them is this Rust-compiled WASM
> binary in your browser.  The two codebases share **zero** signing
> primitives."*

**Use your hands — gesture two separate blocks.**

> *"In plain English: even if someone hacks us, they can't forge
> facts that your browser won't **instantly** reject."*

---

## 02:40 – 03:00 · Close

> *"No blockchain.  No central timestamp server.  No vendor lock-in.
> A Canon fact is exactly two strings — a hex envelope and a public
> key.  Both fit in a QR code."*

**[Hold up the QR printout, or flash the slide.]**

> *"Here it is.  Every one of you can check this **right now, live**,
> from your seat.  Four seconds.  No app, no account.  Thank you."*

**Leave the QR code on screen.  Smile.**

---

## Q&A buffer (2 minutes, if asked)

### "What if Canon gets compromised?"

> *"Only the **new** seals issued from the moment of compromise are
> suspect.  Every previously issued fact stays verifiable, because
> each one carries its own public key in its header.  We rotate keys
> routinely; the `kid` on the seal changes — that makes it instantly
> visible."*

### "Why not just use blockchain?"

> *"Because blockchain doesn't solve a problem we have.  We don't need
> to prove **we** signed something — a public key is enough.
> Blockchain would give us a global-consensus timestamp server, which
> we don't need.  What we need is: the seal must be unchanged.
> Ed25519 delivers that in sixty-four bytes, at zero ongoing cost."*

### "Why COSE_Sign1?"

> *"Because it's an IETF standard — RFC 9052.  JSON web tokens aren't
> deterministic, so you can't guarantee two verifiers operate on the
> exact same bytes.  CBOR is byte-exact, compact, and fits in a QR
> code.  Plus: in ten years, COSE will still be the standard the IoT
> world relies on — we didn't invent anything."*

### "How big can this scale?"

> *"An envelope is typically two hundred bytes plus the public key.
> A company with ten thousand emails per day produces under two
> megabytes of signed facts per day.  That fits in any database, any
> backup, any email footer.  Scaling isn't a concern."*

### "Can I try this today?"

> *"Yes.  Scan the QR code, the demo runs in your browser.  For the
> signer integration: we ship a Rust sidecar, Docker-ready, one JSON
> line in, one JSON line out.  Ten minutes to your first signed fact
> out of your stack."*

---

## Backup plan — if the Wi-Fi dies

1. **Browser is already fully loaded** before you start.  WASM is
   in the cache.
2. If the Wi-Fi goes down: the verifier **still works** — it makes
   **zero** network calls after the initial load.  Point the jury
   to it:
   > *"Watch — we just cut the Wi-Fi.  It still runs.  Zero servers,
   > zero dependencies."*
   This turns the outage into an **additional proof point**, not a
   problem.
3. The QR code printout is independent of everything.

---

## Voice + body language

- **Pace:** Calm, almost slow.  Cryptography doesn't need to rush,
  and calm projects more confidence than a fireworks display of
  jargon.
- **Hands:** When you explain the architecture (02:10), use both
  hands to gesture two separate blocks.  It anchors "separation"
  visually.
- **Gaze:** Hook and close — at the audience.  Demo — at the screen.
- **Don't explain the tamper moment** — show it and let it breathe.
  The silence after the red seal is your best argument.
