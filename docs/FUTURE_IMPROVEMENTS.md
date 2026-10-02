# Future Improvements

Ordered by what the measurements say is missing, not by what is fun to build.

---

## Tier 1 — Fixes a measured failure

### 1. Email header analysis with SPF, DKIM and DMARC

**Why first.** **11 of the 12 false negatives** on the test split are business
email compromise: plausible sender, correct grammar, no link, no attachment, no
urgency. All eleven score exactly 0. Body-text analysis cannot catch them,
because nothing in the body is wrong. Authentication results are the missing
signal. (The twelfth is a threshold near-miss, addressed by item 10 instead.)

**Approach.** Parse `Received`, `Authentication-Results`, `Return-Path` and
`Reply-To` from a real `.eml`. Flag: authentication failure, `Reply-To` domain
differing from `From`, and a `Received` chain inconsistent with the claimed
origin.

**Effort:** medium. **Impact:** the single largest available gain.

### 2. First-time-sender and display-name impersonation

**Why.** The other half of the same gap. "Maria D'Souza" arriving from an
address you have never corresponded with is the strongest available signal when
the message body is clean.

**Approach.** Keep a table of previously seen `(display_name, address)` pairs.
Flag a known display name with a new address, and any first-time sender who
asks for money or credentials.

**Effort:** low — it is a table and a lookup. **Impact:** high.

### 3. Out-of-band verification prompt for payment changes

**Why.** The only control that works when the email genuinely comes from a
compromised legitimate account. No amount of detection helps there.

**Approach.** When a message mentions a bank-detail or payment change, escalate
the recommendation regardless of score: *"Call the sender on a number you
already had. Do not use a number from this email."*

**Effort:** trivial. **Impact:** disproportionate — it is a process control the
tool can prompt.

---

## Tier 2 — Closes a known blind spot

### 4. QR-code extraction (quishing)

Attackers moved payloads into images precisely because text scanners cannot read
them. Decode QR codes from attached images and feed the URL into the existing
static analyzer. **Effort:** low (`pyzbar`). **Impact:** covers a growing vector.

### 5. Attachment hash reputation — opt-in

Compute SHA-256 of an uploaded file and look it up. This **breaks the current
no-network guarantee**, so it must be explicitly opt-in, clearly labelled, and
off by default. Note that submitting a hash leaks the fact that you have the
file. **Effort:** low. **Impact:** medium.

### 6. URL and domain reputation — opt-in

Same constraint. Domain age is a strong signal: phishing domains are usually
days old. Same privacy caveat — a lookup tells a third party what you are
investigating. **Effort:** low. **Impact:** medium.

### 7. Multilingual support

The keyword lists and regexes are English. A non-English phishing email scores
near zero, which is a silent failure — worse than an error. At minimum, detect
the language and warn that analysis is unreliable. **Effort:** medium.

---

## Tier 3 — Makes it operational

### 8. SIEM / ticketing integration

Push each analysis to Splunk, Elastic or a ticketing system so a reported email
opens a triage case with indicators pre-populated. **Effort:** medium.

### 9. Analyst feedback loop and drift monitoring

Let an analyst mark a verdict wrong and store the correction. Two payoffs:
recalibrating rule weights against real judgements, and detecting **model
drift** — phishing language changes, and a model trained once decays silently.
Track score distribution over time and alert when it shifts.

**Effort:** medium. **Impact:** high — it is the difference between a project
and a maintained system.

### 10. Per-organisation rule tuning

Rule weights are global constants. A logistics firm gets legitimate "urgent
delivery" mail constantly; a law firm does not. Move the weights to
configuration and let an administrator tune them against their own traffic.
**Effort:** low.

### 11. Report export as PDF

One click to attach the full analysis to a ticket. **Effort:** low.
**Impact:** small but frequently requested.

---

## Tier 4 — Research

### 12. Transformer text classifier

`ml/optional_bert.py` scaffolds DistilBERT. It is optional, never imported by
the backend, and **no metric for it appears anywhere in this repository,
because it has not been run.**

Worth testing whether it catches any of the 11 BEC misses. My expectation is
that it will not — the signal is absent from the text, not merely subtle — and
testing that expectation is the point.

**Effort:** medium (needs PyTorch, ~2–2.5 GB). **Impact:** unknown by design.

### 13. Explainability for the ML channel

The rule engine explains itself; the model does not. SHAP or LIME over the
TF-IDF features would let the UI show *"these terms pushed this toward
phishing."* Careful: a plausible-looking explanation for a wrong prediction is
worse than no explanation, so it needs validating before it is shown to users.
**Effort:** medium.

### 14. Adversarial robustness testing

Measure how the score degrades under evasion: homoglyphs, zero-width
characters, image-only bodies, URL-shortener chains, text split across HTML
tags. **This should arguably be higher.** Every detection system is eventually
tested by someone trying to break it, and I have not measured how easily mine
bends. **Effort:** medium. **Impact:** high, and currently unknown.

### 15. Real labelled data under authorisation

The honest limitation of this project: results come from synthetic data and do
not transfer unchanged to real inboxes. Evaluating against an authorised
corpus of real reported phish is the only way to know what the numbers mean.
**Effort:** high — mostly legal and ethical, not technical.

---

## Explicitly out of scope

| Not doing | Why |
|---|---|
| Sending simulated phishing to real people | Requires organisational authorisation this project cannot grant. Templates are for pasting into the analyzer, not for sending. |
| Automatic URL visiting or sandbox detonation | Confirms the address is live, leaks the analyst's IP, and risks payload execution. The no-network guarantee is a feature. |
| Attachment execution or unpacking | Same reasoning. Filename only. |
| Auto-blocking or auto-deleting mail | A tool with a measured false-negative rate should not take irreversible action. Recommend; let a human decide. |
| Claiming a score is proof | Structural. The output is a risk assessment supporting analyst judgement — never a verdict replacing it. |

---

## If you only do one thing

**Build header authentication (item 1).** It is the direct answer to the only
error class this project actually measured, and everything else is polish by
comparison.
