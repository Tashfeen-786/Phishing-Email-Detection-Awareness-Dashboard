# Project Report
## Phishing Email Detection & Awareness Dashboard

---

## 1. Abstract

This project delivers a working, offline phishing email analyzer that scores an
email from 0 to 100 and explains every point it awards. It analyses five
independent surfaces — sender, subject, body, URLs and attachment filename —
through seven weighted rules, and compares that rule-based approach against
machine learning and a hybrid of the two on an identical held-out split.

On 90 test emails the selected model (Naive Bayes) reaches **F1 0.9535** with
**ROC-AUC 0.9916**, while the rule engine achieves **precision 1.0000 with zero
false positives** across all 312 legitimate emails in the dataset. **The hybrid
approach did not outperform ML on F1** — a result reported as measured rather
than as expected.

All twelve of the rule engine's false negatives were inspected individually:
eleven are business email compromise with no surface indicators at all, and one
is a threshold near-miss. That finding, rather than the headline metric, is the
report's main contribution.

The system comprises 10,604 lines of Python across 41 modules, a 1,879-line
React frontend, 64 passing tests, and an integrated security-awareness module.
All data is synthetic and every domain and IP address is RFC-reserved.

---

## 2. Introduction

### 2.1 Background

Phishing remains the most common initial-access technique because it targets
human judgement rather than a software flaw. Urgency, fear and authority do the
work; the technical indicators are downstream of the psychology.

### 2.2 Motivation

Two gaps motivated this project:

**Commercial filters are opaque.** They return "spam" or "not spam" with no
reasoning. The user learns nothing, cannot challenge a wrong verdict, and is no
better prepared for the next email.

**Awareness training is disconnected from tooling.** Staff attend a session,
then return to an inbox that gives them no help applying it.

### 2.3 Objectives

1. Detect phishing indicators across five independent surfaces.
2. Produce a 0–100 score from documented, auditable weights.
3. Explain every verdict in plain language with the evidence quoted.
4. Compare rule-based, ML and hybrid detection on the same held-out split and
   report what actually happened.
5. Teach the warning signs through an integrated awareness module.
6. Remain strictly defensive: synthetic data, no network calls, no execution.

### 2.4 Scope

**In scope:** static analysis of email text and metadata; rule-based scoring;
classical ML; explainable output; a local web dashboard; awareness content.

**Out of scope:** sending email of any kind; header authentication (SPF/DKIM/
DMARC); live threat intelligence; attachment content inspection; non-English
text; multi-user deployment.

---

## 3. Literature and approach

Three families of approach informed the design:

| Approach | Strength | Weakness |
|---|---|---|
| **Blocklists / signatures** | Near-zero false positives; fast | Useless against new domains, which is what phishing uses |
| **Rule / heuristic engines** | Explainable; tunable; no training data needed | Brittle; miss what has no surface indicators |
| **Machine learning** | Generalises; catches subtle combinations | Opaque; needs labelled data; degrades as language drifts |

This project implements the second and third and **measures both**, rather than
assuming a hybrid inherits the strengths of each. Section 7 shows that
assumption would have been wrong.

---

## 4. System design

### 4.1 Pipeline

```
Input → Preprocessing → {Sender, Content, URL, Attachment} analyzers
      → Feature extraction (39 features)
      → {Rule engine, ML model} → Hybrid
      → Risk score → Classification → Explanation → Recommendations
      → SQLite → API → Dashboard → Awareness
```

Full diagram and module map: [`ARCHITECTURE.md`](ARCHITECTURE.md).

### 4.2 Three design decisions that shaped everything

**One feature function, used twice.** `extract_email_features()` is called by
the training script *and* by the live API. Most "great offline metrics, useless
in production" failures come from a training script that reimplements feature
logic slightly differently. Sharing the function makes that class of bug
impossible.

**Rules and ML stay independent.** The rule engine never consults the model and
the model never sees the rule score. Either can run alone. This matters because
they fail differently — rules miss what has no surface indicators, models miss
what their training data lacked — and keeping them separate makes each failure
visible instead of absorbed.

**Defanging at the boundary.** `hxxp://198[.]51[.]100[.]10/...` is produced
inside the URL analyzer, so no downstream component ever handles a clickable
attacker URL.

### 4.3 Technology choices

| Layer | Choice | Rationale |
|---|---|---|
| API | FastAPI | Automatic OpenAPI docs; Pydantic validation at the boundary |
| Database | SQLite | Zero setup; single file; ships with Python |
| ML | scikit-learn | Trains in ~4 s; reproducible; inspectable |
| Frontend | React + Vite | Fast dev loop; simple build |
| Testing | pytest | Fixtures make database isolation trivial |

Deliberately avoided: paid APIs, cloud services, GPU-only models, heavy CSS
frameworks. The project must run offline on a student laptop.

---

## 5. Dataset

### 5.1 Composition

600 emails, 288 PHISHING (48.0%) / 312 LEGITIMATE, deterministic from seed 42.
338 rows carry URLs, 433 carry attachments, across 36 unique sender domains.

| Tier | Share per class | Purpose |
|---|---|---|
| Clear-cut | ~71% | Obvious lures, obviously benign mail |
| Hard | 20% | Urgent-but-genuine mail; quiet BEC |
| **Indistinguishable** | **9%** | **Shared template pool used by BOTH labels** |

### 5.2 The most important design decision in the project

The first version of the generator had no indistinguishable tier. All three
models scored **1.0000 on every metric**.

The metrics were real. The dataset was the problem: even the "hard" rows used
vocabulary unique to one label, so the task was trivially separable.

A perfect score on a security classifier is a bug report, not an achievement.
It looks fabricated, it teaches nothing, and it hides the only interesting
question — what does the system get wrong, and why?

The generator was rebuilt so ~9% of each class draws from a **shared template
pool**. Those rows are genuinely ambiguous: whether *"please process invoice
4821"* is legitimate depends on whether that invoice exists, and that fact
lives in the accounting system, not in the email. No classifier can resolve it
from the text.

This produced a realistic **irreducible error floor**, and every result in
section 7 is meaningful because of it.

### 5.3 Safety

Every domain is reserved under RFC 2606 / RFC 6761 (`example.com`,
`example.org`, `example.net`, `*.invalid.test`). Every IP is from the RFC 5737
documentation ranges. No real person, company, brand, domain or IP appears
anywhere in the dataset, tests, awareness content or documentation.

---

## 6. Implementation

### 6.1 Rule engine

| Rule | Weight | Trigger |
|---|---|---|
| Suspicious sender | +15 | sender sub-score ≥ 30 |
| Urgency | +10 | time-pressure phrasing |
| Credential request | +20 | asks for password / OTP / PIN / login |
| Suspicious URL | +20 | any link's sub-score ≥ 30 |
| Suspicious attachment | +25 | attachment risk ≥ 40 |
| Generic greeting | +5 | "Dear Customer" / "Dear User" |
| Threat / fear | +10 | suspension, closure, legal action |

Raw maximum **105**, capped at **100**. Bands: 0–20 LOW, 21–40 MODERATE, 41–70
SUSPICIOUS, 71–100 HIGH RISK. These boundaries and the three internal trigger
thresholds are **documented project assumptions**, not an industry standard.

### 6.2 Three detection problems worth recording

**Look-alike domains.** A `rn`→`m` regex was tried and abandoned: without a
reference list it either misses mid-word substitutions or fires on *govern*,
*return* and *learn*. Replaced with edit distance against a reference label
list, splitting labels on `-` and `_` first so `exarnple-support` is caught.

**Registrable domain is the wrong unit.** For `account-check.invalid.test` the
registrable part is `invalid.test` — all the signal is in the subdomain. Sender
checks now scan **every hostname label**.

**Keyword matching is not detection.** "Password hygiene" in a security
newsletter and "confirm your password" differ only in context. Credential
detection became contextual: the first is informational and adds nothing, the
second scores +20. Similarly, bare threat words (*fine*, *blocked*,
*restricted*) were removed after measuring them firing on "that works fine"
and "restricted parking".

### 6.3 A bug worth documenting

`preprocess_dataframe()` emitted a helper column named `url_count` — which is
also a feature name. `pd.concat` silently produced a duplicate, so the fitted
scaler expected 40 inputs while inference supplied 39. **It failed only at
prediction time**, long after training reported success.

Fixed by dropping colliding helper columns and asserting the feature-matrix
width during training. The assertion is what makes the fix durable.

### 6.4 Privacy in the data layer

The raw email body is **not stored** by default; only the sender's *domain* is
persisted, never the full address. Verified by a test that writes an email
containing a unique marker and then greps the entire SQLite file to confirm the
marker is absent.

---

## 7. Results

### 7.1 Model comparison — test split, 90 emails

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | TP/TN/FP/FN |
|---|---|---|---|---|---|---|
| Logistic Regression | 0.9111 | 0.8723 | 0.9535 | 0.9111 | 0.9861 | 41/41/6/2 |
| **Naive Bayes** ← selected | **0.9556** | 0.9535 | 0.9535 | **0.9535** | **0.9916** | 41/45/2/2 |
| Random Forest | 0.9222 | 0.8913 | 0.9535 | 0.9213 | 0.9886 | 41/42/5/2 |

Selection used **validation** F1 only (LR 0.9545 · NB 0.9655 · RF 0.9451). TF-IDF
and the scaler were fitted on the training split alone.

### 7.2 Strategy comparison — identical split

| Strategy | Accuracy | Precision | Recall | F1 | ROC-AUC | FP | FN |
|---|---|---|---|---|---|---|---|
| Rule-based (≥41) | 0.8667 | **1.0000** | 0.7209 | 0.8378 | 0.8503 | **0** | 12 |
| **Machine learning** | **0.9556** | 0.9535 | **0.9535** | **0.9535** | **0.9916** | 2 | 2 |
| Hybrid (60/40) | 0.8778 | **1.0000** | 0.7442 | 0.8533 | 0.9839 | **0** | 11 |

**The hybrid did not win.** The brief asked for measurement rather than
assumption, and this is the measurement. The hybrid is anchored to the
conservative rule score, so it inherits the rule engine's caution: perfect
precision, lower recall than the model alone.

Which to deploy is a risk decision, not a metric decision. If a false positive
means a user stops trusting the tool, the rule engine or the hybrid is the
better operating point despite the lower F1.

### 7.3 Full-dataset rule audit — all 600 rows

| Class | n | Mean | Median | Max | ≥41 |
|---|---|---|---|---|---|
| LEGITIMATE | 312 | **3.3** | 0 | 30 | **0** |
| PHISHING | 288 | 50.8 | 60 | 100 | 197 |

Not one legitimate email in the entire dataset reaches the escalation
threshold; only 7 reach even 21.

### 7.4 Threshold sweep

| Escalate at | Precision | Recall | F1 | FP | FN |
|---|---|---|---|---|---|
| ≥ 1 | 0.8000 | 0.7442 | 0.7711 | 8 | 11 |
| ≥ 21 | 1.0000 | 0.7442 | **0.8533** | 0 | 11 |
| ≥ 41 *(shipped)* | 1.0000 | 0.7209 | 0.8378 | 0 | 12 |
| ≥ 51 | 1.0000 | 0.4651 | 0.6349 | 0 | 23 |
| ≥ 71 | 1.0000 | 0.3488 | 0.5172 | 0 | 28 |

Dropping to ≥1 buys one extra detection and costs eight false alarms.

### 7.5 Demo verification

| Case | Score | Classification |
|---|---|---|
| `security-alert@account-check.invalid.test` — "URGENT: Verify Your Account Immediately" with `http://198.51.100.10/verify-account` | **80/100** | HIGH RISK / LIKELY PHISHING |
| `training@example.org` — "Cybersecurity Workshop Reminder" | **0/100** | LOW RISK |

Six rules fire on the first: sender +15, urgency +10, credential +20, URL +20,
greeting +5, threat +10.

### 7.6 Testing

**64 tests, all passing, 1.6 seconds.** Covers all 25 required scenarios plus
feature-contract, privacy and safety tests — including two that fail the build
if URL analysis ever opens a socket or attachment analysis ever calls `open()`.

---

## 8. Discussion

### 8.1 The finding that matters

All **12 false negatives** were inspected individually, and they split **11 + 1**.

**Eleven are business email compromise:** plausible sender domain, correct
grammar, no link, no attachment, no urgency. Just *"please update the bank
details for invoice 4821."* Every one scores **exactly 0**.

The rule engine correctly declines to fire on every rule, because **there is
nothing on the surface to detect**. This is not a tuning problem — lowering the
threshold to ≥1 still scores all eleven at 0 while adding eight false alarms.

**The twelfth has a different cause and a different fix.** It is reward bait
that scored 30: suspicious sender, urgency and generic greeting fired, but the
URL rule did not, because its shortened link scored 25 against a trigger
threshold of 30. It missed on two thresholds in sequence. This one row is why
false negatives fall from 12 to 11 at the ≥21 cut-off (§7.4), and both the ML
model and the hybrid classified it correctly.

The first draft of this report claimed all twelve were BEC. Reading the rows
individually disproved the tidier claim, which is the argument for publishing
`reports/error_analysis.csv` rather than summarising it.

What would catch them lies outside the message body: SPF/DKIM/DMARC results,
first-time-sender detection, display-name impersonation checks, and — most
effective of all — **out-of-band verification for any payment or bank-detail
change**, meaning a phone call to a number you already had.

The two most effective controls against the class of attack this tool misses
are **not software**. A detection project that surfaces that honestly is more
useful than one that buries it under a better F1.

### 8.2 Precision as a product decision

Zero false positives across 312 legitimate emails is the result this project
most wants to defend. A security tool that cries wolf gets ignored, and an
ignored tool protects nobody. Three specific choices produced it: contextual
credential detection, anchored threat regexes instead of bare words, and a
structural requirement that several signals combine before escalation.

That last choice is also exactly why the BEC emails are missed. The property
that makes the tool trustworthy is the property that makes it blind. That
trade-off is the honest summary of the whole system.

### 8.3 Limitations

1. **Synthetic data.** Results do not transfer unchanged to real inboxes.
2. **No header authentication** — the largest single gap.
3. **Text only.** No OCR, no QR decoding, no HTML rendering.
4. **English only.** Non-English mail scores near zero, which is a silent
   failure rather than a visible one.
5. **No live threat intelligence** — deliberate, since the tool makes no
   network calls.
6. **Small test split.** 90 emails; one or two decisions move a metric by ~1%.
   Treat the figures as indicative, not precise.
7. **Thresholds are assumptions**, documented but not validated against
   production traffic.

---

## 9. Conclusion

The project delivers what it set out to: a working, explainable, strictly
defensive phishing analyzer with a measured comparison of three detection
strategies, 64 passing tests, and an integrated awareness module.

The results worth keeping are the awkward ones. The hybrid lost. The first
training run's perfect score meant the dataset was too easy, not the model good.
The twelve misses were all the one class no keyword list catches.

**Four things this work demonstrates:**

- **Explainability changes what a tool is for.** A score gets dismissed; a score
  with reasons teaches the person reading it.
- **A perfect metric is a warning sign.** Making the dataset honestly harder was
  the single most valuable change made.
- **Precision and recall are a business decision.** Zero false positives at the
  cost of 12 missed phishing emails may well be right — the sweep is published so
  whoever deploys it can choose.
- **Measure before claiming.** The hybrid was expected to win, and reporting
  that it did not is worth more than a tidy conclusion.

---

## 10. References

1. MITRE ATT&CK for Enterprise — T1566 Phishing. https://attack.mitre.org/
   *(Verify identifiers against the current version before citing.)*
2. RFC 2606 — Reserved Top Level DNS Names.
3. RFC 6761 — Special-Use Domain Names.
4. RFC 5737 — IPv4 Address Blocks Reserved for Documentation.
5. scikit-learn documentation — model selection and metrics.
6. FastAPI documentation — https://fastapi.tiangolo.com/

---

## Appendix A — Reproducing every number

```bash
python data/generate_dataset.py     # §5  600 rows, seed 42
python ml/train_model.py            # §7.1 model comparison
python ml/evaluation.py             # §7.2–7.4 strategies + sweep
python ml/predict.py --demo         # §7.5 demo cases
python -m pytest tests/ -v          # §7.6 64 tests
```

## Appendix B — Artifacts

| Path | Contents |
|---|---|
| `reports/ml_metrics.json` | Full per-model metrics and confusion matrices |
| `reports/detection_comparison.json` | Rule vs ML vs hybrid, plus the sweep |
| `reports/error_analysis.csv` | Every misclassified test row |
| `reports/model_comparison.csv` | Model table in CSV form |
| `screenshots/` | 26 evidence items (23 automatic, 3 manual) |
