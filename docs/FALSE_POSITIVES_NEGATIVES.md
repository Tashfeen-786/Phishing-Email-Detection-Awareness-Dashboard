# False Positives & False Negatives

Every figure here comes from `ml/evaluation.py` and the full-dataset rule audit.
Raw data: [`../reports/detection_comparison.json`](../reports/detection_comparison.json)
and [`../reports/error_analysis.csv`](../reports/error_analysis.csv).

---

## 1. The two errors, and what they cost

| | Definition | Cost |
|---|---|---|
| **False positive** | A legitimate email flagged as phishing | The user stops trusting the tool. After a few bad calls they click "ignore" without reading — and the tool's true positives stop mattering too. |
| **False negative** | A phishing email classified as legitimate | An attack reaches the inbox. The user is the last line of defence, unassisted. |

These are not symmetric, and which one you optimise for is a **business
decision**, not a maths one.

---

## 2. Measured results — test split, 90 emails (43 phishing / 47 legitimate)

| Strategy | Precision | Recall | F1 | **FP** | **FN** |
|---|---|---|---|---|---|
| Rule-based (≥41) | **1.0000** | 0.7209 | 0.8378 | **0** | 12 |
| Machine learning | 0.9535 | **0.9535** | **0.9535** | 2 | 2 |
| Hybrid (60/40) | **1.0000** | 0.7442 | 0.8533 | **0** | 11 |

### Full-dataset rule audit, all 600 rows

| Class | n | Mean score | Median | Max | ≥41 |
|---|---|---|---|---|---|
| LEGITIMATE | 312 | **3.3** | 0 | 30 | **0** |
| PHISHING | 288 | 50.8 | 60 | 100 | 197 |

**Not one of the 312 legitimate emails in the entire dataset reaches the
escalation threshold.** Only 7 reach even 21.

---

## 3. False positives: measured 0

Three specific changes produced that, each made after observing a failure:

### 3.1 Credential detection is contextual, not keyword-based

A security-awareness email that mentions **"password hygiene"** or **"never
share your password"** is *about* credentials, it does not *request* them.
Naive keyword matching flags it.

| Text | Finding | Risk |
|---|---|---|
| "This month's topic is password hygiene." | `CREDENTIAL_TOPIC_MENTIONED` (informational) | **+0** |
| "Please confirm your password to continue." | `CREDENTIAL_REQUEST` | **+20** |

Covered by a dedicated test.

### 3.2 Threat detection uses anchored regexes, not bare words

The first version scored single words: *fine*, *blocked*, *restricted*,
*closed*. Measured against the legitimate rows, they fired on "that works
fine", "restricted parking" and "the office will be closed on Friday".

They were **removed**. Threat detection now requires a phrase structure —
`your account will be (permanently )?(closed|suspended|terminated)`.

| Text | Threat rule |
|---|---|
| "The office will be closed on Friday." | not triggered |
| "Your account will be permanently closed." | **+10** |

### 3.3 Several signals are required to escalate

At the ≥41 threshold no single rule can escalate an email on its own — the
largest weight is 25. A genuinely urgent HR message scores 10 and stays LOW.
This is the structural reason the false-positive count is zero, and it is also
precisely why the misses in the next section happen.

---

## 4. False negatives: measured 12

All twelve were inspected individually. They split **11 + 1**.

| Group | Count | Rule score | Character |
|---|---|---|---|
| **Business email compromise** | **11** | all exactly **0** | No link, no attachment, no urgency, no credential request |
| **Threshold near-miss** | **1** | **30** | Reward bait that fired three rules but landed in MODERATE RISK |

### 4.1 The eleven: business email compromise

```
From:    m.dsouza@partner-supplies.example.net     ← plausible, well-formed
Subject: Updated bank details for invoice 4821     ← no urgency words
Body:    Hi Ravi,
         Following our call, please note our account details have
         changed for the upcoming payment. The updated form is with
         accounts. Could you confirm once processed?
         Thanks, Maria
URLs:        (none)                                ← no link to analyse
Attachment:  (none)                                ← no file to analyse
```

Rule score: **0/100 — LOW RISK.**

### Why every rule correctly declines to fire

| Rule | Why not |
|---|---|
| Suspicious sender | Well-formed, reserved domain, no look-alike pattern |
| Urgency | No time pressure — deliberately calm |
| Credential request | None. It asks for a payment, not a password |
| Suspicious URL | No URL exists |
| Suspicious attachment | No attachment exists |
| Generic greeting | Uses a real first name |
| Threat / fear | None |

**This is business email compromise, and the rule engine is blind to it by
construction.** There is nothing on the surface to detect. The message is
malicious because of a fact that is not in the email — the bank details are
wrong, and only the accounting system or a phone call can establish that.

No keyword list fixes this. Lowering the threshold does not fix it either: all
eleven score **exactly 0**, so even a ≥1 cut-off misses every one of them while
costing 8 false positives.

### 4.2 The twelfth: a threshold near-miss

One false negative is **not** BEC, and it is worth reporting separately because
it is the only one that tuning could have caught.

```
From:    claims-desk@password-expiry-notice.invalid.test
Subject: You have been selected for an exclusive gift card
Body:    Dear Member,
         You have been selected to receive a free gift card. This exclusive
         offer expires today. Claim your reward now by confirming your
         personal information at the link below.
         http://bit.ly/example-not-real
         ACT NOW!!!
```

Rule score **30 — MODERATE RISK**, just under the ≥41 escalation threshold.

| Rule | Fired? | Weight |
|---|---|---|
| Suspicious sender | ✅ | +15 |
| Urgency | ✅ | +10 |
| Generic greeting | ✅ | +5 |
| **Suspicious URL** | ❌ | **0** |
| | | **= 30** |

**It missed twice, on two separate thresholds.** The URL
`http://bit.ly/example-not-real` scored **25** — plain HTTP plus a shortener —
against a URL trigger threshold of **30**. Had that rule fired, the email would
have scored 50 and been caught. Then the total of 30 missed the escalation
threshold of 41.

This single row explains a line in the sweep below: false negatives drop from
12 at ≥41 to **11 at ≥21**. That one recovered detection is this email.

Both the ML model (probability 1.00) and the hybrid (58) classified it
correctly. It is a clean illustration of where a rule engine's fixed
thresholds are brittle and a model's learned boundary is not.

### What would actually catch the eleven

| Control | Why it works here |
|---|---|
| **SPF / DKIM / DMARC** | Spoofed sender fails authentication |
| **First-time-sender detection** | "You have never emailed this address before" |
| **Display-name impersonation check** | Known contact name, unknown address |
| **Out-of-band verification for payment changes** | A phone call to a number you already had — the only control that works when the email is genuinely from a compromised legitimate account |
| **Finance process control** | Dual authorisation for any bank-detail change |

The last two are **not software**. The most effective defence against the class
of attack this tool misses is a process, and that is a finding worth more than
another two points of F1.

> **A note on how this section was written.** The first draft said "all 12
> false negatives are business email compromise." Reading the twelve rows
> individually showed that eleven were, and the twelfth was a threshold
> near-miss with a completely different cause and a completely different fix.
> The tidier claim was the wrong one.

---

## 5. The ML model's 2 + 2

| Error | Count | Pattern |
|---|---|---|
| False positive | 2 | Legitimate rows drawn from the **indistinguishable** template pool — vocabulary identical to phishing rows in the same pool |
| False negative | 2 | Phishing rows from the same shared pool |

These are the **irreducible error floor** the dataset was deliberately designed
to have. A model that got these right would be memorising, not generalising —
the text genuinely does not contain enough information to decide.

That is the reason the dataset includes 9% indistinguishable rows per class. The
first version of the generator did not, and all three models scored **1.0000 on
every metric** — a result that looks fabricated, teaches nothing, and conceals
exactly the lesson this document exists to state.

---

## 6. Choosing an operating point

| Escalate at | Precision | Recall | F1 | FP | FN |
|---|---|---|---|---|---|
| ≥ 1 | 0.8000 | 0.7442 | 0.7711 | 8 | 11 |
| ≥ 21 | 1.0000 | 0.7442 | **0.8533** | 0 | 11 |
| ≥ 41 *(default)* | 1.0000 | 0.7209 | 0.8378 | 0 | 12 |
| ≥ 51 | 1.0000 | 0.4651 | 0.6349 | 0 | 23 |
| ≥ 71 | 1.0000 | 0.3488 | 0.5172 | 0 | 28 |

Precision stays at 1.0000 for every threshold from 21 upward. Dropping to ≥1
buys **one** extra detection and costs **eight** false alarms — a bad trade for
a tool whose value depends on being believed.

Note the ≥21 row: it recovers one detection (FN 12 → 11) **at no precision
cost**. That recovered email is the gift-card near-miss from §4.2, and it is
the strongest argument in this table for shipping ≥21 instead.

The project ships ≥41 as the more conservative default. A SOC with analyst
capacity to review the extra volume should prefer **≥21** — on this split it is
strictly better, with the same perfect precision and one more catch.

---

## 7. What this means in practice

1. **Never present a score as proof.** The UI shows the band, the reasons and
   the evidence, and recommends verification through a known channel.
2. **A LOW RISK verdict is not a clean bill of health.** It means *no surface
   indicators were found* — which is exactly what the 11 missed BEC emails look
   like. The UI wording reflects this.
3. **Layer the defences.** This tool covers message-content analysis. It does
   not replace header authentication, endpoint protection, finance process
   controls, or a trained human.
4. **Verify out of band for anything involving money or credentials**, however
   the email scores.
