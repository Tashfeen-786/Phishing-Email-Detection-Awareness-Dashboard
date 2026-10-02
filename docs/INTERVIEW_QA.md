# Interview Questions & Answers

Ten questions, in the order an interviewer is likely to ask them. Every number
below is measured — you can reproduce all of them with `run_tests.bat`,
`train_model.bat` and `python ml/evaluation.py`.

**Only quote figures you can defend.** If you change the dataset seed, re-run
the pipeline and update these answers.

---

## 1. Explain your project.

I developed a **Phishing Email Detection & Awareness Dashboard** that analyses
an email for phishing indicators and explains every part of its verdict.

It examines five surfaces independently — sender, subject, body, URLs and
attachment filename — and extracts security features such as urgency,
credential requests, suspicious URL structure, generic greetings and risky
attachment types. Those feed a rule-based scoring engine that produces a
**0–100 risk score** and a classification: Low Risk, Moderate Risk, Suspicious,
or High Risk / Likely Phishing.

Alongside the rules I trained a machine-learning model — TF-IDF text features
plus 39 structured features, comparing Logistic Regression, Naive Bayes and
Random Forest. Naive Bayes was selected on validation F1 and reached **F1
0.9535 with ROC-AUC 0.9916** on a held-out test split of 90 emails.

The dashboard shows the detected indicators, the recommended actions, the
analysis history, and a full awareness module that teaches the warning signs.

Two design decisions matter most. First, **explainability is a requirement, not
a feature** — the tool never returns a bare score; it names every rule that
fired and quotes the evidence, because an analyst who cannot justify a verdict
cannot defend it. Second, **everything is synthetic and strictly defensive** —
600 generated emails using only RFC-reserved domains, and the application never
opens a link, resolves a hostname or executes an attachment.

---

## 2. What is phishing and how does your system detect it?

Phishing is social engineering: an attacker persuades someone to do something
unsafe — reveal credentials, open a malicious attachment, transfer money, or
visit a deceptive site. The attack targets human judgement under pressure, not
a software vulnerability.

**My system never relies on a single indicator.** It combines signals from the
sender, the subject and body language, the URLs and the attachment filename.
Seven weighted rules fire independently and add up:

| Rule | Weight |
|---|---|
| Suspicious sender | +15 |
| Urgency language | +10 |
| Credential request | +20 |
| Suspicious URL | +20 |
| Suspicious attachment | +25 |
| Generic greeting | +5 |
| Threat / fear language | +10 |

An email with urgency **and** a credential request **and** a suspicious URL
scores 50 and lands in SUSPICIOUS. An email with only urgency scores 10 and
stays LOW.

That is the whole philosophy: one signal is a question, several signals in a
context that does not add up is an answer — and a human still makes the final
call.

---

## 3. How does your URL analyzer identify suspicious links?

It performs **static analysis without ever opening the URL**. It parses the
string and checks the scheme, hostname, length, subdomain depth, whether the
host is a raw IP address, whether a shortener is used, whether credential
keywords appear in the path, whether there is an `@` in the authority, and
whether the host uses Punycode.

One point I make explicitly: **HTTPS does not prove a site is safe.**
Certificates are free and automated, so a phishing page can be served over TLS.
Missing HTTPS is a signal; present HTTPS is not an all-clear.

Two safety properties I'd highlight:

- Output is always **defanged** — `http://198.51.100.10/verify-account` becomes
  `hxxp://198[.]51[.]100[.]10/verify-account` before it reaches the API, the
  database or the browser. The tool cannot hand a user a clickable attacker
  link.
- A test monkey-patches `socket.connect`, `socket.create_connection` and
  `socket.gethostbyname` to raise. **If anyone ever adds a network call to the
  analyzer, the test suite fails.** The ethical constraint is enforced by CI,
  not by a comment.

---

## 4. What features did you use for phishing detection?

**39 structured features**, grouped by surface:

- **Content:** urgency count, credential count, threat count, financial-pressure
  count, reward-bait count, generic greeting, uppercase ratio, exclamation
  count, grammar issues, subject length, body length, word count.
- **Sender:** domain length, subdomain count, digits in domain, look-alike
  distance, free-mail flag, display-name mismatch, suspicious TLD.
- **URL:** URL count, suspicious URL count, has-raw-IP, has-shortener, max URL
  risk, uses-HTTPS, maximum subdomain depth, keyword-in-path.
- **Attachment:** has attachment, is executable, is script, is macro Office,
  double extension, archive.

For the ML model these are concatenated with **TF-IDF** over subject + body
(word 1–2 grams, `min_df=2`, 2,725 terms) giving 2,764 columns total.

The detail I'd want an interviewer to notice: **training and inference call the
same `extract_email_features()` function.** Most "great offline metrics, useless
in production" failures come from a training script that reimplements feature
logic slightly differently. Sharing the function makes that impossible.

I hit a real bug there. A preprocessing helper emitted a column called
`url_count`, which is also a feature name, so `pd.concat` silently produced a
duplicate — the scaler expected 40 inputs while inference supplied 39. It only
failed at prediction time. I now drop colliding helper columns and assert the
feature-matrix width during training.

---

## 5. How does your phishing risk score work?

Each rule contributes a fixed weight. The raw maximum is **105**, capped at
**100**, and mapped to four bands:

| Score | Classification |
|---|---|
| 0–20 | LOW RISK |
| 21–40 | MODERATE RISK |
| 41–70 | SUSPICIOUS |
| 71–100 | HIGH RISK / LIKELY PHISHING |

A dedicated test drives all seven rules simultaneously and asserts that the raw
105 caps to exactly 100, and eight more tests check each band boundary.

**I am explicit that these thresholds are project assumptions, not an industry
standard.** So are the three internal trigger thresholds (sender ≥ 30, URL ≥ 30,
attachment ≥ 40). I document them so they can be challenged, and
`ml/evaluation.py` sweeps the escalation threshold to show what each choice
costs:

| Escalate at | Precision | Recall | F1 |
|---|---|---|---|
| ≥ 1 | 0.8000 | 0.7442 | 0.7711 |
| ≥ 21 | 1.0000 | 0.7442 | **0.8533** |
| ≥ 41 (default) | 1.0000 | 0.7209 | 0.8378 |
| ≥ 71 | 1.0000 | 0.3488 | 0.5172 |

In production I would calibrate these against representative traffic and
analyst feedback rather than keep my own defaults.

---

## 6. What machine-learning techniques did you use?

TF-IDF over the email text plus the 39 structured features, min-max scaled. I
trained **Logistic Regression, Naive Bayes and Random Forest** on a stratified
70/15/15 split (418/90/90, seed 42), selecting on **validation** F1 so the test
split stayed untouched until the end.

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC |
|---|---|---|---|---|---|
| Logistic Regression | 0.9111 | 0.8723 | 0.9535 | 0.9111 | 0.9861 |
| **Naive Bayes** ← selected | **0.9556** | 0.9535 | 0.9535 | **0.9535** | **0.9916** |
| Random Forest | 0.9222 | 0.8913 | 0.9535 | 0.9213 | 0.9886 |

TF-IDF and the scaler are fitted on the **training split only** — fitting on the
full dataset leaks test information and inflates the result.

**The most interesting thing that happened was a failure.** My first run scored
**1.0000 on every metric for all three models.** The metrics were real; the
dataset was the problem. My "hard" examples still used vocabulary unique to one
class, so the task was trivially separable. I rebuilt the generator so ~9% of
each class is drawn from a **shared template pool** — messages that are
genuinely ambiguous, because whether "please process invoice 4821" is legitimate
depends on whether that invoice exists, a fact that is not in the email. That
gave the dataset a realistic error floor and turned the evaluation into
something worth reading.

I kept the rule engine regardless, because it explains itself and the model
does not.

---

## 7. Why are precision and recall important in phishing detection?

They describe two different failures with two different costs.

**Precision** — of the emails I flagged, how many were actually phishing. Low
precision means false alarms, and false alarms are how a security tool gets
switched off. A filter nobody trusts protects nobody.

**Recall** — of the phishing emails present, how many I caught. Low recall means
a real attack reaches an inbox.

Accuracy alone hides both, especially with class imbalance. F1 balances them,
which is why I selected the model on F1.

The measured trade-off in my project makes this concrete, on the same 90-email
test split:

| Strategy | Precision | Recall | F1 | FP | FN |
|---|---|---|---|---|---|
| Rule-based | **1.0000** | 0.7209 | 0.8378 | **0** | 12 |
| ML | 0.9535 | **0.9535** | **0.9535** | 2 | 2 |
| Hybrid | **1.0000** | 0.7442 | 0.8533 | **0** | 11 |

Note that **the hybrid did not win on F1** — I expected it to, and reporting the
measurement instead of the expectation is the honest outcome.

Which would I deploy? If the tool advises non-specialists, I would take the
rule engine or the hybrid: zero false positives preserves trust, and the missed
emails are the BEC cases that need header authentication anyway. That is a risk
decision, not a metric decision.

---

## 8. What are false positives and false negatives in your project?

**False positive** — a legitimate email flagged as phishing. Measured: **0 out
of 47** legitimate test emails reached the escalation threshold, and across all
312 legitimate rows in the dataset the mean score is **3.3/100**. I got there by
making detection contextual: "password hygiene" in a training email is
informational and adds nothing, while "confirm your password" scores +20. I also
removed bare words like *fine*, *blocked* and *restricted* from the threat
lexicon after measuring them firing on "that works fine" and "restricted
parking".

**False negative** — phishing classified as legitimate. Measured: **12 out of 43**
phishing test emails scored below 41. I read all twelve individually, and they
split 11 + 1.

**Eleven were business email compromise** — plausible sender domain, correct
grammar, no link, no attachment, no urgency. Just "please update the bank
details for invoice 4821". All eleven scored **exactly 0**.

The rule engine cannot see these, because there is nothing on the surface to
see. That is not a tuning problem; no keyword list solves it, and even a ≥1
threshold misses all eleven.

**The twelfth was different, and I'd mention it because it's the one tuning
could have caught.** Reward bait that scored 30 — suspicious sender, urgency
and generic greeting all fired, but the URL rule didn't. Its shortened link
scored 25 against a trigger threshold of 30, so it missed twice over: once on
the URL threshold, once on the escalation threshold. That single email is why
false negatives drop from 12 to 11 when I lower the cut-off to 21.

I keep the distinction because the two have different fixes: the eleven need
header authentication, the twelfth needs threshold calibration. It is the
argument for signals the body does not contain: SPF/DKIM/DMARC results,
first-time-sender detection, and out-of-band verification for any payment
change — a phone call to a number you already had.

I report that gap prominently rather than hiding it, because it is the most
useful thing the evaluation produced.

---

## 9. How did you make this cybersecurity project safe?

Safety was a design constraint, not a disclaimer at the end.

- **Synthetic data only.** 600 generated emails. Every domain is reserved by
  RFC 2606 / RFC 6761 (`example.com`, `example.org`, `*.invalid.test`) and every
  IP is from the RFC 5737 documentation ranges. No real person, company or brand
  appears anywhere.
- **The application never sends email, never harvests credentials, and contains
  no phishing page.** It is an analyser, full stop.
- **URLs are analysed as strings**, never opened or resolved — enforced by a
  test that patches the socket functions to raise.
- **Attachments are judged by filename only**, never read or executed —
  enforced by a test that patches `builtins.open`.
- **Privacy by default.** The raw email body is **not stored** unless explicitly
  enabled, and only the sender's *domain* is persisted, never the full address.
  There's a test that writes an email containing a unique marker string, then
  greps the whole SQLite file to confirm the marker is absent.
- **Standard web hygiene:** parameterised SQL with whitelisted sort columns,
  React escaping, PBKDF2-SHA256 at 200,000 iterations, `.env` git-ignored, and
  the server bound to localhost by default.

The three simulation templates in the awareness module are labelled for
classroom discussion and for testing this analyzer — explicitly not for sending
to anyone.

---

## 10. How can this project be improved for a real SOC environment?

In priority order, driven by what the measurement showed:

1. **Email header analysis with SPF, DKIM and DMARC.** This is the top item
   because it directly addresses my 12 measured false negatives. No amount of
   body-text tuning catches a well-written BEC email.
2. **First-time-sender and display-name-impersonation detection** against a
   contact history — the second half of the same gap.
3. **Reputation enrichment** — URL, domain-age and attachment-hash lookups
   against a threat-intelligence feed. Clearly opt-in, since it breaks the
   current no-network guarantee.
4. **SIEM / ticketing integration** so a reported email automatically opens a
   triage case with the indicators pre-populated.
5. **An analyst feedback loop** — let an analyst mark a verdict wrong, store it,
   and use it to recalibrate weights and monitor **model drift**. Phishing
   language changes; a model trained once decays.
6. **Stronger NLP** — a transformer for the text channel. I scaffolded
   DistilBERT in `ml/optional_bert.py` but kept it strictly optional and report
   no metric for it, because I have not run it.
7. **QR-code extraction** for quishing, and multilingual keyword sets.

The constant across all of these: **the score supports the analyst's
investigation, it does not replace their judgement.** The moment a tool claims
certainty it stops being useful, because the analyst stops thinking.

---

## Questions you should be ready for

- *"Your dataset is synthetic — how do you know any of this transfers?"*
  I don't, and I say so in the Limitations section. What the project
  demonstrates is the pipeline, the explainability and the evaluation
  discipline. The honest next step is labelled real mail under authorisation.
- *"Why Naive Bayes? That's a simple model."*
  It won on validation F1 and it trains in about a second. TF-IDF is
  high-dimensional and sparse, which suits NB. I had no reason to pick a heavier
  model that measured worse.
- *"90 test emails is small."*
  It is. One or two decisions move a metric by roughly 1%, so I treat these as
  indicative, not precise — which is why I also report the full 600-row rule
  audit alongside them.
