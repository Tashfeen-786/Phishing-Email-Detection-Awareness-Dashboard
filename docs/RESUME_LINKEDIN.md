# Résumé & LinkedIn Material

Copy-paste ready. **Every number below is measured** — reproduce them with
`run_tests.bat`, `train_model.bat` and `python ml/evaluation.py` before you use
them anywhere. If you change the dataset seed, re-run and update.

---

## 1. Résumé entry — full version

> **Phishing Email Detection & Awareness Dashboard** — *Python, FastAPI, scikit-learn, React, SQLite*
>
> - Built a defensive email-analysis platform that scores phishing risk 0–100 across five surfaces (sender, subject, body, URLs, attachment filename) and **explains every point it awards**, so analysts can audit and defend each verdict.
> - Engineered **39 structured features** plus TF-IDF and compared Logistic Regression, Naive Bayes and Random Forest on a stratified 70/15/15 split; selected on validation F1 and achieved **F1 0.9535 / ROC-AUC 0.9916** on a held-out test set.
> - Benchmarked rule-based vs ML vs hybrid detection on an identical split, finding the **rule engine achieved precision 1.0000 with zero false positives** across 312 legitimate emails, while ML gave the highest F1 — and documented the trade-off rather than claiming the hybrid was best.
> - Diagnosed all **12 false negatives** individually — 11 were business email compromise with no surface indicators, 1 a threshold near-miss — and used the finding to argue for SPF/DKIM/DMARC and out-of-band payment verification.
> - Wrote **64 pytest tests** covering 25 detection scenarios, including safety tests that fail the build if URL analysis ever opens a socket or attachment analysis ever touches the filesystem.
> - Shipped a React dashboard (5 KPI cards, 6 charts, searchable history) and an integrated awareness module mapped to MITRE ATT&CK T1566.

---

## 2. Résumé entry — three lines

> **Phishing Email Detection & Awareness Dashboard** — *Python, FastAPI, scikit-learn, React*
> Built an explainable phishing analyzer scoring emails 0–100 across sender, content, URL and attachment signals; achieved **F1 0.9535 / ROC-AUC 0.9916** with **zero false positives** across 312 legitimate samples.
> Benchmarked rule-based vs ML vs hybrid detection on an identical held-out split and documented the precision/recall trade-off; 64 automated tests including safety guarantees that block network and filesystem access.

---

## 3. Résumé entry — one line

> **Phishing Email Detection & Awareness Dashboard** — Explainable email threat analyzer (Python/FastAPI/React) with rule-based and ML detection; **F1 0.9535, zero false positives on 312 legitimate samples**, 64 automated tests.

---

## 4. Skills this evidences

**Security:** phishing analysis · threat detection engineering · MITRE ATT&CK
mapping · SOC triage workflow · security awareness · defensive tooling · secure
coding · privacy by design

**ML:** feature engineering · TF-IDF · model selection and comparison ·
precision/recall trade-offs · ROC-AUC · error analysis · leakage prevention ·
threshold calibration

**Engineering:** Python · FastAPI · REST API design · SQLite schema design and
migrations · React · data visualisation · pytest · CI-ready test suites ·
technical documentation

---

## 5. LinkedIn post

> **What I learned building a phishing detector: the hybrid model lost.**
>
> I just finished a Phishing Email Detection & Awareness Dashboard, and the
> most useful result was the one I didn't expect.
>
> The plan was standard: a rule engine, an ML model, then a hybrid that beats
> both. I benchmarked all three on the same held-out split of 90 emails.
>
> → Rule-based: F1 0.8378, **precision 1.0000, zero false positives**
> → ML (Naive Bayes): **F1 0.9535**, ROC-AUC 0.9916
> → Hybrid: F1 0.8533, precision 1.0000
>
> **The hybrid didn't win.** I could have quietly reported it as the best
> approach. Instead I looked at why.
>
> The rule engine never flagged a legitimate email — not one, across all 312 in
> the dataset. But it missed 12 phishing emails. I read all 12.
>
> **Eleven were business email compromise:** plausible sender, correct grammar,
> no link, no attachment, no urgency. Just *"please update the bank details for
> invoice 4821."* All eleven scored exactly zero.
>
> (The twelfth was a threshold near-miss — it scored 30 against a cut-off of 41.
> I nearly wrote "all 12 were BEC" because it made a tidier story. Reading the
> rows individually is what stopped me.)
>
> There is nothing on the surface to detect. No keyword list fixes that. The
> controls that actually work are SPF/DKIM/DMARC, first-time-sender detection,
> and a phone call to a number you already had.
>
> Two other things I'd tell anyone starting a similar project:
>
> **1. A perfect score is a bug report.** My first training run hit 1.0000 on
> every metric. The metrics were real — my synthetic dataset was too easy. I
> rebuilt it so 9% of each class is genuinely ambiguous. Only then did the
> evaluation say anything useful.
>
> **2. Explainability changes what the tool is for.** Every verdict names the
> rules that fired and quotes the evidence. A score gets ignored; a score with
> reasons teaches the person reading it.
>
> Everything is synthetic and strictly defensive — RFC-reserved domains only,
> and the app never opens a link or touches an attachment. There are tests that
> fail the build if anyone adds a network call.
>
> Repo in the comments. Happy to talk about the BEC finding — it's the part I'd
> build on next.
>
> \#CyberSecurity #Phishing #MachineLearning #BlueTeam #Python #InfoSec

---

## 6. LinkedIn post — short version

> Built a Phishing Email Detection & Awareness Dashboard: it scores emails
> 0–100 and **explains every point**, naming each rule that fired.
>
> Measured on a held-out split of 90 emails:
> → ML: **F1 0.9535**, ROC-AUC 0.9916
> → Rules: **precision 1.0000 — zero false positives** across 312 legitimate samples
>
> The 12 misses were all business email compromise — no link, no attachment, no
> urgency, nothing to detect. That gap is the argument for SPF/DKIM/DMARC and
> out-of-band verification, and reporting it honestly was more valuable than
> another two points of F1.
>
> Synthetic data only, strictly defensive, 64 automated tests.
>
> \#CyberSecurity #MachineLearning #Phishing #Python

---

## 7. LinkedIn headline options

> Cybersecurity Enthusiast | Phishing Detection & Email Security | Python · FastAPI · Machine Learning

> Aspiring SOC Analyst | Built an explainable phishing detection platform with ML and integrated awareness training

> Security Engineering | Threat Detection · Explainable ML · Defensive Tooling

---

## 8. "About" paragraph

> I build defensive security tooling with a bias toward explainability. My most
> recent project is a Phishing Email Detection & Awareness Dashboard: it
> analyses an email across five surfaces, scores the risk 0–100, and names every
> indicator behind that score — because a verdict an analyst cannot justify is a
> verdict they cannot use.
>
> Working on it taught me that the interesting results are the awkward ones. The
> hybrid model I expected to win came third on F1. My first ML run scored a
> perfect 1.0000, which turned out to mean my dataset was too easy rather than
> my model was good. And the 12 phishing emails the rule engine missed were all
> business email compromise — the class no keyword list catches, and the reason
> header authentication and out-of-band verification exist.
>
> I care about measuring honestly, documenting the gaps, and building tools
> people actually trust enough to use.

---

## 9. Talking points for an interview

Keep these ready — they are the parts that show judgement rather than syntax:

| Prompt | Your 30-second answer |
|---|---|
| *"Tell me about a time something didn't work."* | The perfect 1.0000 first run. Real metrics, unusable dataset. I rebuilt the generator with genuinely ambiguous rows so the evaluation had an error floor. |
| *"When did the data change your mind?"* | I assumed the hybrid would win. It came third on F1. I reported the measurement, and the interesting part was *why* — the rule engine's caution caps its recall. |
| *"How do you handle a trade-off with no right answer?"* | Zero false positives vs 12 missed phish (11 of them BEC). I published the threshold sweep so whoever deploys it can choose, instead of hard-coding my preference. |
| *"How do you ensure your work is ethical?"* | I encoded it as tests. URL analysis fails the suite if it opens a socket; attachment analysis fails if it calls `open()`. A comment is a promise, a test is a guarantee. |

---

## 10. Before you publish

- [ ] Re-run `run_tests.bat` and confirm the test count still matches
- [ ] Re-run `train_model.bat` and confirm the metrics still match
- [ ] Push to GitHub and add the real URL (see [`GITHUB_STRATEGY.md`](GITHUB_STRATEGY.md))
- [ ] Capture screenshots 24–26
- [ ] Re-read the claims above and delete anything you cannot demonstrate live
