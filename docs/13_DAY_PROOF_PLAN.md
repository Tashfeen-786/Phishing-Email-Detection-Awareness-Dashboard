# 13-Day Proof Plan

A day-by-day plan for building this project and evidencing each stage.

> **How to read this document.** The *files* and *functionality* columns
> describe work that exists in this repository and has been executed. The
> *commit* column is a **suggested message** — commits are a MANUAL USER ACTION,
> because no repository exists until you create one. No commit hash, no
> repository URL and no contribution graph has been invented anywhere in this
> project.

---

## Day 1 — Architecture and repository

**Files created**
```
README.md · LICENSE · .gitignore · .env.example · requirements.txt
docs/ARCHITECTURE.md
backend/config.py · backend/utils/logger.py
(empty package skeleton: backend/{models,routes,services,utils})
```

**Functionality.** Settings load from `.env` with working defaults, so the
project runs with no configuration at all. Two loggers are separated from the
start: an application log and a security log, because mixing audit events with
debug noise makes both useless.

**Suggested commit**
```
chore: project skeleton, configuration and architecture documentation
```

**Screenshot:** `01_project_structure.png` — **AUTO**

**What it proves.** The layout was designed before any code was written:
analyzers separated from routes, models separated from services. A reviewer can
see the shape of the system in one image.

---

## Day 2 — Synthetic dataset

**Files created**
```
data/generate_dataset.py  →  data/phishing_email_dataset.csv
```

**Functionality.** A deterministic generator producing 600 labelled emails
(48% phishing) from a seed. Three tiers: clear-cut, hard, and **indistinguishable**
(9%, drawn from a template pool shared by both labels) so the dataset has a
realistic irreducible error floor.

Only RFC 2606 / RFC 6761 reserved domains and RFC 5737 documentation IPs.

**Suggested commit**
```
feat(data): deterministic synthetic email generator with reserved domains only
```

**Screenshot:** `02_dataset_generation.png` — **AUTO**

**What it proves.** 600 rows, 48.0% phishing, 36 unique sender domains, seed 42.
Re-running reproduces the file byte for byte, which is what makes every later
metric checkable.

---

## Day 3 — Email preprocessing

**Files created**
```
backend/services/preprocessing.py
backend/utils/text_utils.py · backend/utils/validators.py
```

**Functionality.** Whitespace and control-character normalisation, sender
splitting, URL extraction from free text (trailing punctuation and unbalanced
brackets stripped), duplicate removal, and `clean_text` construction for the ML
model.

**Suggested commit**
```
feat(preprocessing): normalisation, URL extraction and input validation
```

**Screenshot:** covered by `23_test_results.png` — **AUTO**

**What it proves.** Preprocessing has direct test coverage: empty subject, empty
body, completely empty input and URL-in-body extraction all pass.

---

## Day 4 — Sender and content analysis

**Files created**
```
backend/services/sender_analyzer.py
backend/services/content_analyzer.py
backend/utils/keywords.py
```

**Functionality.** Sender: format validation, look-alike detection by **edit
distance** against a reference label list, action-word compounds, digit
substitution, subdomain depth, display-name mismatch. Content: urgency, threat,
credential, financial, reward, greeting, shouting, punctuation, grammar.

Two decisions worth recording:

- Sender checks run over **every hostname label**, not just the registrable
  domain — `account-check.invalid.test` resolves to a registrable part of
  `invalid.test`, so a registrable-only check under-scores it badly.
- Credential detection is **contextual**. "Password hygiene" in a training email
  produces an informational note and adds no risk; "confirm your password"
  scores +20.

**Suggested commit**
```
feat(analysis): sender and content analyzers with contextual credential detection
```

**Screenshot:** `09_explainable_findings.png` — **AUTO**

**What it proves.** Each finding carries its own evidence string, so the score
is auditable rather than asserted.

---

## Day 5 — URL analysis

**Files created**
```
backend/services/url_analyzer.py
```

**Functionality.** Static analysis of scheme, host shape, raw IPs, shorteners,
subdomain count, path keywords, `@` tricks, punycode, length and encoding.
Output is always defanged.

**Suggested commit**
```
feat(url): static URL analyzer with defanged output and no network access
```

**Screenshot:** `10_url_analysis.png` — **AUTO**

**What it proves.** `hxxp://198[.]51[.]100[.]10/verify-account` appears in the
UI — the tool cannot hand a user a clickable attacker link, and a test fails if
anyone ever adds a socket call.

---

## Day 6 — Attachment analysis

**Files created**
```
backend/services/attachment_analyzer.py
```

**Functionality.** Extension classification (executable, script, macro Office,
archive, document), double-extension detection, risk scoring. Filename only.

**Suggested commit**
```
feat(attachment): filename-only extension risk analysis
```

**Screenshot:** covered by `07_phishing_result_high_risk.png` — **AUTO**

**What it proves.** `invoice.pdf.exe` is flagged as a double extension without
any file being read — enforced by a test that patches `builtins.open`.

---

## Day 7 — Risk engine

**Files created**
```
backend/services/risk_engine.py
backend/services/feature_extractor.py
backend/services/analysis_service.py
```

**Functionality.** Seven weighted rules (15/10/20/20/25/5/10), raw maximum 105
capped at 100, four documented bands, `why` list, prioritised recommendations,
and the 39-feature extractor shared with training.

**Suggested commit**
```
feat(risk): weighted rule engine with capped scoring and explainable output
```

**Screenshots:** `07_phishing_result_high_risk.png`, `08_legitimate_result_low_risk.png` — **AUTO**

**What it proves.** The documented demo cases land exactly where the
specification says: phishing **80/100 HIGH RISK**, legitimate **0/100 LOW RISK**.

---

## Day 8 — Machine learning

**Files created**
```
ml/train_model.py · ml/evaluation.py · ml/predict.py · ml/optional_bert.py
backend/services/ml_service.py
reports/ml_metrics.json · reports/detection_comparison.json
```

**Functionality.** Stratified 70/15/15 split, TF-IDF fitted on train only,
three models compared, selection by validation F1, bundle saved with the exact
test-row IDs so evaluation can reuse the identical split.

**This is the day the most useful thing went wrong.** The first run returned
**1.0000 on every metric for all three models**. The metrics were real, but the
dataset was too separable — the "hard" rows still used vocabulary unique to one
label. Rather than report a perfect score, the dataset was rebuilt with 9%
genuinely indistinguishable rows.

**Suggested commits**
```
feat(ml): TF-IDF + structured feature training pipeline for three models
fix(data): add indistinguishable rows so evaluation has a realistic error floor
feat(ml): rule vs ML vs hybrid comparison on an identical held-out split
```

**Screenshots:** `18_ml_metrics.png`, `19_confusion_matrix.png`,
`20_model_comparison.png`, `21_roc_curves.png`, `22_detection_comparison.png` — **AUTO**

**What it proves.** Naive Bayes reaches F1 **0.9535** on the test split with
2 false positives and 2 false negatives, and the **hybrid did not beat ML** —
reported as measured rather than as hoped.

---

## Day 9 — Dashboard

**Files created**
```
frontend/ (package.json, vite.config.js, index.html)
frontend/src/{main,App}.jsx · src/styles.css · src/services/api.js
frontend/src/components/common.jsx · src/pages/Dashboard.jsx · src/pages/Analyzer.jsx
backend/routes/{analyze,dashboard}_routes.py · backend/app.py
```

**Functionality.** FastAPI with Swagger, plus a React dashboard: 5 cards, 6
charts, the analyzer form and a standalone link checker. The frontend calls only
relative paths; Vite proxies `/api` to the backend.

**Suggested commit**
```
feat(ui): React dashboard with five summary cards and six charts
```

**Screenshots:** `04_dashboard_overview.png`, `05_dashboard_charts.png`,
`06_email_analyzer_form.png`, `16_swagger_docs.png`, `17_api_health.png` — **AUTO**

**What it proves.** Charts are populated from real database rows, and Swagger
documents all 26 routes automatically.

---

## Day 10 — Awareness module

**Files created**
```
backend/services/awareness_content.py
backend/routes/awareness_routes.py
frontend/src/pages/Awareness.jsx
```

**Functionality.** Ten spotting techniques, a ten-point checklist, six
micro-lessons, three safe practice templates, an incident playbook, a ten-stage
SOC workflow and a MITRE ATT&CK mapping. Content lives in one backend module so
the API and UI cannot drift apart.

**Suggested commit**
```
feat(awareness): training module with checklist, lessons and MITRE mapping
```

**Screenshots:** `11_awareness_spot.png`, `12_awareness_checklist.png`,
`13_awareness_mitre.png` — **AUTO**

**What it proves.** The awareness half is a real feature, not a paragraph in the
README. The MITRE tab carries an explicit "verify before you cite" warning.

---

## Day 11 — Analysis history

**Files created**
```
backend/models/database.py · backend/models/repository.py · backend/models/schemas.py
backend/routes/history_routes.py · backend/utils/security.py
frontend/src/pages/History.jsx · scripts/seed_demo.py
```

**Functionality.** SQLite with foreign keys and cascade deletes, search, band
filter, minimum-score filter, sortable columns (whitelisted), pagination, full
stored report, delete. Schema v2 adds structured URL columns with an in-place
migration.

**Suggested commit**
```
feat(history): SQLite persistence with search, filtering, sorting and deletion
```

**Screenshots:** `14_history_list.png`, `15_history_detail.png` — **AUTO**

**What it proves.** Analyses persist with their indicators and defanged links,
and deleting a row cascades — verified by a test that counts orphans directly
in SQLite.

---

## Day 12 — Testing

**Files created**
```
tests/conftest.py · tests/test_detection.py · pytest.ini
```

**Functionality.** 64 tests covering all 25 required scenarios plus
feature-contract, privacy and safety tests. Every test runs against a temporary
database.

**Suggested commit**
```
test: 64 tests covering all 25 required scenarios plus safety guarantees
```

**Screenshot:** `23_test_results.png` — **AUTO**

**What it proves.** `64 passed`. Includes the two tests that protect the
project's ethical promises: no network call from URL analysis, no filesystem
access from attachment analysis.

---

## Day 13 — Documentation

**Files created**
```
README.md (28 sections) · screenshots/README.md
docs/PROJECT_REPORT.md · docs/ARCHITECTURE.md · docs/13_DAY_PROOF_PLAN.md
docs/MITRE_MAPPING.md · docs/SOC_WORKFLOW.md · docs/FALSE_POSITIVES_NEGATIVES.md
docs/SECURITY_AND_PRIVACY.md · docs/GITHUB_STRATEGY.md
docs/RESUME_LINKEDIN.md · docs/INTERVIEW_QA.md · docs/FUTURE_IMPROVEMENTS.md
scripts/capture_screenshots.py · scripts/render_terminal.py
```

**Functionality.** Full written documentation, plus the two scripts that
regenerate the evidence pack from the running application.

**Suggested commit**
```
docs: complete documentation set and reproducible evidence capture
```

**Screenshots:** `24_github_repository.png`, `25_github_commits.png`,
`26_readme_preview.png` — **MANUAL USER ACTION REQUIRED**

**What it proves.** Once you push, these three show the repository, its history
and the rendered README. They are the only items in the pack that cannot be
generated automatically, and they have deliberately been left absent rather
than mocked up.

---

## Summary

| Day | Theme | Evidence | Status |
|---|---|---|---|
| 1 | Architecture | `01` | AUTO |
| 2 | Dataset | `02` | AUTO |
| 3 | Preprocessing | `23` | AUTO |
| 4 | Sender + content | `09` | AUTO |
| 5 | URL analysis | `10` | AUTO |
| 6 | Attachments | `07` | AUTO |
| 7 | Risk engine | `07`, `08` | AUTO |
| 8 | Machine learning | `03`, `18`–`22` | AUTO |
| 9 | Dashboard | `04`–`06`, `16`, `17` | AUTO |
| 10 | Awareness | `11`–`13` | AUTO |
| 11 | History | `14`, `15` | AUTO |
| 12 | Testing | `23` | AUTO |
| 13 | Documentation | `24`–`26` | **MANUAL** |

**23 of 26 evidence items are generated automatically by scripts in this
repository.**
