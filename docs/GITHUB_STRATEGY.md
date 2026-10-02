# GitHub Strategy

> **MANUAL USER ACTION REQUIRED.** No repository exists yet. Nothing in this
> project contains a commit hash, a repository URL, a contribution graph or a
> star count, because inventing any of those would be dishonest. This document
> tells you exactly what to run.

---

## 1. Before your first commit

Confirm nothing sensitive is staged:

```bash
cd Phishing-Email-Detection-Awareness-Dashboard
git init
git add .
git status
```

**Read the list. If you see any of these, stop:**

| Must not appear | Why |
|---|---|
| `.env` | May contain your `SECRET_KEY` |
| `.venv/` | Hundreds of MB of machine-specific binaries |
| `node_modules/` | Same, worse |
| `*.db`, `*.db-wal`, `*.db-shm` | Your analysis history |
| `__pycache__/`, `.pytest_cache/` | Build noise |
| `models/*.joblib` | Large binary; regenerate with `train_model.bat` |

`.gitignore` already covers all of these. If one still shows up, it was
committed before the ignore rule existed — remove it with
`git rm -r --cached <path>`.

---

## 2. Suggested commit sequence

A single "initial commit" containing 60 files tells a reviewer nothing. This
sequence mirrors the [13-day plan](13_DAY_PROOF_PLAN.md) and shows how the
project was actually built.

```bash
# Day 1 — foundation
git add README.md LICENSE .gitignore .env.example requirements.txt backend/config.py backend/utils/logger.py
git commit -m "chore: project skeleton, configuration and architecture documentation"

# Day 2 — dataset
git add data/generate_dataset.py
git commit -m "feat(data): deterministic synthetic email generator with reserved domains only"

# Day 3 — preprocessing
git add backend/services/preprocessing.py backend/utils/text_utils.py backend/utils/validators.py
git commit -m "feat(preprocessing): normalisation, URL extraction and input validation"

# Day 4 — sender + content
git add backend/services/sender_analyzer.py backend/services/content_analyzer.py backend/utils/keywords.py
git commit -m "feat(analysis): sender and content analyzers with contextual credential detection"

# Day 5 — URLs
git add backend/services/url_analyzer.py
git commit -m "feat(url): static URL analyzer with defanged output and no network access"

# Day 6 — attachments
git add backend/services/attachment_analyzer.py
git commit -m "feat(attachment): filename-only extension risk analysis"

# Day 7 — risk engine
git add backend/services/risk_engine.py backend/services/feature_extractor.py backend/services/analysis_service.py
git commit -m "feat(risk): weighted rule engine with capped scoring and explainable output"

# Day 8 — machine learning
git add ml/train_model.py backend/services/ml_service.py
git commit -m "feat(ml): TF-IDF + structured feature training pipeline for three models"
git add data/generate_dataset.py
git commit -m "fix(data): add indistinguishable rows so evaluation has a realistic error floor"
git add ml/evaluation.py ml/predict.py ml/optional_bert.py reports/
git commit -m "feat(ml): rule vs ML vs hybrid comparison on an identical held-out split"

# Day 9 — API + dashboard
git add backend/app.py backend/routes/ backend/models/
git commit -m "feat(api): FastAPI application with automatic Swagger documentation"
git add frontend/
git commit -m "feat(ui): React dashboard with five summary cards and six charts"

# Day 10 — awareness
git add backend/services/awareness_content.py backend/routes/awareness_routes.py frontend/src/pages/Awareness.jsx
git commit -m "feat(awareness): training module with checklist, lessons and MITRE mapping"

# Day 11 — history
git add backend/routes/history_routes.py backend/utils/security.py scripts/seed_demo.py
git commit -m "feat(history): SQLite persistence with search, filtering, sorting and deletion"

# Day 12 — tests
git add tests/ pytest.ini
git commit -m "test: 64 tests covering all 25 required scenarios plus safety guarantees"

# Day 13 — docs + evidence
git add docs/ screenshots/ scripts/capture_screenshots.py scripts/render_terminal.py *.bat
git commit -m "docs: complete documentation set and reproducible evidence capture"
```

### Why this style

**Conventional Commits** (`feat:`, `fix:`, `test:`, `docs:`, `chore:`) with a
scope. The `fix(data)` commit is deliberately kept rather than squashed away —
it records that the first training run scored a perfect 1.0000 and that the
dataset was rebuilt in response. **A reviewer learns more from that commit than
from a clean history.**

---

## 3. Push

```bash
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/Phishing-Email-Detection-Awareness-Dashboard.git
git push -u origin main
```

---

## 4. Repository settings

**Description**
> Defensive phishing email analyzer with explainable rule-based scoring, an ML
> comparison, and an integrated awareness module. Synthetic data only.

**Topics**
`cybersecurity` · `phishing-detection` · `email-security` · `machine-learning`
· `fastapi` · `react` · `security-awareness` · `blue-team` · `explainable-ai`
· `python`

**Settings to enable**
- Issues (shows the project is maintained)
- A `v1.0.0` release once the evidence pack is complete

**Do NOT enable**
- GitHub Pages — the frontend needs the backend; a broken demo is worse than none

---

## 5. Recommended additions

### `.github/workflows/tests.yml`

Proof the suite passes on a clean machine, not just yours:

```yaml
name: tests
on: [push, pull_request]
jobs:
  pytest:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install -r requirements.txt
      - run: python data/generate_dataset.py
      - run: python -m pytest tests/ -v
```

A green badge is evidence a reviewer can verify without cloning.

### Pin the README

The README is the whole pitch. Make sure `screenshots/04_dashboard_overview.png`
and `screenshots/07_phishing_result_high_risk.png` render — a reviewer who sees
a working dashboard in the first screen reads further.

---

## 6. Then take screenshots 24–26

| Save as | Capture |
|---|---|
| `screenshots/24_github_repository.png` | Repository home, file list visible |
| `screenshots/25_github_commits.png` | The Commits page (`/commits/main`) |
| `screenshots/26_readme_preview.png` | Home page scrolled to the rendered README |

**Windows:** `Win + Shift + S`, select, paste into Paint, save as PNG.

---

## 7. What not to do

| Don't | Why |
|---|---|
| Backdate commits to fake a 13-day history | Trivially detectable, and it destroys your credibility over something that did not need faking |
| Commit the `.db` file | It contains your analysis history |
| Commit `models/*.joblib` | Large binary; `train_model.bat` regenerates it in ~4 seconds |
| Push real phishing samples | Even for research — they contain other people's data |
| Claim metrics you have not run | Every number in this repo is reproducible. Keep it that way. |
