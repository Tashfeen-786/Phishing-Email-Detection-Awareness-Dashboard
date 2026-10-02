# Sample Emails

Six `.eml` files plus a CSV, for exercising the analyzer without typing
anything. **All are synthetic.** Every domain is RFC 2606 / RFC 6761 reserved
and every IP is from the RFC 5737 documentation ranges.

## Measured results

These scores were produced by posting each file to `POST /api/analyze/upload`
on this build. Re-run the table at any time with the command at the bottom.

| File | Score | Classification | What it demonstrates |
|---|---|---|---|
| `01_phishing_credential_urgent.eml` | **80** | HIGH RISK / LIKELY PHISHING | The documented demo case: 6 rules fire at once |
| `02_legitimate_training_reminder.eml` | **0** | LOW RISK | The documented benign case. Mentions "password hygiene" and still scores 0 — contextual credential detection |
| `03_phishing_attachment_invoice.eml` | **65** | SUSPICIOUS | Double extension `invoice_4821.pdf.exe` (+25), detected from the filename alone |
| `04_legitimate_it_maintenance.eml` | **0** | LOW RISK | Says "unavailable", "deadline" and "no action required" without tripping the threat rule |
| `05_phishing_bec_no_indicators.eml` | **0** | LOW RISK | ⚠️ **A deliberate, documented false negative** |
| `06_phishing_reward_bait.eml` | **45** | SUSPICIOUS | Reward bait, shouting, excessive punctuation, raw-IP link |

## Sample 05 is meant to fail

`05_phishing_bec_no_indicators.eml` is a **business email compromise** message.
Plausible sender, correct grammar, no link, no attachment, no urgency — so
every rule correctly declines to fire and it scores 0.

It is included precisely because it fails. This is the class of attack that
accounts for **11 of the 12 false negatives** on the test split, and no keyword
list catches it. Catching it needs SPF/DKIM/DMARC, first-time-sender detection, and
a phone call to a number you already had.

Full analysis: [`../docs/FALSE_POSITIVES_NEGATIVES.md`](../docs/FALSE_POSITIVES_NEGATIVES.md)

## About the attachment in sample 03

Sample 03 is a real MIME multipart message whose attachment part is named
`invoice_4821.pdf.exe`. **The part contains one paragraph of inert plain text**
— no code, nothing executable. The filename exists so the double-extension
check has something to find.

The analyzer never opens it regardless. A test patches `builtins.open` to raise
during attachment analysis, so reading a file would fail the suite.

## How to use these

**In the dashboard:** open http://localhost:5173 → Email Analyzer → copy the
sender, subject and body from any file into the form.

**Via the API:**
```bash
curl -X POST http://127.0.0.1:8000/api/analyze/upload \
     -F "file=@samples/01_phishing_credential_urgent.eml"
```

**Reproduce the whole table** (backend must be running):
```bash
for f in samples/*.eml; do
  printf "%-42s " "$(basename $f)"
  curl -s -X POST http://127.0.0.1:8000/api/analyze/upload -F "file=@$f" \
    | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['risk_score'], d['classification'])"
done
```

**Windows (Command Prompt):**
```bat
curl -X POST http://127.0.0.1:8000/api/analyze/upload -F "file=@samples/01_phishing_credential_urgent.eml"
```
