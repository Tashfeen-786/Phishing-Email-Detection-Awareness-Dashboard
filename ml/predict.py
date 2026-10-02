"""
ml/predict.py
=============
Command-line phishing analysis - the same engine the API and dashboard use.

Examples
--------
Analyse the built-in demo cases (no arguments needed):

    python ml/predict.py --demo

Analyse one email you type on the command line:

    python ml/predict.py ^
        --sender "security-alert@account-check.invalid.test" ^
        --subject "URGENT: Verify Your Account Immediately" ^
        --body "Your account will be suspended. Click to verify your password." ^
        --url "http://198.51.100.10/verify-account"

Analyse a whole CSV (same columns as the generated dataset) and write a report:

    python ml/predict.py --csv data/phishing_email_dataset.csv --limit 25

Output as JSON for scripting:

    python ml/predict.py --demo --json

SAFETY
------
This tool performs STATIC analysis only. It never opens a URL, never resolves a
hostname, never downloads anything and never executes an attachment. The
attachment check looks at the FILENAME only.
"""

from __future__ import annotations

import argparse
import json
import sys
import textwrap
from pathlib import Path
from typing import Any, Dict, List

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.config import settings
from backend.services.analysis_service import analyze_email

BAR_WIDTH = 40

DEMO_CASES = [
    {
        "name": "Demo 1 - phishing (expected HIGH RISK)",
        "sender": "security-alert@account-check.invalid.test",
        "subject": "URGENT: Verify Your Account Immediately",
        "body": ("Dear Customer,\n\nYour account has been temporarily suspended due to unusual "
                 "activity. You must verify your identity within 24 hours or your account will "
                 "be permanently closed.\n\nClick here to confirm your password and login "
                 "details: http://198.51.100.10/verify-account\n\nFailure to act will result in "
                 "immediate termination of service.\n\nAccount Security Team"),
        "urls": "http://198.51.100.10/verify-account",
        "attachment_name": "",
    },
    {
        "name": "Demo 2 - legitimate (expected LOW RISK)",
        "sender": "training@example.org",
        "subject": "Cybersecurity Workshop Reminder",
        "body": ("Hello,\n\nThis is a reminder that our internal cybersecurity workshop takes "
                 "place on Thursday at 3 PM in Training Room B. We will cover password hygiene "
                 "and safe browsing habits.\n\nThe agenda is attached. No registration is "
                 "needed.\n\nBest regards,\nLearning and Development"),
        "urls": "",
        "attachment_name": "workshop_agenda.pdf",
    },
]


def _bar(score: int, width: int = BAR_WIDTH) -> str:
    filled = int(round(score / 100 * width))
    return "[" + "#" * filled + "." * (width - filled) + "]"


def print_report(result: Dict[str, Any], title: str = "") -> None:
    """Human-readable analyst report for a single email."""
    line = "=" * 78
    print(line)
    if title:
        print(title)
        print("-" * 78)
    print(f"  From        : {result['input']['sender']}")
    print(f"  Subject     : {result['input']['subject']}")
    print(f"  Analysed at : {result['analyzed_at']}  ({result['duration_ms']} ms)")
    print("-" * 78)
    print(f"  RISK SCORE  : {result['risk_score']}/100  {_bar(result['risk_score'])}")
    print(f"  CLASSIFIED  : {result['classification']}")
    print(f"  BAND MEANING: {result['band_meaning']}")

    ml = result.get("ml_detection", {})
    if ml.get("available"):
        print(f"  ML MODEL    : {ml['model_name']} -> {ml['prediction']} "
              f"({ml['probability'] * 100:.1f}% phishing probability)")
        hybrid = result.get("hybrid_detection", {})
        if hybrid:
            print(f"  HYBRID      : {hybrid['combined_score']}/100 "
                  f"(rule {hybrid['rule_weight']:.0%} + ML {hybrid['ml_weight']:.0%})")
    else:
        print("  ML MODEL    : not loaded (rule engine only) - run ml/train_model.py to enable")

    print("-" * 78)
    print("  WHY? (each line is a rule that actually fired)")
    if result["why"]:
        for item in result["why"]:
            print(f"    * {item}")
    else:
        print("    * No rule-based phishing indicator was triggered.")

    if result["indicators"]:
        print("-" * 78)
        scored = result["indicator_count"]
        total = len(result["indicators"])
        info = total - scored
        print(f"  INDICATORS: {scored} risk-bearing"
              + (f" + {info} informational (add no risk)" if info else ""))
        for ind in result["indicators"][:14]:
            print(f"    [{ind['severity']:<8}] {ind['indicator_type']}: {ind['description']}")
            if ind.get("evidence"):
                print(f"               evidence: {str(ind['evidence'])[:90]}")
        if len(result["indicators"]) > 14:
            print(f"    ... and {len(result['indicators']) - 14} more")

    print("-" * 78)
    print("  RECOMMENDED ACTIONS")
    for i, rec in enumerate(result["recommendations"], 1):
        if isinstance(rec, dict):
            print(f"    {i:>2}. [{rec.get('priority', 'INFO'):<8}] {rec.get('action', '')}")
            detail = rec.get("detail", "")
            if detail:
                for line in textwrap.wrap(detail, width=68):
                    print(f"          {line}")
        else:
            print(f"    {i:>2}. {rec}")

    if result.get("detection_notes"):
        print("-" * 78)
        for note in result["detection_notes"]:
            print(f"  NOTE: {note}")
    print(line)
    print()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyse an email for phishing indicators (static analysis only).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--sender", default="")
    parser.add_argument("--subject", default="")
    parser.add_argument("--body", default="")
    parser.add_argument("--url", action="append", dest="urls", default=[],
                        help="may be given more than once")
    parser.add_argument("--attachment", default="")
    parser.add_argument("--demo", action="store_true", help="run the two documented demo cases")
    parser.add_argument("--csv", help="analyse a CSV file with the dataset's columns")
    parser.add_argument("--limit", type=int, default=10, help="rows to read from --csv")
    parser.add_argument("--no-ml", action="store_true", help="rule engine only")
    parser.add_argument("--json", action="store_true", help="print JSON instead of a report")
    args = parser.parse_args()

    use_ml = not args.no_ml

    if args.demo:
        outputs: List[Dict[str, Any]] = []
        for case in DEMO_CASES:
            result = analyze_email(
                sender=case["sender"], subject=case["subject"], body=case["body"],
                urls=case["urls"], attachment_name=case["attachment_name"], use_ml=use_ml,
            )
            outputs.append(result)
            if not args.json:
                print_report(result, case["name"])
        if args.json:
            print(json.dumps(outputs, indent=2, default=str))
        return 0

    if args.csv:
        import pandas as pd
        path = Path(args.csv)
        if not path.exists():
            print(f"[error] file not found: {path}")
            return 1
        frame = pd.read_csv(path).head(args.limit)
        summary = []
        for record in frame.to_dict("records"):
            result = analyze_email(
                sender=str(record.get("sender", "")),
                subject=str(record.get("subject", "")),
                body=str(record.get("body", "")),
                urls=str(record.get("urls", "") or ""),
                attachment_name=str(record.get("attachment_name", "") or ""),
                use_ml=use_ml,
            )
            summary.append({
                "email_id": record.get("email_id", ""),
                "actual": record.get("label", "?"),
                "score": result["risk_score"],
                "classification": result["classification"],
                "indicators": result["indicator_count"],
            })
        if args.json:
            print(json.dumps(summary, indent=2, default=str))
        else:
            print(f"{'EMAIL ID':<10} {'ACTUAL':<12} {'SCORE':>6}  {'CLASSIFICATION':<26} IND")
            print("-" * 74)
            for row in summary:
                print(f"{row['email_id']:<10} {row['actual']:<12} {row['score']:>6}  "
                      f"{row['classification']:<26} {row['indicators']}")
            print("-" * 74)
            print(f"{len(summary)} rows analysed from {path}")
        return 0

    if not any([args.sender, args.subject, args.body, args.urls, args.attachment]):
        parser.print_help()
        print("\n[hint] nothing to analyse. Try:  python ml/predict.py --demo")
        return 1

    result = analyze_email(
        sender=args.sender, subject=args.subject, body=args.body,
        urls=args.urls, attachment_name=args.attachment, use_ml=use_ml,
    )
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print_report(result, "Command-line analysis")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
