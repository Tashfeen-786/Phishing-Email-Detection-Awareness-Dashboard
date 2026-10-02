"""
scripts/seed_demo.py
====================
Populate the database with a realistic set of analysed emails so the dashboard
has something to show the first time you open it.

    python scripts/seed_demo.py                 # add ~24 demo analyses
    python scripts/seed_demo.py --count 60      # more rows
    python scripts/seed_demo.py --reset         # wipe history first
    python scripts/seed_demo.py --from-dataset  # sample the generated CSV

Every row is produced by running the REAL analysis pipeline over synthetic
emails - nothing is inserted with a hand-written score. If you delete the
database and re-run this script you will get the same verdicts, because the
rule engine is deterministic.

SAFETY: all senders, domains, URLs and IP addresses below are reserved for
documentation (RFC 2606 / RFC 6761 / RFC 5737). Nothing here is a real target
and no message is ever sent.
"""

from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path
from typing import Any, Dict, List

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.models.database import init_db
from backend.models.repository import delete_all_analyses, save_analysis
from backend.services.analysis_service import analyze_email

# ---------------------------------------------------------------------------
# Hand-picked demo emails covering every band the dashboard can display.
# ---------------------------------------------------------------------------
DEMO_EMAILS: List[Dict[str, str]] = [
    # ---------------- high risk ----------------
    {
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
        "sender": "payroll@secure-payments-verify.invalid.test",
        "subject": "Action Required: Salary Payment On Hold",
        "body": ("Dear Employee,\n\nYour salary payment has been placed on hold. Confirm your "
                 "bank details immediately using the secure form attached, or the payment will "
                 "be cancelled.\n\nPayroll Department"),
        "urls": "http://203.0.113.45/payroll-update",
        "attachment_name": "salary_details.html",
    },
    {
        "sender": "it-helpdesk@examp1e-support.invalid.test",
        "subject": "Your mailbox will be deactivated - verify now",
        "body": ("Dear User,\n\nYour mailbox has exceeded its storage quota and will be "
                 "deactivated within 12 hours. Verify your login credentials now to keep your "
                 "mailbox active.\n\nIT Helpdesk"),
        "urls": "http://192.0.2.77/mailbox-verify",
        "attachment_name": "verify_form.html",
    },
    {
        "sender": "no-reply@invoice-secure-billing.invalid.test",
        "subject": "Overdue invoice - final notice before legal action",
        "body": ("Dear Sir/Madam,\n\nOur records show an unpaid invoice. This is your final "
                 "notice. Failure to comply will result in legal action. Open the attached "
                 "statement and settle immediately.\n\nAccounts Department"),
        "urls": "",
        "attachment_name": "invoice_overdue.pdf.exe",
    },
    {
        "sender": "rewards@prize-claim-centre.invalid.test",
        "subject": "Congratulations! You have won a gift card",
        "body": ("Dear Winner,\n\nCongratulations! You have been selected to receive a gift "
                 "card. Claim your prize within 48 hours by confirming your personal details "
                 "and card number.\n\nClick here: http://198.51.100.99/claim-prize"),
        "urls": "http://198.51.100.99/claim-prize",
        "attachment_name": "",
    },
    # ---------------- suspicious / moderate ----------------
    {
        "sender": "hr-notice@corp-exec-office.invalid.test",
        "subject": "Quick request",
        "body": ("Hi,\n\nAre you at your desk? I need you to handle something for me before "
                 "the end of the day. It is time sensitive - let me know once you are "
                 "free.\n\nSent from my phone"),
        "urls": "",
        "attachment_name": "",
    },
    {
        "sender": "documents@shared-drive-access.invalid.test",
        "subject": "A document has been shared with you",
        "body": ("Hello,\n\nA document has been shared with you. Sign in with your email "
                 "password to view it.\n\nhttps://shared-drive-access.invalid.test/open?id=8842"),
        "urls": "https://shared-drive-access.invalid.test/open?id=8842",
        "attachment_name": "",
    },
    {
        "sender": "alerts@bank-account-review.invalid.test",
        "subject": "Unusual sign-in detected",
        "body": ("Dear Customer,\n\nWe detected an unusual sign-in on your account. If this was "
                 "not you, review the activity using the link below.\n\n"
                 "http://203.0.113.19/review"),
        "urls": "http://203.0.113.19/review",
        "attachment_name": "",
    },
    {
        "sender": "delivery@parcel-tracking-update.invalid.test",
        "subject": "Your parcel could not be delivered",
        "body": ("Hello,\n\nYour parcel could not be delivered because of an incomplete "
                 "address. Confirm your details within 24 hours or the parcel will be "
                 "returned.\n\nhttp://192.0.2.200/redelivery"),
        "urls": "http://192.0.2.200/redelivery",
        "attachment_name": "",
    },
    {
        "sender": "accounts@supplier-portal.invalid.test",
        "subject": "Invoice 7742 - remittance details",
        "body": ("Dear Priya,\n\nPlease find invoice 7742 attached for last month's services. "
                 "Our bank details have been updated this quarter. Kindly use the new "
                 "beneficiary account for payment.\n\nRegards,\nAccounts Receivable"),
        "urls": "",
        "attachment_name": "invoice_7742.pdf",
    },
    {
        "sender": "noreply@survey-rewards-portal.invalid.test",
        "subject": "Complete this short survey for a bonus",
        "body": ("Hello,\n\nComplete our two-minute survey and claim a cash bonus. Offer "
                 "expires today.\n\nhttp://bit.ly/3xamples"),
        "urls": "http://bit.ly/3xamples",
        "attachment_name": "",
    },
    {
        "sender": "update@password-expiry-notice.invalid.test",
        "subject": "Your password expires today",
        "body": ("Dear User,\n\nYour password expires today. Reset it now to avoid losing "
                 "access to your account.\n\nhttps://password-expiry-notice.invalid.test/reset"),
        "urls": "https://password-expiry-notice.invalid.test/reset",
        "attachment_name": "",
    },
    # ---------------- legitimate ----------------
    {
        "sender": "training@example.org",
        "subject": "Cybersecurity Workshop Reminder",
        "body": ("Hello,\n\nThis is a reminder that our internal cybersecurity workshop takes "
                 "place on Thursday at 3 PM in Training Room B. We will cover password hygiene "
                 "and safe browsing habits.\n\nThe agenda is attached. No registration is "
                 "needed.\n\nBest regards,\nLearning and Development"),
        "urls": "",
        "attachment_name": "workshop_agenda.pdf",
    },
    {
        "sender": "hr@example.com",
        "subject": "Updated leave policy for the next quarter",
        "body": ("Hi team,\n\nThe updated leave policy takes effect from next quarter. The "
                 "summary is attached, and the full document is on the intranet.\n\nDo reach "
                 "out if you have questions.\n\nHR Team"),
        "urls": "https://intranet.example.com/policies/leave",
        "attachment_name": "leave_policy_summary.pdf",
    },
    {
        "sender": "notifications@example.net",
        "subject": "Your monthly usage report is ready",
        "body": ("Hello,\n\nYour monthly usage report is now available in your dashboard. No "
                 "action is required.\n\nYou can view it at your convenience from the reports "
                 "section.\n\nThe Team"),
        "urls": "https://example.net/reports/monthly",
        "attachment_name": "usage_report.pdf",
    },
    {
        "sender": "library@university.example.org",
        "subject": "Book return reminder",
        "body": ("Dear student,\n\nThis is a friendly reminder that two borrowed books are due "
                 "next Monday. You can renew them online or at the counter.\n\nLibrary "
                 "Services"),
        "urls": "https://university.example.org/library/renew",
        "attachment_name": "",
    },
    {
        "sender": "devops@example.com",
        "subject": "Scheduled maintenance this weekend",
        "body": ("Team,\n\nWe have scheduled maintenance for Saturday between 2 AM and 5 AM. "
                 "The staging environment will be unavailable during that window. Production "
                 "is unaffected.\n\nThanks,\nPlatform Engineering"),
        "urls": "",
        "attachment_name": "",
    },
    {
        "sender": "conference@example.org",
        "subject": "Your talk has been accepted",
        "body": ("Dear speaker,\n\nWe are glad to confirm that your talk has been accepted for "
                 "the October track. The schedule and speaker guidelines are attached.\n\n"
                 "Congratulations and see you there.\n\nProgramme Committee"),
        "urls": "",
        "attachment_name": "speaker_guidelines.pdf",
    },
    {
        "sender": "helpdesk@example.com",
        "subject": "Ticket #4821 has been resolved",
        "body": ("Hello,\n\nYour ticket #4821 regarding the printer on the third floor has been "
                 "resolved. If the issue returns, reply to this message and the ticket will be "
                 "reopened.\n\nIT Service Desk"),
        "urls": "",
        "attachment_name": "",
    },
    {
        "sender": "accounts@contracts.example.org",
        "subject": "Purchase order 5510 acknowledgement",
        "body": ("Hello Arjun,\n\nWe acknowledge receipt of purchase order 5510. Delivery is "
                 "scheduled as agreed and our account details remain as stated in the "
                 "contract.\n\nKind regards,\nSales Support"),
        "urls": "",
        "attachment_name": "po_5510.pdf",
    },
    {
        "sender": "newsletter@example.net",
        "subject": "September product update",
        "body": ("Hi there,\n\nHere is what shipped in September: faster search, a redesigned "
                 "settings page and improved export.\n\nYou are receiving this because you "
                 "subscribed to product updates.\n\nThe Product Team"),
        "urls": "https://example.net/changelog/september",
        "attachment_name": "",
    },
    {
        "sender": "facilities@example.com",
        "subject": "Office closed on Friday for maintenance",
        "body": ("Dear all,\n\nThe office will be closed on Friday for scheduled electrical "
                 "maintenance. Please plan to work from home that day.\n\nFacilities"),
        "urls": "",
        "attachment_name": "",
    },
    {
        "sender": "security-awareness@example.org",
        "subject": "Monthly security tip: verifying senders",
        "body": ("Hello,\n\nThis month's tip covers how to verify a sender before acting on a "
                 "request. Remember that no one from IT will ever ask for your password by "
                 "email.\n\nIf a message pressures you to act quickly, slow down and verify "
                 "through a channel you already trust.\n\nSecurity Awareness Team"),
        "urls": "",
        "attachment_name": "security_tip_september.pdf",
    },
    {
        "sender": "project-updates@example.com",
        "subject": "Sprint 14 summary",
        "body": ("Team,\n\nSprint 14 closed with 23 of 25 points delivered. The two remaining "
                 "items move to Sprint 15. Retro notes are in the shared folder.\n\nThanks for "
                 "the solid work.\n\nProject Management"),
        "urls": "",
        "attachment_name": "sprint14_summary.pdf",
    },
]


def seed_from_dataset(count: int, seed: int) -> List[Dict[str, str]]:
    """Sample rows from the generated CSV instead of the curated list."""
    import pandas as pd
    from backend.config import settings

    path = Path(settings.DATASET_PATH)
    if not path.exists():
        print(f"[error] dataset not found: {path}")
        print("        run:  python data/generate_dataset.py")
        return []
    frame = pd.read_csv(path).sample(n=min(count, 600), random_state=seed)
    return [{
        "sender": str(r["sender"]),
        "subject": str(r["subject"]),
        "body": str(r["body"]),
        "urls": str(r.get("urls") or ""),
        "attachment_name": str(r.get("attachment_name") or ""),
    } for r in frame.to_dict("records")]


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed the dashboard with demo analyses.")
    parser.add_argument("--count", type=int, default=len(DEMO_EMAILS),
                        help="how many analyses to insert")
    parser.add_argument("--reset", action="store_true",
                        help="delete existing history before seeding")
    parser.add_argument("--from-dataset", action="store_true",
                        help="sample the generated CSV instead of the curated demo list")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--no-ml", action="store_true", help="rule engine only")
    args = parser.parse_args()

    init_db()

    if args.reset:
        removed = delete_all_analyses()
        print(f"[reset] removed {removed} existing analyses")

    if args.from_dataset:
        emails = seed_from_dataset(args.count, args.seed)
    else:
        emails = list(DEMO_EMAILS)
        if args.count > len(emails):
            rng = random.Random(args.seed)
            while len(emails) < args.count:
                emails.append(rng.choice(DEMO_EMAILS))
        emails = emails[:args.count]

    if not emails:
        return 1

    print(f"Analysing and saving {len(emails)} demo emails ...")
    counts: Dict[str, int] = {}
    for i, email in enumerate(emails, 1):
        result = analyze_email(
            sender=email["sender"], subject=email["subject"], body=email["body"],
            urls=email.get("urls", ""), attachment_name=email.get("attachment_name", ""),
            use_ml=not args.no_ml,
        )
        save_analysis(result)
        counts[result["classification"]] = counts.get(result["classification"], 0) + 1
        print(f"  [{i:>3}/{len(emails)}] {result['risk_score']:>3}/100  "
              f"{result['classification']:<28} {email['subject'][:44]}")

    print("-" * 74)
    print("Seeded. Classification breakdown:")
    for name in ["HIGH RISK / LIKELY PHISHING", "SUSPICIOUS", "MODERATE RISK", "LOW RISK"]:
        if name in counts:
            print(f"  {name:<30} {counts[name]}")
    print("-" * 74)
    print("Open the dashboard at http://localhost:5173 to see the charts populated.")
    print("Every score above was computed by the real pipeline - none were typed in.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
