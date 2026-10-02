"""
data/generate_dataset.py
========================
PURPOSE
-------
Generate the project's SYNTHETIC email dataset.

    python data/generate_dataset.py                 # 600 rows, seed 42
    python data/generate_dataset.py --rows 800      # custom size
    python data/generate_dataset.py --seed 7        # different seed
    python data/generate_dataset.py --out data/other.csv

OUTPUT
------
    data/phishing_email_dataset.csv
    columns: email_id, sender, sender_domain, subject, body, urls,
             attachment_name, label
    labels : LEGITIMATE | PHISHING

===========================================================================
>>> SAFETY - READ THIS <<<
===========================================================================
Every value produced here is FICTIONAL.

* Domains use only RFC 2606 / RFC 6761 reserved names:
  example.com, example.org, example.net, and the reserved
  .test / .invalid top-level domains.
* IP addresses use only RFC 5737 documentation ranges:
  192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24.
* One template intentionally references a shortener host with an obviously
  fake path (``/example-not-real``) so the shortener DETECTION can be tested.
  It is not a real short link and resolves to nothing.
* No real company, brand, person or malicious URL appears anywhere.
* Nothing in this file sends mail: there is no SMTP code in the project.

===========================================================================
DETERMINISM
===========================================================================
``random.Random(seed)`` is used everywhere (never the global ``random``
module), so the same seed always produces a byte-identical CSV. This matters
because the ML metrics in reports/ must be reproducible by anyone who clones
the repository.

===========================================================================
DESIGN: WHY "HARD" EXAMPLES ARE INCLUDED
===========================================================================
A naive generator makes phishing rows obvious (every phishing row shouts
"URGENT" and every legitimate row is calm). A model trained on that scores
~100% and teaches nothing.

This generator therefore also produces:

  * HARD LEGITIMATE (~12% of legitimate rows) - genuine mail that really is
    urgent, really does contain a deadline, really does contain a link.
    These are the FALSE-POSITIVE pressure cases.
  * HARD PHISHING (~14% of phishing rows) - well-written business-email-
    compromise style messages with no urgency, no link, no attachment and
    correct grammar. These are the FALSE-NEGATIVE pressure cases.

The resulting metrics are lower but honest, and they make the
false-positive / false-negative discussion in the report real rather than
theoretical.
"""

from __future__ import annotations

import argparse
import csv
import random
import sys
from pathlib import Path
from typing import Dict, List, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

DEFAULT_ROWS = 600
DEFAULT_SEED = 42
DEFAULT_OUT = PROJECT_ROOT / "data" / "phishing_email_dataset.csv"

COLUMNS = ["email_id", "sender", "sender_domain", "subject", "body", "urls",
           "attachment_name", "label"]

# ---------------------------------------------------------------------------
# Safe building blocks
# ---------------------------------------------------------------------------
FIRST_NAMES = ["Anita", "Rahul", "Priya", "Arjun", "Meera", "Vikram", "Sneha", "Karan",
               "Divya", "Rohan", "Isha", "Nikhil", "Tara", "Aditya", "Neha", "Sameer",
               "Ananya", "Manav", "Pooja", "Kabir", "Lakshmi", "Dev", "Riya", "Omar"]
TEAMS = ["Engineering", "Operations", "Finance", "Research", "Admissions", "Library",
         "Placement Cell", "Quality", "Facilities", "Student Affairs", "Analytics"]
COURSES = ["Network Security", "Data Structures", "Cloud Computing", "Cryptography",
           "Operating Systems", "Machine Learning", "Database Systems", "Web Security"]
PRODUCTS = ["wireless keyboard", "USB-C hub", "desk lamp", "notebook set", "laptop stand",
            "external SSD", "webcam cover", "cable organiser", "ergonomic mouse"]
MONTHS = ["January", "February", "March", "April", "May", "June", "July",
          "August", "September", "October", "November", "December"]
WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]

# ---- Legitimate senders (reserved domains only) ---------------------------
LEGIT_SENDERS: List[Tuple[str, str]] = [
    ("registrar", "university.example.org"),
    ("notices", "notices.example.org"),
    ("academics", "example.org"),
    ("hr", "example.org"),
    ("people-ops", "hr.example.org"),
    ("payroll", "hr.example.org"),
    ("projects", "example.com"),
    ("team-updates", "example.com"),
    ("calendar", "example.com"),
    ("meetings", "mail.example.com"),
    ("orders", "shop.example.net"),
    ("support", "shop.example.net"),
    ("newsletter", "news.example.org"),
    ("digest", "news.example.org"),
    ("no-reply", "accounts.example.com"),
    ("security-notifications", "accounts.example.com"),
    ("statements", "bank.example.net"),
    ("customer-care", "bank.example.net"),
    ("it-helpdesk", "example.com"),
    ("library", "example.org"),
    ("placement", "example.org"),
    ("training", "example.org"),
]

# ---- Phishing senders (all fictional / reserved) --------------------------
PHISH_LOCALS = ["security-alert", "account-verify", "no-reply-security", "helpdesk-support",
                "billing-dept", "payment-notice", "password-reset", "delivery-notice",
                "hr-update", "ceo.office", "verification", "admin-support", "notification-service",
                "claims-desk", "rewards-team", "it-support"]
PHISH_DOMAINS = [
    "account-check.invalid.test",
    "secure-login-verify.invalid.test",
    "mail-account-update.invalid.test",
    "billing-support-desk.invalid.test",
    "verify.secure.account.invalid.test",
    "examp1e-secure.invalid.test",
    "exarnple-support.invalid.test",
    "hr-portal-update.invalid.test",
    "corp-exec-office.invalid.test",
    "parcel-track-delivery.invalid.test",
    "rewards-claim-centre.invalid.test",
    "login.verify.account-services.invalid.test",
    "invoice-payments-desk.invalid.test",
    "password-expiry-notice.invalid.test",
    "id-check.secure-mail.invalid.test",
    "account.update.billing.invalid.test",
]
# Look-alikes of the project's own reserved domains (never of a real brand).
PHISH_LOOKALIKE_DOMAINS = ["examp1e.invalid.test", "exarnple.invalid.test",
                           "exampie-secure.invalid.test", "3xample-support.invalid.test"]

# ---- Safe URLs -------------------------------------------------------------
LEGIT_URL_TEMPLATES = [
    "https://www.example.org/notices/{n}",
    "https://portal.example.com/projects/{n}",
    "https://hr.example.org/policies/{n}",
    "https://shop.example.net/orders/{n}",
    "https://news.example.org/issue/{n}",
    "https://accounts.example.com/settings/security",
    "https://bank.example.net/statements/{n}",
    "https://example.org/library/catalogue/{n}",
    "https://meet.example.com/room/{n}",
    "https://example.com/docs/{n}",
]
PHISH_URL_TEMPLATES = [
    "http://198.51.100.{ip}/verify-account",
    "http://203.0.113.{ip}/secure/login",
    "http://192.0.2.{ip}/billing/payment",
    "http://198.51.100.{ip}/password/reset",
    "https://secure-login.account-verify.invalid.test/update?id={n}",
    "http://verify.account.billing-support-desk.invalid.test/confirm",
    "http://examp1e-secure.invalid.test/signin",
    "http://bit.ly/example-not-real",
    "http://tinyurl.com/example-not-real",
    "https://login.secure.account.mail-account-update.invalid.test/verify",
    "http://203.0.113.{ip}/claim-your-prize",
    "http://parcel-track-delivery.invalid.test/redelivery/pay?ref={n}",
    "https://www.example.org@203.0.113.{ip}/account",
    "http://192.0.2.{ip}/hr/salary-revision",
]

# ---- Attachments ----------------------------------------------------------
LEGIT_ATTACHMENTS = ["", "", "", "", "agenda.pdf", "minutes.docx", "timetable.pdf",
                     "report_q3.xlsx", "receipt.pdf", "policy_update.pdf", "syllabus.pdf",
                     "newsletter.pdf", "invoice_{n}.pdf", "photos.zip", "statement_{n}.pdf"]
PHISH_ATTACHMENTS = ["", "", "invoice_{n}.pdf.exe", "payment_details.docm", "scan_{n}.js",
                     "delivery_label.scr", "secure_document.zip", "payroll_update.xlsm",
                     "account_statement.pdf.scr", "verify_form.html", "update.bat",
                     "setup_patch.ps1", "receipt_{n}.pdf.vbs", "documents.rar"]

# ---------------------------------------------------------------------------
# LEGITIMATE TEMPLATES (8 categories from the brief)
# ---------------------------------------------------------------------------
def _legit_templates(rng: random.Random) -> Dict[str, List[Dict[str, str]]]:
    n = rng.randint(1000, 9999)
    name = rng.choice(FIRST_NAMES)
    team = rng.choice(TEAMS)
    course = rng.choice(COURSES)
    product = rng.choice(PRODUCTS)
    month = rng.choice(MONTHS)
    day = rng.choice(WEEKDAYS)
    hour = rng.choice(["9:00 AM", "10:30 AM", "11:00 AM", "2:00 PM", "3:30 PM", "4:00 PM"])
    room = rng.choice(["Seminar Hall 2", "Room B-204", "Auditorium", "Lab 3", "Conference Room 1"])

    return {
        "university_notice": [
            {"subject": f"{course} - revised class schedule for {month}",
             "body": (f"Dear {name},\n\nThe timetable for {course} has been revised for {month}. "
                      f"Classes will now be held on {day} at {hour} in {room}. The updated "
                      f"schedule is available on the department noticeboard and on the student "
                      f"portal.\n\nNo action is required from your side.\n\nRegards,\n"
                      f"Academic Office")},
            {"subject": f"Semester examination timetable published",
             "body": (f"Dear Students,\n\nThe examination timetable for the current semester has "
                      f"been published on the student portal. Please check your subject codes "
                      f"and report to the examination hall fifteen minutes before each paper.\n\n"
                      f"Examination Section")},
            {"subject": f"Library: {course} reference books now available",
             "body": (f"Hello {name},\n\nThe reference books you requested for {course} are now "
                      f"available at the circulation desk. They can be borrowed for fourteen "
                      f"days using your student card.\n\nLibrary Services")},
            {"subject": f"Cybersecurity Workshop Reminder",
             "body": (f"Hello {name},\n\nThis is a reminder that the cybersecurity workshop takes "
                      f"place on {day} at {hour} in {room}. The session covers safe browsing "
                      f"habits, how to recognise suspicious messages, and good password hygiene. "
                      f"Bring your laptop if you would like to follow the exercises.\n\n"
                      f"No registration is required.\n\nRegards,\nTraining Team")},
        ],
        "hr_update": [
            {"subject": f"Updated leave policy effective {month}",
             "body": (f"Dear {name},\n\nThe leave policy has been updated effective {month}. The "
                      f"main change is that carried-forward leave may now be used until the end "
                      f"of the financial year. The full policy document is attached and is also "
                      f"on the HR portal.\n\nHR Team")},
            {"subject": f"{team} team - annual appraisal window opens",
             "body": (f"Hi {name},\n\nThe annual appraisal window for the {team} team opens next "
                      f"week and closes at the end of {month}. Please complete your "
                      f"self-assessment on the HR portal when you have time. Your manager will "
                      f"schedule the review discussion afterwards.\n\nPeople Operations")},
            {"subject": "Payslip for last month is available",
             "body": (f"Dear {name},\n\nYour payslip for last month is now available on the HR "
                      f"portal under Payroll. Sign in using your usual single sign-on. If any "
                      f"detail looks incorrect, raise a ticket with Payroll and we will review "
                      f"it.\n\nPayroll Team")},
        ],
        "project_update": [
            {"subject": f"Sprint {rng.randint(10, 40)} summary - {team}",
             "body": (f"Hi team,\n\nSummary of this sprint: the reporting module is complete, the "
                      f"export bug is fixed, and the {team} dashboard is in review. Two items "
                      f"moved to the next sprint because of a dependency on the data pipeline.\n\n"
                      f"Notes are in the shared folder.\n\nThanks,\n{name}")},
            {"subject": f"Code review requested for pull request #{n % 500}",
             "body": (f"Hello,\n\nI have opened pull request #{n % 500} with the changes we "
                      f"discussed. It touches the parser and adds tests. Could you review it "
                      f"when convenient? There is no rush - it is not blocking anything.\n\n"
                      f"Thanks,\n{name}")},
            {"subject": f"Status report - {month}",
             "body": (f"Dear {team} team,\n\nAttached is the monthly status report for {month}. "
                      f"Overall progress is on track, with one dependency pending from the "
                      f"vendor. Details and the updated plan are in the document.\n\n"
                      f"Regards,\n{name}")},
        ],
        "meeting_reminder": [
            {"subject": f"Reminder: {team} weekly sync on {day}",
             "body": (f"Hi all,\n\nA reminder that our weekly {team} sync is on {day} at {hour} "
                      f"in {room}. The agenda is attached. If you cannot attend, send your "
                      f"updates beforehand and we will cover them.\n\nThanks,\n{name}")},
            {"subject": f"Calendar invitation: project review, {day} {hour}",
             "body": (f"Hello {name},\n\nA project review meeting has been scheduled for {day} at "
                      f"{hour}. The meeting link is in the calendar invitation. Please review the "
                      f"agenda in advance.\n\nRegards,\nProject Management Office")},
            {"subject": "Meeting moved to next week",
             "body": (f"Hi {name},\n\nThe design discussion has been moved to next {day} at "
                      f"{hour} because two attendees are travelling. The calendar entry has been "
                      f"updated, so no action is needed.\n\nBest,\n{rng.choice(FIRST_NAMES)}")},
        ],
        "shopping_confirmation": [
            {"subject": f"Order #{n} confirmed - {product}",
             "body": (f"Hello {name},\n\nThank you for your order. Your {product} (order #{n}) "
                      f"has been confirmed and will be dispatched within two working days. You "
                      f"can track it from the Orders section of your account.\n\n"
                      f"Customer Support")},
            {"subject": f"Your order #{n} has been delivered",
             "body": (f"Hi {name},\n\nYour order #{n} was delivered today. If anything is missing "
                      f"or damaged, you can raise a return from the Orders page within seven "
                      f"days.\n\nThanks for shopping with us.")},
            {"subject": f"Invoice for order #{n}",
             "body": (f"Dear {name},\n\nPlease find the invoice for order #{n} attached for your "
                      f"records. No payment is due - the amount was already charged at "
                      f"checkout.\n\nBilling Team")},
        ],
        "newsletter": [
            {"subject": f"{month} newsletter: {team} highlights",
             "body": (f"Hello,\n\nIn this issue: highlights from the {team} team, an interview "
                      f"with a recent graduate, and upcoming events for {month}. Read the full "
                      f"issue online.\n\nYou are receiving this because you subscribed. You can "
                      f"unsubscribe at any time from the link in the footer.")},
            {"subject": "Weekly digest: security tips and community news",
             "body": (f"Hi,\n\nThis week's digest covers password managers, why software updates "
                      f"matter, and a short piece on recognising suspicious messages. Nothing in "
                      f"this newsletter ever asks you for a password.\n\nThe Editors")},
            {"subject": f"Event announcement: {course} guest lecture",
             "body": (f"Hello,\n\nWe are hosting a guest lecture on {course} on {day} at {hour} "
                      f"in {room}. Entry is open to all students and staff. Seats are limited but "
                      f"no booking is required.\n\nEvents Team")},
        ],
        "password_change_confirmation": [
            {"subject": "Your password was changed successfully",
             "body": (f"Hello {name},\n\nThis message confirms that the password for your account "
                      f"was changed successfully on {day}. No further action is needed.\n\n"
                      f"If you did not make this change, open the account settings page yourself "
                      f"from your browser or app and review your active sessions. We will never "
                      f"ask you to send us your password.\n\nAccount Security")},
            {"subject": "Security settings updated",
             "body": (f"Hi {name},\n\nTwo-factor authentication was enabled on your account "
                      f"today. This message is a confirmation only.\n\nIf this was not you, sign "
                      f"in directly through the official app and review your security "
                      f"settings.\n\nAccount Security")},
            {"subject": "New sign-in to your account",
             "body": (f"Hello {name},\n\nWe noticed a new sign-in to your account from a browser "
                      f"you have not used before. If this was you, no action is needed.\n\nYou "
                      f"can review recent activity from the security page of your account. We "
                      f"will never ask for your password by email.\n\nAccount Security")},
        ],
        "bank_style_notification": [
            {"subject": f"Monthly statement for account ending {n % 10000:04d}",
             "body": (f"Dear {name},\n\nYour monthly statement for the account ending "
                      f"{n % 10000:04d} is now available. You can view it by signing in to "
                      f"the banking app or by typing our website address into your browser "
                      f"yourself.\n\nWe never send statements as attachments and we never ask "
                      f"for your PIN or one-time password.\n\nCustomer Care")},
            {"subject": "Transaction alert: card payment recorded",
             "body": (f"Dear Customer,\n\nA card payment was recorded on your account today. If "
                      f"you recognise this transaction, no action is needed.\n\nIf you do not, "
                      f"call the number printed on the back of your card. Do not call numbers "
                      f"sent to you in a message.\n\nCustomer Care")},
            {"subject": "Service notice: scheduled maintenance",
             "body": (f"Dear Customer,\n\nOnline banking will be unavailable for scheduled "
                      f"maintenance on {day} between 1:00 AM and 4:00 AM. No action is required "
                      f"and no information is needed from you.\n\nCustomer Care")},
        ],
    }


# ---------------------------------------------------------------------------
# AMBIGUOUS TEMPLATE PAIRS - the heart of realistic evaluation
# ---------------------------------------------------------------------------
# Each entry produces TWO messages that share the same sender-domain pool, the
# same subject and almost the same body. Only a small contextual detail differs
# (bank details "unchanged" vs "updated", payment through "the usual channel"
# vs "the new account"). This is exactly how business-email-compromise works in
# reality, and it is the only honest way to make a synthetic dataset produce
# genuine false positives and false negatives instead of a perfect score.
#
# Both sides are drawn from SHARED_BUSINESS_DOMAINS, so the sender domain
# carries no label information at all for these rows.
# ---------------------------------------------------------------------------
SHARED_BUSINESS_DOMAINS = [
    "supplier-portal.invalid.test",
    "accounts-team.invalid.test",
    "partner-services.invalid.test",
    "vendor-desk.invalid.test",
    "example.com",
    "example.net",
    "contracts.example.org",
]
SHARED_BUSINESS_LOCALS = ["accounts", "finance", "sales", "billing", "contracts",
                          "procurement", "operations", "admin"]


def _ambiguous_pair(rng: random.Random) -> Tuple[Dict[str, str], Dict[str, str]]:
    """Return ``(legitimate_variant, phishing_variant)`` of one near-identical email."""
    name = rng.choice(FIRST_NAMES)
    n = rng.randint(1000, 9999)
    families = [
        (
            {"subject": f"Invoice {n} - remittance details",
             "body": (f"Dear {name},\n\nPlease find invoice {n} attached for last month's "
                      f"services. Our bank details are unchanged from previous invoices. "
                      f"Payment is due within thirty days.\n\nRegards,\nAccounts Receivable")},
            {"subject": f"Invoice {n} - remittance details",
             "body": (f"Dear {name},\n\nPlease find invoice {n} attached for last month's "
                      f"services. Our bank details have been updated this quarter. Kindly use "
                      f"the new beneficiary account for payment.\n\nRegards,\n"
                      f"Accounts Receivable")},
        ),
        (
            {"subject": "Following up on our conversation",
             "body": (f"Hi {name},\n\nFollowing up on our conversation last week. I have shared "
                      f"the revised proposal with the finance team and they will process it "
                      f"through the usual channel.\n\nLet me know if you need anything "
                      f"else.\n\nBest regards")},
            {"subject": "Following up on our conversation",
             "body": (f"Hi {name},\n\nFollowing up on our conversation last week. I have shared "
                      f"the revised proposal with the finance team and they will route the "
                      f"payment to the new account we discussed.\n\nLet me know if you need "
                      f"anything else.\n\nBest regards")},
        ),
        (
            {"subject": f"Purchase order {n} acknowledgement",
             "body": (f"Hello {name},\n\nWe acknowledge receipt of purchase order {n}. Delivery "
                      f"is scheduled as agreed and our account details remain as stated in the "
                      f"contract.\n\nKind regards,\nSales Support")},
            {"subject": f"Purchase order {n} acknowledgement",
             "body": (f"Hello {name},\n\nWe acknowledge receipt of purchase order {n}. Delivery "
                      f"is scheduled as agreed. Please note our accounts team has moved to a new "
                      f"beneficiary account for this contract.\n\nKind regards,\nSales Support")},
        ),
        (
            {"subject": "Re: contract renewal",
             "body": (f"Hello {name},\n\nThanks for the update. The renewal looks fine from our "
                      f"side. Payment will follow the schedule in the existing agreement.\n\n"
                      f"Regards")},
            {"subject": "Re: contract renewal",
             "body": (f"Hello {name},\n\nThanks for the update. The renewal looks fine from our "
                      f"side. One change: please route this year's payment to the account "
                      f"listed in the attached schedule rather than the previous one.\n\n"
                      f"Regards")},
        ),
        (
            {"subject": "Quarterly review document",
             "body": (f"Hi {name},\n\nI have shared the quarterly review document with you in "
                      f"the folder we normally use. Let me know your comments by the end of the "
                      f"week.\n\nThanks")},
            {"subject": "Quarterly review document",
             "body": (f"Hi {name},\n\nI have shared the quarterly review document with you. It "
                      f"is in an external folder this time. Please review it and confirm "
                      f"receipt.\n\nThanks")},
        ),
        (
            {"subject": "Are you available?",
             "body": (f"Hi {name},\n\nAre you at your desk? I wanted to check the status of the "
                      f"vendor list before this afternoon's review.\n\nThanks")},
            {"subject": "Are you available?",
             "body": (f"Hi {name},\n\nAre you at your desk? I have a task I need handled "
                      f"discreetly before the end of the day.\n\nThanks")},
        ),
        (
            {"subject": "Banking provider change",
             "body": (f"Dear {name},\n\nOur company is migrating its banking provider next "
                      f"quarter. No action is required from you - we will send the formal "
                      f"notification on company letterhead through our account manager, and "
                      f"will confirm it by phone.\n\nFinance Department")},
            {"subject": "Banking provider change",
             "body": (f"Dear {name},\n\nOur company has changed its banking provider. All "
                      f"future remittances should be directed to the new account shown on the "
                      f"attached letterhead. Existing invoices remain unchanged.\n\nThank you "
                      f"for your cooperation.\n\nFinance Department")},
        ),
    ]
    return rng.choice(families)


# ---- Hard legitimate cases (false-positive pressure) ----------------------
def _hard_legit(rng: random.Random) -> Dict[str, str]:
    name = rng.choice(FIRST_NAMES)
    team = rng.choice(TEAMS)
    n = rng.randint(1000, 9999)
    options = [
        {"subject": "Urgent: submit your compliance documents today",
         "body": (f"Dear Team,\n\nThis is an urgent reminder that the compliance documents must "
                  f"be submitted today. The deadline cannot be extended because of the audit "
                  f"schedule. Please upload them through the HR portal that you normally use.\n\n"
                  f"HR Department")},
        {"subject": f"Action required: timesheet approval closes in 24 hours",
         "body": (f"Hi {name},\n\nTimesheet approval for the {team} team closes within 24 hours. "
                  f"Please approve the pending entries in the portal so payroll can be processed "
                  f"on time.\n\nThank you,\nPayroll")},
        {"subject": "Immediate attention: server maintenance window moved",
         "body": (f"Hello,\n\nThe maintenance window has been moved and now starts in two hours. "
                  f"Please save your work and sign out of the reporting system before then. "
                  f"Service will be restored by the morning.\n\nIT Operations")},
        {"subject": f"Final notice: library books overdue",
         "body": (f"Dear {name},\n\nThis is a final notice that two borrowed books are overdue. "
                  f"Please return them this week to avoid a late fee. You can renew them from "
                  f"the library catalogue if you still need them.\n\nLibrary Services")},
        {"subject": "Your password expires in 3 days - change it in the portal",
         "body": (f"Hello {name},\n\nYour corporate password expires in three days. Please change "
                  f"it using the company portal that you normally sign in to, or press "
                  f"Ctrl+Alt+Delete on your work machine and choose Change Password.\n\n"
                  f"We will never email you a link to reset it and we will never ask you to send "
                  f"us your password.\n\nIT Helpdesk")},
        {"subject": f"Invoice {n} is due this week",
         "body": (f"Dear Accounts,\n\nInvoice {n} for last month's services is due this week. The "
                  f"invoice is attached. Our bank details are unchanged and are the same ones "
                  f"printed on every previous invoice.\n\nRegards,\nAccounts Receivable")},
        {"subject": "Security alert: new device signed in to your account",
         "body": (f"Hello {name},\n\nA new device signed in to your account. If this was you, no "
                  f"action is needed.\n\nIf it was not you, open the account settings page "
                  f"directly from your browser and sign out all sessions. We will never ask for "
                  f"your password.\n\nAccount Security")},
    ]
    return rng.choice(options)


# ---------------------------------------------------------------------------
# PHISHING TEMPLATES (7 patterns from the brief)
# ---------------------------------------------------------------------------
def _phish_templates(rng: random.Random) -> Dict[str, List[Dict[str, str]]]:
    n = rng.randint(1000, 9999)
    amount = rng.choice(["4,820", "12,400", "980", "37,500", "2,150", "8,640"])
    greeting = rng.choice(["Dear Customer", "Dear User", "Dear Account Holder",
                           "Dear Valued Customer", "Dear Member", "Dear Sir/Madam"])

    return {
        "fake_account_verification": [
            {"subject": "URGENT: Verify Your Account Immediately",
             "body": (f"{greeting},\n\nWe detected unusual sign-in activity on your account. Your "
                      f"account will be suspended within 24 hours unless you verify your "
                      f"password immediately.\n\nClick here to verify your account and restore "
                      f"full access.\n\nFailure to comply will result in permanent deletion of "
                      f"your data.\n\nAccount Security Team")},
            {"subject": "Action Required: Confirm your account details now",
             "body": (f"{greeting},\n\nOur security system has flagged your account. To avoid "
                      f"suspension you must confirm your account and re-enter your password "
                      f"using the secure link below.\n\nThis is your final notice. Act now to "
                      f"keep your access.\n\nVerification Department")},
            {"subject": "Your mailbox will be deactivated - verify now",
             "body": (f"{greeting},\n\nYour mailbox has exceeded its storage quota and will be "
                      f"deactivated today. Verify your account immediately to keep receiving "
                      f"messages.\n\nClick the link below and sign in here to restore your "
                      f"mailbox.\n\nWebmail Support")},
        ],
        "fake_invoice": [
            {"subject": f"Outstanding payment: invoice {n} overdue",
             "body": (f"{greeting},\n\nOur records show an outstanding payment of {amount} "
                      f"against invoice {n}. The amount is overdue and legal action may follow "
                      f"if it is not settled.\n\nPlease review the attached invoice and process "
                      f"the payment immediately using our updated bank details.\n\n"
                      f"Accounts Department")},
            {"subject": f"Payment failed - urgent action required for invoice {n}",
             "body": (f"{greeting},\n\nYour recent payment of {amount} failed. To avoid service "
                      f"interruption, update your payment method immediately by clicking the "
                      f"link below and confirming your card details.\n\nBilling Team")},
            {"subject": "Final reminder: unpaid balance on your account",
             "body": (f"{greeting},\n\nThis is a final reminder regarding the unpaid balance of "
                      f"{amount} on your account. Your service will be restricted within 48 "
                      f"hours. Open the attached statement and release payment today.\n\n"
                      f"Collections")},
        ],
        "fake_prize": [
            {"subject": "Congratulations! You have won a cash reward",
             "body": (f"{greeting},\n\nCongratulations! You have won a cash reward of {amount} in "
                      f"our monthly lucky draw. You are one of the selected winners.\n\nTo claim "
                      f"your prize, confirm your personal details and bank account within 48 "
                      f"hours by clicking here.\n\nUnclaimed prizes are forfeited.\n\n"
                      f"Rewards Team")},
            {"subject": "You have been selected for an exclusive gift card",
             "body": (f"{greeting},\n\nYou have been selected to receive a free gift card. This "
                      f"exclusive offer expires today.\n\nClaim your reward now by confirming "
                      f"your personal information at the link below.\n\nPromotions Desk")},
            {"subject": "Winner announcement - claim your prize now",
             "body": (f"{greeting},\n\nYou are a winner in this month's lucky draw! Act now - "
                      f"this limited time offer expires in 12 hours.\n\nClick here to claim your "
                      f"prize and provide your identity documents for verification.\n\n"
                      f"Lucky Draw Committee")},
        ],
        "fake_password_expiration": [
            {"subject": "Your password expires today - immediate action required",
             "body": (f"{greeting},\n\nYour password expires today. If you do not reset your "
                      f"password within 24 hours your access will be revoked and your account "
                      f"will be locked.\n\nUse the link below to verify your password and keep "
                      f"your account active.\n\nIT Support")},
            {"subject": "Password Expiry Notice - Act Now",
             "body": (f"{greeting},\n\nOur records show that your login credentials have expired. "
                      f"Confirm your username and password immediately using the secure portal "
                      f"below to avoid losing access to company resources.\n\nHelpdesk")},
            {"subject": "URGENT: Password reset required for your mailbox",
             "body": (f"{greeting},\n\nA password reset is required for your mailbox. Please "
                      f"enter your current password and new password on the verification page "
                      f"below within 2 hours.\n\nFailure to comply will result in account "
                      f"suspension.\n\nMail Administrator")},
        ],
        "fake_delivery": [
            {"subject": "Delivery failed - reschedule required immediately",
             "body": (f"{greeting},\n\nWe attempted to deliver your parcel but the address was "
                      f"incomplete. Your package will be returned within 24 hours.\n\nConfirm "
                      f"your personal details and pay the small redelivery fee using the link "
                      f"below to reschedule.\n\nDelivery Team")},
            {"subject": f"Parcel {n} is on hold - customs payment due",
             "body": (f"{greeting},\n\nParcel {n} is on hold pending an outstanding payment of "
                      f"customs charges. Process the payment immediately or the parcel will be "
                      f"returned to the sender.\n\nClick here to release your package.\n\n"
                      f"Shipping Department")},
            {"subject": "Your shipment could not be delivered - urgent",
             "body": (f"{greeting},\n\nYour shipment could not be delivered. Open the attached "
                      f"delivery label and confirm your address details today to arrange "
                      f"redelivery.\n\nLogistics Support")},
        ],
        "fake_hr_request": [
            {"subject": "Salary revision notice - confirm your bank details",
             "body": (f"{greeting},\n\nA salary revision has been approved for this quarter. To "
                      f"process the revised amount, confirm your personal details and bank "
                      f"account information using the HR portal link below within 24 hours.\n\n"
                      f"Failure to respond will delay your payment.\n\nHR Department")},
            {"subject": "URGENT: Update your employee record today",
             "body": (f"{greeting},\n\nYour employee record is incomplete. Update your personal "
                      f"information and verify your account immediately, or payroll processing "
                      f"for this month will be suspended.\n\nClick here to complete the "
                      f"form.\n\nHuman Resources")},
            {"subject": "Mandatory policy acknowledgement - action required",
             "body": (f"{greeting},\n\nAll employees must acknowledge the revised policy today. "
                      f"Sign in here using your corporate credentials to confirm. Access to "
                      f"company systems will be restricted for employees who do not comply.\n\n"
                      f"HR Compliance")},
        ],
        "fake_executive_request": [
            {"subject": "Quick favour - urgent and confidential",
             "body": (f"Hi,\n\nI am in meetings all day and cannot take calls. I need you to "
                      f"process an urgent wire transfer of {amount} to a new beneficiary today. "
                      f"Keep this confidential until the announcement.\n\nReply as soon as you "
                      f"see this.\n\nSent from my phone")},
            {"subject": "Are you available? Urgent request",
             "body": (f"Hello,\n\nAre you at your desk? I need a payment released immediately to "
                      f"the updated bank details below. It is time sensitive and must not be "
                      f"discussed with anyone else yet.\n\nRegards,\nManaging Director")},
            {"subject": "Immediate action: purchase gift vouchers for clients",
             "body": (f"Hi,\n\nI need you to purchase gift cards for a client meeting this "
                      f"afternoon. Buy them now and send me the codes - I will approve the "
                      f"reimbursement later. Do not delay, the meeting is today.\n\n"
                      f"Sent from my mobile")},
        ],
    }


# ---- Hard phishing cases (false-negative pressure) ------------------------
def _hard_phish(rng: random.Random) -> Dict[str, str]:
    """The phishing side of an ambiguous pair (see :func:`_ambiguous_pair`)."""
    return _ambiguous_pair(rng)[1]


def _hard_legit_business(rng: random.Random) -> Dict[str, str]:
    """The legitimate side of an ambiguous pair - the false-positive pressure case."""
    return _ambiguous_pair(rng)[0]


# ---------------------------------------------------------------------------
# INDISTINGUISHABLE ROWS - modelling the irreducible error floor
# ---------------------------------------------------------------------------
# The templates below are drawn from the SAME pool for BOTH labels, from the
# SAME sender domains, with the SAME attachment pool and no URLs.
#
# This is deliberate and it is not label noise. It represents the real,
# well-documented situation in business-email compromise: the text of the
# message genuinely does not contain enough information to decide. Whether
# "please process invoice 4821" is legitimate depends on whether that invoice
# exists - a fact that lives in the accounting system, not in the email.
#
# WHY INCLUDE THEM?
#   * A synthetic dataset without them yields ~100% on every metric, which
#     looks fabricated, teaches nothing, and hides the real lesson.
#   * With them, the evaluation produces genuine false positives and false
#     negatives, so the report's FP/FN section describes measured behaviour
#     rather than a hypothetical.
#   * They set a realistic Bayes error: no text-only model can exceed it, which
#     is exactly the argument for header authentication (SPF/DKIM/DMARC),
#     first-time-sender detection and out-of-band payment verification.
#
# Roughly 8% of the dataset is generated this way, split evenly between labels.
# ---------------------------------------------------------------------------
def _indistinguishable(rng: random.Random) -> Dict[str, str]:
    """A neutral business email that is used for BOTH labels."""
    name = rng.choice(FIRST_NAMES)
    n = rng.randint(1000, 9999)
    month = rng.choice(MONTHS)
    options = [
        {"subject": f"Invoice {n} attached",
         "body": (f"Dear {name},\n\nPlease find invoice {n} for {month} attached. Kindly process "
                  f"it at your earliest convenience.\n\nRegards,\nAccounts")},
        {"subject": "Updated contact details",
         "body": (f"Hello {name},\n\nPlease update our contact details in your records. The "
                  f"main line and the address are on the attached sheet.\n\nThank you,\n"
                  f"Administration")},
        {"subject": f"Payment reminder - invoice {n}",
         "body": (f"Dear {name},\n\nThis is a reminder that payment for invoice {n} is due next "
                  f"week. Please let us know if you need anything from our side.\n\nRegards,\n"
                  f"Accounts")},
        {"subject": "Document for your review",
         "body": (f"Hi {name},\n\nAttaching the document for your review. Let me know your "
                  f"comments when you get a chance.\n\nThanks")},
        {"subject": "Follow-up from today's meeting",
         "body": (f"Hi {name},\n\nThanks for the meeting today. I will circulate the summary "
                  f"shortly. Please confirm the figures on your side.\n\nBest regards")},
        {"subject": f"Statement of account - {month}",
         "body": (f"Dear {name},\n\nPlease find the statement of account for {month}. Do let us "
                  f"know if anything does not reconcile with your records.\n\nRegards,\n"
                  f"Finance")},
        {"subject": "Revised schedule attached",
         "body": (f"Hello {name},\n\nThe revised schedule is attached. Please review it and "
                  f"confirm that the dates work for your team.\n\nKind regards")},
    ]
    return rng.choice(options)


# ---------------------------------------------------------------------------
# Row builders
# ---------------------------------------------------------------------------
def _make_legit_row(rng: random.Random, email_id: int, kind: str = "plain") -> Dict[str, str]:
    """Build one LEGITIMATE row.

    ``kind`` is one of:
      ``plain``            - a clearly benign message from one of the 8 categories
      ``hard``             - urgent-but-genuine, or the legitimate side of an
                             ambiguous business pair (false-positive pressure)
      ``indistinguishable``- a neutral business email drawn from the pool that is
                             shared with the PHISHING label (see _indistinguishable)
    """
    local, domain = rng.choice(LEGIT_SENDERS)
    ambiguous = False

    if kind == "indistinguishable":
        tpl = _indistinguishable(rng)
        local = rng.choice(SHARED_BUSINESS_LOCALS)
        domain = rng.choice(SHARED_BUSINESS_DOMAINS)
        return {
            "email_id": f"EML{email_id:05d}",
            "sender": f"{local}@{domain}",
            "sender_domain": domain,
            "subject": tpl["subject"],
            "body": tpl["body"],
            "urls": "",
            "attachment_name": rng.choice(
                ["", "", "invoice_{n}.pdf", "schedule.pdf", "statement.pdf", "document.pdf"]
            ).format(n=rng.randint(1000, 9999)),
            "label": "LEGITIMATE",
        }

    if kind == "hard":
        # Half of the hard legitimate rows are "urgent but genuine" (urgency
        # false-positive pressure); the other half are the legitimate side of an
        # ambiguous business pair, sent from the SHARED domain pool so the sender
        # domain carries no label information.
        if rng.random() < 0.5:
            tpl = _hard_legit(rng)
        else:
            tpl = _hard_legit_business(rng)
            ambiguous = True
            local = rng.choice(SHARED_BUSINESS_LOCALS)
            domain = rng.choice(SHARED_BUSINESS_DOMAINS)
    else:
        groups = _legit_templates(rng)
        category = rng.choice(list(groups.keys()))
        tpl = rng.choice(groups[category])

    urls: List[str] = []
    if not ambiguous and rng.random() < 0.55:
        for _ in range(rng.choice([1, 1, 1, 2])):
            url = rng.choice(LEGIT_URL_TEMPLATES).format(n=rng.randint(100, 9999))
            if url not in urls:
                urls.append(url)

    if ambiguous:
        attachment = rng.choice(["", "", "", "invoice_{n}.pdf", "schedule.pdf",
                                 "remittance_letter.pdf"]).format(n=rng.randint(1000, 9999))
    else:
        attachment = rng.choice(LEGIT_ATTACHMENTS).format(n=rng.randint(1000, 9999))

    body = tpl["body"]
    if urls and "http" not in body:
        body += f"\n\nMore information: {urls[0]}"

    return {
        "email_id": f"EML{email_id:05d}",
        "sender": f"{local}@{domain}",
        "sender_domain": domain,
        "subject": tpl["subject"],
        "body": body,
        "urls": " ".join(urls),
        "attachment_name": attachment,
        "label": "LEGITIMATE",
    }


def _make_phish_row(rng: random.Random, email_id: int, kind: str = "plain") -> Dict[str, str]:
    """Build one PHISHING row.

    ``kind`` is one of:
      ``plain``            - an overt lure with clear indicators
      ``hard``             - the phishing side of an ambiguous business pair
                             (false-negative pressure)
      ``indistinguishable``- a neutral business email drawn from the pool that is
                             shared with the LEGITIMATE label
    """
    local = rng.choice(PHISH_LOCALS)

    if kind == "indistinguishable":
        tpl = _indistinguishable(rng)
        local = rng.choice(SHARED_BUSINESS_LOCALS)
        domain = rng.choice(SHARED_BUSINESS_DOMAINS)
        return {
            "email_id": f"EML{email_id:05d}",
            "sender": f"{local}@{domain}",
            "sender_domain": domain,
            "subject": tpl["subject"],
            "body": tpl["body"],
            "urls": "",
            "attachment_name": rng.choice(
                ["", "", "invoice_{n}.pdf", "schedule.pdf", "statement.pdf", "document.pdf"]
            ).format(n=rng.randint(1000, 9999)),
            "label": "PHISHING",
        }

    if kind == "hard":
        # Hard phishing looks structurally ordinary: plausible sender from the
        # SAME domain pool legitimate business mail uses, no link, no risky
        # attachment, no urgency, correct grammar. Only the CONTEXT gives it
        # away - which is precisely why these produce real false negatives.
        domain = rng.choice(SHARED_BUSINESS_DOMAINS)
        local = rng.choice(SHARED_BUSINESS_LOCALS)
        tpl = _hard_phish(rng)
        urls: List[str] = []
        attachment = rng.choice(["", "", "", "invoice_{n}.pdf", "schedule.pdf",
                                 "remittance_letter.pdf"]).format(n=rng.randint(1000, 9999))
    else:
        domain = rng.choice(PHISH_DOMAINS + PHISH_LOOKALIKE_DOMAINS)
        groups = _phish_templates(rng)
        category = rng.choice(list(groups.keys()))
        tpl = rng.choice(groups[category])
        urls = []
        if rng.random() < 0.88:
            for _ in range(rng.choice([1, 1, 2, 2, 3])):
                url = rng.choice(PHISH_URL_TEMPLATES).format(
                    ip=rng.randint(2, 250), n=rng.randint(1000, 9999))
                if url not in urls:
                    urls.append(url)
        attachment = rng.choice(PHISH_ATTACHMENTS).format(n=rng.randint(1000, 9999))

    body = tpl["body"]
    if urls and "http" not in body:
        body += f"\n\n{urls[0]}"
    # Occasional shouting / exclamation spam, a real stylistic marker.
    if kind == "plain" and rng.random() < 0.25:
        body = body.replace("immediately", "IMMEDIATELY").replace("now", "NOW")
    if kind == "plain" and rng.random() < 0.20:
        body += "\n\nACT NOW!!!"

    return {
        "email_id": f"EML{email_id:05d}",
        "sender": f"{local}@{domain}",
        "sender_domain": domain,
        "subject": tpl["subject"],
        "body": body,
        "urls": " ".join(urls),
        "attachment_name": attachment,
        "label": "PHISHING",
    }


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------
def generate_dataset(rows: int = DEFAULT_ROWS, seed: int = DEFAULT_SEED,
                     phishing_ratio: float = 0.48,
                     hard_ratio: float = 0.20,
                     indistinguishable_ratio: float = 0.09) -> List[Dict[str, str]]:
    """Build the dataset in memory (deterministic for a given ``seed``).

    Composition
    -----------
    ``indistinguishable_ratio`` of each class is drawn from a SHARED template
    pool, giving the dataset a realistic irreducible error floor.
    ``hard_ratio`` of each class is a near-miss case (urgent-but-genuine mail on
    the legitimate side, quiet business-email-compromise on the phishing side).
    The remainder are clear-cut examples.
    """
    rng = random.Random(seed)
    n_phish = int(round(rows * phishing_ratio))
    n_legit = rows - n_phish

    n_ind_legit = int(round(n_legit * indistinguishable_ratio))
    n_ind_phish = int(round(n_phish * indistinguishable_ratio))
    n_hard_legit = int(round(n_legit * hard_ratio))
    n_hard_phish = int(round(n_phish * hard_ratio))

    records: List[Dict[str, str]] = []
    eid = 1
    for i in range(n_legit):
        if i < n_ind_legit:
            kind = "indistinguishable"
        elif i < n_ind_legit + n_hard_legit:
            kind = "hard"
        else:
            kind = "plain"
        records.append(_make_legit_row(rng, eid, kind=kind))
        eid += 1
    for i in range(n_phish):
        if i < n_ind_phish:
            kind = "indistinguishable"
        elif i < n_ind_phish + n_hard_phish:
            kind = "hard"
        else:
            kind = "plain"
        records.append(_make_phish_row(rng, eid, kind=kind))
        eid += 1

    rng.shuffle(records)
    for index, record in enumerate(records, start=1):    # re-number after shuffling
        record["email_id"] = f"EML{index:05d}"
    return records


def write_csv(records: List[Dict[str, str]], out_path: Path) -> Path:
    """Write the dataset to CSV with a stable column order."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS, quoting=csv.QUOTE_MINIMAL)
        writer.writeheader()
        writer.writerows(records)
    return out_path


def summarise(records: List[Dict[str, str]]) -> Dict[str, object]:
    """Small textual summary printed after generation."""
    total = len(records)
    phish = sum(1 for r in records if r["label"] == "PHISHING")
    with_urls = sum(1 for r in records if r["urls"].strip())
    with_attach = sum(1 for r in records if r["attachment_name"].strip())
    domains = {r["sender_domain"] for r in records}
    return {
        "total": total,
        "phishing": phish,
        "legitimate": total - phish,
        "phishing_pct": round(phish / total * 100, 1) if total else 0,
        "with_urls": with_urls,
        "with_attachment": with_attach,
        "unique_sender_domains": len(domains),
        "avg_body_length": round(sum(len(r["body"]) for r in records) / total, 1) if total else 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate the synthetic phishing email dataset.")
    parser.add_argument("--rows", type=int, default=DEFAULT_ROWS, help="number of rows (default 600)")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED, help="random seed (default 42)")
    parser.add_argument("--out", type=str, default=str(DEFAULT_OUT), help="output CSV path")
    args = parser.parse_args()

    if args.rows < 500:
        print(f"[warn] {args.rows} rows requested; the project brief asks for 500+. Continuing.")

    records = generate_dataset(rows=args.rows, seed=args.seed)
    out_path = write_csv(records, Path(args.out))
    stats = summarise(records)

    print("=" * 70)
    print("SYNTHETIC DATASET GENERATED")
    print("=" * 70)
    print(f"  file                  : {out_path}")
    print(f"  rows                  : {stats['total']}")
    print(f"  PHISHING              : {stats['phishing']} ({stats['phishing_pct']}%)")
    print(f"  LEGITIMATE            : {stats['legitimate']}")
    print(f"  rows with URL(s)      : {stats['with_urls']}")
    print(f"  rows with attachment  : {stats['with_attachment']}")
    print(f"  unique sender domains : {stats['unique_sender_domains']}")
    print(f"  avg body length       : {stats['avg_body_length']} characters")
    print(f"  seed                  : {args.seed} (deterministic - same seed, same file)")
    print("-" * 70)
    print("  SAFETY: all domains are RFC 2606 / RFC 6761 reserved names and all")
    print("          IP addresses are from RFC 5737 documentation ranges.")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
