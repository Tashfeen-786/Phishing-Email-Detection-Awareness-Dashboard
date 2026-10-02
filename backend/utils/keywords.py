"""
backend/utils/keywords.py
=========================
PURPOSE
-------
Central, documented lexicons ("keyword dictionaries") used by every analyzer in
this project. Keeping them in ONE file means:

  * the detection logic is auditable (a SOC analyst can review the word lists),
  * the same vocabulary is used by the rule engine AND the ML feature builder,
  * tuning detection = editing one file, not hunting through the codebase.

SAFETY
------
These are *defensive* detection lexicons. They describe language that phishing
emails commonly use so the software can WARN a user. Nothing here generates
phishing content.

IMPORTANT DETECTION PHILOSOPHY
------------------------------
A keyword is a WEAK SIGNAL. The word "urgent" appears in thousands of perfectly
legitimate business emails. That is why:

  * categories are combined (multi-signal detection),
  * credential / personal-information requests use CONTEXTUAL REGEX patterns,
    not bare keywords, so "the workshop covers password hygiene" is NOT treated
    as "please send your password",
  * every finding carries a severity and a human-readable explanation.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# 1. CONTENT / SOCIAL-ENGINEERING LEXICONS
# ---------------------------------------------------------------------------

#: Words and phrases that manufacture time pressure so the reader acts before
#: thinking. Classic social-engineering lever: "urgency".
URGENCY_KEYWORDS = [
    "urgent", "urgently", "immediately", "immediate action", "act now",
    "right away", "as soon as possible", "asap", "time sensitive",
    "time-sensitive", "expires today", "expires in", "expiring soon",
    "final notice", "last warning", "last chance", "don't delay",
    "do not delay", "within 24 hours", "within 12 hours", "within 48 hours",
    "before it is too late", "before it's too late", "quick action",
    "respond now", "reply immediately", "limited time", "hurry",
    "deadline today", "action required", "immediate attention",
]

#: Fear / threat / consequence language. Phishing frequently threatens loss of
#: access, legal action, or money to trigger a panic response.
#: Only phrases that are unambiguous on their own belong here.
#:
#: Bare words were deliberately REMOVED after measuring them: "fine" matches
#: "that works fine", "blocked" matches "the date is blocked out", "restricted"
#: matches "restricted parking", and "will be closed" matches "the office will
#: be closed on Friday". Flexible phrasing is handled by THREAT_REGEXES below,
#: which requires a subject and a consequence rather than a lone word.
THREAT_KEYWORDS = [
    "account will be suspended", "account has been suspended",
    "account suspension", "has been locked", "account locked",
    "account disabled", "permanently deleted", "permanent deletion",
    "legal action", "law enforcement", "criminal charges", "court order",
    "unauthorized access", "unauthorised access", "suspicious activity",
    "security breach", "security alert", "security warning",
    "unusual sign-in", "unusual login", "your access will be revoked",
    "failure to comply", "you will lose", "service interruption",
    "policy violation", "terms of service violation", "late fee",
    "final warning", "final notice", "immediate termination",
]

#: Threat phrasing is rarely a fixed string. Real lures write "your account will
#: be PERMANENTLY closed", "has been TEMPORARILY suspended", "may be subject to
#: legal action". A fixed-phrase list misses every one of those because of the
#: adverb in the middle, so these anchored patterns allow up to two filler words
#: between the auxiliary verb and the consequence.
#:
#: They stay anchored to a subject + consequence pair, so ordinary sentences such
#: as "the office will be closed on Friday" still need the account/access/service
#: subject to match, keeping false positives low.
THREAT_REGEXES = [
    # "your account has been temporarily suspended", "access will be revoked"
    (r"\b(?:account|access|mailbox|profile|service|subscription|card|wallet)\b"
     r"(?:\s+\w+){0,3}?\s+"
     r"(?:will|shall|may|would|could|has|have|had|is|are|was|were)\s+"
     r"(?:be\s+|been\s+)?(?:\w+\s+){0,2}?"
     r"(?:suspend|suspended|clos|closed|lock|locked|disabl|disabled|deactivat|"
     r"deactivated|terminat|terminated|delet|deleted|revok|revoked|block|blocked|"
     r"restrict|restricted|limit|limited|frozen|freeze)\b",
     "threatened account suspension or closure"),
    # "your data will be permanently deleted", "your access shall be revoked".
    #
    # The leading "your" is deliberate and load-bearing. Without it this pattern
    # fires on ordinary announcements such as "the office will be closed on
    # Friday" - measured, not guessed. Requiring the second person keeps the
    # match on the shape phishing actually uses: a loss aimed at the reader.
    (r"\byour\s+(?:\w+\s+){0,3}?(?:will|shall|may)\s+be\s+(?:\w+\s+){0,2}?"
     r"(?:suspended|closed|locked|disabled|deactivated|terminated|deleted|revoked|"
     r"blocked|restricted|frozen|forfeited)\b",
     "stated negative consequence for the reader"),
    # "failure to (verify|comply|respond) will ..."
    (r"\bfailure\s+to\s+\w+(?:\s+\w+){0,3}\s+(?:will|shall|may)\b",
     "consequence for not complying"),
    # "unusual / unrecognised / unauthorised activity on your account"
    (r"\b(?:unusual|unrecogni[sz]ed|unauthori[sz]ed|suspicious|abnormal|irregular)\s+"
     r"(?:sign[- ]?in|login|log[- ]?in|activity|access|attempt|transaction)\b",
     "claimed unusual account activity"),
    # "within 24 hours or ..." - deadline tied to a penalty
    (r"\bwithin\s+\d+\s*(?:minutes?|hours?|days?)\b(?:[^.]{0,60}?)\bor\b",
     "deadline paired with a consequence"),
    # "subject to legal action / penalty / prosecution"
    (r"\bsubject\s+to\s+(?:\w+\s+){0,2}?"
     r"(?:legal\s+action|prosecution|penalt(?:y|ies)|fine|suspension|closure)\b",
     "threat of legal or financial penalty"),
]

#: Money pressure: fake invoices, overdue bills, refunds and payment redirects.
FINANCIAL_KEYWORDS = [
    "invoice", "invoice due", "outstanding payment", "payment due",
    "overdue", "unpaid", "billing", "billing issue", "payment failed",
    "payment declined", "refund", "reimbursement", "wire transfer",
    "bank transfer", "remittance", "purchase order", "tax", "gst",
    "transaction", "credit card", "debit card", "settle your account",
    "release payment", "process the payment", "update your payment",
    "payment method", "beneficiary", "account number",
]

#: Reward / greed lever: lotteries, prizes, gift cards, bonuses.
REWARD_KEYWORDS = [
    "you have won", "you've won", "congratulations", "winner", "prize",
    "lottery", "lucky draw", "reward", "gift card", "voucher", "cash bonus",
    "claim your", "free gift", "you are selected", "you have been selected",
    "exclusive offer", "no cost", "100% free",
]

#: Words that *suggest* credentials are the topic. On their own these are NOT
#: enough to raise a credential-request finding (see CREDENTIAL_REQUEST_PATTERNS).
CREDENTIAL_KEYWORDS = [
    "password", "passwords", "passcode", "credential", "credentials",
    "username", "user id", "login", "log in", "sign in", "signin",
    "one time password", "one-time password", "otp", "mfa code",
    "2fa code", "verification code", "security code", "pin",
    "security question", "recovery code",
]

#: Words about personal data. Again, context decides (see patterns below).
PERSONAL_INFO_KEYWORDS = [
    "personal details", "personal information", "date of birth",
    "aadhaar", "social security", "ssn", "passport number",
    "driver licence", "driver license", "mother's maiden name",
    "full name and address", "kyc", "identity verification",
]

#: "Do this now" instructions that point away from the safe, official channel.
SUSPICIOUS_CTA_KEYWORDS = [
    "click here", "click the link", "click below", "follow this link",
    "open the attached", "open the attachment", "download the attached",
    "scan the qr", "scan this qr", "log in here", "login here",
    "verify here", "update here", "confirm here", "tap here",
    "use the link below", "access your account here",
]

#: Impersonal salutations. Real organisations that already know you usually use
#: your name; bulk phishing cannot.
GENERIC_GREETINGS = [
    "dear user", "dear customer", "dear client", "dear member",
    "dear account holder", "dear sir/madam", "dear sir or madam",
    "dear sir", "dear madam", "dear valued customer", "dear employee",
    "dear subscriber", "hello user", "hello customer", "hi user",
    "attention user", "attention customer", "to whom it may concern",
    "dear email user", "dear beneficiary",
]

# ---------------------------------------------------------------------------
# 2. CONTEXTUAL REGEX PATTERNS (precision-focused detection)
# ---------------------------------------------------------------------------
# These regexes look for the ACT OF ASKING, not merely the topic. This is the
# single biggest false-positive reducer in the project.

#: "verify your password", "confirm your account credentials", "re-enter your PIN"
CREDENTIAL_REQUEST_PATTERNS = [
    r"\b(verify|confirm|validate|update|re-?enter|reenter|provide|submit|send|share|enter|reset|restore|recover)\b"
    r"(?:\s+\w+){0,3}?\s+"
    r"\b(password|passcode|credential|credentials|username|user\s?id|login|log-?in|sign-?in|"
    r"otp|one[-\s]?time\s+password|pin|security\s+code|verification\s+code|account\s+details|"
    r"account\s+information|banking\s+details)\b",

    r"\b(password|credentials|login|account)\b(?:\s+\w+){0,3}?\s+"
    r"\b(will\s+expire|expires|has\s+expired|is\s+about\s+to\s+expire|must\s+be\s+(?:reset|updated|verified))\b",

    r"\b(sign|log)\s?in\s+(?:here|below|now|immediately|to\s+(?:verify|confirm|validate|avoid|restore))\b",

    r"\b(verify|confirm|validate|authenticate|re-?activate|reactivate|unlock|restore)\s+"
    r"(?:your\s+|the\s+)?(account|identity|mailbox|email\s+account|profile|access)\b",

    r"\byour\s+(password|credentials|login\s+details)\b(?:\s+\w+){0,4}?\s+\b(required|needed|requested)\b",
]

#: "confirm your personal details", "update your billing information"
PERSONAL_INFO_REQUEST_PATTERNS = [
    r"\b(confirm|verify|update|provide|submit|share|send|complete|re-?submit)\b"
    r"(?:\s+\w+){0,3}?\s+"
    r"\b(personal\s+(?:details|information|data)|contact\s+details|billing\s+(?:details|information|address)|"
    r"bank\s+(?:details|account)|card\s+details|kyc|identity\s+documents|date\s+of\s+birth|"
    r"address\s+and\s+phone|payment\s+(?:details|information|method))\b",

    r"\b(fill|complete)\s+(?:in\s+|out\s+)?(?:the\s+|this\s+)?(attached\s+)?(form|questionnaire)\b"
    r"(?:\s+\w+){0,4}?\s+\b(details|information|identity|verification)\b",
]

#: Payment-redirect / invoice-fraud phrasing (business email compromise style).
FINANCIAL_PRESSURE_PATTERNS = [
    r"\b(release|process|approve|authorise|authorize|make|initiate|transfer)\b"
    r"(?:\s+\w+){0,3}?\s+\b(payment|funds|transfer|amount|invoice)\b",
    r"\b(updated?|new|revised|changed)\s+(bank|beneficiary|account|payment)\s+(details|information|account)\b",
    r"\b(invoice|payment|balance)\b(?:\s+\w+){0,3}?\s+\b(overdue|due|unpaid|pending|outstanding)\b",
    r"\b(outstanding|unpaid|overdue)\s+(payment|invoice|amount|balance|dues?)\b",
]

# ---------------------------------------------------------------------------
# 3. SENDER LEXICONS
# ---------------------------------------------------------------------------

#: Tokens that look "official" and are heavily abused inside *the domain itself*
#: (e.g. secure-account-verify.invalid.test). Legitimate organisations normally
#: use their brand as the registrable domain, not a security verb.
SENDER_DOMAIN_SUSPICIOUS_TOKENS = [
    "secure", "security", "account", "accounts", "verify", "verification",
    "validate", "confirm", "update", "login", "signin", "auth", "recovery",
    "support", "helpdesk", "service", "billing", "payment", "invoice",
    "alert", "notice", "notify", "unlock", "restore", "webmail", "mailbox",
    "id-check", "check",
]

#: Local-part (before the "@") tokens frequently used by bulk phishing.
SENDER_LOCALPART_SUSPICIOUS_TOKENS = [
    "security-alert", "security_alert", "securityalert", "alert", "no-reply-security",
    "account-verify", "verify", "verification", "admin-support", "helpdesk-support",
    "billing-dept", "payment-dept", "it-support-desk", "password-reset",
    "urgent", "notification-service",
]

#: Character substitutions used to build look-alike domains
#: (documented for the awareness module; detection is generic, not brand-based).
LOOKALIKE_SUBSTITUTIONS = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
}

#: Generic look-alike SHAPES (no reference list needed):
#:   - a digit sitting inside an otherwise alphabetic label  (examp1e)
#:   - three or more hyphen-joined words                     (secure-login-verify-now)
LOOKALIKE_REGEXES = [
    r"^[a-z]{2,}[013457]{1,2}[a-z]{1,}$",
    r"^[a-z]{3,}-[a-z]{3,}-[a-z]{3,}",
]

#: Reference labels for EDIT-DISTANCE look-alike detection.
#:
#: Generic "shape" rules cannot catch every impersonation - the classic
#: "rn" -> "m" substitution is invisible without something to compare against.
#: Real deployments solve this with an allow-list of the domains the
#: organisation actually owns or expects, and flag anything that is *close but
#: not equal* to one of them.
#:
#: This project ships the reserved documentation labels it legitimately uses.
#: Extend the list (or the LOOKALIKE_REFERENCE_LABELS environment variable) with
#: your own organisation's domain labels to make the check meaningful for you.
LOOKALIKE_REFERENCE_LABELS = [
    "example", "examples", "university", "accounts", "support",
    "helpdesk", "payments", "security", "training", "library",
]

#: Maximum edit distance at which a label counts as a look-alike of a
#: reference label (1 or 2 - beyond that the words are simply different).
LOOKALIKE_MAX_DISTANCE = 2

# ---------------------------------------------------------------------------
# 4. URL LEXICONS
# ---------------------------------------------------------------------------

#: Keywords that, when found inside a URL, indicate the link is trying to look
#: like a login / payment destination.
URL_SUSPICIOUS_KEYWORDS = [
    "verify", "verification", "account", "login", "signin", "sign-in",
    "secure", "security", "update", "confirm", "password", "credential",
    "banking", "bank", "payment", "invoice", "billing", "wallet",
    "unlock", "restore", "recovery", "suspended", "webscr", "authenticate",
    "validate", "session", "token", "otp", "kyc", "refund", "claim", "prize",
]

#: Hostname fragments used by URL-shortening services. Detected as a PATTERN:
#: shorteners are legitimate tools, but they hide the true destination, which
#: matters for phishing triage.
URL_SHORTENER_PATTERNS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "rebrand.ly", "s.id",
    "short.link", "lnk.to", "t.ly", "shrtco.de", "v.gd", "clck.ru",
]

#: Schemes that must never be trusted inside an email body.
DANGEROUS_URL_SCHEMES = ["javascript", "data", "vbscript", "file", "ftp", "smb", "telnet"]

# ---------------------------------------------------------------------------
# 5. ATTACHMENT LEXICONS
# ---------------------------------------------------------------------------

#: Directly executable on Windows / by a script host. Highest attachment risk.
EXECUTABLE_EXTENSIONS = [
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".msi", ".msp",
    ".cpl", ".jar", ".hta", ".lnk", ".reg", ".gadget", ".application",
]

#: Script files interpreted by Windows Script Host / PowerShell / node.
SCRIPT_EXTENSIONS = [
    ".js", ".jse", ".vbs", ".vbe", ".ps1", ".psm1", ".wsf", ".wsh",
    ".sh", ".py", ".pl", ".scpt",
]

#: Archives are not malicious by themselves, but they are the standard way to
#: smuggle an executable past a simple extension filter.
ARCHIVE_EXTENSIONS = [
    ".zip", ".rar", ".7z", ".iso", ".img", ".cab", ".ace", ".arj",
    ".tar", ".gz", ".tgz", ".bz2", ".xz",
]

#: Office formats that can carry macros (VBA).
MACRO_OFFICE_EXTENSIONS = [".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm", ".xlam", ".ppam"]

#: Formats that are expected in normal business mail. Still "verify if unexpected".
COMMON_SAFE_EXTENSIONS = [
    ".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt", ".txt",
    ".csv", ".png", ".jpg", ".jpeg", ".gif", ".rtf", ".odt", ".ods", ".ics",
]

#: Extensions that a *double extension* attack typically hides behind
#: (invoice.pdf.exe -> the victim sees "invoice.pdf").
DOUBLE_EXTENSION_DECOYS = [
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt",
    ".jpg", ".jpeg", ".png", ".gif", ".csv", ".htm", ".html", ".zip",
]

__all__ = [
    "URGENCY_KEYWORDS", "THREAT_KEYWORDS", "THREAT_REGEXES", "FINANCIAL_KEYWORDS",
    "REWARD_KEYWORDS", "CREDENTIAL_KEYWORDS", "PERSONAL_INFO_KEYWORDS",
    "SUSPICIOUS_CTA_KEYWORDS", "GENERIC_GREETINGS",
    "CREDENTIAL_REQUEST_PATTERNS", "PERSONAL_INFO_REQUEST_PATTERNS",
    "FINANCIAL_PRESSURE_PATTERNS",
    "SENDER_DOMAIN_SUSPICIOUS_TOKENS", "SENDER_LOCALPART_SUSPICIOUS_TOKENS",
    "LOOKALIKE_SUBSTITUTIONS", "LOOKALIKE_REGEXES",
    "LOOKALIKE_REFERENCE_LABELS", "LOOKALIKE_MAX_DISTANCE",
    "URL_SUSPICIOUS_KEYWORDS", "URL_SHORTENER_PATTERNS", "DANGEROUS_URL_SCHEMES",
    "EXECUTABLE_EXTENSIONS", "SCRIPT_EXTENSIONS", "ARCHIVE_EXTENSIONS",
    "MACRO_OFFICE_EXTENSIONS", "COMMON_SAFE_EXTENSIONS", "DOUBLE_EXTENSION_DECOYS",
]
