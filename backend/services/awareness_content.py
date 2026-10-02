"""
backend/services/awareness_content.py
=====================================
PURPOSE
-------
All security-awareness content, in one place, as plain Python data so the API
and the React frontend stay in sync.

CONTENT
-------
* HOW_TO_SPOT              - the 10 checks from the project brief
* BEFORE_YOU_CLICK         - the "Before You Click" checklist
* MICRO_LESSONS            - 6 x 60-90 second lessons
* SIMULATION_TEMPLATES     - 3 SAFE, clearly-labelled training templates
* PLAYBOOK                 - what to do when a message is suspicious
* FALSE_POSITIVE_NEGATIVE  - worked examples of both error types
* SOC_WORKFLOW             - the analyst triage flow
* MITRE_MAPPING            - conceptual mapping to MITRE ATT&CK

>>> SAFETY <<<
The simulation templates are TEMPLATES FOR TRAINING MATERIAL. They contain
placeholders, reserved example domains and an explicit banner. The application
cannot and does not send email: there is no SMTP client anywhere in this
project. They exist so a student can discuss awareness programmes, not so
anyone can run a campaign.
"""

from __future__ import annotations

from typing import Any, Dict, List

# ---------------------------------------------------------------------------
# "How to Spot a Phishing Email" - the 10 required checks
# ---------------------------------------------------------------------------
HOW_TO_SPOT: List[Dict[str, str]] = [
    {
        "number": 1,
        "title": "Check the sender address, not the display name",
        "what": "Expand the 'From' field and read the actual address after the '@'.",
        "why": "The display name is free text chosen by the sender. 'IT Helpdesk' can sit in "
               "front of any address in the world. Only the domain after the '@' is meaningful.",
        "example": "IT Helpdesk <no-reply@it-support-desk.invalid.test>",
    },
    {
        "number": 2,
        "title": "Read the domain spelling character by character",
        "what": "Compare the domain with the one you already know, letter by letter.",
        "why": "Look-alike domains swap 0 for o, 1 for l, or use 'rn' where you expect 'm'. "
               "At normal reading speed the brain corrects the spelling for you.",
        "example": "examp1e.invalid.test instead of example.com",
    },
    {
        "number": 3,
        "title": "Be suspicious of unexpected urgency",
        "what": "Ask: why does this have to happen in the next few minutes?",
        "why": "Urgency is manufactured to stop you verifying. A genuine organisation will "
               "still be there tomorrow and will let you use official channels.",
        "example": "\"Your account will be suspended within 24 hours.\"",
    },
    {
        "number": 4,
        "title": "Inspect links before clicking",
        "what": "Hover on desktop, long-press on mobile, and read the destination.",
        "why": "Link text and link destination are completely independent. The visible text "
               "can read like a trusted site while the destination is anything at all.",
        "example": "Text says example.org, destination is hxxp://198[.]51[.]100[.]10/verify",
    },
    {
        "number": 5,
        "title": "Never supply credentials from an email link",
        "what": "Close the email, open the site or app yourself, and sign in there.",
        "why": "No legitimate organisation needs your password, OTP or PIN by email. "
               "A credential request is one of the strongest phishing signals there is.",
        "example": "\"Verify your password to keep your mailbox active.\"",
    },
    {
        "number": 6,
        "title": "Treat unexpected attachments as hostile",
        "what": "Confirm with the sender through a different channel before opening anything.",
        "why": "Opening the file is what executes the payload. Enable 'show file extensions' "
               "in Windows so invoice.pdf.exe cannot hide behind a fake document icon.",
        "example": "invoice.pdf.exe, payroll_update.docm, delivery_note.zip",
    },
    {
        "number": 7,
        "title": "Notice generic greetings",
        "what": "See whether the message uses your actual name.",
        "why": "A provider that holds your account record usually knows your name. Bulk "
               "phishing is sent to thousands of addresses at once and cannot personalise.",
        "example": "\"Dear Customer\", \"Dear Account Holder\"",
    },
    {
        "number": 8,
        "title": "Question unusual payment requests",
        "what": "Verify any change of bank details or urgent transfer by phone, on a number "
                "you already had.",
        "why": "Invoice fraud and payment redirection are the highest-value email attacks. "
               "The email often arrives exactly when a payment really is expected.",
        "example": "\"Please note our updated bank details for the outstanding invoice.\"",
    },
    {
        "number": 9,
        "title": "Watch for threatening language",
        "what": "Note any threat of suspension, penalty, legal action or data loss.",
        "why": "Fear narrows attention. Under pressure people click first and think second - "
               "which is the entire point of the message.",
        "example": "\"Failure to comply will result in permanent deletion of your data.\"",
    },
    {
        "number": 10,
        "title": "Judge the context",
        "what": "Ask: was I expecting this, from this person, about this, right now?",
        "why": "Context is the signal no attacker fully controls. A perfectly written email "
               "about a parcel you never ordered is still wrong.",
        "example": "A 'delivery failed' notice when you have not ordered anything.",
    },
]

# ---------------------------------------------------------------------------
# "Before You Click" checklist
# ---------------------------------------------------------------------------
BEFORE_YOU_CLICK: List[Dict[str, str]] = [
    {"check": "Do I know the sender, and is the domain after '@' the one I expect?",
     "if_no": "Stop. Verify through a channel you already trust."},
    {"check": "Was I expecting this message and this attachment?",
     "if_no": "Stop. Unexpected + attachment = confirm before opening."},
    {"check": "Have I hovered over every link and read the real destination?",
     "if_no": "Hover first. Read the hostname from the right-hand side."},
    {"check": "Is the destination's registrable domain the organisation's real domain?",
     "if_no": "Do not click. Trust words in a subdomain mean nothing."},
    {"check": "Is the message asking for a password, OTP, PIN or card details?",
     "if_no": "Good. If yes: it is phishing until proven otherwise."},
    {"check": "Is it pressuring me with a deadline, a threat or a prize?",
     "if_no": "Good. If yes: slow down - pressure is the attack."},
    {"check": "Does it ask me to change payment or bank details?",
     "if_no": "Good. If yes: verify by phone on a number you already had."},
    {"check": "Can I reach the same place by typing the address myself or using the app?",
     "if_no": "Then you probably do not need the link at all."},
    {"check": "If I am wrong, what is the worst outcome?",
     "if_no": "When the answer is 'account takeover', the check is always worth 60 seconds."},
    {"check": "Do I know how to report this in my organisation?",
     "if_no": "Find out now, before you need it. Reporting protects everyone else too."},
]

# ---------------------------------------------------------------------------
# Micro-lessons (60-90 seconds each)
# ---------------------------------------------------------------------------
MICRO_LESSONS: List[Dict[str, Any]] = [
    {
        "id": "hover-to-verify",
        "title": "Hover to Verify",
        "duration": "60 seconds",
        "summary": "The text of a link and its destination are two different things.",
        "content": [
            "In HTML mail, the words you see and the address you go to are separate values. "
            "An attacker controls both.",
            "On a desktop, hover the pointer over the link and read the address in the status "
            "bar. On mobile, press and hold until a preview appears - do not tap.",
            "Read the hostname from the RIGHT. The registrable domain is the label immediately "
            "before the first single slash.",
            "If the destination does not match the words, the message is deceptive - no matter "
            "how well it is written.",
        ],
        "try_this": "Analyse a link whose visible text is https://www.example.org/login but "
                    "whose destination is http://198.51.100.10/verify-account. The URL analyzer "
                    "reports a displayed-vs-destination mismatch.",
    },
    {
        "id": "url-anatomy",
        "title": "URL Anatomy",
        "duration": "90 seconds",
        "summary": "Learn to find the real owner of a web address in three seconds.",
        "content": [
            "A URL looks like: scheme://subdomains.registrable-domain.tld/path?query",
            "Example: https://login.secure.account.attacker-site.invalid.test/verify",
            "  - scheme            https        (encryption only - NOT trust)",
            "  - subdomains        login.secure.account   (free text, means nothing)",
            "  - registrable domain attacker-site.invalid.test  <-- THE REAL OWNER",
            "  - path              /verify      (also free text)",
            "The owner is always the part immediately before the FIRST single slash. Everything "
            "to its left was chosen by whoever registered the domain.",
            "HTTPS does not mean safe. Certificates are free and automated, so the padlock only "
            "tells you the connection is encrypted - not who is on the other end.",
        ],
        "try_this": "Paste https://www.example.org.secure-login.invalid.test/account into the "
                    "URL analyzer. The registrable domain is secure-login.invalid.test, not "
                    "example.org.",
    },
    {
        "id": "sender-spoofing",
        "title": "Sender Spoofing",
        "duration": "75 seconds",
        "summary": "Why the 'From' line is the least trustworthy part of an email.",
        "content": [
            "SMTP was designed in 1982 without authentication. The 'From' header a human sees "
            "is written by the sender and is not verified by the protocol itself.",
            "SPF, DKIM and DMARC were added later to authenticate the sending domain. They help, "
            "but only when the receiving organisation enforces them - and they do not protect "
            "against a look-alike domain that is genuinely owned by the attacker.",
            "Display-name spoofing needs no technical skill at all: anyone can set their display "
            "name to 'Finance Department'.",
            "Practical rule: treat the 'From' line as a claim, not a fact. Verify anything "
            "important through a channel you already trust.",
        ],
        "try_this": "Analyse a message where the display name is 'IT Helpdesk' but the address "
                    "is no-reply@random-mailer.invalid.test - the sender analyzer reports a "
                    "display-name mismatch.",
    },
    {
        "id": "qr-and-voice-phishing",
        "title": "QR and Voice Phishing (quishing and vishing)",
        "duration": "75 seconds",
        "summary": "Phishing has moved off the page and onto your camera and your phone.",
        "content": [
            "QUISHING: a QR code in an email or poster hides the destination completely - there "
            "is nothing to hover over. Scanning also moves you to a personal phone, which is "
            "usually outside corporate filtering.",
            "Defence: use a scanner that shows the URL before opening it, read the registrable "
            "domain, and never sign in to anything you reached from a QR code in an email.",
            "VISHING: a phone call, often following the email, that adds pressure and "
            "authority. Caller ID is as easy to spoof as a display name.",
            "Defence: hang up and call back on a number you already had - from a bill, a card, "
            "or the organisation's official site. Never a number from the message.",
            "Combined attacks (email + call) are far more convincing than either alone, because "
            "the second channel appears to confirm the first.",
        ],
        "try_this": "Ask yourself: if a call 'confirms' an email, what independent evidence do "
                    "I actually have? (Answer: none - the attacker controls both.)",
    },
    {
        "id": "invoice-scams",
        "title": "Invoice and Payment Scams",
        "duration": "90 seconds",
        "summary": "The highest-value email attack needs no malware at all.",
        "content": [
            "Business email compromise works by changing where money goes. There is no "
            "attachment to scan and no link to block - just a believable request.",
            "Typical shapes: a 'supplier' announcing new bank details; a forwarded invoice with "
            "an altered account number; an 'executive' asking for an urgent confidential "
            "transfer while they are 'in a meeting'.",
            "Signals: a change of payment details, urgency plus secrecy, a reply-to address "
            "that differs from the from-address, and pressure to bypass the normal process.",
            "Defence is a PROCESS, not a filter: every change of bank details is verified by "
            "phone on a previously known number, and payments above a threshold need a second "
            "approver. Technology alone cannot catch a well-written request.",
        ],
        "try_this": "Analyse: 'Please note our updated bank details for invoice 4821. Process "
                    "the payment today.' The content analyzer reports financial pressure.",
    },
    {
        "id": "credential-theft-awareness",
        "title": "Credential Theft Awareness",
        "duration": "90 seconds",
        "summary": "What actually happens after you type your password into the wrong page.",
        "content": [
            "A credential-harvesting page is a copy of a login screen. It posts your username "
            "and password to the attacker, then usually redirects you to the real site so "
            "nothing feels wrong.",
            "Modern kits also proxy the session in real time, so they capture the one-time code "
            "and the session cookie as well. That is why 'I have MFA' is not a complete answer.",
            "Stolen credentials are used for mailbox rules, internal spearphishing from your "
            "real account, and access to anything that shares the password.",
            "If you think you typed a password into the wrong place: change it immediately from "
            "a device you trust, sign out all active sessions, check your mailbox forwarding "
            "rules, and tell your security team. Speed limits the damage.",
            "Prevention that works: a password manager (it will not autofill on the wrong "
            "domain - a very reliable warning), unique passwords, and phishing-resistant MFA "
            "such as a passkey or a hardware key.",
        ],
        "try_this": "Notice that your password manager refusing to autofill is itself a "
                    "detection signal. The manager checks the domain; your eyes may not.",
    },
]

# ---------------------------------------------------------------------------
# SAFE simulation templates (training material only - nothing is ever sent)
# ---------------------------------------------------------------------------
SIMULATION_TEMPLATES: List[Dict[str, Any]] = [
    {
        "id": "password-expiry",
        "name": "Password Expiry (training template)",
        "teaching_point": "Credential request + urgency + generic greeting.",
        "sender": "it-support@mail-service.invalid.test",
        "subject": "Action required: your {company} password expires today",
        "body": ("Dear User,\n\n"
                 "Our records show that your {company} password expires today. To avoid losing "
                 "access to your mailbox, verify your password within 24 hours using the link "
                 "below.\n\n"
                 "http://203.0.113.24/password/verify\n\n"
                 "IT Support"),
        "indicators_taught": ["generic greeting", "urgency", "credential request",
                              "raw IP URL", "non-HTTPS URL"],
    },
    {
        "id": "parcel-delivery",
        "name": "Parcel Delivery (training template)",
        "teaching_point": "Small-payment bait + shortened link + personal-data request.",
        "sender": "delivery-notice@parcel-track.invalid.test",
        "subject": "Delivery failed for {name} - reschedule required",
        "body": ("Hello {name},\n\n"
                 "We attempted delivery of your parcel but the address was incomplete. "
                 "Please confirm your personal details and pay the redelivery fee.\n\n"
                 "Reschedule: http://bit.ly/example-not-real\n\n"
                 "Delivery Team"),
        "indicators_taught": ["personal information request", "URL shortener",
                              "financial pressure", "suspicious sender domain"],
    },
    {
        "id": "executive-request",
        "name": "Executive Request (training template)",
        "teaching_point": "Authority + secrecy + payment change, with no link or attachment.",
        "sender": "ceo.office@corp-exec.invalid.test",
        "subject": "Quick favour - confidential",
        "body": ("Hi {name},\n\n"
                 "I am in meetings all day. I need you to process the payment for the "
                 "outstanding invoice using our updated bank details. Keep this between us "
                 "until the announcement.\n\n"
                 "Sent from my phone"),
        "indicators_taught": ["financial pressure", "authority pressure", "secrecy request",
                              "display-name mismatch", "no link and no attachment - a deliberate "
                              "false-negative teaching case"],
    },
]

SIMULATION_SAFETY_NOTE = (
    "These are TRAINING TEMPLATES for classroom discussion and for testing this analyzer. "
    "This application contains no SMTP client and cannot send email. All addresses use "
    "reserved example/invalid domains (RFC 2606 / RFC 6761) and all IP addresses come from the "
    "RFC 5737 documentation ranges. Real awareness campaigns must be authorised in writing by "
    "the organisation, must never capture real credentials, and must always end in education "
    "rather than punishment."
)

# ---------------------------------------------------------------------------
# Response playbook
# ---------------------------------------------------------------------------
PLAYBOOK: List[Dict[str, str]] = [
    {"step": "1. Stop",
     "detail": "Do not click, do not reply, do not open attachments, do not forward it to "
               "colleagues 'to check'."},
    {"step": "2. Report",
     "detail": "Use your mail client's 'Report phishing' button, or forward the message AS AN "
               "ATTACHMENT to your security team so the original headers survive."},
    {"step": "3. Block / delete",
     "detail": "Follow your organisation's guidance. Deleting before reporting destroys the "
               "evidence the SOC needs, so report first."},
    {"step": "4. Reset if exposed",
     "detail": "If you entered a password anywhere: change it immediately from a device you "
               "trust, and change it anywhere else you reused it."},
    {"step": "5. Check MFA and sessions",
     "detail": "Review active sessions, sign out everywhere, and confirm no new MFA method or "
               "mailbox forwarding rule was added."},
    {"step": "6. Escalate",
     "detail": "If money moved or credentials were entered, this is an incident. Escalate "
               "immediately - early reporting is what limits the damage."},
    {"step": "7. Learn",
     "detail": "Share the pattern (not blame) with the team. Awareness improves when people can "
               "report mistakes without fear."},
]

# ---------------------------------------------------------------------------
# False positives / false negatives
# ---------------------------------------------------------------------------
FALSE_POSITIVE_NEGATIVE: Dict[str, Any] = {
    "false_positive": {
        "definition": "A legitimate email that the system classifies as phishing.",
        "example_sender": "hr@example.org",
        "example_subject": "Urgent: Submit your documents today",
        "example_body": ("Dear Team,\n\nThis is an urgent reminder to submit your compliance "
                         "documents today. The deadline cannot be extended.\n\nHR Department"),
        "why_it_happens": ("The urgency rule fires on 'Urgent' and 'today'. The email is "
                           "genuine, but the language it uses overlaps exactly with the "
                           "language phishing uses."),
        "cost": ("Alert fatigue. If the tool cries wolf, analysts start to ignore it and users "
                 "stop reporting - which makes the organisation LESS safe than having no tool."),
        "mitigation": ("Require multiple independent categories before escalating; weight "
                       "structural signals (raw-IP URL, executable attachment) above language; "
                       "calibrate thresholds on validation data; keep a human in the loop."),
    },
    "false_negative": {
        "definition": "A phishing email that the system classifies as legitimate.",
        "example_sender": "accounts@supplier-portal.invalid.test",
        "example_subject": "Invoice 4821 - updated remittance details",
        "example_body": ("Good morning Anita,\n\nPlease find our revised remittance details for "
                         "invoice 4821, effective this quarter. Kindly update your records "
                         "before the next payment run.\n\nRegards,\nAccounts Receivable"),
        "why_it_happens": ("No urgency, no threat, no credential request, no link, no "
                           "attachment, correct grammar and a personalised greeting. There is "
                           "almost nothing for a content-based detector to catch - the attack "
                           "is entirely in the CONTEXT (a bank-detail change)."),
        "cost": ("Direct loss. A missed business-email-compromise message can cost more than "
                 "every other category combined."),
        "mitigation": ("Signals the content analyzer cannot see: authentication results "
                       "(SPF/DKIM/DMARC), first-time-sender detection, reply-to mismatch, "
                       "domain age, and a payment process that verifies bank-detail changes by "
                       "phone. Technology plus process, not technology alone."),
    },
    "why_multiple_signals": (
        "Every individual indicator has a legitimate use. Urgency appears in genuine deadlines; "
        "links appear in every newsletter; attachments appear in every invoice. A single "
        "indicator is therefore evidence, never proof. Combining independent signal families - "
        "sender structure, language, URL structure and attachment type - is what separates a "
        "usable detector from a noise generator. It is also why this project shows WHY it "
        "scored an email the way it did: an analyst can overrule a wrong score in seconds when "
        "the reasoning is visible, and cannot do so at all when it is hidden."
    ),
}

# ---------------------------------------------------------------------------
# SOC analyst workflow
# ---------------------------------------------------------------------------
SOC_WORKFLOW: List[Dict[str, str]] = [
    {"stage": "1. Email reported",
     "detail": "A user reports a suspicious message, or a gateway quarantines it. The original "
               "message is preserved with full headers.",
     "tool_support": "Paste the sender, subject and body into the analyzer, or upload the "
                     ".eml sample."},
    {"stage": "2. Initial triage",
     "detail": "Is this a one-off or part of a campaign? How many recipients? Did anyone click?",
     "tool_support": "The dashboard shows the detection trend and the top sender domains."},
    {"stage": "3. Sender analysis",
     "detail": "Inspect the envelope and header addresses, display name, domain structure and "
               "authentication results.",
     "tool_support": "The sender analyzer scores domain structure, subdomain depth, look-alike "
                     "shape and display-name mismatch."},
    {"stage": "4. URL analysis",
     "detail": "Extract every URL and examine it without visiting it. Detonate only in an "
               "approved sandbox, never from a workstation.",
     "tool_support": "Static URL analysis with a defanged representation for the ticket."},
    {"stage": "5. Attachment metadata analysis",
     "detail": "Record filenames, extensions and hashes. Submit hashes to reputation services; "
               "detonate only in a sandbox.",
     "tool_support": "Filename and extension analysis, including the double-extension check. "
                     "This project never opens the file."},
    {"stage": "6. Content analysis",
     "detail": "Identify the social-engineering pretext: what is the message trying to make the "
               "recipient do?",
     "tool_support": "Category detection for urgency, fear, financial pressure, credential "
                     "requests, reward bait and personal-data requests."},
    {"stage": "7. Risk score",
     "detail": "Combine the signals into a single triage number so the queue can be ordered.",
     "tool_support": "0-100 rule score with the contribution of every rule shown."},
    {"stage": "8. Analyst review",
     "detail": "THE HUMAN STEP. The analyst applies context the tool does not have: is this "
               "supplier real, was this invoice expected, is this the CEO's normal style?",
     "tool_support": "Explainable findings let the analyst confirm or overrule the score in "
                     "seconds instead of re-reading the whole message."},
    {"stage": "9. Classification",
     "detail": "Benign / spam / phishing / BEC / malware delivery - recorded for metrics and "
               "for the next similar case.",
     "tool_support": "Stored classification plus indicators, searchable in the history view."},
    {"stage": "10. Recommended response",
     "detail": "Block sender and domain, purge from mailboxes, reset exposed credentials, add "
               "detections, notify affected users, feed indicators to the SIEM.",
     "tool_support": "Prioritised recommended actions per analysis."},
]

SOC_WORKFLOW_NOTE = (
    "Automated scoring SUPPORTS analyst judgement; it does not replace it. The tool is fast and "
    "consistent but has no context: it cannot know whether your organisation really does use "
    "that supplier, or whether the CEO really is travelling this week. The analyst has that "
    "context and cannot read a thousand emails a day. Each is strongest where the other is "
    "weakest, which is exactly why the score is presented with its reasoning attached."
)

# ---------------------------------------------------------------------------
# MITRE ATT&CK mapping (conceptual)
# ---------------------------------------------------------------------------
MITRE_MAPPING: Dict[str, Any] = {
    "framework": "MITRE ATT&CK for Enterprise",
    "reference": "https://attack.mitre.org/",
    "disclaimer": (
        "This is a CONCEPTUAL mapping for documentation purposes. Technique identifiers change "
        "between ATT&CK versions - always confirm the current ID and name at attack.mitre.org "
        "before quoting them in a report. No identifier here has been invented; anything the "
        "author was not certain of has been described in words instead of given an ID."
    ),
    "techniques": [
        {
            "id": "T1566",
            "name": "Phishing",
            "tactic": "Initial Access",
            "relevance": "The parent technique for the whole project. The dashboard analyses "
                         "messages that attempt initial access through email.",
            "project_coverage": "Rule engine, ML model and risk score operate at this level.",
        },
        {
            "id": "T1566.001",
            "name": "Spearphishing Attachment",
            "tactic": "Initial Access",
            "relevance": "A targeted email carrying a malicious file.",
            "project_coverage": "Attachment analyzer: executable and script extensions, "
                                "macro-enabled Office formats, suspicious archives, double "
                                "extensions and right-to-left override tricks - all from the "
                                "filename only, never by opening the file.",
        },
        {
            "id": "T1566.002",
            "name": "Spearphishing Link",
            "tactic": "Initial Access",
            "relevance": "A targeted email carrying a link to a credential-harvesting or "
                         "malware-delivery page.",
            "project_coverage": "Static URL analyzer: raw IP hosts, dangerous schemes, "
                                "shorteners, deceptive subdomain structure, '@' obfuscation, "
                                "Punycode, keyword lures and displayed-vs-destination mismatch.",
        },
        {
            "id": "T1566.003",
            "name": "Spearphishing via Service",
            "tactic": "Initial Access",
            "relevance": "Delivery through a third-party service (social media, messaging, "
                         "collaboration platforms) rather than corporate email.",
            "project_coverage": "Partially in scope. The analyzers work on any pasted text, so "
                                "a message body from another service can be assessed - but this "
                                "project has no connector for those platforms, and the awareness "
                                "module covers the concept explicitly.",
        },
        {
            "id": "T1598",
            "name": "Phishing for Information",
            "tactic": "Reconnaissance",
            "relevance": "Messages that harvest information rather than deliver a payload.",
            "project_coverage": "Content analyzer detects personal-information and credential "
                                "requests, which is exactly this behaviour.",
        },
        {
            "id": "T1204.001",
            "name": "User Execution: Malicious Link",
            "tactic": "Execution",
            "relevance": "The attack only succeeds when the user clicks.",
            "project_coverage": "Recommendations and the awareness module target this step - "
                                "the last point at which the chain can be broken by a person.",
        },
        {
            "id": "T1204.002",
            "name": "User Execution: Malicious File",
            "tactic": "Execution",
            "relevance": "The attack only succeeds when the user opens the file.",
            "project_coverage": "Attachment findings plus explicit 'do not open' guidance.",
        },
        {
            "id": "T1534",
            "name": "Internal Spearphishing",
            "tactic": "Lateral Movement",
            "relevance": "After a mailbox is compromised, phishing continues from a genuine "
                         "internal account - where sender checks no longer help.",
            "project_coverage": "Discussed in the awareness module as the reason content and "
                                "context analysis still matter when the sender is legitimate.",
        },
        {
            "id": "T1656",
            "name": "Impersonation",
            "tactic": "Defense Evasion",
            "relevance": "Pretending to be a trusted person or brand, including display-name "
                         "spoofing and look-alike domains.",
            "project_coverage": "Sender analyzer: display-name mismatch and look-alike domain "
                                "shape detection.",
        },
    ],
    "mitigations": [
        {"id": "M1017", "name": "User Training",
         "project_coverage": "The entire awareness module: 10 checks, the Before-You-Click "
                             "checklist, six micro-lessons and three safe training templates."},
        {"id": "M1054", "name": "Software Configuration",
         "project_coverage": "Documented recommendations: enforce SPF/DKIM/DMARC, show file "
                             "extensions in Windows, disable Office macros from the internet."},
        {"id": "M1021", "name": "Restrict Web-Based Content",
         "project_coverage": "Discussed as a future improvement (URL reputation and rewriting "
                             "at the gateway)."},
    ],
    "why_mapping_matters": (
        "Mapping detections to a shared framework turns a local tool into something a security "
        "team can reason about. It shows which techniques you cover and - more usefully - which "
        "you do not, lets detection gaps be tracked over time, and gives analysts, engineers and "
        "management a common vocabulary in reports and post-incident reviews."
    ),
}


def get_all_content() -> Dict[str, Any]:
    """Return the entire awareness bundle (served by GET /api/awareness)."""
    return {
        "how_to_spot": HOW_TO_SPOT,
        "before_you_click": BEFORE_YOU_CLICK,
        "micro_lessons": MICRO_LESSONS,
        "simulation_templates": SIMULATION_TEMPLATES,
        "simulation_safety_note": SIMULATION_SAFETY_NOTE,
        "playbook": PLAYBOOK,
        "false_positive_negative": FALSE_POSITIVE_NEGATIVE,
        "soc_workflow": SOC_WORKFLOW,
        "soc_workflow_note": SOC_WORKFLOW_NOTE,
        "mitre_mapping": MITRE_MAPPING,
    }
