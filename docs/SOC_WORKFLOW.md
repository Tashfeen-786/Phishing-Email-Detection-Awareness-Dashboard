# SOC Workflow

How this tool fits the path a reported phishing email actually takes through a
security operations centre. The tool is a **decision aid at stages 2–4**; every
other stage needs a human.

---

| # | Stage | What happens | How this project helps |
|---|---|---|---|
| 1 | **1. Email reported** | A user reports a suspicious message, or a gateway quarantines it. The original message is preserved with full headers. | Paste the sender, subject and body into the analyzer, or upload the .eml sample. |
| 2 | **2. Initial triage** | Is this a one-off or part of a campaign? How many recipients? Did anyone click? | The dashboard shows the detection trend and the top sender domains. |
| 3 | **3. Sender analysis** | Inspect the envelope and header addresses, display name, domain structure and authentication results. | The sender analyzer scores domain structure, subdomain depth, look-alike shape and display-name mismatch. |
| 4 | **4. URL analysis** | Extract every URL and examine it without visiting it. Detonate only in an approved sandbox, never from a workstation. | Static URL analysis with a defanged representation for the ticket. |
| 5 | **5. Attachment metadata analysis** | Record filenames, extensions and hashes. Submit hashes to reputation services; detonate only in a sandbox. | Filename and extension analysis, including the double-extension check. This project never opens the file. |
| 6 | **6. Content analysis** | Identify the social-engineering pretext: what is the message trying to make the recipient do? | Category detection for urgency, fear, financial pressure, credential requests, reward bait and personal-data requests. |
| 7 | **7. Risk score** | Combine the signals into a single triage number so the queue can be ordered. | 0-100 rule score with the contribution of every rule shown. |
| 8 | **8. Analyst review** | THE HUMAN STEP. The analyst applies context the tool does not have: is this supplier real, was this invoice expected, is this the CEO's normal style? | Explainable findings let the analyst confirm or overrule the score in seconds instead of re-reading the whole message. |
| 9 | **9. Classification** | Benign / spam / phishing / BEC / malware delivery - recorded for metrics and for the next similar case. | Stored classification plus indicators, searchable in the history view. |
| 10 | **10. Recommended response** | Block sender and domain, purge from mailboxes, reset exposed credentials, add detections, notify affected users, feed indicators to the SIEM. | Prioritised recommended actions per analysis. |

---

## The limit of automation

> Every individual indicator has a legitimate use. Urgency appears in genuine deadlines; links appear in every newsletter; attachments appear in every invoice. A single indicator is therefore evidence, never proof. Combining independent signal families — sender structure, language, URL structure and attachment type — is what separates a usable detector from a noise generator. It is also why this project shows WHY it scored an email the way it did: an analyst can overrule a wrong score in seconds when the reasoning is visible, and cannot do so at all when it is hidden.

---

## Incident playbook — "I think I clicked"

Speed matters far more than blame. Reporting early is what limits the damage.

1. Stop. Do not click, do not reply, do not open attachments, do not forward it to colleagues 'to check'.
2. Report. Use your mail client's 'Report phishing' button, or forward the message AS AN ATTACHMENT to your security team so the original headers survive.
3. Block / delete. Follow your organisation's guidance. Deleting before reporting destroys the evidence the SOC needs, so report first.
4. Reset if exposed. If you entered a password anywhere: change it immediately from a device you trust, and change it anywhere else you reused it.
5. Check MFA and sessions. Review active sessions, sign out everywhere, and confirm no new MFA method or mailbox forwarding rule was added.
6. Escalate. If money moved or credentials were entered, this is an incident. Escalate immediately - early reporting is what limits the damage.
7. Learn. Share the pattern (not blame) with the team. Awareness improves when people can report mistakes without fear.

---

*Generated from `backend/services/awareness_content.py`.*