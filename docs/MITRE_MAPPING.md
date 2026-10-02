# MITRE ATT&CK Mapping

**Framework:** MITRE ATT&CK for Enterprise  
**Reference:** https://attack.mitre.org/

> ## ⚠️ Verify before you cite
>
> This is a CONCEPTUAL mapping for documentation purposes. Technique identifiers change between ATT&CK versions — always confirm the current ID and name at attack.mitre.org before quoting them in a report. No identifier here has been invented; anything the author was not certain of has been described in words instead of given an ID.

---

## Techniques

| ID | Technique | Tactic | Why it applies | How this project covers it |
|---|---|---|---|---|
| `T1566` | Phishing | Initial Access | The parent technique for the whole project. The dashboard analyses messages that attempt initial access through email. | Rule engine, ML model and risk score operate at this level. |
| `T1566.001` | Spearphishing Attachment | Initial Access | A targeted email carrying a malicious file. | Attachment analyzer: executable and script extensions, macro-enabled Office formats, suspicious archives, double extensions and right-to-left override tricks - all from the filename only, never by opening the file. |
| `T1566.002` | Spearphishing Link | Initial Access | A targeted email carrying a link to a credential-harvesting or malware-delivery page. | Static URL analyzer: raw IP hosts, dangerous schemes, shorteners, deceptive subdomain structure, '@' obfuscation, Punycode, keyword lures and displayed-vs-destination mismatch. |
| `T1566.003` | Spearphishing via Service | Initial Access | Delivery through a third-party service (social media, messaging, collaboration platforms) rather than corporate email. | Partially in scope. The analyzers work on any pasted text, so a message body from another service can be assessed - but this project has no connector for those platforms, and the awareness module covers the concept explicitly. |
| `T1598` | Phishing for Information | Reconnaissance | Messages that harvest information rather than deliver a payload. | Content analyzer detects personal-information and credential requests, which is exactly this behaviour. |
| `T1204.001` | User Execution: Malicious Link | Execution | The attack only succeeds when the user clicks. | Recommendations and the awareness module target this step - the last point at which the chain can be broken by a person. |
| `T1204.002` | User Execution: Malicious File | Execution | The attack only succeeds when the user opens the file. | Attachment findings plus explicit 'do not open' guidance. |
| `T1534` | Internal Spearphishing | Lateral Movement | After a mailbox is compromised, phishing continues from a genuine internal account - where sender checks no longer help. | Discussed in the awareness module as the reason content and context analysis still matter when the sender is legitimate. |
| `T1656` | Impersonation | Defense Evasion | Pretending to be a trusted person or brand, including display-name spoofing and look-alike domains. | Sender analyzer: display-name mismatch and look-alike domain shape detection. |

---

## Mitigations

| ID | Mitigation | How this project covers it |
|---|---|---|
| `M1017` | User Training | The entire awareness module: 10 checks, the Before-You-Click checklist, six micro-lessons and three safe training templates. |
| `M1054` | Software Configuration | Documented recommendations: enforce SPF/DKIM/DMARC, show file extensions in Windows, disable Office macros from the internet. |
| `M1021` | Restrict Web-Based Content | Discussed as a future improvement (URL reputation and rewriting at the gateway). |

---

## Why map at all?

Mapping detections to a shared framework turns a local tool into something a security team can reason about. It shows which techniques you cover and - more usefully - which you do not, lets detection gaps be tracked over time, and gives analysts, engineers and management a common vocabulary in reports and post-incident reviews.

---

## What this project does NOT cover

Being explicit about gaps is the point of a mapping. This project does **not**
address:

- **T1566.004 (Spearphishing Voice)** and SMS-based phishing — out of scope; the
  tool analyses email text.
- **Post-compromise techniques** — credential use, persistence, lateral movement.
  Detection stops at the message.
- **Header-based spoofing detection** — SPF, DKIM and DMARC results are not
  parsed, so a message that fails authentication but reads well will pass. This
  is the single largest gap and is the top item in
  [`FUTURE_IMPROVEMENTS.md`](FUTURE_IMPROVEMENTS.md).
- **Malicious payload analysis** — attachments are judged by filename only. The
  file is never opened, by design.

A mapping that only lists what you cover is marketing. The gaps are the part a
security team actually needs.

---

*Generated from `backend/services/awareness_content.py`, which is the single source of truth shared by the API, the dashboard and this document.*