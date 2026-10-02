"""
backend/services/attachment_analyzer.py
=======================================
PURPOSE
-------
Assess the RISK OF AN ATTACHMENT **from its filename only**.

>>> SAFETY GUARANTEE <<<
This module receives a *string*. It does not receive file bytes, does not write
files, does not open files, does not unpack archives and, above all, does NEVER
EXECUTE ANYTHING. There is no ``subprocess``, ``os.system``, ``zipfile`` or
``exec`` anywhere in this project's analysis path. Static metadata inspection is
the only safe way to reason about an attachment inside a student project.

WHAT IS DETECTED
----------------
* executable extensions  .exe .scr .bat .cmd .com .pif .msi .jar .hta .lnk .reg
* script extensions      .js .vbs .ps1 .wsf .jse .vbe .psm1 .sh
* double extensions      invoice.pdf.exe  (the decoy ".pdf" hides ".exe")
* macro-enabled Office   .docm .xlsm .pptm
* suspicious archives    .zip .rar .7z .iso .img  (containers for the above)
* right-to-left override U+202E used to render "x.exe" as "x.txt"
* no extension / very long names / spoofed spacing
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List

from backend.utils.keywords import (
    ARCHIVE_EXTENSIONS,
    COMMON_SAFE_EXTENSIONS,
    DOUBLE_EXTENSION_DECOYS,
    EXECUTABLE_EXTENSIONS,
    MACRO_OFFICE_EXTENSIONS,
    SCRIPT_EXTENSIONS,
)
from backend.utils.text_utils import sanitize_text

# --------------------------------------------------------------------------
# Weights (project assumptions - see docs/RISK_SCORING.md)
# --------------------------------------------------------------------------
W_DOUBLE_EXTENSION = 85
W_EXECUTABLE = 70
W_SCRIPT = 65
W_MACRO_OFFICE = 50
W_ARCHIVE = 30
W_RTL_OVERRIDE = 90
W_NO_EXTENSION = 20
W_LONG_NAME = 10
W_MANY_SPACES = 15
W_LURE_NAME = 10

#: An attachment is treated as "suspicious" by the rule engine at or above this.
ATTACHMENT_SUSPICIOUS_THRESHOLD = 40

#: Lure words commonly used in malicious attachment names.
_LURE_WORDS = [
    "invoice", "payment", "receipt", "statement", "salary", "payslip",
    "resume", "cv", "order", "shipment", "delivery", "refund", "bonus",
    "urgent", "confidential", "scan", "doc", "report", "contract", "purchase",
]

#: U+202E RIGHT-TO-LEFT OVERRIDE and friends.
_RTL_CHARS = ["\u202e", "\u202b", "\u202d", "\u2066", "\u2067"]


def _finding(indicator_type: str, description: str, severity: str,
             evidence: str = "", weight: int = 0) -> Dict[str, Any]:
    return {
        "category": "ATTACHMENT",
        "indicator_type": indicator_type,
        "description": description,
        "severity": severity,
        "evidence": sanitize_text(evidence, 200),
        "weight": weight,
    }


def get_extension(filename: str) -> str:
    """Return the final extension (lower-cased, with dot) or ''."""
    return os.path.splitext(sanitize_text(filename, 255).strip())[1].lower()


def get_all_extensions(filename: str) -> List[str]:
    """Return every dotted suffix that looks like an extension.

    ``invoice.pdf.exe`` -> ``['.pdf', '.exe']``
    ``report.2024.xlsx`` -> ``['.xlsx']``  (a numeric chunk is not an extension)
    """
    name = sanitize_text(filename, 255).strip()
    parts = name.split(".")
    if len(parts) < 2:
        return []
    exts: List[str] = []
    for chunk in parts[1:]:
        candidate = "." + chunk.lower()
        if re.fullmatch(r"\.[a-z]{1,6}[0-9]{0,2}", candidate) and not chunk.isdigit():
            exts.append(candidate)
    return exts


def analyze_attachment(filename: str | None) -> Dict[str, Any]:
    """Analyse ONE attachment filename. Returns risk score + explainable findings.

    Parameters
    ----------
    filename : str | None
        The attachment's name, e.g. ``"invoice.pdf.exe"``. May be ``None``/empty.

    Returns
    -------
    dict with ``attachment_risk`` (0-100), ``attachment_findings`` (list),
    ``extension``, ``all_extensions``, ``has_double_extension``, ``suspicious``.
    """
    raw = "" if filename is None else str(filename)
    name = sanitize_text(raw, 255).strip()
    findings: List[Dict[str, Any]] = []
    score = 0

    if not name:
        return {
            "filename": "", "attachment_risk": 0,
            "attachment_findings": [_finding(
                "NO_ATTACHMENT",
                "No attachment was supplied with this email.", "INFO")],
            "extension": "", "all_extensions": [], "has_double_extension": False,
            "is_executable": False, "is_script": False, "is_archive": False,
            "is_macro_office": False, "suspicious": False,
            "threshold": ATTACHMENT_SUSPICIOUS_THRESHOLD,
            "summary": "No attachment supplied.",
        }

    # The RTL check must use the RAW value: sanitize_text strips the character.
    if any(ch in raw for ch in _RTL_CHARS):
        score += W_RTL_OVERRIDE
        findings.append(_finding(
            "RTL_OVERRIDE_IN_FILENAME",
            "The filename contains a Unicode right-to-left override character. This is used "
            "to reverse the way the name is displayed so that 'report\\u202Excod.exe' appears "
            "on screen as 'reportexe.docx'. There is no legitimate reason for this in an "
            "email attachment.",
            "HIGH", repr(raw)[:120], W_RTL_OVERRIDE,
        ))

    ext = get_extension(name)
    all_exts = get_all_extensions(name)

    # ------------------------------------------------------ double extension
    has_double = False
    if len(all_exts) >= 2 and all_exts[-2] in DOUBLE_EXTENSION_DECOYS:
        dangerous_last = all_exts[-1] in (EXECUTABLE_EXTENSIONS + SCRIPT_EXTENSIONS)
        has_double = True
        weight = W_DOUBLE_EXTENSION if dangerous_last else 35
        score += weight
        findings.append(_finding(
            "DOUBLE_EXTENSION",
            f"The filename uses a double extension ('{all_exts[-2]}' followed by "
            f"'{all_exts[-1]}'). Windows hides known extensions by default, so the recipient "
            f"may only see '{name.rsplit(all_exts[-1], 1)[0].rstrip('.')}' and believe the file "
            f"is a {all_exts[-2].lstrip('.').upper()} document. The operating system will "
            f"actually treat it as a {all_exts[-1].lstrip('.').upper()} file.",
            "HIGH", name, weight,
        ))

    # ----------------------------------------------------------- executables
    is_executable = ext in EXECUTABLE_EXTENSIONS
    is_script = ext in SCRIPT_EXTENSIONS
    is_archive = ext in ARCHIVE_EXTENSIONS
    is_macro = ext in MACRO_OFFICE_EXTENSIONS

    if is_executable and not has_double:
        score += W_EXECUTABLE
        findings.append(_finding(
            "EXECUTABLE_ATTACHMENT",
            f"'{ext}' is a directly executable file type. Opening it runs code on the "
            "machine with the user's privileges. Normal business correspondence does not "
            "require executable attachments. This file must never be opened - it should be "
            "reported to the security team.",
            "HIGH", name, W_EXECUTABLE,
        ))
    elif is_executable and has_double:
        findings.append(_finding(
            "EXECUTABLE_ATTACHMENT",
            f"The real file type is '{ext}', which is directly executable.",
            "HIGH", name, 0,
        ))

    if is_script:
        add = W_SCRIPT if not has_double else 0
        score += add
        findings.append(_finding(
            "SCRIPT_ATTACHMENT",
            f"'{ext}' is a script file. Windows Script Host, PowerShell or Node will execute "
            "it. Script attachments are a standard malware-delivery method (they are small, "
            "text-based and easy to obfuscate).",
            "HIGH", name, add,
        ))

    if is_macro:
        score += W_MACRO_OFFICE
        findings.append(_finding(
            "MACRO_ENABLED_DOCUMENT",
            f"'{ext}' is a macro-enabled Office document. Macros are program code embedded "
            "in the document. Never click 'Enable Content' on a file that arrived "
            "unexpectedly.",
            "HIGH", name, W_MACRO_OFFICE,
        ))

    if is_archive:
        score += W_ARCHIVE
        findings.append(_finding(
            "SUSPICIOUS_ARCHIVE",
            f"'{ext}' is an archive. Archives are not malicious in themselves, but they are "
            "the standard container used to smuggle an executable past filters that only "
            "look at the outer extension - and password-protected archives also defeat "
            "antivirus scanning at the gateway.",
            "MEDIUM", name, W_ARCHIVE,
        ))

    # ------------------------------------------------------- no extension
    if not ext:
        score += W_NO_EXTENSION
        findings.append(_finding(
            "NO_FILE_EXTENSION",
            "The attachment has no file extension, so its true type cannot be judged from "
            "the name. Treat it as unknown and unverified.",
            "MEDIUM", name, W_NO_EXTENSION,
        ))

    # ----------------------------------------------------- cosmetic tricks
    if len(name) > 80:
        score += W_LONG_NAME
        findings.append(_finding(
            "OVERLONG_FILENAME",
            f"The filename is {len(name)} characters long. Very long names push the real "
            "extension out of the visible area in many mail clients.",
            "LOW", name[:80], W_LONG_NAME,
        ))
    if re.search(r"\s{4,}", raw) or re.search(r"\.\s+[a-z]{2,4}$", raw, re.IGNORECASE):
        score += W_MANY_SPACES
        findings.append(_finding(
            "PADDED_FILENAME",
            "The filename contains a long run of spaces before the extension. This padding "
            "is used to hide the real extension behind the edge of the window.",
            "MEDIUM", repr(raw)[:120], W_MANY_SPACES,
        ))

    # -------------------------------------------------------- lure wording
    stem = os.path.splitext(name)[0].lower()
    lures = [w for w in _LURE_WORDS if re.search(rf"(?<![a-z]){w}(?![a-z])", stem)]
    if lures and (is_executable or is_script or is_archive or is_macro or has_double):
        score += W_LURE_NAME
        findings.append(_finding(
            "LURE_FILENAME",
            f"The filename uses business-lure wording ({', '.join(lures[:3])}) combined with "
            "a risky file type. The wording exists purely to make opening the file feel "
            "routine.",
            "MEDIUM", name, W_LURE_NAME,
        ))

    # ---------------------------------------------------- ordinary documents
    if ext in COMMON_SAFE_EXTENSIONS and not has_double and not is_archive:
        findings.append(_finding(
            "COMMON_DOCUMENT_TYPE",
            f"'{ext}' is a common document type and carries no direct execution risk from "
            "its extension alone. Still verify that you were expecting the file - document "
            "formats can contain embedded links and, in some cases, active content.",
            "INFO", name, 0,
        ))

    if not findings:
        findings.append(_finding(
            "UNRECOGNISED_EXTENSION",
            f"'{ext}' is not in the project's known-safe or known-risky lists. Verify the "
            "file type with the sender through a trusted channel before opening.",
            "LOW", name, 0,
        ))

    score = max(0, min(100, score))
    suspicious = score >= ATTACHMENT_SUSPICIOUS_THRESHOLD

    if suspicious:
        summary = (f"Attachment risk {score}/100 - '{name}' shows high-risk characteristics. "
                   "Do not open it.")
    elif score > 0:
        summary = f"Attachment risk {score}/100 - '{name}' warrants caution."
    else:
        summary = f"Attachment risk {score}/100 - '{name}' shows no risky filename characteristics."

    return {
        "filename": name,
        "attachment_risk": score,
        "attachment_findings": findings,
        "extension": ext,
        "all_extensions": all_exts,
        "has_double_extension": has_double,
        "is_executable": is_executable,
        "is_script": is_script,
        "is_archive": is_archive,
        "is_macro_office": is_macro,
        "suspicious": suspicious,
        "threshold": ATTACHMENT_SUSPICIOUS_THRESHOLD,
        "summary": summary,
    }


def analyze_attachments(filenames: List[str] | None) -> Dict[str, Any]:
    """Analyse several attachment names and aggregate the worst case."""
    names = [n for n in (filenames or []) if str(n).strip()]
    if not names:
        single = analyze_attachment(None)
        return {
            "attachment_reports": [], "attachment_count": 0, "attachment_risk": 0,
            "attachment_findings": single["attachment_findings"],
            "suspicious": False, "summary": single["summary"],
        }
    reports = [analyze_attachment(n) for n in names]
    worst = max(r["attachment_risk"] for r in reports)
    findings: List[Dict[str, Any]] = []
    for r in reports:
        findings.extend(r["attachment_findings"])
    return {
        "attachment_reports": reports,
        "attachment_count": len(reports),
        "attachment_risk": worst,
        "attachment_findings": findings,
        "suspicious": worst >= ATTACHMENT_SUSPICIOUS_THRESHOLD,
        "summary": (f"{len(reports)} attachment name(s) inspected statically; highest risk "
                    f"{worst}/100. No attachment was opened or executed."),
    }
