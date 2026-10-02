"""
backend/services/sender_analyzer.py
===================================
PURPOSE
-------
Analyse the *sender* of an email and produce:

    {
      "sender_risk_score": 0-100,
      "sender_findings": [ {...}, ... ],
      ...parsed metadata...
    }

WHAT IT LOOKS AT
----------------
1. Email format validity                    - malformed senders are a red flag
2. Registrable domain & TLD                 - structural context
3. Domain length                            - very long domains hide intent
4. Subdomain count                          - login.secure.account.invalid.test
5. Unusual characters                       - non-ASCII / punycode / homoglyphs
6. Display-name vs address mismatch         - "IT Helpdesk <x@random.invalid.test>"
7. Look-alike shapes                        - examp1e, exarnple, long hyphen chains
8. Security-verb tokens inside the domain   - secure-account-verify.invalid.test
9. Free-mail style local parts for "official" senders

WHAT IT DELIBERATELY DOES **NOT** DO
------------------------------------
* It does not perform DNS, WHOIS or reputation lookups (no network access at
  analysis time - the project is offline and safe by design).
* It does **not** label an unfamiliar domain as malicious. An unknown domain
  contributes little or nothing; only *structural* anomalies add risk.
* It never claims certainty. The score is a triage aid.

SCORING
-------
Each check contributes points, the total is capped at 100. The weights are
PROJECT ASSUMPTIONS documented in docs/RISK_SCORING.md and should be calibrated
against validation data before production use.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from backend.utils.keywords import (
    LOOKALIKE_MAX_DISTANCE,
    LOOKALIKE_REFERENCE_LABELS,
    LOOKALIKE_REGEXES,
    SENDER_DOMAIN_SUSPICIOUS_TOKENS,
    SENDER_LOCALPART_SUSPICIOUS_TOKENS,
)
from backend.utils.text_utils import (
    parse_sender,
    registrable_parts,
    sanitize_text,
)
from backend.utils.validators import validate_email_address

# --------------------------------------------------------------------------
# Weights (project assumptions - see docs/RISK_SCORING.md)
# --------------------------------------------------------------------------
W_INVALID_FORMAT = 30
W_SUSPICIOUS_DOMAIN_TOKEN = 25
W_EXTRA_DOMAIN_TOKEN = 8
W_ACTION_COMPOUND_LABEL = 15
W_EXCESSIVE_SUBDOMAINS = 18
W_LONG_DOMAIN = 10
W_HYPHEN_HEAVY = 10
W_DIGITS_IN_DOMAIN = 8
W_UNUSUAL_CHARACTERS = 25
W_PUNYCODE = 25
W_DISPLAY_NAME_MISMATCH = 20
W_LOOKALIKE_SHAPE = 30
W_LOCALPART_TOKEN = 10
W_NUMERIC_LOCALPART = 8
W_IP_DOMAIN = 30

#: A sender is treated as "suspicious" by the rule engine at or above this score.
SENDER_SUSPICIOUS_THRESHOLD = 30

#: Domains reserved for documentation/testing (RFC 2606 / RFC 6761). Using them
#: is *expected* in this project, so they are NOT penalised on their own.
RESERVED_SAFE_DOMAINS = {"example.com", "example.org", "example.net", "example.edu",
                         "invalid.test", "test", "invalid", "localhost", "example"}

#: Organisation-sounding words that should not appear in a free-mail display name.
_ORG_WORDS = [
    "bank", "support", "helpdesk", "help desk", "security", "it team", "it-team",
    "administrator", "admin", "payroll", "hr", "human resources", "finance",
    "accounts", "billing", "service desk", "team", "department", "office",
    "university", "college", "ceo", "director", "manager",
]

_NON_ASCII = re.compile(r"[^\x00-\x7F]")
_ALLOWED_DOMAIN_CHARS = re.compile(r"^[a-z0-9.\-]+$")
_ALLOWED_LOCAL_CHARS = re.compile(r"^[A-Za-z0-9._%+\-]+$")


def _edit_distance(a: str, b: str, max_distance: int = 2) -> int:
    """Levenshtein distance with early exit once ``max_distance`` is exceeded.

    Used for look-alike domain detection: a label that is 1-2 edits away from a
    label the organisation expects ("examp1e" vs "example") is a classic
    impersonation, while a label that is far away is simply a different word.

    Returns ``max_distance + 1`` when the true distance is larger (the caller
    only needs to know "close or not").
    """
    if abs(len(a) - len(b)) > max_distance:
        return max_distance + 1
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            current.append(min(previous[j] + 1, current[j - 1] + 1,
                               previous[j - 1] + (ca != cb)))
        if min(current) > max_distance:
            return max_distance + 1
        previous = current
    return previous[-1]


def _finding(indicator_type: str, description: str, severity: str,
             evidence: str = "", weight: int = 0) -> Dict[str, Any]:
    """Build one explainable finding record."""
    return {
        "category": "SENDER",
        "indicator_type": indicator_type,
        "description": description,
        "severity": severity,          # INFO | LOW | MEDIUM | HIGH
        "evidence": sanitize_text(evidence, 200),
        "weight": weight,
    }


def analyze_sender(sender: str, display_name: str | None = None) -> Dict[str, Any]:
    """Analyse a sender address and return a risk score plus explainable findings.

    Parameters
    ----------
    sender:
        Either ``user@example.org`` or ``Display Name <user@example.org>``.
    display_name:
        Optional display name supplied separately by the UI. When both are
        present the explicit parameter wins.

    Returns
    -------
    dict with keys:
        ``sender_risk_score`` (int 0-100), ``sender_findings`` (list of dicts),
        ``address``, ``local_part``, ``domain``, ``registrable_domain``,
        ``subdomain_count``, ``domain_length``, ``display_name``,
        ``is_valid_format``, ``suspicious`` (bool), ``summary`` (str).
    """
    parsed = parse_sender(sender)
    if display_name:
        parsed["display_name"] = sanitize_text(display_name, 200).strip()

    address = parsed["address"]
    domain = parsed["domain"]
    local = parsed["local_part"]
    findings: List[Dict[str, Any]] = []
    score = 0

    # ---------------------------------------------------------------- 1. format
    is_valid, reason = validate_email_address(sender)
    if not is_valid:
        score += W_INVALID_FORMAT
        findings.append(_finding(
            "INVALID_SENDER_FORMAT",
            f"Sender address is not a valid email format. {reason} "
            "Malformed sender headers are common in spoofed or machine-generated mail.",
            "HIGH", address or str(sender), W_INVALID_FORMAT,
        ))
    else:
        findings.append(_finding(
            "SENDER_FORMAT_OK",
            "Sender address is syntactically valid. Valid syntax does not prove the "
            "sender is genuine - addresses can be spoofed.",
            "INFO", address, 0,
        ))

    parts = registrable_parts(domain)
    registrable = str(parts["registrable"])
    subdomain_count = int(parts["subdomain_count"])
    domain_length = len(domain)

    # ------------------------------------------------- 2. raw IP as the domain
    if domain and re.fullmatch(r"\[?[0-9a-f:.]+\]?", domain) and re.search(r"\d", domain) \
            and (domain.count(".") == 3 or ":" in domain):
        score += W_IP_DOMAIN
        findings.append(_finding(
            "SENDER_IP_DOMAIN",
            "The sender domain is a raw IP address instead of a hostname. "
            "Legitimate organisations send from named domains.",
            "HIGH", domain, W_IP_DOMAIN,
        ))

    # ------------------------------------------- 3. security verbs in the domain
    #
    # NOTE ON RESERVED TLDs
    # ---------------------
    # With reserved suffixes such as ".invalid.test" the simple registrable-domain
    # heuristic classifies "account-check.invalid.test" as subdomain
    # "account-check" + registrable "invalid.test". The meaningful, attacker-chosen
    # label is therefore NOT always the registrable one. To stay correct for both
    # real and reserved suffixes, the token checks below run over EVERY label of
    # the hostname, weighted by position: the registrable label counts most, other
    # labels still count, and a hyphenated label built out of security verbs
    # ("account-check", "secure-login-verify") is scored on its own because that
    # SHAPE is the phishing pattern, wherever it sits in the name.
    _SUFFIX_WORDS = {"com", "org", "net", "edu", "gov", "mil", "int", "co", "ac",
                     "invalid", "test", "example", "localhost", "in", "uk", "io"}
    all_labels: List[str] = list(parts["labels"])  # type: ignore[arg-type]
    meaningful_labels = [lb for lb in all_labels if lb not in _SUFFIX_WORDS]

    if registrable:
        domain_body = registrable.rsplit(".", 1)[0] if "." in registrable else registrable
        sub_text = ".".join(parts["subdomains"])  # type: ignore[arg-type]
        haystack_reg = re.split(r"[.\-_]", domain_body)
        haystack_sub = re.split(r"[.\-_]", sub_text)

        reg_tokens = [t for t in haystack_reg if t in SENDER_DOMAIN_SUSPICIOUS_TOKENS]
        sub_tokens = [t for t in haystack_sub if t in SENDER_DOMAIN_SUSPICIOUS_TOKENS]

        if reg_tokens:
            add = W_SUSPICIOUS_DOMAIN_TOKEN + W_EXTRA_DOMAIN_TOKEN * (len(reg_tokens) - 1)
            score += add
            findings.append(_finding(
                "SUSPICIOUS_SENDER_DOMAIN",
                "The registered part of the sender domain contains security/action words "
                f"({', '.join(sorted(set(reg_tokens)))}). Attackers register domains such as "
                "'secure-account-verify' so the address *looks* official; genuine "
                "organisations normally use their brand name.",
                "HIGH", registrable, add,
            ))
        if sub_tokens and not reg_tokens:
            add = min(24, W_EXTRA_DOMAIN_TOKEN * len(set(sub_tokens)))
            score += add
            findings.append(_finding(
                "SUSPICIOUS_SENDER_SUBDOMAIN",
                "Security/action words appear in the sender subdomain "
                f"({', '.join(sorted(set(sub_tokens)))}). Only the registrable domain "
                "identifies the real owner - subdomains can say anything.",
                "MEDIUM", domain, add,
            ))

        # ---- hyphenated "action compound" label, anywhere in the hostname ----
        for label in meaningful_labels:
            if "-" not in label:
                continue
            tokens = [t for t in re.split(r"[\-_]", label) if t]
            hits = [t for t in tokens if t in SENDER_DOMAIN_SUSPICIOUS_TOKENS]
            if hits and len(hits) * 2 >= len(tokens):
                score += W_ACTION_COMPOUND_LABEL
                findings.append(_finding(
                    "ACTION_COMPOUND_DOMAIN_LABEL",
                    f"The hostname contains the label '{label}', which is built out of "
                    f"security/action words ({', '.join(sorted(set(hits)))}) joined by hyphens. "
                    "Real organisations name domains after themselves; compounds like "
                    "'account-check' or 'secure-login-verify' exist purely to make an address "
                    "read as official.",
                    "HIGH", label, W_ACTION_COMPOUND_LABEL,
                ))
                break

    # ------------------------------------------------- 4. excessive subdomains
    if subdomain_count >= 3:
        score += W_EXCESSIVE_SUBDOMAINS
        findings.append(_finding(
            "EXCESSIVE_SUBDOMAINS",
            f"The sender domain has {subdomain_count} subdomain levels. Deeply nested "
            "hostnames are used to push the real, registrable domain out of sight.",
            "MEDIUM", domain, W_EXCESSIVE_SUBDOMAINS,
        ))
    elif subdomain_count == 2:
        add = W_EXCESSIVE_SUBDOMAINS // 2
        score += add
        findings.append(_finding(
            "MULTIPLE_SUBDOMAINS",
            f"The sender domain has {subdomain_count} subdomain levels, which is more "
            "nesting than a typical corporate sender uses.",
            "LOW", domain, add,
        ))

    # ------------------------------------------------------- 5. domain length
    if domain_length > 30:
        score += W_LONG_DOMAIN
        findings.append(_finding(
            "LONG_SENDER_DOMAIN",
            f"The sender domain is unusually long ({domain_length} characters). Length is "
            "often used to bury a look-alike string inside an address.",
            "LOW", domain, W_LONG_DOMAIN,
        ))

    # ------------------------------------------ 6. hyphens / digits in domain
    if registrable:
        reg_body = registrable.rsplit(".", 1)[0]
        hyphens = reg_body.count("-")
        if hyphens >= 2:
            score += W_HYPHEN_HEAVY
            findings.append(_finding(
                "HYPHEN_HEAVY_DOMAIN",
                f"The registrable domain contains {hyphens} hyphens. Multi-hyphen domains "
                "('secure-login-update') are a recognised phishing pattern.",
                "MEDIUM", registrable, W_HYPHEN_HEAVY,
            ))
        elif hyphens == 1 and any(t in reg_body for t in SENDER_DOMAIN_SUSPICIOUS_TOKENS):
            score += W_HYPHEN_HEAVY // 2
            findings.append(_finding(
                "HYPHENATED_ACTION_DOMAIN",
                "The registrable domain combines a hyphen with a security/action word. "
                "This shape is frequently used to imitate an official portal.",
                "LOW", registrable, W_HYPHEN_HEAVY // 2,
            ))
        # Digit/letter mixing is checked across every meaningful label, so a
        # look-alike hidden in a subdomain ("examp1e.invalid.test") is not missed.
        digit_label = next(
            (lb for lb in meaningful_labels if re.search(r"[a-z][0-9]|[0-9][a-z]", lb)), None
        )
        if digit_label:
            score += W_DIGITS_IN_DOMAIN
            findings.append(_finding(
                "DIGITS_IN_DOMAIN",
                f"Digits are mixed with letters in the domain label '{digit_label}'. "
                "Digit-for-letter substitution (0 for o, 1 for l) is the classic look-alike "
                "technique.",
                "LOW", digit_label, W_DIGITS_IN_DOMAIN,
            ))

    # ------------------------------------------------- 7. unusual characters
    if domain and _NON_ASCII.search(domain):
        score += W_UNUSUAL_CHARACTERS
        findings.append(_finding(
            "UNUSUAL_CHARACTERS_IN_DOMAIN",
            "The sender domain contains non-ASCII characters. Homoglyph characters from "
            "other alphabets can render almost identically to Latin letters.",
            "HIGH", domain, W_UNUSUAL_CHARACTERS,
        ))
    elif domain and not _ALLOWED_DOMAIN_CHARS.fullmatch(domain):
        score += W_UNUSUAL_CHARACTERS // 2
        findings.append(_finding(
            "UNEXPECTED_DOMAIN_CHARACTERS",
            "The sender domain contains characters outside the normal set "
            "(letters, digits, dot, hyphen).",
            "MEDIUM", domain, W_UNUSUAL_CHARACTERS // 2,
        ))

    if domain.startswith("xn--") or ".xn--" in domain:
        score += W_PUNYCODE
        findings.append(_finding(
            "PUNYCODE_DOMAIN",
            "The sender domain uses Punycode ('xn--'), meaning it was written with "
            "international characters. This is legal, but it is also how "
            "internationalised-domain-name spoofing works.",
            "HIGH", domain, W_PUNYCODE,
        ))

    if local and not _ALLOWED_LOCAL_CHARS.fullmatch(local) and local:
        score += W_UNUSUAL_CHARACTERS // 2
        findings.append(_finding(
            "UNUSUAL_CHARACTERS_IN_LOCAL_PART",
            "The part before '@' contains unusual characters.",
            "MEDIUM", local, W_UNUSUAL_CHARACTERS // 2,
        ))

    # ------------------------------------------------- 8. look-alike domains
    # Two complementary checks, both run over EVERY meaningful label so a
    # look-alike hidden in a subdomain ("examp1e.invalid.test") is caught:
    #   (a) generic SHAPE rules - digit inside a word, long hyphen chains;
    #   (b) EDIT-DISTANCE against reference labels the organisation expects.
    #       This is the only way to catch "exarnple" (rn -> m), because without
    #       something to compare with, "rn" is just two ordinary letters.
    if meaningful_labels:
        matched_label = None
        matched_reason = ""
        for label in meaningful_labels:
            if any(re.search(rx, label) for rx in LOOKALIKE_REGEXES):
                matched_label = label
                matched_reason = ("it has a digit substituted inside a word, or is a long "
                                  "hyphen-joined chain")
                break
        if matched_label is None:
            # Hyphenated labels are split so "exarnple-support" is compared as
            # "exarnple" + "support" rather than as one long string.
            candidates: List[str] = []
            for label in meaningful_labels:
                candidates.extend(p for p in re.split(r"[\-_]", label) if p)
            for token in candidates:
                if len(token) < 5 or token in LOOKALIKE_REFERENCE_LABELS:
                    continue
                for reference in LOOKALIKE_REFERENCE_LABELS:
                    distance = _edit_distance(token, reference, LOOKALIKE_MAX_DISTANCE)
                    if 0 < distance <= LOOKALIKE_MAX_DISTANCE:
                        matched_label = token
                        matched_reason = (f"it is only {distance} character edit(s) away from "
                                          f"the expected label '{reference}'")
                        break
                if matched_label:
                    break
        if matched_label:
            score += W_LOOKALIKE_SHAPE
            findings.append(_finding(
                "POSSIBLE_LOOKALIKE_DOMAIN",
                f"The domain label '{matched_label}' looks like an impersonation attempt: "
                f"{matched_reason}. Read the domain character by character and compare it with "
                "the organisation's real address - at reading speed the brain silently corrects "
                "these substitutions.",
                "HIGH", matched_label, W_LOOKALIKE_SHAPE,
            ))

    # ------------------------------------------------------ 9. local part
    if local:
        low_local = local.lower()
        matched_tokens = [t for t in SENDER_LOCALPART_SUSPICIOUS_TOKENS if t in low_local]
        if matched_tokens:
            score += W_LOCALPART_TOKEN
            findings.append(_finding(
                "SUSPICIOUS_LOCAL_PART",
                "The mailbox name before '@' uses alert/verification wording "
                f"({', '.join(sorted(set(matched_tokens))[:3])}), a common way to make a "
                "message look like an automated security notice.",
                "LOW", local, W_LOCALPART_TOKEN,
            ))
        if re.fullmatch(r"[a-z]{0,4}\d{4,}", low_local):
            score += W_NUMERIC_LOCALPART
            findings.append(_finding(
                "MACHINE_GENERATED_LOCAL_PART",
                "The mailbox name looks machine generated (mostly digits), which is typical "
                "of throw-away bulk-mail accounts.",
                "LOW", local, W_NUMERIC_LOCALPART,
            ))

    # --------------------------------------------- 10. display-name mismatch
    dn = (parsed.get("display_name") or "").strip()
    if dn:
        dn_low = dn.lower()
        if "@" in dn and dn_low.split("@")[-1].strip(">").strip() not in {domain, ""}:
            score += W_DISPLAY_NAME_MISMATCH
            findings.append(_finding(
                "DISPLAY_NAME_MISMATCH",
                "The display name itself contains a different email address from the real "
                "sender address. This is a direct impersonation attempt.",
                "HIGH", f"{dn} vs {address}", W_DISPLAY_NAME_MISMATCH,
            ))
        else:
            org_words = [w for w in _ORG_WORDS if w in dn_low]
            dn_tokens = {t for t in re.split(r"[^a-z0-9]+", dn_low) if len(t) > 2}
            domain_tokens = {t for t in re.split(r"[^a-z0-9]+", domain) if len(t) > 2}
            overlap = dn_tokens & domain_tokens
            if org_words and not overlap:
                score += W_DISPLAY_NAME_MISMATCH
                findings.append(_finding(
                    "DISPLAY_NAME_MISMATCH",
                    f"The display name claims an organisational role ('{org_words[0]}') but no "
                    "part of it matches the sending domain. Display names are free text and "
                    "are the easiest field in an email to fake.",
                    "HIGH", f"{dn} vs {domain}", W_DISPLAY_NAME_MISMATCH,
                ))
            elif not overlap and dn_tokens and domain_tokens:
                findings.append(_finding(
                    "DISPLAY_NAME_DOMAIN_NOT_ALIGNED",
                    "The display name does not share any word with the sending domain. "
                    "This is common for personal mail and is only weak context on its own.",
                    "INFO", f"{dn} vs {domain}", 0,
                ))

    # --------------------------------------------------- 11. reserved domains
    if registrable in RESERVED_SAFE_DOMAINS:
        findings.append(_finding(
            "RESERVED_DEMO_DOMAIN",
            "This domain is reserved for documentation and testing (RFC 2606 / RFC 6761). "
            "It is used here because the project runs on synthetic data only.",
            "INFO", registrable, 0,
        ))

    score = max(0, min(100, score))
    suspicious = score >= SENDER_SUSPICIOUS_THRESHOLD

    if suspicious:
        summary = (f"Sender risk {score}/100 - structural anomalies were found in the sender "
                   f"address. Treat the sender as unverified until confirmed out-of-band.")
    elif score > 0:
        summary = (f"Sender risk {score}/100 - minor observations only. Nothing here proves the "
                   f"sender is malicious.")
    else:
        summary = (f"Sender risk {score}/100 - no structural anomalies detected in the sender "
                   f"address. This does not prove the sender is genuine.")

    return {
        "sender_risk_score": score,
        "sender_findings": findings,
        "raw": parsed["raw"],
        "address": address,
        "display_name": dn,
        "local_part": local,
        "domain": domain,
        "registrable_domain": registrable,
        "tld": parts["tld"],
        "domain_length": domain_length,
        "subdomain_count": subdomain_count,
        "is_valid_format": is_valid,
        "suspicious": suspicious,
        "threshold": SENDER_SUSPICIOUS_THRESHOLD,
        "summary": summary,
    }
