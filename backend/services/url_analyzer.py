"""
backend/services/url_analyzer.py
================================
PURPOSE
-------
STATIC analysis of URLs found in (or supplied alongside) an email.

>>> SAFETY GUARANTEE <<<
This module performs **string analysis only**. It never opens a socket, never
resolves DNS, never issues an HTTP request and never renders a page. There is
no networking import in this file at all - ``urllib.parse`` is a pure text
parser. Visiting a suspicious URL is itself a security event; a defensive tool
must never do it on the analyst's behalf.

Every URL that leaves this module is DEFANGED
(``http://198.51.100.10/x`` -> ``hxxp://198[.]51[.]100[.]10/x``) so that it
cannot be clicked from the dashboard, the database or a log file.

WHAT IS ANALYSED
----------------
scheme, hostname, port, path, query, fragment, URL length, hostname length,
subdomain count, raw-IP usage, suspicious keywords, shortener patterns,
unusual/encoded characters, '@' obfuscation, executable file in path,
deceptive brand-in-subdomain structure, HTTPS presence.

ABOUT HTTPS
-----------
HTTPS means the connection is encrypted. It says NOTHING about who owns the
site. Certificates are free and automated, so most phishing pages today are
served over HTTPS with a valid padlock. This module therefore treats missing
HTTPS as a small negative signal, and never treats present HTTPS as a positive
one - it only removes a penalty.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List
from urllib.parse import parse_qs, unquote, urlsplit

from backend.utils.keywords import (
    DANGEROUS_URL_SCHEMES,
    EXECUTABLE_EXTENSIONS,
    SCRIPT_EXTENSIONS,
    URL_SHORTENER_PATTERNS,
    URL_SUSPICIOUS_KEYWORDS,
)
from backend.utils.text_utils import (
    defang_url,
    is_ip_literal,
    registrable_parts,
    sanitize_text,
)

# --------------------------------------------------------------------------
# Weights (project assumptions - see docs/RISK_SCORING.md)
# --------------------------------------------------------------------------
W_RAW_IP = 30
W_DANGEROUS_SCHEME = 40
W_NO_HTTPS = 10
W_SUSPICIOUS_KEYWORD_FIRST = 15
W_SUSPICIOUS_KEYWORD_EXTRA = 5
W_EXCESSIVE_SUBDOMAINS = 15
W_SHORTENER = 15
W_LONG_URL = 10
W_LONG_HOSTNAME = 8
W_UNUSUAL_CHARACTERS = 20
W_AT_OBFUSCATION = 30
W_NON_STANDARD_PORT = 12
W_EXECUTABLE_IN_PATH = 30
W_HYPHEN_HEAVY_HOST = 10
W_PUNYCODE = 25
W_ENCODED_HEAVY = 12
W_DECEPTIVE_STRUCTURE = 15
W_MISMATCH_DISPLAY = 25

#: A URL is treated as "suspicious" by the rule engine at or above this score.
URL_SUSPICIOUS_THRESHOLD = 30

LONG_URL_THRESHOLD = 75
LONG_HOSTNAME_THRESHOLD = 30

#: Reserved / documentation ranges (RFC 5737, RFC 3849) used by the samples.
_DOC_IP_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.")

_NON_ASCII = re.compile(r"[^\x00-\x7F]")
_HOST_ALLOWED = re.compile(r"^[a-z0-9.\-\[\]:]+$")


def _finding(indicator_type: str, description: str, severity: str,
             evidence: str = "", weight: int = 0) -> Dict[str, Any]:
    return {
        "category": "URL",
        "indicator_type": indicator_type,
        "description": description,
        "severity": severity,
        "evidence": sanitize_text(evidence, 200),
        "weight": weight,
    }


def analyze_url(url: str, display_text: str | None = None) -> Dict[str, Any]:
    """Statically analyse a single URL. **Never** opens the URL.

    Parameters
    ----------
    url:
        The URL string, exactly as it appeared in the email.
    display_text:
        Optional anchor text that was shown to the user. When the visible text
        itself looks like a different host, a MISMATCH finding is raised
        (the "displayed URL vs destination" check).

    Returns
    -------
    dict with ``url_risk_score`` (0-100), ``url_findings`` (list),
    ``safe_representation`` (defanged) and the parsed components.
    """
    original = sanitize_text(url, 2048).strip()
    findings: List[Dict[str, Any]] = []
    score = 0

    if not original:
        return {
            "url": "", "safe_representation": "", "url_risk_score": 0,
            "url_findings": [_finding("EMPTY_URL", "No URL supplied.", "INFO")],
            "scheme": "", "hostname": "", "port": None, "path": "", "query": "",
            "fragment": "", "url_length": 0, "hostname_length": 0,
            "subdomain_count": 0, "registrable_domain": "", "is_ip": False,
            "uses_https": False, "is_shortener": False, "suspicious": False,
            "suspicious_keywords": [], "threshold": URL_SUSPICIOUS_THRESHOLD,
            "summary": "No URL supplied.",
        }

    # ------------------------------------------------------------------ parse
    to_parse = original if "://" in original else f"http://{original}"
    try:
        parts = urlsplit(to_parse)
    except ValueError:
        return {
            "url": original, "safe_representation": defang_url(original),
            "url_risk_score": 40,
            "url_findings": [_finding(
                "UNPARSEABLE_URL",
                "The URL could not be parsed. Malformed URLs are used to confuse both "
                "humans and simple filters.", "HIGH", original, 40)],
            "scheme": "", "hostname": "", "port": None, "path": "", "query": "",
            "fragment": "", "url_length": len(original), "hostname_length": 0,
            "subdomain_count": 0, "registrable_domain": "", "is_ip": False,
            "uses_https": False, "is_shortener": False, "suspicious": True,
            "suspicious_keywords": [], "threshold": URL_SUSPICIOUS_THRESHOLD,
            "summary": "URL could not be parsed.",
        }

    scheme = (parts.scheme or "").lower()
    hostname = (parts.hostname or "").lower()
    try:
        port = parts.port
    except ValueError:
        port = None
        findings.append(_finding(
            "INVALID_PORT", "The URL contains an invalid port value.", "MEDIUM", original, 10))
        score += 10

    path = parts.path or ""
    query = parts.query or ""
    fragment = parts.fragment or ""
    lower_all = original.lower()
    decoded = unquote(original).lower()

    reg = registrable_parts(hostname)
    registrable = str(reg["registrable"])
    subdomain_count = int(reg["subdomain_count"])
    uses_https = scheme == "https"
    is_ip = is_ip_literal(hostname)

    # -------------------------------------------------------- 1. scheme risks
    if scheme in DANGEROUS_URL_SCHEMES and scheme not in {"ftp"}:
        score += W_DANGEROUS_SCHEME
        findings.append(_finding(
            "DANGEROUS_URL_SCHEME",
            f"The link uses the '{scheme}:' scheme. Schemes such as javascript:, data: and "
            "vbscript: execute content instead of navigating to a page and must never be "
            "followed from an email.",
            "HIGH", scheme, W_DANGEROUS_SCHEME,
        ))
    elif scheme == "ftp":
        score += W_DANGEROUS_SCHEME // 2
        findings.append(_finding(
            "NON_WEB_SCHEME",
            "The link uses the 'ftp:' scheme, which is unusual in normal business email "
            "and transmits data without modern transport protection.",
            "MEDIUM", scheme, W_DANGEROUS_SCHEME // 2,
        ))
    elif scheme == "http":
        score += W_NO_HTTPS
        findings.append(_finding(
            "NO_HTTPS",
            "The link uses plain HTTP, so any data submitted travels unencrypted. "
            "Important: the reverse is NOT true - HTTPS does not make a site trustworthy, "
            "because attackers obtain free certificates for phishing pages too.",
            "MEDIUM", scheme, W_NO_HTTPS,
        ))
    elif scheme == "https":
        findings.append(_finding(
            "HTTPS_PRESENT",
            "The link uses HTTPS. This only means the connection is encrypted - it does "
            "NOT mean the destination is legitimate. Most phishing sites use HTTPS today.",
            "INFO", scheme, 0,
        ))
    elif "://" not in original:
        findings.append(_finding(
            "SCHEME_MISSING",
            "The link has no scheme (it begins with 'www.' or a bare host). The mail client "
            "will guess one, usually http://.",
            "LOW", original[:60], 0,
        ))

    # ------------------------------------------------------------ 2. raw IP
    if is_ip:
        score += W_RAW_IP
        note = ""
        if hostname.startswith(_DOC_IP_PREFIXES):
            note = (" (This particular address is from an RFC 5737 documentation range and "
                    "is safe to use in examples.)")
        findings.append(_finding(
            "RAW_IP_URL",
            "The link points at a raw IP address instead of a domain name. Legitimate "
            "organisations publish named hostnames; raw IPs are used to bypass "
            "domain-reputation checks and to hide ownership." + note,
            "HIGH", hostname, W_RAW_IP,
        ))

    # ------------------------------------------------- 3. '@' obfuscation
    authority = to_parse.split("://", 1)[1].split("/", 1)[0] if "://" in to_parse else ""
    if "@" in authority:
        score += W_AT_OBFUSCATION
        findings.append(_finding(
            "AT_SIGN_OBFUSCATION",
            "The URL contains '@' before the host. Everything BEFORE the '@' is ignored by "
            "the browser, so 'https://www.example.com@203.0.113.9/' actually goes to "
            "203.0.113.9. This is a deliberate deception technique.",
            "HIGH", authority[:80], W_AT_OBFUSCATION,
        ))

    # --------------------------------------------------- 4. shortener pattern
    is_shortener = any(hostname == s or hostname.endswith("." + s) for s in URL_SHORTENER_PATTERNS)
    if is_shortener:
        score += W_SHORTENER
        findings.append(_finding(
            "URL_SHORTENER",
            "The link uses a URL-shortening service. Shorteners are legitimate tools, but "
            "they hide the real destination, so the recipient cannot inspect it before "
            "clicking. In triage, always expand the link in a safe environment.",
            "MEDIUM", hostname, W_SHORTENER,
        ))

    # -------------------------------------------------- 5. subdomain nesting
    if subdomain_count >= 4:
        score += W_EXCESSIVE_SUBDOMAINS + 5
        findings.append(_finding(
            "EXCESSIVE_SUBDOMAINS",
            f"The hostname has {subdomain_count} subdomain levels. Long chains such as "
            "'login.secure.account.attacker.test' are built so the trustworthy-looking "
            "words appear first and the real owner disappears off the right-hand edge of a "
            "narrow mobile address bar.",
            "HIGH", hostname, W_EXCESSIVE_SUBDOMAINS + 5,
        ))
    elif subdomain_count == 3:
        score += W_EXCESSIVE_SUBDOMAINS
        findings.append(_finding(
            "EXCESSIVE_SUBDOMAINS",
            f"The hostname has {subdomain_count} subdomain levels, more nesting than a "
            "typical public web page uses.",
            "MEDIUM", hostname, W_EXCESSIVE_SUBDOMAINS,
        ))

    # ----------------------------------------- 6. deceptive brand structure
    if subdomain_count >= 1 and registrable:
        sub_text = ".".join(reg["subdomains"])  # type: ignore[arg-type]
        sub_tokens = {t for t in re.split(r"[.\-_]", sub_text) if t}
        deceptive = sub_tokens & set(URL_SUSPICIOUS_KEYWORDS)
        if deceptive:
            score += W_DECEPTIVE_STRUCTURE
            findings.append(_finding(
                "DECEPTIVE_URL_STRUCTURE",
                "Trust words (" + ", ".join(sorted(deceptive)[:4]) + ") appear in the "
                f"subdomain while the actual registered domain is '{registrable}'. "
                "Only the registrable domain identifies the owner - read a URL from the "
                "right, not from the left.",
                "HIGH", hostname, W_DECEPTIVE_STRUCTURE,
            ))

    # -------------------------------------------- 7. suspicious keywords
    keyword_hits = sorted({k for k in URL_SUSPICIOUS_KEYWORDS
                           if re.search(rf"(?<![a-z]){re.escape(k)}(?![a-z])", decoded)})
    if keyword_hits:
        add = W_SUSPICIOUS_KEYWORD_FIRST + W_SUSPICIOUS_KEYWORD_EXTRA * (len(keyword_hits) - 1)
        add = min(add, 30)
        score += add
        findings.append(_finding(
            "SUSPICIOUS_URL_KEYWORDS",
            "The URL contains credential/payment words (" + ", ".join(keyword_hits[:6]) +
            "). Attackers put reassuring words in the path so the link reads like a login "
            "or billing page.",
            "MEDIUM" if len(keyword_hits) < 3 else "HIGH", ", ".join(keyword_hits[:6]), add,
        ))

    # -------------------------------------------------- 8. length signals
    url_length = len(original)
    if url_length > LONG_URL_THRESHOLD:
        score += W_LONG_URL
        findings.append(_finding(
            "LONG_URL",
            f"The URL is {url_length} characters long. Very long URLs are used to push the "
            "meaningful part out of view in mail clients and mobile browsers.",
            "LOW", f"{url_length} characters", W_LONG_URL,
        ))
    hostname_length = len(hostname)
    if hostname_length > LONG_HOSTNAME_THRESHOLD:
        score += W_LONG_HOSTNAME
        findings.append(_finding(
            "LONG_HOSTNAME",
            f"The hostname is {hostname_length} characters long, which is unusual for a "
            "genuine public service.",
            "LOW", hostname, W_LONG_HOSTNAME,
        ))

    # ------------------------------------------------ 9. unusual characters
    if _NON_ASCII.search(original):
        score += W_UNUSUAL_CHARACTERS
        findings.append(_finding(
            "UNUSUAL_CHARACTERS_IN_URL",
            "The URL contains non-ASCII characters. Look-alike letters from other alphabets "
            "can make a hostile domain visually identical to a real one.",
            "HIGH", original[:80], W_UNUSUAL_CHARACTERS,
        ))
    if hostname.startswith("xn--") or ".xn--" in hostname:
        score += W_PUNYCODE
        findings.append(_finding(
            "PUNYCODE_HOSTNAME",
            "The hostname is Punycode-encoded ('xn--'), meaning it contains international "
            "characters. This is the mechanism behind homograph domain spoofing.",
            "HIGH", hostname, W_PUNYCODE,
        ))
    if hostname and not _HOST_ALLOWED.fullmatch(hostname):
        score += W_UNUSUAL_CHARACTERS // 2
        findings.append(_finding(
            "UNEXPECTED_HOST_CHARACTERS",
            "The hostname contains characters outside the normal set.",
            "MEDIUM", hostname, W_UNUSUAL_CHARACTERS // 2,
        ))
    encoded_count = len(re.findall(r"%[0-9a-fA-F]{2}", original))
    if encoded_count >= 4:
        score += W_ENCODED_HEAVY
        findings.append(_finding(
            "HEAVY_PERCENT_ENCODING",
            f"The URL contains {encoded_count} percent-encoded characters. Heavy encoding is "
            "used to hide keywords from simple filters and from the reader.",
            "MEDIUM", f"{encoded_count} encoded sequences", W_ENCODED_HEAVY,
        ))

    # -------------------------------------------- 10. hyphen-heavy hostname
    if registrable:
        reg_body = registrable.rsplit(".", 1)[0]
        if reg_body.count("-") >= 2:
            score += W_HYPHEN_HEAVY_HOST
            findings.append(_finding(
                "HYPHEN_HEAVY_HOSTNAME",
                f"The registered domain '{registrable}' contains multiple hyphens, a shape "
                "commonly used to assemble trustworthy-sounding phrases.",
                "MEDIUM", registrable, W_HYPHEN_HEAVY_HOST,
            ))

    # ------------------------------------------------- 11. non-standard port
    if port is not None and port not in (80, 443):
        score += W_NON_STANDARD_PORT
        findings.append(_finding(
            "NON_STANDARD_PORT",
            f"The URL specifies port {port}. Public services almost always use 80 or 443; "
            "an unusual port often indicates a temporary or hidden host.",
            "MEDIUM", str(port), W_NON_STANDARD_PORT,
        ))

    # -------------------------------------------- 12. executable in the path
    path_lower = path.lower()
    risky_ext = [e for e in (EXECUTABLE_EXTENSIONS + SCRIPT_EXTENSIONS) if path_lower.endswith(e)]
    if risky_ext:
        score += W_EXECUTABLE_IN_PATH
        findings.append(_finding(
            "EXECUTABLE_DOWNLOAD_LINK",
            f"The link points directly at a '{risky_ext[0]}' file. Following it would start "
            "a download of executable or script content.",
            "HIGH", path[:80], W_EXECUTABLE_IN_PATH,
        ))

    # ------------------------------- 13. displayed text vs destination
    if display_text:
        dtext = sanitize_text(display_text, 300).strip()
        shown_hosts = re.findall(r"(?:https?://)?((?:[a-z0-9\-]+\.)+[a-z]{2,63})", dtext.lower())
        if shown_hosts:
            shown_reg = str(registrable_parts(shown_hosts[0])["registrable"])
            if shown_reg and registrable and shown_reg != registrable:
                score += W_MISMATCH_DISPLAY
                findings.append(_finding(
                    "DISPLAYED_URL_MISMATCH",
                    f"The visible link text shows '{shown_reg}' but the destination is "
                    f"'{registrable}'. The text of a link is free-form and can say anything; "
                    "only the destination matters. Hover (or long-press on mobile) to reveal it.",
                    "HIGH", f"{shown_reg} -> {registrable}", W_MISMATCH_DISPLAY,
                ))

    if not findings:
        findings.append(_finding(
            "NO_URL_INDICATORS",
            "No static URL risk indicators were detected. This does not certify the "
            "destination as safe - it only means the string itself looks ordinary.",
            "INFO", original[:80], 0,
        ))

    score = max(0, min(100, score))
    suspicious = score >= URL_SUSPICIOUS_THRESHOLD
    safe_repr = defang_url(original)

    if suspicious:
        summary = f"URL risk {score}/100 - multiple static indicators. Do not open this link."
    elif score > 0:
        summary = f"URL risk {score}/100 - minor observations only."
    else:
        summary = f"URL risk {score}/100 - no static indicators found."

    return {
        "url": original,
        "safe_representation": safe_repr,
        "url_risk_score": score,
        "url_findings": findings,
        "scheme": scheme,
        "hostname": hostname,
        "port": port,
        "path": path,
        "query": query,
        "query_params": {k: v[:1] for k, v in parse_qs(query).items()} if query else {},
        "fragment": fragment,
        "url_length": url_length,
        "hostname_length": hostname_length,
        "subdomain_count": subdomain_count,
        "registrable_domain": registrable,
        "is_ip": is_ip,
        "uses_https": uses_https,
        "is_shortener": is_shortener,
        "suspicious_keywords": keyword_hits,
        "suspicious": suspicious,
        "threshold": URL_SUSPICIOUS_THRESHOLD,
        "summary": summary,
    }


def analyze_urls(urls: List[str]) -> Dict[str, Any]:
    """Analyse a list of URLs and aggregate the results.

    Returns the per-URL reports plus ``max_url_risk``, ``suspicious_url_count``,
    ``has_ip_url`` and ``has_shortened_url_pattern`` (used as ML features and by
    the rule engine).
    """
    reports = [analyze_url(u) for u in urls if str(u).strip()]
    if not reports:
        return {
            "url_reports": [], "url_count": 0, "suspicious_url_count": 0,
            "max_url_risk": 0, "has_ip_url": False, "has_shortened_url_pattern": False,
            "has_non_https_url": False, "suspicious": False,
            "summary": "No URLs were found in this email.",
        }
    suspicious_count = sum(1 for r in reports if r["suspicious"])
    max_risk = max(r["url_risk_score"] for r in reports)
    return {
        "url_reports": reports,
        "url_count": len(reports),
        "suspicious_url_count": suspicious_count,
        "max_url_risk": max_risk,
        "has_ip_url": any(r["is_ip"] for r in reports),
        "has_shortened_url_pattern": any(r["is_shortener"] for r in reports),
        "has_non_https_url": any(r["scheme"] in ("http", "") for r in reports),
        "suspicious": max_risk >= URL_SUSPICIOUS_THRESHOLD,
        "summary": (f"{len(reports)} URL(s) analysed statically; {suspicious_count} exceeded the "
                    f"suspicion threshold of {URL_SUSPICIOUS_THRESHOLD}/100. No URL was opened."),
    }
