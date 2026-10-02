"""
backend/utils/text_utils.py
===========================
PURPOSE
-------
Safe text helpers shared by the analyzers:

  * phrase / regex matching with word boundaries,
  * URL extraction from an email body (string parsing only - never fetched),
  * "defanging" a URL so it can be displayed and stored without being
    accidentally clickable,
  * input sanitisation used before anything is persisted or returned.

SECURITY NOTES
--------------
1. URLs are extracted with a regular expression. The application NEVER performs
   a network request against an extracted URL. All URL analysis in this project
   is STATIC STRING ANALYSIS.
2. `defang_url()` rewrites "http://" as "hxxp://" and "." as "[.]". This is a
   standard SOC convention so that a suspicious URL pasted into a ticket, a log
   file, or a dashboard cannot be clicked by accident.
3. `sanitize_text()` strips control characters (including the right-to-left
   override U+202E used to disguise filenames) and enforces a maximum length.
   The React frontend additionally escapes everything it renders - we never use
   `dangerouslySetInnerHTML`.
"""

from __future__ import annotations

import html
import re
import unicodedata
from typing import Dict, Iterable, List, Tuple

# ---------------------------------------------------------------------------
# Regular expressions
# ---------------------------------------------------------------------------

#: Matches http/https/ftp/… URLs and bare "www." hosts inside free text.
URL_REGEX = re.compile(
    r"""(?xi)
    \b
    (?:
        (?:https?|ftp|ftps|file|javascript|data|vbscript)://[^\s<>"'\)\]\},]+
        |
        www\.[^\s<>"'\)\]\},]+
    )
    """
)

#: Matches an email address (used for sender parsing and body scanning).
EMAIL_REGEX = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,63}")

#: 'Display Name <user@example.com>' style sender headers.
DISPLAY_NAME_REGEX = re.compile(r"^\s*(?P<name>[^<>]*?)\s*<\s*(?P<addr>[^<>\s]+@[^<>\s]+)\s*>\s*$")

#: Dotted-quad IPv4 literal.
IPV4_REGEX = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

#: Control characters that should never survive into storage or the UI.
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2066-\u2069]")

#: Trailing punctuation frequently glued to a URL by a sentence.
_TRAILING_PUNCT = ".,;:!?\"')]}>"

# Maximum characters we ever accept for a single free-text field.
MAX_TEXT_LENGTH = 50_000


# ---------------------------------------------------------------------------
# Sanitisation
# ---------------------------------------------------------------------------
def sanitize_text(value: object, max_length: int = MAX_TEXT_LENGTH) -> str:
    """Return a safe, length-bounded plain-text version of ``value``.

    Steps
    -----
    1. coerce to ``str`` (``None`` becomes an empty string),
    2. normalise Unicode to NFKC so homoglyph tricks collapse to a canonical
       form before analysis,
    3. delete control characters and bidirectional-override characters,
    4. truncate to ``max_length``.

    This is deliberately *not* HTML escaping: the value stays plain text and the
    React UI escapes it at render time. Escaping here as well would produce
    double-escaped output such as ``&amp;amp;``.
    """
    if value is None:
        return ""
    text = str(value)
    text = unicodedata.normalize("NFKC", text)
    text = _CONTROL_CHARS.sub("", text)
    if len(text) > max_length:
        text = text[:max_length]
    return text


def escape_for_html(value: str) -> str:
    """HTML-escape a string.

    Used only when a value could end up inside a generated HTML/report file
    (for example the evidence report). The live API returns JSON and the React
    client escapes on render, so this is not applied to API responses.
    """
    return html.escape(sanitize_text(value), quote=True)


# ---------------------------------------------------------------------------
# Matching helpers
# ---------------------------------------------------------------------------
def _phrase_regex(phrase: str) -> re.Pattern:
    """Build a word-boundary regex for a (possibly multi-word) phrase."""
    parts = [re.escape(p) for p in phrase.split()]
    body = r"\s+".join(parts)
    return re.compile(rf"(?<![\w]){body}(?![\w])", re.IGNORECASE)


_PHRASE_CACHE: Dict[str, re.Pattern] = {}


def find_phrases(text: str, phrases: Iterable[str]) -> List[Tuple[str, int]]:
    """Return ``[(phrase, occurrences), ...]`` for every phrase present in ``text``.

    Matching is case-insensitive and respects word boundaries, so "pin" does not
    match "shipping" and "otp" does not match "adopt".
    """
    if not text:
        return []
    hits: List[Tuple[str, int]] = []
    for phrase in phrases:
        rx = _PHRASE_CACHE.get(phrase)
        if rx is None:
            rx = _phrase_regex(phrase)
            _PHRASE_CACHE[phrase] = rx
        count = len(rx.findall(text))
        if count:
            hits.append((phrase, count))
    return hits


def count_phrases(text: str, phrases: Iterable[str]) -> int:
    """Total number of phrase occurrences (not distinct phrases)."""
    return sum(c for _, c in find_phrases(text, phrases))


def find_patterns(text: str, patterns: Iterable[str]) -> List[str]:
    """Return the matched snippets for a list of regex ``patterns``.

    Snippets are truncated to 120 characters so a finding never leaks a large
    chunk of the original email into the database or the UI.
    """
    if not text:
        return []
    out: List[str] = []
    for pattern in patterns:
        for m in re.finditer(pattern, text, re.IGNORECASE):
            snippet = " ".join(m.group(0).split())[:120]
            if snippet and snippet.lower() not in [o.lower() for o in out]:
                out.append(snippet)
    return out


def find_labeled_patterns(text: str, patterns: Iterable) -> List[Tuple[str, str]]:
    """Like :func:`find_patterns`, but for ``(regex, human_label)`` pairs.

    Returns a list of ``(label, snippet)``. The label is what an analyst reads
    in the finding ("threatened account suspension or closure"); the snippet is
    the matched text, truncated to 120 characters so a finding never leaks a
    large chunk of the original email into the database or the UI.

    Each label is reported at most once, no matter how many times it matches.
    """
    if not text:
        return []
    out: List[Tuple[str, str]] = []
    seen: set = set()
    for pattern, label in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match and label not in seen:
            snippet = " ".join(match.group(0).split())[:120]
            out.append((label, snippet))
            seen.add(label)
    return out


# ---------------------------------------------------------------------------
# URL helpers (STATIC ONLY - nothing here opens a connection)
# ---------------------------------------------------------------------------
def extract_urls(text: str) -> List[str]:
    """Extract URLs from free text using a regex. Never performs a request.

    Trailing sentence punctuation is stripped, and unbalanced closing brackets
    are removed so "see https://example.com/page." yields a clean URL.
    """
    if not text:
        return []
    found: List[str] = []
    for raw in URL_REGEX.findall(text):
        url = raw.strip()
        while url and url[-1] in _TRAILING_PUNCT:
            if url[-1] == ")" and url.count("(") > url.count(")"):
                break
            url = url[:-1]
        if url and url not in found:
            found.append(url)
    return found


def split_url_field(value: str) -> List[str]:
    """Split the dataset's ``urls`` column (space/newline/comma separated)."""
    if not value:
        return []
    parts = re.split(r"[\s,;|]+", str(value).strip())
    return [p for p in parts if p]


def defang_url(url: str) -> str:
    """Return a non-clickable ("defanged") representation of a URL.

    ``http://198.51.100.10/verify`` -> ``hxxp://198[.]51[.]100[.]10/verify``

    This is what gets STORED in the database and SHOWN in the dashboard so that
    no analyst, log viewer or chat client turns the string into a live link.
    """
    if not url:
        return ""
    safe = sanitize_text(url, 2048)
    safe = re.sub(r"^http://", "hxxp://", safe, flags=re.IGNORECASE)
    safe = re.sub(r"^https://", "hxxps://", safe, flags=re.IGNORECASE)
    safe = re.sub(r"^ftp://", "fxp://", safe, flags=re.IGNORECASE)
    scheme, sep, rest = safe.partition("://")
    if sep:
        host_and_path = rest.split("/", 1)
        host = host_and_path[0].replace(".", "[.]")
        path = "/" + host_and_path[1] if len(host_and_path) > 1 else ""
        return f"{scheme}://{host}{path}"
    return safe.replace(".", "[.]")


def is_ip_literal(host: str) -> bool:
    """True when ``host`` is a raw IPv4 literal or a bracketed IPv6 literal."""
    if not host:
        return False
    host = host.strip().lower()
    if host.startswith("[") and host.endswith("]"):
        return True
    if not IPV4_REGEX.match(host):
        return False
    try:
        return all(0 <= int(o) <= 255 for o in host.split("."))
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Sender helpers
# ---------------------------------------------------------------------------
def parse_sender(sender: str) -> Dict[str, str]:
    """Split a sender header into display name, address, local part and domain.

    Accepts both ``user@example.com`` and ``Support Team <user@example.com>``.
    Returns empty strings for anything that could not be parsed - callers treat
    that as "invalid sender format" rather than crashing.
    """
    raw = sanitize_text(sender, 512).strip()
    display_name, address = "", raw
    m = DISPLAY_NAME_REGEX.match(raw)
    if m:
        display_name = m.group("name").strip().strip('"').strip()
        address = m.group("addr").strip()
    address = address.strip("<> ").strip()
    local, _, domain = address.partition("@")
    return {
        "raw": raw,
        "display_name": display_name,
        "address": address,
        "local_part": local.strip(),
        "domain": domain.strip().lower(),
    }


def extract_domain(sender: str) -> str:
    """Convenience wrapper returning only the (lower-cased) sender domain."""
    return parse_sender(sender)["domain"]


def registrable_parts(domain: str) -> Dict[str, object]:
    """Break a hostname into labels and estimate the registrable domain.

    We deliberately avoid a Public Suffix List dependency (extra package, needs
    periodic updates). Instead we use a documented heuristic:

      * labels          -> ['mail', 'account-check', 'invalid', 'test']
      * registrable     -> last two labels, or last three when the second-to-last
                           label is a common second-level suffix (co.uk, ac.in …)
      * subdomain_count -> number of labels in front of the registrable domain

    The heuristic is good enough for risk *signals*; it is documented as an
    assumption in docs/LIMITATIONS.md.
    """
    domain = (domain or "").strip().lower().strip(".")
    if not domain:
        return {"labels": [], "registrable": "", "subdomains": [], "subdomain_count": 0, "tld": ""}
    labels = domain.split(".")
    two_level_suffixes = {
        "co", "com", "net", "org", "gov", "edu", "ac", "mil", "or", "ne", "gob", "gv",
    }
    if len(labels) >= 3 and labels[-2] in two_level_suffixes and len(labels[-1]) <= 3:
        reg_len = 3
    else:
        reg_len = 2
    reg_len = min(reg_len, len(labels))
    registrable = ".".join(labels[-reg_len:])
    subdomains = labels[:-reg_len]
    return {
        "labels": labels,
        "registrable": registrable,
        "subdomains": subdomains,
        "subdomain_count": len(subdomains),
        "tld": labels[-1],
    }


# ---------------------------------------------------------------------------
# Misc text statistics used as ML/rule features
# ---------------------------------------------------------------------------
def uppercase_ratio(text: str) -> float:
    """Fraction of alphabetic characters that are upper-case (0.0 - 1.0).

    SHOUTING is a mild manipulation signal ("URGENT ACTION REQUIRED!!!").
    """
    if not text:
        return 0.0
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return 0.0
    return round(sum(1 for c in letters if c.isupper()) / len(letters), 4)


def exclamation_count(text: str) -> int:
    """Number of '!' characters - excessive use correlates with pressure tactics."""
    return (text or "").count("!")


def normalize_whitespace(text: str) -> str:
    """Collapse runs of whitespace; keeps analysis stable across formats."""
    return re.sub(r"\s+", " ", text or "").strip()


def truncate(text: str, limit: int = 200) -> str:
    """Shorten text for safe display/storage, adding an ellipsis."""
    text = sanitize_text(text)
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"
