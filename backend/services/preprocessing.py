"""
backend/services/preprocessing.py
=================================
PURPOSE
-------
Turn a raw email (or a raw dataset row) into a clean, analysable structure
WITHOUT destroying the evidence that phishing detection depends on.

FUNCTIONS
---------
``preprocess_email``      - single email -> normalised dict
``clean_text_for_ml``     - conservative cleaning used ONLY for the ML text field
``preprocess_dataframe``  - dataset-level cleaning (nulls, duplicates, derived columns)
``parse_email_file``      - safe .eml/.txt parsing (stdlib ``email`` module)

==========================================================================
WHY AGGRESSIVE TEXT CLEANING IS DANGEROUS FOR PHISHING DETECTION
==========================================================================
A generic NLP pipeline usually does: lowercase -> strip punctuation -> strip
digits -> remove stop-words -> stem. Applied blindly to security data, each of
those steps deletes evidence:

  lowercase everything      -> "URGENT ACTION REQUIRED" and "urgent action
                               required" become identical, and the SHOUTING
                               signal (uppercase_ratio) is gone.
  strip punctuation         -> "!!!" disappears, and, far worse, URLs are
                               destroyed: "http://198.51.100.10/verify" becomes
                               "http 198 51 100 10 verify" - no scheme, no host,
                               no raw-IP indicator.
  strip digits              -> raw-IP URLs, invoice numbers and look-alike
                               domains ("examp1e") are flattened.
  remove stop-words         -> "you have won" -> "won"; "act now" -> "act".
                               The manipulation phrasing is the signal.
  stemming/lemmatising      -> "verification"/"verify"/"verified" collapse, which
                               is fine for topic modelling and harmful when the
                               grammatical form is what distinguishes a
                               statement from a request.

THE RULE FOLLOWED IN THIS PROJECT
---------------------------------
1. Structural features are computed FIRST, on the ORIGINAL text.
2. Only then is a *separate*, lightly-cleaned copy produced for TF-IDF.
3. The original text is never overwritten.
"""

from __future__ import annotations

import email
import re
from email import policy
from email.parser import BytesParser, Parser
from typing import Any, Dict, List, Optional

from backend.utils.text_utils import (
    extract_domain,
    extract_urls,
    normalize_whitespace,
    parse_sender,
    sanitize_text,
    split_url_field,
)

#: Placeholder tokens keep the *existence* of a URL/number visible to TF-IDF
#: while removing the high-cardinality literal value.
URL_TOKEN = " urltoken "
IP_TOKEN = " iptoken "
EMAIL_TOKEN = " emailtoken "
NUMBER_TOKEN = " numtoken "

_IP_IN_TEXT = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_EMAIL_IN_TEXT = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,63}")
_URL_IN_TEXT = re.compile(r"(?:https?|ftp)://\S+|www\.\S+", re.IGNORECASE)
_LONG_NUMBER = re.compile(r"\b\d{3,}\b")
_HTML_TAG = re.compile(r"<[^>]{1,200}>")


def clean_text_for_ml(text: str) -> str:
    """Conservative cleaning for the TF-IDF input ONLY.

    What it does
    ------------
    * strips HTML tags (keeps the visible words),
    * replaces URLs / IPs / emails / long numbers with stable placeholder tokens
      so the model learns "a link is present" instead of memorising one host,
    * lower-cases and collapses whitespace.

    What it deliberately does NOT do
    --------------------------------
    * it does not remove punctuation (``!`` and ``?`` carry pressure signal),
    * it does not remove stop-words ("you have won" must survive),
    * it does not stem.

    The structural/rule features are ALWAYS computed on the original text, so
    nothing detected here is lost.
    """
    text = sanitize_text(text)
    if not text:
        return ""
    text = _HTML_TAG.sub(" ", text)
    text = _URL_IN_TEXT.sub(URL_TOKEN, text)
    text = _IP_IN_TEXT.sub(IP_TOKEN, text)
    text = _EMAIL_IN_TEXT.sub(EMAIL_TOKEN, text)
    text = _LONG_NUMBER.sub(NUMBER_TOKEN, text)
    text = text.lower()
    return normalize_whitespace(text)


def preprocess_email(
    sender: str,
    subject: str,
    body: str,
    urls: Optional[str | List[str]] = None,
    attachment_name: Optional[str] = None,
    display_name: Optional[str] = None,
) -> Dict[str, Any]:
    """Normalise one email into the structure every analyzer consumes.

    Steps
    -----
    1. sanitise every field (control characters removed, length bounded),
    2. parse the sender into display name / address / local part / domain,
    3. extract URLs from the body **and** merge any explicitly supplied URLs
       (de-duplicated, order preserved),
    4. derive the attachment extension,
    5. produce the ML text field with :func:`clean_text_for_ml`.

    Missing values are handled by substituting empty strings - the analyzers
    then report "empty subject"/"empty body" as findings rather than failing.
    """
    sender = sanitize_text(sender, 320)
    subject = sanitize_text(subject, 998)
    body = sanitize_text(body)
    attachment_name = sanitize_text(attachment_name or "", 255).strip()

    parsed_sender = parse_sender(sender)
    if display_name:
        parsed_sender["display_name"] = sanitize_text(display_name, 200).strip()

    body_urls = extract_urls(body)
    subject_urls = extract_urls(subject)
    explicit: List[str] = []
    if isinstance(urls, str):
        explicit = split_url_field(urls)
    elif isinstance(urls, list):
        explicit = [sanitize_text(u, 2048).strip() for u in urls if str(u).strip()]

    all_urls: List[str] = []
    for u in body_urls + subject_urls + explicit:
        if u and u not in all_urls:
            all_urls.append(u)

    attachment_ext = ""
    if attachment_name and "." in attachment_name:
        attachment_ext = "." + attachment_name.rsplit(".", 1)[1].lower()

    return {
        "sender": sender,
        "sender_display_name": parsed_sender["display_name"],
        "sender_address": parsed_sender["address"],
        "sender_local_part": parsed_sender["local_part"],
        "sender_domain": parsed_sender["domain"],
        "subject": subject,
        "body": body,
        "urls": all_urls,
        "url_count": len(all_urls),
        "attachment_name": attachment_name,
        "attachment_extension": attachment_ext,
        "combined_text": f"{subject}\n{body}".strip(),
        "ml_text": clean_text_for_ml(f"{subject} {body}"),
        "is_subject_empty": subject.strip() == "",
        "is_body_empty": body.strip() == "",
    }


def parse_email_file(content: bytes, filename: str = "sample.eml") -> Dict[str, str]:
    """Safely parse an uploaded ``.eml`` / ``.txt`` sample.

    SECURITY
    --------
    * Parsing is done with the Python standard-library ``email`` package, which
      is a pure text parser - it does not fetch remote content, does not run
      scripts and does not follow ``cid:``/``http:`` references.
    * Only ``text/plain`` and ``text/html`` parts are read. HTML parts are
      reduced to visible text by :func:`clean_text_for_ml`-style tag stripping -
      the raw HTML is never returned to the browser for rendering.
    * Attachments inside the file are NOT extracted or written to disk; only
      their declared filenames are collected for static name analysis.

    Returns ``{"sender", "subject", "body", "attachment_name"}``.
    """
    try:
        text = content.decode("utf-8", errors="replace")
    except Exception:                                   # pragma: no cover
        text = ""

    if filename.lower().endswith(".eml") or re.match(r"(?im)^(from|subject|to|date)\s*:", text):
        try:
            msg = BytesParser(policy=policy.default).parsebytes(content)
        except Exception:                               # pragma: no cover
            msg = Parser(policy=policy.default).parsestr(text)

        sender = str(msg.get("From", "") or "")
        subject = str(msg.get("Subject", "") or "")

        body_parts: List[str] = []
        attachment_names: List[str] = []
        try:
            if msg.is_multipart():
                for part in msg.walk():
                    ctype = part.get_content_type()
                    disp = str(part.get("Content-Disposition") or "")
                    if "attachment" in disp.lower():
                        fname = part.get_filename()
                        if fname:
                            attachment_names.append(str(fname))
                        continue
                    if ctype == "text/plain":
                        body_parts.append(part.get_content())
                    elif ctype == "text/html":
                        body_parts.append(_HTML_TAG.sub(" ", part.get_content()))
            else:
                payload = msg.get_content()
                if msg.get_content_type() == "text/html":
                    payload = _HTML_TAG.sub(" ", payload)
                body_parts.append(payload)
        except Exception:                               # pragma: no cover
            body_parts.append(text)

        return {
            "sender": sanitize_text(sender, 320),
            "subject": sanitize_text(subject, 998),
            "body": sanitize_text("\n".join(p for p in body_parts if p)),
            "attachment_name": sanitize_text(attachment_names[0] if attachment_names else "", 255),
        }

    # ---- plain .txt sample: try a tiny "From:/Subject:" header convention ----
    sender, subject, body_lines = "", "", []
    lines = text.splitlines()
    header_done = False
    for line in lines:
        if not header_done:
            m = re.match(r"(?i)^\s*(from|sender)\s*:\s*(.+)$", line)
            if m:
                sender = m.group(2).strip()
                continue
            m = re.match(r"(?i)^\s*subject\s*:\s*(.+)$", line)
            if m:
                subject = m.group(1).strip()
                continue
            m = re.match(r"(?i)^\s*attachment\s*:\s*(.+)$", line)
            if m:
                body_lines.append(line)
                continue
            if line.strip() == "" and (sender or subject):
                header_done = True
                continue
        body_lines.append(line)

    attachment = ""
    m = re.search(r"(?im)^\s*attachment\s*:\s*(.+)$", text)
    if m:
        attachment = m.group(1).strip()
        body_lines = [l for l in body_lines if not re.match(r"(?i)^\s*attachment\s*:", l)]

    return {
        "sender": sanitize_text(sender, 320),
        "subject": sanitize_text(subject, 998),
        "body": sanitize_text("\n".join(body_lines).strip()),
        "attachment_name": sanitize_text(attachment, 255),
    }


# ---------------------------------------------------------------------------
# Dataset-level preprocessing (used by the ML pipeline)
# ---------------------------------------------------------------------------
def preprocess_dataframe(df, verbose: bool = True):
    """Clean a dataset DataFrame and add the derived columns the ML pipeline needs.

    Operations
    ----------
    1. **Missing values** - required text columns are filled with ``""`` so the
       feature extractor sees an empty field (and can report it) instead of NaN.
       Rows missing the *label* are dropped: an unlabelled row cannot be used
       for supervised training.
    2. **Duplicate removal** - exact duplicates on (sender, subject, body) are
       dropped. Near-identical bulk messages would otherwise leak between the
       train and test split and inflate the metrics.
    3. **Normalisation** - the label column is upper-cased and trimmed; the
       sender domain is lower-cased. Subject/body case is PRESERVED.
    4. **Derived columns** - ``sender_domain`` (recomputed when missing),
       ``attachment_extension``, ``url_list``, ``url_count``, ``clean_text``.

    Returns ``(clean_df, report_dict)``.
    """
    import pandas as pd  # imported lazily so the API does not need pandas at import time

    report: Dict[str, Any] = {"rows_in": int(len(df))}

    text_cols = ["sender", "sender_domain", "subject", "body", "urls", "attachment_name"]
    for col in text_cols:
        if col not in df.columns:
            df[col] = ""
    report["missing_values_filled"] = int(df[text_cols].isna().sum().sum())
    df[text_cols] = df[text_cols].fillna("")

    if "label" in df.columns:
        before = len(df)
        df = df[df["label"].notna()].copy()
        report["rows_dropped_missing_label"] = int(before - len(df))
        df["label"] = df["label"].astype(str).str.strip().str.upper()
    else:
        report["rows_dropped_missing_label"] = 0

    before = len(df)
    df = df.drop_duplicates(subset=["sender", "subject", "body"]).copy()
    report["duplicates_removed"] = int(before - len(df))

    df["sender"] = df["sender"].astype(str).map(lambda s: sanitize_text(s, 320))
    df["subject"] = df["subject"].astype(str).map(lambda s: sanitize_text(s, 998))
    df["body"] = df["body"].astype(str).map(sanitize_text)
    df["sender_domain"] = df.apply(
        lambda r: (str(r["sender_domain"]).strip().lower() or extract_domain(str(r["sender"]))),
        axis=1,
    )
    df["attachment_name"] = df["attachment_name"].astype(str).map(lambda s: sanitize_text(s, 255))
    df["attachment_extension"] = df["attachment_name"].map(
        lambda n: ("." + n.rsplit(".", 1)[1].lower()) if isinstance(n, str) and "." in n else ""
    )
    df["url_list"] = df["urls"].astype(str).map(split_url_field)
    df["url_count"] = df["url_list"].map(len)
    df["clean_text"] = (df["subject"].astype(str) + " " + df["body"].astype(str)).map(clean_text_for_ml)

    report["rows_out"] = int(len(df))
    if verbose:
        print(f"[preprocess] rows in={report['rows_in']} out={report['rows_out']} "
              f"duplicates_removed={report['duplicates_removed']} "
              f"missing_filled={report['missing_values_filled']}")
    return df.reset_index(drop=True), report
