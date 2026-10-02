"""
backend/utils/validators.py
===========================
PURPOSE
-------
Input validation helpers used by the API layer *in addition to* Pydantic.

Pydantic validates TYPES and LENGTHS. These helpers validate SECURITY
PROPERTIES:

  * is the uploaded filename safe (no path traversal, allowed extension)?
  * is the upload within the size limit?
  * is the supplied string actually shaped like an email address / URL?

Failing validation returns a clear reason string so the API can answer with a
422/400 and a helpful message instead of a stack trace.
"""

from __future__ import annotations

import os
import re
from typing import List, Optional, Tuple

from backend.config import settings
from backend.utils.text_utils import EMAIL_REGEX, sanitize_text

#: Anything that could escape the intended directory.
_PATH_TRAVERSAL = re.compile(r"(\.\./|\.\.\\|^/|^\\|^[A-Za-z]:[\\/])")

#: Characters that are illegal in a Windows filename (also a good general filter).
_ILLEGAL_FILENAME_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


def validate_email_address(value: str) -> Tuple[bool, str]:
    """Return ``(is_valid, reason)`` for a sender address.

    An *invalid* sender is itself a security finding, not a crash: the API
    accepts the analysis request and the sender analyzer reports
    "sender address is not a valid email format".
    """
    raw = sanitize_text(value, 320).strip()
    if not raw:
        return False, "Sender is empty."
    addr = raw
    if "<" in raw and ">" in raw:
        addr = raw[raw.rfind("<") + 1: raw.rfind(">")].strip()
    if not EMAIL_REGEX.fullmatch(addr):
        return False, "Sender is not a syntactically valid email address."
    if addr.count("@") != 1:
        return False, "Sender must contain exactly one '@'."
    local, _, domain = addr.partition("@")
    if not local or len(local) > 64:
        return False, "Sender local part is empty or longer than 64 characters."
    if not domain or "." not in domain or len(domain) > 253:
        return False, "Sender domain is empty, has no dot, or is too long."
    return True, "Valid email address format."


def validate_url_string(value: str) -> Tuple[bool, str]:
    """Return ``(is_valid, reason)`` for a URL supplied to /api/analyze/url."""
    raw = sanitize_text(value, 2048).strip()
    if not raw:
        return False, "URL is empty."
    if len(raw) > 2048:
        return False, "URL exceeds 2048 characters."
    if re.search(r"\s", raw):
        return False, "URL must not contain whitespace."
    if "://" not in raw and not raw.lower().startswith("www."):
        return False, "URL must include a scheme (for example https://) or start with www."
    return True, "Valid URL string."


def validate_upload_filename(filename: str) -> Tuple[bool, str]:
    """Validate an uploaded file name.

    Checks, in order:
      1. not empty,
      2. no path-traversal sequence,
      3. no directory component,
      4. no illegal characters,
      5. extension is in ``ALLOWED_UPLOAD_EXTENSIONS`` (default .txt/.eml).
    """
    name = sanitize_text(filename, 255).strip()
    if not name:
        return False, "Filename is empty."
    if _PATH_TRAVERSAL.search(name):
        return False, "Filename contains a path-traversal sequence."
    if os.path.basename(name) != name:
        return False, "Filename must not contain a directory component."
    if _ILLEGAL_FILENAME_CHARS.search(name):
        return False, "Filename contains illegal characters."
    ext = os.path.splitext(name)[1].lower()
    if ext not in settings.ALLOWED_UPLOAD_EXTENSIONS:
        allowed = ", ".join(settings.ALLOWED_UPLOAD_EXTENSIONS)
        return False, f"Only {allowed} sample files may be uploaded (received '{ext or 'no extension'}')."
    return True, "Filename accepted."


def validate_upload_size(size_bytes: int) -> Tuple[bool, str]:
    """Reject uploads larger than ``MAX_UPLOAD_BYTES`` (default 256 KB)."""
    if size_bytes <= 0:
        return False, "Uploaded file is empty."
    if size_bytes > settings.MAX_UPLOAD_BYTES:
        limit_kb = settings.MAX_UPLOAD_BYTES // 1024
        return False, f"Uploaded file exceeds the {limit_kb} KB limit."
    return True, "Upload size accepted."


def validate_attachment_name(filename: Optional[str]) -> Tuple[bool, str]:
    """Validate an attachment *name* typed into the analyzer form.

    The attachment is never uploaded or executed - only its name is analysed.
    """
    if filename is None or str(filename).strip() == "":
        return True, "No attachment supplied."
    name = sanitize_text(filename, 255).strip()
    if _PATH_TRAVERSAL.search(name):
        return False, "Attachment name contains a path-traversal sequence."
    if len(name) > 255:
        return False, "Attachment name exceeds 255 characters."
    return True, "Attachment name accepted."


def validate_classification(value: Optional[str], allowed: List[str]) -> Tuple[bool, str]:
    """Validate a ``classification`` query-string filter against a whitelist."""
    if value is None or value == "":
        return True, "No classification filter."
    if value.upper() not in [a.upper() for a in allowed]:
        return False, f"Unknown classification '{value}'. Allowed: {', '.join(allowed)}."
    return True, "Classification filter accepted."
