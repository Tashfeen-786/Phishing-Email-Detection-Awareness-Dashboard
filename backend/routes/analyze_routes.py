"""
backend/routes/analyze_routes.py
================================
Analysis endpoints.

===========================================================================
API CONTRACT
===========================================================================

POST /api/analyze
    Purpose        Run the full phishing-analysis workflow on one email.
    Request        JSON EmailAnalysisRequest
                   {sender, subject, body, urls?, attachment_name?,
                    display_name?, save?, use_ml?}
    Validation     Pydantic types + max lengths; sanitise control characters;
                   at least one of subject/body must be non-empty.
    Auth           Not required (public analyser). Optional bearer token is
                   accepted and recorded when supplied.
    Authorization  n/a
    Rate limit     RATE_LIMIT_REQUESTS per RATE_LIMIT_WINDOW_SECONDS per IP.
    Response 200   Full analysis object (risk score, classification, findings,
                   recommendations, per-analyzer detail, features, ML, hybrid).
    Errors         422 validation error (empty subject AND body, bad types)
                   429 rate limit exceeded
                   500 unexpected server error (generic message, details logged)

POST /api/analyze/url
    Purpose        Static analysis of a single URL. The URL is NEVER opened.
    Request        JSON {url, display_text?}
    Validation     Non-empty, <= 2048 chars, no whitespace, scheme or 'www.'
    Auth           Not required.        Rate limit: same bucket as /api/analyze.
    Response 200   UrlAnalysisResponse
    Errors         422 invalid URL string, 429 rate limited

POST /api/analyze/upload
    Purpose        Analyse a SAFE sample file (.txt/.eml) instead of typing.
    Request        multipart/form-data: file=<sample>, save=<bool>
    Validation     Extension whitelist (.txt/.eml), size <= MAX_UPLOAD_BYTES,
                   filename has no path component and no traversal sequence.
    Auth           Not required.        Rate limit: same bucket.
    Response 200   Same shape as /api/analyze, plus ``parsed_from_file``.
    Errors         400 rejected file (reason given), 413 too large, 429

GET  /api/features
    Purpose        Documentation of every engineered feature.
    Response 200   {feature_names: [...], descriptions: {...}, count: int}

GET  /api/ml/info
    Purpose        Report whether an ML model is loaded, and its real metrics.
    Response 200   model_info() - ``available:false`` when not trained.
                   Metrics are read from the saved bundle; nothing is invented.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status

from backend.config import settings
from backend.models import repository
from backend.models.schemas import (
    AnalysisResponse,
    EmailAnalysisRequest,
    UrlAnalysisRequest,
    UrlAnalysisResponse,
)
from backend.services import ml_service
from backend.services.analysis_service import analyze_email, analyze_single_url
from backend.services.feature_extractor import FEATURE_NAMES, describe_features
from backend.services.preprocessing import parse_email_file
from backend.utils.logger import app_logger, log_security_event
from backend.utils.security import analysis_limiter
from backend.utils.validators import (
    validate_upload_filename,
    validate_upload_size,
    validate_url_string,
)

router = APIRouter(prefix="/api", tags=["Analysis"])


def _client_ip(request: Request) -> str:
    """Best-effort client identity for rate limiting."""
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def rate_limit(request: Request) -> None:
    """FastAPI dependency enforcing the analysis rate limit."""
    if not settings.RATE_LIMIT_ENABLED:
        return
    key = f"{_client_ip(request)}::analysis"
    allowed, remaining, retry_after = analysis_limiter.check(key)
    if not allowed:
        log_security_event("rate_limit.exceeded", client=_client_ip(request),
                           path=str(request.url.path), retry_after=retry_after)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Try again in {retry_after} second(s).",
            headers={"Retry-After": str(retry_after)},
        )


@router.post("/analyze", response_model=AnalysisResponse, status_code=status.HTTP_200_OK,
             summary="Analyse an email for phishing indicators",
             response_description="Explainable phishing risk assessment")
def analyze(payload: EmailAnalysisRequest, request: Request, _: None = Depends(rate_limit)):
    """Run the complete detection workflow and optionally store safe metadata."""
    if not payload.subject.strip() and not payload.body.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Provide at least a subject or a body to analyse.",
        )
    try:
        result = analyze_email(
            sender=payload.sender,
            subject=payload.subject,
            body=payload.body,
            urls=payload.urls,
            attachment_name=payload.attachment_name,
            display_name=payload.display_name,
            use_ml=payload.use_ml,
        )
    except Exception as exc:                                    # pragma: no cover
        app_logger.exception("Analysis failed: %s", exc)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="Analysis failed. See the server log for details.")

    result["saved"] = False
    result["analysis_id"] = None
    if payload.save:
        try:
            result["analysis_id"] = repository.save_analysis(result, source="api")
            result["saved"] = True
        except Exception as exc:                                # pragma: no cover
            app_logger.error("Could not save analysis: %s", exc)
            result["save_error"] = "Analysis completed but could not be saved to history."
    return result


@router.post("/analyze/url", response_model=UrlAnalysisResponse,
             summary="Statically analyse a single URL (never opened)",
             response_description="Static URL risk assessment")
def analyze_url_endpoint(payload: UrlAnalysisRequest, request: Request,
                         _: None = Depends(rate_limit)):
    """Analyse a URL as a STRING. No DNS, no HTTP request, no rendering."""
    ok, reason = validate_url_string(payload.url)
    if not ok:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=reason)
    return analyze_single_url(payload.url, payload.display_text)


@router.post("/analyze/upload", summary="Analyse an uploaded .txt/.eml sample",
             response_description="Explainable phishing risk assessment")
async def analyze_upload(request: Request, file: UploadFile = File(...),
                         save: bool = Form(default=True), _: None = Depends(rate_limit)):
    """Accept a SAFE sample file, parse it with the stdlib email parser, analyse it.

    SECURITY
    --------
    * extension whitelist (.txt/.eml) and size limit are enforced BEFORE parsing,
    * the file is read into memory and never written to disk,
    * the parser does not fetch remote content and does not execute anything,
    * HTML parts are reduced to visible text; raw HTML is never returned.
    """
    ok, reason = validate_upload_filename(file.filename or "")
    if not ok:
        log_security_event("upload.rejected", filename=str(file.filename), reason=reason,
                           client=_client_ip(request))
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=reason)

    content = await file.read(settings.MAX_UPLOAD_BYTES + 1)
    ok, reason = validate_upload_size(len(content))
    if not ok:
        log_security_event("upload.rejected", filename=str(file.filename), reason=reason,
                           size=len(content), client=_client_ip(request))
        code = (status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
                if len(content) > settings.MAX_UPLOAD_BYTES else status.HTTP_400_BAD_REQUEST)
        raise HTTPException(status_code=code, detail=reason)

    parsed = parse_email_file(content, file.filename or "sample.eml")
    if not parsed["subject"].strip() and not parsed["body"].strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="No readable subject or body was found in the uploaded file.")

    result = analyze_email(
        sender=parsed["sender"], subject=parsed["subject"], body=parsed["body"],
        attachment_name=parsed["attachment_name"],
    )
    result["parsed_from_file"] = {
        "filename": file.filename,
        "size_bytes": len(content),
        "sender": parsed["sender"],
        "subject": parsed["subject"],
        "attachment_name": parsed["attachment_name"],
    }
    result["saved"] = False
    result["analysis_id"] = None
    if save:
        result["analysis_id"] = repository.save_analysis(result, source="upload")
        result["saved"] = True
    log_security_event("upload.analyzed", filename=str(file.filename), size=len(content),
                       risk_score=result["risk_score"], classification=result["classification"])
    return result


@router.get("/features", summary="Documentation of the engineered features")
def features_documentation():
    """Return every feature name with a plain-English description."""
    return {
        "count": len(FEATURE_NAMES),
        "feature_names": FEATURE_NAMES,
        "descriptions": describe_features(),
        "note": ("These features are computed on the ORIGINAL text. A separate, lightly "
                 "cleaned copy is used for TF-IDF so that cleaning never destroys evidence."),
    }


@router.get("/ml/info", summary="Machine-learning model status and real metrics")
def ml_info():
    """Report the loaded model and the metrics recorded at training time.

    When no model has been trained this returns ``available: false`` with the
    reason. No metric is ever invented.
    """
    return ml_service.model_info()
