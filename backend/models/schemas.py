"""
backend/models/schemas.py
=========================
PURPOSE
-------
Pydantic v2 request/response models.

WHY THIS MATTERS FOR SECURITY
-----------------------------
Pydantic is the FIRST validation layer of the API:

  * every field has an explicit type and a maximum length, so an oversized or
    malformed payload is rejected with HTTP 422 before it reaches any analyzer,
  * unknown fields are ignored rather than trusted,
  * field validators strip control characters via ``sanitize_text``,
  * FastAPI turns these models into the OpenAPI/Swagger schema automatically,
    which is the API documentation served at /docs.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from backend.utils.text_utils import sanitize_text


# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------
class EmailAnalysisRequest(BaseModel):
    """Body of ``POST /api/analyze``."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "sender": "security-alert@account-check.invalid.test",
                "subject": "URGENT: Verify Your Account Immediately",
                "body": ("Dear Customer,\n\nWe detected unusual sign-in activity. Your account "
                         "will be suspended within 24 hours unless you verify your password "
                         "immediately.\n\nVerify here: http://198.51.100.10/verify-account\n\n"
                         "Account Security Team"),
                "urls": "http://198.51.100.10/verify-account",
                "attachment_name": "account_form.pdf",
                "display_name": "Account Security Team",
                "save": True,
                "use_ml": True,
            }
        }
    )

    sender: str = Field(default="", max_length=320,
                        description="Sender address, optionally 'Name <addr@domain>'.")
    subject: str = Field(default="", max_length=998, description="Email subject line.")
    body: str = Field(default="", max_length=50_000, description="Plain-text email body.")
    urls: Optional[str] = Field(default=None, max_length=8_000,
                                description="Optional extra URLs, whitespace separated. "
                                            "URLs inside the body are detected automatically.")
    attachment_name: Optional[str] = Field(default=None, max_length=255,
                                           description="Attachment FILENAME only - never file content.")
    display_name: Optional[str] = Field(default=None, max_length=200,
                                        description="Optional sender display name.")
    save: bool = Field(default=True, description="Persist safe metadata to the history table.")
    use_ml: bool = Field(default=True, description="Include the optional ML prediction.")

    @field_validator("sender", "subject", "body", "urls", "attachment_name", "display_name")
    @classmethod
    def _clean(cls, v):
        return sanitize_text(v) if v is not None else v


class UrlAnalysisRequest(BaseModel):
    """Body of ``POST /api/analyze/url``."""

    model_config = ConfigDict(
        json_schema_extra={"example": {"url": "http://198.51.100.10/verify-account",
                                       "display_text": "https://www.example.org/login"}}
    )

    url: str = Field(min_length=1, max_length=2048, description="URL to analyse STATICALLY.")
    display_text: Optional[str] = Field(default=None, max_length=300,
                                        description="Optional visible link text, to detect a "
                                                    "displayed-vs-destination mismatch.")

    @field_validator("url", "display_text")
    @classmethod
    def _clean(cls, v):
        return sanitize_text(v, 2048) if v is not None else v


class RegisterRequest(BaseModel):
    """Body of ``POST /api/register`` (optional authentication module)."""

    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.\-]+$")
    password: str = Field(min_length=8, max_length=128)
    role: str = Field(default="analyst", pattern=r"^(analyst|admin)$")


class LoginRequest(BaseModel):
    """Body of ``POST /api/login``."""

    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


# ---------------------------------------------------------------------------
# Responses
# ---------------------------------------------------------------------------
class FindingModel(BaseModel):
    category: str
    indicator_type: str
    description: str
    severity: str
    evidence: str = ""


class RecommendationModel(BaseModel):
    priority: str
    action: str
    detail: str


class AnalysisResponse(BaseModel):
    """Response of ``POST /api/analyze``.

    ``model_config extra='allow'`` keeps the full analyzer detail without having
    to restate the entire nested structure here; the important top-level fields
    stay typed and documented.
    """

    model_config = ConfigDict(extra="allow")

    analysis_id: Optional[str] = None
    analyzed_at: str
    risk_score: int = Field(ge=0, le=100)
    classification: str
    risk_state: str
    band_meaning: str
    why: List[str]
    indicator_count: int
    recommendations: List[RecommendationModel]
    detection_notes: List[str]
    assumption_note: str
    saved: bool = False


class UrlAnalysisResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    url: str
    safe_representation: str
    url_risk_score: int = Field(ge=0, le=100)
    suspicious: bool
    summary: str
    notes: List[str]


class AnalysisListItem(BaseModel):
    model_config = ConfigDict(extra="allow")

    analysis_id: str
    sender_domain: str
    subject: str
    risk_score: int
    classification: str
    created_at: str


class AnalysisListResponse(BaseModel):
    items: List[AnalysisListItem]
    total: int
    limit: int
    offset: int
    sort_by: str
    order: str


class DashboardStatsResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    total_analyzed: int
    likely_phishing: int
    suspicious: int
    low_risk: int
    average_risk_score: float


class MessageResponse(BaseModel):
    message: str
    detail: Optional[str] = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    username: str
    role: str


class ErrorResponse(BaseModel):
    """Uniform error envelope returned by the exception handlers."""

    error: str
    detail: str
    status_code: int
    path: Optional[str] = None


class HealthResponse(BaseModel):
    status: str
    app: str
    version: str
    ml_available: bool
    database: str
    dataset_present: bool
    details: Dict[str, Any] = {}
