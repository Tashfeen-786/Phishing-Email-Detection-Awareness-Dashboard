"""
backend/routes/history_routes.py
================================
Analysis-history endpoints.

===========================================================================
API CONTRACT
===========================================================================

GET /api/analyses
    Purpose        List stored analyses with filter / search / sort / paging.
    Query params   classification  (LOW RISK | MODERATE RISK | SUSPICIOUS |
                                    HIGH RISK / LIKELY PHISHING)
                   search          matches subject or sender_domain (LIKE)
                   min_score, max_score   0-100
                   sort_by         created_at | risk_score | classification |
                                   sender_domain | subject   (whitelisted)
                   order           asc | desc
                   limit           1-500 (default 50)
                   offset          >= 0
    Validation     classification is checked against the allowed list;
                   sort_by is resolved through a whitelist (never interpolated
                   from user input) -> SQL injection is impossible.
    Auth           Not required by default.
    Response 200   {items, total, limit, offset, sort_by, order}
    Errors         422 unknown classification / invalid range

GET /api/analyses/{analysis_id}
    Purpose        One stored analysis with its indicators and URL rows.
    Validation     Path parameter length bounded.
    Response 200   Analysis record; 404 when the id does not exist.

DELETE /api/analyses/{analysis_id}
    Purpose        Delete one analysis. Indicators and URL rows cascade.
    Auth           Required ONLY when REQUIRE_AUTH=true (see .env.example).
                   When enabled, an 'Authorization: Bearer <token>' header from
                   POST /api/login must be supplied, otherwise 401.
    Authorization  Any authenticated role may delete its own history in this
                   single-tenant student build; docs/SECURITY.md describes the
                   per-owner model needed for multi-user deployments.
    Response 200   {message: "..."}         404 when the id does not exist.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status

from backend.models import repository
from backend.models.schemas import AnalysisListResponse, MessageResponse
from backend.routes.auth_routes import require_auth_if_enabled
from backend.services.risk_engine import CLASSIFICATIONS
from backend.utils.logger import log_security_event
from backend.utils.validators import validate_classification

router = APIRouter(prefix="/api", tags=["History"])


@router.get("/analyses", response_model=AnalysisListResponse,
            summary="List stored analyses (filter, search, sort, paginate)")
def list_analyses(
    classification: str | None = Query(default=None, max_length=40,
                                       description="Exact classification filter."),
    search: str | None = Query(default=None, max_length=100,
                               description="Substring match on subject or sender domain."),
    min_score: int | None = Query(default=None, ge=0, le=100),
    max_score: int | None = Query(default=None, ge=0, le=100),
    sort_by: str = Query(default="created_at",
                         pattern="^(created_at|risk_score|classification|sender_domain|subject)$"),
    order: str = Query(default="desc", pattern="^(asc|desc)$"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    """Return a page of the analysis history."""
    ok, reason = validate_classification(classification, CLASSIFICATIONS)
    if not ok:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=reason)
    if min_score is not None and max_score is not None and min_score > max_score:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                            detail="min_score must not be greater than max_score.")
    return repository.list_analyses(
        classification=classification, search=search, min_score=min_score,
        max_score=max_score, sort_by=sort_by, order=order, limit=limit, offset=offset,
    )


@router.get("/analyses/{analysis_id}", summary="Get one stored analysis")
def get_analysis(analysis_id: str = Path(..., min_length=1, max_length=64)):
    """Return one stored analysis including indicators and defanged URL rows."""
    record = repository.get_analysis(analysis_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail=f"No analysis found with id '{analysis_id}'.")
    return record


@router.delete("/analyses/{analysis_id}", response_model=MessageResponse,
               summary="Delete one stored analysis")
def delete_analysis(request: Request,
                    analysis_id: str = Path(..., min_length=1, max_length=64),
                    principal: dict | None = Depends(require_auth_if_enabled)):
    """Delete an analysis. Indicators and URL rows are removed by ON DELETE CASCADE."""
    deleted = repository.delete_analysis(analysis_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail=f"No analysis found with id '{analysis_id}'.")
    log_security_event("analysis.deleted", analysis_id=analysis_id,
                       actor=(principal or {}).get("sub", "anonymous"))
    return {"message": "Analysis deleted.", "detail": analysis_id}
