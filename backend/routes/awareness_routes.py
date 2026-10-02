"""
backend/routes/awareness_routes.py
==================================
Security-awareness endpoints (read-only educational content).

===========================================================================
API CONTRACT
===========================================================================
GET /api/awareness              Full awareness bundle (all sections).
GET /api/awareness/lessons      The six micro-lessons only.
GET /api/awareness/checklist    "Before You Click" checklist + the 10 checks.
GET /api/awareness/simulations  SAFE training templates + the safety note.
GET /api/awareness/soc          SOC analyst workflow + the "supports, does not
                                replace" note.
GET /api/awareness/mitre        Conceptual MITRE ATT&CK mapping.
GET /api/awareness/errors       False-positive / false-negative explanations.

All are public, require no authentication, take no parameters (except the
optional ``lesson_id`` path parameter) and return 200 with static JSON.
404 is returned for an unknown lesson id.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Path, status

from backend.services.awareness_content import (
    BEFORE_YOU_CLICK,
    FALSE_POSITIVE_NEGATIVE,
    HOW_TO_SPOT,
    MICRO_LESSONS,
    MITRE_MAPPING,
    PLAYBOOK,
    SIMULATION_SAFETY_NOTE,
    SIMULATION_TEMPLATES,
    SOC_WORKFLOW,
    SOC_WORKFLOW_NOTE,
    get_all_content,
)

router = APIRouter(prefix="/api/awareness", tags=["Awareness"])


@router.get("", summary="Complete security-awareness content bundle")
def awareness_all():
    """Everything the Awareness page needs, in one request."""
    return get_all_content()


@router.get("/lessons", summary="Micro-lessons")
def lessons():
    """Six 60-90 second lessons."""
    return {"micro_lessons": MICRO_LESSONS, "count": len(MICRO_LESSONS)}


@router.get("/lessons/{lesson_id}", summary="One micro-lesson")
def lesson(lesson_id: str = Path(..., max_length=64)):
    """Return a single lesson by id, or 404."""
    for item in MICRO_LESSONS:
        if item["id"] == lesson_id:
            return item
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                        detail=f"No micro-lesson with id '{lesson_id}'.")


@router.get("/checklist", summary="How to spot phishing + Before You Click")
def checklist():
    """The 10 checks and the pre-click checklist."""
    return {"how_to_spot": HOW_TO_SPOT, "before_you_click": BEFORE_YOU_CLICK,
            "playbook": PLAYBOOK}


@router.get("/simulations", summary="Safe awareness-training templates")
def simulations():
    """Training templates. This application cannot send email - see the note."""
    return {"templates": SIMULATION_TEMPLATES, "safety_note": SIMULATION_SAFETY_NOTE}


@router.get("/soc", summary="SOC analyst workflow")
def soc():
    """The ten-stage triage workflow a SOC analyst follows."""
    return {"workflow": SOC_WORKFLOW, "note": SOC_WORKFLOW_NOTE}


@router.get("/mitre", summary="Conceptual MITRE ATT&CK mapping")
def mitre():
    """Phishing-related ATT&CK techniques and how this project relates to them."""
    return MITRE_MAPPING


@router.get("/errors", summary="False positives and false negatives explained")
def errors():
    """Worked examples of both error types and why multiple signals matter."""
    return FALSE_POSITIVE_NEGATIVE
