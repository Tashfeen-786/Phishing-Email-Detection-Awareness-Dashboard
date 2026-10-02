"""
backend/app.py
==============
FastAPI application entry point.

RUN (from the project root)
---------------------------
    uvicorn backend.app:app --reload --host 127.0.0.1 --port 8000

    Swagger UI : http://127.0.0.1:8000/docs
    ReDoc      : http://127.0.0.1:8000/redoc
    OpenAPI    : http://127.0.0.1:8000/openapi.json

WHAT THIS FILE DOES
-------------------
1. builds the FastAPI app with rich OpenAPI metadata,
2. registers CORS for the Vite dev server (explicit origins, not "*"),
3. adds security response headers on every reply,
4. installs uniform JSON error handlers (no stack traces leak to clients),
5. mounts every router,
6. initialises the SQLite schema on startup.

SECURITY HEADERS SET ON EVERY RESPONSE
--------------------------------------
X-Content-Type-Options: nosniff          stop MIME sniffing
X-Frame-Options: DENY                    stop click-jacking
Referrer-Policy: no-referrer             do not leak URLs to third parties
Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none'
                                         the API returns JSON only, so nothing
                                         needs to be loadable from it. Even if a
                                         response were ever rendered as HTML,
                                         this policy blocks script execution.
Permissions-Policy                       disable camera/microphone/geolocation
Cache-Control: no-store (on /api/*)      analysis results are not cached
"""

from __future__ import annotations

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from backend.config import settings
from backend.models.database import init_db
from backend.routes import (
    analyze_routes,
    auth_routes,
    awareness_routes,
    dashboard_routes,
    history_routes,
)
from backend.services import ml_service
from backend.utils.logger import app_logger, log_security_event

DESCRIPTION = """
**Defensive** cybersecurity API for analysing email content, sender patterns, URLs,
attachment filenames and social-engineering indicators, and for producing an
**explainable** phishing risk assessment.

### Safety guarantees built into this API
* URLs are analysed as **text only** - the service never opens, resolves or fetches a link.
* Attachments are assessed from the **filename only** - nothing is downloaded, unpacked or executed.
* Email **bodies are not stored** by default; only safe metadata is persisted.
* Stored URLs are **defanged** (`hxxp://198[.]51[.]100[.]10/`) so no database row is clickable.
* All demonstration data uses reserved domains (RFC 2606 / RFC 6761) and documentation IP
  ranges (RFC 5737).

### Honesty guarantees
* A risk score is a **triage aid**, never proof. Every score ships with the rules that produced it.
* Rule weights and thresholds are **project assumptions** and are published at
  `GET /api/dashboard/rules`.
* If no ML model has been trained, `GET /api/ml/info` reports `available: false` - no metric is
  ever invented.

*This project is designed for cybersecurity education and defensive analysis using synthetic or
authorized data.*
"""

TAGS_METADATA = [
    {"name": "Analysis", "description": "Analyse emails and URLs. Static and non-executing."},
    {"name": "History", "description": "Stored analysis metadata: list, read, delete."},
    {"name": "Dashboard", "description": "Aggregated analytics for the SOC dashboard."},
    {"name": "Awareness", "description": "Security-awareness content, playbooks and MITRE mapping."},
    {"name": "Authentication (optional)",
     "description": "Local accounts. Disabled by default; enable with REQUIRE_AUTH=true."},
    {"name": "System", "description": "Health and metadata."},
]

app = FastAPI(
    title=settings.APP_NAME,
    description=DESCRIPTION,
    version=settings.APP_VERSION,
    openapi_tags=TAGS_METADATA,
    contact={"name": "Phishing Email Detection & Awareness Dashboard",
             "url": "http://127.0.0.1:8000/docs"},
    license_info={"name": "MIT (educational use)"},
)

# ---------------------------------------------------------------------------
# CORS - explicit origins, never "*" together with credentials
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.CORS_ALLOW_ALL else settings.CORS_ORIGINS,
    allow_origin_regex=None if settings.CORS_ALLOW_ALL else r"http://(localhost|127\.0\.0\.1):\d+",
    allow_credentials=not settings.CORS_ALLOW_ALL,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
    max_age=600,
)


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------
@app.middleware("http")
async def security_headers(request: Request, call_next):
    """Attach defensive response headers to every reply."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["X-Phishguard-Safety"] = "static-analysis-only; no-url-fetch; no-file-execution"
    path = request.url.path
    if path.startswith("/api"):
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
        )
        response.headers["Cache-Control"] = "no-store"
    return response


# ---------------------------------------------------------------------------
# Uniform error handling - clients get JSON, servers get the stack trace
# ---------------------------------------------------------------------------
@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    """422 with a readable summary of what failed validation."""
    problems = [
        {"field": ".".join(str(p) for p in err.get("loc", []) if p != "body"),
         "message": err.get("msg", "invalid value")}
        for err in exc.errors()
    ]
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"error": "Validation error",
                 "detail": "; ".join(f"{p['field']}: {p['message']}" for p in problems) or
                           "Request body failed validation.",
                 "problems": problems,
                 "status_code": status.HTTP_422_UNPROCESSABLE_ENTITY,
                 "path": str(request.url.path)},
    )


@app.exception_handler(StarletteHTTPException)
async def http_error_handler(request: Request, exc: StarletteHTTPException):
    """Consistent JSON envelope for every HTTPException."""
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": "Request failed", "detail": str(exc.detail),
                 "status_code": exc.status_code, "path": str(request.url.path)},
        headers=getattr(exc, "headers", None),
    )


@app.exception_handler(Exception)
async def unhandled_error_handler(request: Request, exc: Exception):
    """500 without leaking internals. The full trace goes to the server log only."""
    app_logger.exception("Unhandled error on %s: %s", request.url.path, exc)
    log_security_event("server.error", path=str(request.url.path), error=type(exc).__name__)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": "Internal server error",
                 "detail": "An unexpected error occurred. See the server log for details.",
                 "status_code": 500, "path": str(request.url.path)},
    )


# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------
app.include_router(analyze_routes.router)
app.include_router(history_routes.router)
app.include_router(dashboard_routes.router)
app.include_router(awareness_routes.router)
app.include_router(auth_routes.router)


# ---------------------------------------------------------------------------
# System endpoints
# ---------------------------------------------------------------------------
@app.get("/", tags=["System"], summary="API root")
def root():
    """Basic service metadata and where to find the docs."""
    return {
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "running",
        "docs": "/docs",
        "openapi": "/openapi.json",
        "dashboard_hint": "Start the React frontend and open http://localhost:5173",
        "safety": ("Defensive project. URLs are never fetched; attachments are never executed; "
                   "all demonstration data is synthetic."),
        "disclaimer": ("This project is designed for cybersecurity education and defensive "
                       "analysis using synthetic or authorized data."),
    }


@app.get("/api/health", tags=["System"], summary="Health check")
def health():
    """Report service health, ML availability, database and dataset presence."""
    db_ok, db_detail = True, "ok"
    try:
        from backend.models.database import table_names
        tables = table_names()
        db_ok = "analyses" in tables
        db_detail = f"{len(tables)} tables"
    except Exception as exc:                            # pragma: no cover
        db_ok, db_detail = False, str(exc)
    return {
        "status": "healthy" if db_ok else "degraded",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "ml_available": ml_service.is_available(),
        "database": db_detail,
        "dataset_present": settings.DATASET_PATH.exists(),
        "details": {
            "environment": settings.ENVIRONMENT,
            "database_path": str(settings.DATABASE_PATH),
            "model_path": str(settings.MODEL_PATH),
            "store_email_body": settings.STORE_EMAIL_BODY,
            "require_auth": settings.REQUIRE_AUTH,
            "rate_limit": f"{settings.RATE_LIMIT_REQUESTS}/{settings.RATE_LIMIT_WINDOW_SECONDS}s"
            if settings.RATE_LIMIT_ENABLED else "disabled",
        },
    }


@app.on_event("startup")
def on_startup() -> None:
    """Create the database schema and report the ML model state."""
    settings.ensure_directories()
    init_db()
    available = ml_service.is_available()
    app_logger.info("%s v%s started (ML model %s)", settings.APP_NAME, settings.APP_VERSION,
                    "loaded" if available else "not trained - rule engine only")
    log_security_event("app.startup", version=settings.APP_VERSION, ml_available=available)


if __name__ == "__main__":                              # pragma: no cover
    import uvicorn
    uvicorn.run("backend.app:app", host=settings.HOST, port=settings.PORT, reload=True)
