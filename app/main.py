"""
PII Anonymization Service - FastAPI Application (Multi-tenant)
"""
import logging
import time
import json
from pathlib import Path
from contextlib import asynccontextmanager
from typing import Optional

import structlog
from fastapi import FastAPI, HTTPException, Request, status, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
from starlette.responses import Response
from pydantic import BaseModel, Field

from .config import settings
from .models import (
    AnonymizeRequest, AnonymizeResponse,
    DeanonymizeRequest, DeanonymizeResponse,
    HealthResponse, ErrorResponse,
)
from .anonymizer import anonymizer
from .llm_service import llm_service
from .dependencies import get_current_user, get_current_user_optional
from .integration import (
    platform_integration,
    PlatformAnonymizeResponse, PlatformDeanonymizeResponse,
)
from .openai_proxy import (
    openai_proxy_service, OpenAIProxyRequest, OpenAIProxyResponse,
)
from .routers.auth_router import router as auth_router
from .routers.user_router import router as user_router
from .routers.data_viewer_router import router as data_viewer_router
from .routers.admin_router import router as admin_router


# Models for white-label integration API
class ProcessMessageRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=10000)
    agent_id: Optional[str] = None
    session_id: Optional[str] = None
    return_mapping: bool = False


class ProcessMessageResponse(BaseModel):
    original_message: str
    safe_message: str
    mapping_id: str
    pii_detected: list = Field(default_factory=list)
    processing_time_ms: int
    has_pii: bool


# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer() if settings.log_format == "json"
        else structlog.dev.ConsoleRenderer(),
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()

# Prometheus metrics
REQUEST_COUNT = Counter("pii_anonymizer_requests_total", "Total requests", ["endpoint", "status"])
REQUEST_LATENCY = Histogram("pii_anonymizer_request_duration_seconds", "Request latency", ["endpoint"], buckets=[0.5, 1.0, 2.0, 3.0, 4.0, 5.0, 10.0])
INFERENCE_LATENCY = Histogram("pii_anonymizer_inference_duration_seconds", "LLM inference latency", buckets=[1.0, 2.0, 3.0, 4.0, 5.0, 7.5, 10.0])
PII_DETECTED = Counter("pii_anonymizer_pii_detected_total", "Total PII items detected", ["pii_type"])

SERVICE_START_TIME = time.time()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting PII Anonymization Service...")

    # Initialize database
    try:
        from .database import init_database
        init_database()
        logger.info("Database initialized")
    except Exception as e:
        logger.warning(f"Could not initialize database: {e}")

    # Initialize multi-tenant tables
    try:
        from .platform_db import init_platform_tables
        init_platform_tables()
        logger.info("Multi-tenant tables initialized")
    except Exception as e:
        logger.warning(f"Could not initialize platform tables: {e}")

    # Start background sync service
    try:
        from .client_db_sync import sync_service
        await sync_service.start()
    except Exception as e:
        logger.warning(f"Could not start sync service: {e}")

    # Load LLM model if enabled
    if settings.use_llm:
        logger.info(f"Loading model from {settings.model_path}...")
        success = llm_service.load_model()
        if not success:
            logger.error("Failed to load model!")
        else:
            logger.info("Model loaded successfully", **llm_service.get_stats())
    else:
        logger.info("Running in regex-only mode (LLM disabled)")

    yield

    # Cleanup
    try:
        from .client_db_sync import sync_service
        await sync_service.stop()
    except Exception:
        pass
    logger.info("Shutting down PII Anonymization Service...")


app = FastAPI(
    title="PII Anonymization Service",
    description="AI-powered PII anonymization with multi-tenant support.",
    version="2.0.0",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth_router)
app.include_router(user_router)
app.include_router(data_viewer_router)
app.include_router(admin_router)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    duration = time.time() - start_time
    logger.info("request", method=request.method, path=request.url.path,
                status_code=response.status_code, duration_ms=int(duration * 1000))
    return response


# === Public Endpoints ===

@app.post("/anonymize", response_model=AnonymizeResponse, responses={500: {"model": ErrorResponse}, 503: {"model": ErrorResponse}})
async def anonymize_text(request: AnonymizeRequest):
    start_time = time.time()
    use_llm = request.use_llm if request.use_llm is not None else settings.use_llm
    if use_llm and not llm_service.is_loaded:
        raise HTTPException(status_code=503, detail="Model not loaded")
    try:
        anonymized_text, mapping, pii_types, processing_time_ms = anonymizer.anonymize(
            request.text,
            use_llm=request.use_llm,
            seed_values=request.seed_values,
        )
        mapping_id = anonymizer.store_mapping(mapping)
        REQUEST_COUNT.labels(endpoint="/anonymize", status="success").inc()
        REQUEST_LATENCY.labels(endpoint="/anonymize").observe(time.time() - start_time)
        for pt in pii_types:
            PII_DETECTED.labels(pii_type=pt).inc()
        return AnonymizeResponse(original=request.text, anonymized=anonymized_text,
                                 mapping=mapping if request.return_mapping else None,
                                 mapping_id=mapping_id, processing_time_ms=processing_time_ms, pii_found=pii_types)
    except Exception as e:
        REQUEST_COUNT.labels(endpoint="/anonymize", status="error").inc()
        raise HTTPException(status_code=500, detail=f"Anonymization failed: {str(e)}")


@app.post("/deanonymize", response_model=DeanonymizeResponse, responses={400: {"model": ErrorResponse}, 404: {"model": ErrorResponse}})
async def deanonymize_text(request: DeanonymizeRequest):
    start_time = time.time()
    if request.mapping:
        mapping = request.mapping
    elif request.mapping_id:
        mapping = anonymizer.get_mapping(request.mapping_id)
        if mapping is None:
            raise HTTPException(status_code=404, detail=f"Mapping not found: {request.mapping_id}")
    else:
        raise HTTPException(status_code=400, detail="Either mapping_id or mapping must be provided")
    restored_text = anonymizer.deanonymize(request.text, mapping)
    processing_time_ms = int((time.time() - start_time) * 1000)
    return DeanonymizeResponse(anonymized=request.text, restored=restored_text, processing_time_ms=processing_time_ms)


@app.get("/health", response_model=HealthResponse)
async def health_check():
    return HealthResponse(status="healthy" if llm_service.is_loaded else "degraded",
                          model_loaded=llm_service.is_loaded, model_path=llm_service.model_path,
                          uptime_seconds=time.time() - SERVICE_START_TIME)


@app.get("/metrics")
async def metrics():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


# === White-label API v1 ===

@app.post("/api/v1/process", response_model=ProcessMessageResponse, tags=["Integration"])
async def process_message(request: ProcessMessageRequest):
    start_time = time.time()
    if settings.use_llm and not llm_service.is_loaded:
        raise HTTPException(status_code=503, detail="Model not loaded")
    try:
        anonymized_text, mapping, pii_types, processing_time_ms = anonymizer.anonymize(request.message)
        mapping_id = anonymizer.store_mapping(mapping)
        REQUEST_COUNT.labels(endpoint="/api/v1/process", status="success").inc()
        return ProcessMessageResponse(original_message=request.message, safe_message=anonymized_text,
                                      mapping_id=mapping_id, pii_detected=pii_types,
                                      processing_time_ms=processing_time_ms, has_pii=len(mapping) > 0)
    except Exception as e:
        REQUEST_COUNT.labels(endpoint="/api/v1/process", status="error").inc()
        raise HTTPException(status_code=500, detail=f"Processing failed: {str(e)}")


@app.post("/api/v1/restore", tags=["Integration"])
async def restore_message(text: str, mapping_id: str):
    mapping = anonymizer.get_mapping(mapping_id)
    if mapping is None:
        raise HTTPException(status_code=404, detail=f"Mapping not found: {mapping_id}")
    return {"restored_message": anonymizer.deanonymize(text, mapping)}


# === Platform Integration API v2 (authenticated) ===

async def parse_request_body(request: Request) -> dict:
    body = await request.body()
    body_str = body.decode('utf-8')
    try:
        data = json.loads(body_str)
        if isinstance(data, str):
            data = json.loads(data)
        return data
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {str(e)}")


@app.post("/api/v2/anonymize", response_model=PlatformAnonymizeResponse, tags=["Platform Integration"])
async def platform_anonymize(request: Request, user: dict = Depends(get_current_user)):
    data = await parse_request_body(request)
    message = data.get("message")
    if not message:
        raise HTTPException(status_code=400, detail="Field 'message' is required")
    logger.warning(
        f"[ANON-DEBUG] user_id={user.get('id')} message={message!r} "
        f"session_id={data.get('session_id')!r}"
    )
    result = platform_integration.anonymize_for_platform(
        message=message,
        page_id=data.get("page_id"),
        existing_session_id=data.get("session_id"), user_id=user.get("id"),
    )
    logger.warning(
        f"[ANON-DEBUG] result: session={result.session_id} anonymized={result.anonymized_message!r} "
        f"pii_count={result.pii_count} pii_found={result.pii_found}"
    )
    return result


@app.post("/api/v2/deanonymize", response_model=PlatformDeanonymizeResponse, tags=["Platform Integration"])
async def platform_deanonymize(request: Request, user: dict = Depends(get_current_user)):
    data = await parse_request_body(request)
    message = data.get("message")
    session_id = data.get("session_id")
    if not message:
        raise HTTPException(status_code=400, detail="Field 'message' is required")
    if not session_id:
        raise HTTPException(status_code=400, detail="Field 'session_id' is required")
    logger.warning(
        f"[DEANON-DEBUG] session_id={session_id!r} message={message!r}"
    )
    result = platform_integration.deanonymize_for_platform(
        message=message, session_id=session_id, user_id=user.get("id"),
    )
    logger.warning(
        f"[DEANON-DEBUG] result: success={result.success} restored={result.restored_message!r}"
    )
    return result


@app.post("/api/v2/openai-proxy", response_model=OpenAIProxyResponse, tags=["Platform Integration"])
async def openai_proxy(request: Request, user: dict = Depends(get_current_user)):
    data = await parse_request_body(request)
    try:
        proxy_request = OpenAIProxyRequest(**data)
        response = await openai_proxy_service.process_request(proxy_request)
        try:
            from .database import pii_db
            pii_db.log_action(action="openai_proxy", session_id=response.pii_session_id,
                              details={"model": proxy_request.model, "pii_count": response.pii_count},
                              user_id=user.get("id"))
        except Exception:
            pass
        return response
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Proxy error: {str(e)}")


@app.get("/api/v2/session/{session_id}", tags=["Platform Integration"])
async def get_session_info(session_id: str, user: dict = Depends(get_current_user)):
    try:
        from .database import pii_db
        session = pii_db.get_session(session_id)
        mapping = pii_db.get_mapping(session_id)
        return {"session": session, "mapping": mapping, "placeholder_count": len(mapping) if mapping else 0}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v2/stats", tags=["Platform Integration"])
async def get_db_stats(user: dict = Depends(get_current_user)):
    try:
        from .database import pii_db
        return pii_db.get_stats(user_id=user.get("id"))
    except Exception as e:
        return {"error": str(e), "using_memory_cache": True}


@app.get("/api/v2/sessions", tags=["Platform Integration"])
async def list_sessions(limit: int = 50, user: dict = Depends(get_current_user)):
    try:
        from .database import get_connection
        from psycopg2.extras import RealDictCursor
        with get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                user_id = user.get("id")
                if user_id:
                    cur.execute("""
                        SELECT s.session_id, s.page_id, s.created_at, s.expires_at,
                               COUNT(m.id) as mapping_count
                        FROM pii_sessions s LEFT JOIN pii_mappings m ON s.session_id = m.session_id
                        WHERE s.user_id = %s GROUP BY s.id ORDER BY s.created_at DESC LIMIT %s
                    """, (user_id, limit))
                else:
                    cur.execute("""
                        SELECT s.session_id, s.page_id, s.created_at, s.expires_at,
                               COUNT(m.id) as mapping_count
                        FROM pii_sessions s LEFT JOIN pii_mappings m ON s.session_id = m.session_id
                        GROUP BY s.id ORDER BY s.created_at DESC LIMIT %s
                    """, (limit,))
                return {"count": len(cur.fetchall() or []), "sessions": [dict(s) for s in cur.fetchall() or []]}
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/v2/mappings", tags=["Platform Integration"])
async def list_mappings(limit: int = 100, session_id: Optional[str] = None, user: dict = Depends(get_current_user)):
    try:
        from .database import get_connection
        from psycopg2.extras import RealDictCursor
        with get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                if session_id:
                    cur.execute("SELECT * FROM pii_mappings WHERE session_id = %s ORDER BY created_at DESC LIMIT %s", (session_id, limit))
                else:
                    cur.execute("SELECT * FROM pii_mappings ORDER BY created_at DESC LIMIT %s", (limit,))
                mappings = [dict(m) for m in cur.fetchall()]
                return {"count": len(mappings), "mappings": mappings}
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/v2/audit", tags=["Platform Integration"])
async def view_audit_log(limit: int = 50, user: dict = Depends(get_current_user)):
    try:
        from .database import get_connection
        from psycopg2.extras import RealDictCursor
        with get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT * FROM pii_audit_log ORDER BY created_at DESC LIMIT %s", (limit,))
                logs = cur.fetchall()
                return {"count": len(logs), "logs": [dict(l) for l in logs]}
    except Exception as e:
        return {"error": str(e)}


# === Web Interface ===

STATIC_DIR = Path(__file__).parent / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", include_in_schema=False)
async def root():
    return HTMLResponse('<script>window.location.href=localStorage.getItem("access_token")?"/dashboard":"/login"</script>')


@app.get("/login", include_in_schema=False)
async def login_page():
    login_file = STATIC_DIR / "login.html"
    if login_file.exists():
        return FileResponse(str(login_file))
    return HTMLResponse("<h1>Login page not found</h1>")


@app.get("/dashboard", include_in_schema=False)
async def dashboard_page():
    dash_file = STATIC_DIR / "dashboard.html"
    if dash_file.exists():
        return FileResponse(str(dash_file))
    return HTMLResponse("<h1>Dashboard not found</h1>")


@app.get("/admin", include_in_schema=False)
async def admin_panel():
    admin_file = STATIC_DIR / "admin.html"
    if admin_file.exists():
        return FileResponse(str(admin_file))
    return {"error": "Admin panel not found"}


@app.get("/client_schema.sql", include_in_schema=False)
async def download_schema():
    schema_file = Path(__file__).parent.parent / "client_schema.sql"
    if schema_file.exists():
        return FileResponse(str(schema_file), media_type="text/plain", filename="client_schema.sql")
    raise HTTPException(404, "Schema file not found")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=settings.host, port=settings.port,
                workers=settings.workers, log_level=settings.log_level.lower())
