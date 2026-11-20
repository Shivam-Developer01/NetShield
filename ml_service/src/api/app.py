"""
NetShield FastAPI Service Core Application
Initializes FastAPI app, configures CORS, handles global exception sanitization,
request correlation tracing, and pre-loads ML production bundles at startup.
"""

import os
import sys
import uuid
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

# Ensure api and inference packages are in sys.path
API_DIR = os.path.dirname(__file__)
INFERENCE_DIR = os.path.abspath(os.path.join(API_DIR, "..", "inference"))

for d in [API_DIR, INFERENCE_DIR]:
    if d not in sys.path:
        sys.path.append(d)

from pipeline import get_inference_pipeline
from routes import router

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("netshield_ml_api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI Lifespan Context Manager.
    Pre-loads production model bundles into memory at server startup.
    """
    logger.info("Initializing NetShield ML Service...")
    try:
        pipeline = get_inference_pipeline()
        logger.info(f"Production ML models pre-loaded successfully: {list(pipeline.bundles.keys())}")
    except Exception as e:
        logger.error(f"Critical failure during production model startup: {e}")
    yield
    logger.info("Shutting down NetShield ML Service...")


app = FastAPI(
    title="NetShield ML Inference API",
    description=(
        "Production AI-Powered Network Intrusion Detection Inference Engine. "
        "Provides real-time multi-class classification for legacy (NSL-KDD) and modern (CICIDS2017) network traffic."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Request Correlation Middleware
@app.middleware("http")
async def add_request_id_middleware(request: Request, call_next):
    request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
    request.state.request_id = request_id
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response

# Configure CORS
cors_origins_env = os.getenv("CORS_ORIGINS", "http://localhost:3000,http://localhost:5173,http://127.0.0.1:3000,http://127.0.0.1:5173,http://backend:5000")
origins = [origin.strip() for origin in cors_origins_env.split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """
    Custom validation exception handler for clean HTTP 422 responses.
    Sanitizes errors and avoids exposing internal filesystem info.
    """
    errors = exc.errors()
    sanitized_errors = []
    for err in errors:
        msg = err.get("msg", "Invalid input value")
        loc = [str(item) for item in err.get("loc", []) if item != "body"]
        sanitized_errors.append({"field": ".".join(loc), "message": msg})

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "Unprocessable Entity",
            "message": "Input validation failed. Please check the required fields and value formats.",
            "details": sanitized_errors
        }
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Global catch-all exception handler to prevent raw traceback leakage.
    """
    req_id = getattr(request.state, "request_id", "unknown")
    logger.error(f"[{req_id}] Unhandled server error on {request.url}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal Server Error",
            "message": "An unexpected error occurred while processing the request."
        }
    )

# Register routes
app.include_router(router)


if __name__ == "__main__":
    import uvicorn
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("app:app", host=host, port=port, reload=False, workers=1)
