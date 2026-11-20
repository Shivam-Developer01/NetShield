"""
NetShield ML Service Standalone Runner
Executes the FastAPI ML Inference microservice using environment configuration.
Can be executed from project root via: python ml_service/run_server.py
"""

import os
import sys

# Add project root to sys.path for robust module resolution
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Attempt loading environment variables from .env file if available
try:
    from dotenv import load_dotenv
    env_file = os.path.join(os.path.dirname(__file__), ".env")
    if os.path.exists(env_file):
        load_dotenv(env_file)
except ImportError:
    pass


def main():
    import uvicorn
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", 8000))
    workers = int(os.getenv("WORKERS", 1))
    log_level = os.getenv("LOG_LEVEL", "info").lower()

    print("=" * 60)
    print("STARTING NETSHIELD FASTAPI ML INFERENCE SERVICE")
    print("=" * 60)
    print(f"  -> Host: {host}")
    print(f"  -> Port: {port}")
    print(f"  -> Workers: {workers} (Resource-conscious CPU mode)")
    print(f"  -> OpenAPI Docs: http://{host}:{port}/docs")
    print("=" * 60)

    uvicorn.run(
        "ml_service.src.api.app:app",
        host=host,
        port=port,
        workers=workers,
        log_level=log_level
    )


if __name__ == "__main__":
    main()
