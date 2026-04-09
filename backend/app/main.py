"""PhishNet FastAPI application entry point.

Configures middleware, exception handlers, routers, and lifecycle events.
"""

import time
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import ORJSONResponse

from app.config import settings
from app.database import close_db, init_db
from app.core.exceptions import (
    PhishNetException,
    phishnet_exception_handler,
    validation_exception_handler,
    generic_exception_handler,
)
from app.api.auth import router as auth_router
from app.api.urls import router as url_router
from app.api.emails import router as email_router
from app.api.threats import router as threat_router
from app.api.dashboard import router as dashboard_router
from app.api.reports import router as report_router
from app.api.extension import router as extension_router

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle: startup and shutdown hooks."""
    # Startup
    logger.info(
        "Starting PhishNet",
        version=settings.APP_VERSION,
        env=settings.APP_ENV,
    )

    if settings.is_testing:
        await init_db()

    logger.info("PhishNet started successfully")
    yield

    # Shutdown
    logger.info("Shutting down PhishNet")
    await close_db()
    logger.info("PhishNet shutdown complete")


def create_app() -> FastAPI:
    """Application factory: build and configure the FastAPI instance."""
    application = FastAPI(
        title=settings.APP_NAME,
        description=(
            "AI-powered phishing detection system. Analyzes URLs, emails, "
            "and web content to identify phishing threats using machine learning "
            "ensemble models including Random Forest, Gradient Boosting, and BERT."
        ),
        version=settings.APP_VERSION,
        docs_url="/docs" if not settings.is_production else None,
        redoc_url="/redoc" if not settings.is_production else None,
        openapi_url="/openapi.json" if not settings.is_production else None,
        default_response_class=ORJSONResponse,
        lifespan=lifespan,
    )

    # -------------------------------------------------------------------------
    # Middleware
    # -------------------------------------------------------------------------

    # CORS
    application.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID", "X-Process-Time"],
    )

    # Trusted hosts in production
    if settings.is_production:
        application.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=["*.phishnet.io", "phishnet.io"],
        )

    # Request timing middleware
    @application.middleware("http")
    async def add_process_time_header(request: Request, call_next):
        start_time = time.perf_counter()
        response: Response = await call_next(request)
        process_time = (time.perf_counter() - start_time) * 1000
        response.headers["X-Process-Time"] = f"{process_time:.2f}ms"
        return response

    # Request logging middleware
    @application.middleware("http")
    async def log_requests(request: Request, call_next):
        logger.info(
            "Request received",
            method=request.method,
            path=request.url.path,
            client=request.client.host if request.client else "unknown",
        )
        response = await call_next(request)
        logger.info(
            "Response sent",
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
        )
        return response

    # -------------------------------------------------------------------------
    # Exception handlers
    # -------------------------------------------------------------------------
    application.add_exception_handler(PhishNetException, phishnet_exception_handler)
    application.add_exception_handler(ValueError, validation_exception_handler)
    application.add_exception_handler(Exception, generic_exception_handler)

    # -------------------------------------------------------------------------
    # Routers
    # -------------------------------------------------------------------------
    api_prefix = settings.API_PREFIX

    application.include_router(
        auth_router,
        prefix=f"{api_prefix}/auth",
        tags=["Authentication"],
    )
    application.include_router(
        url_router,
        prefix=f"{api_prefix}/urls",
        tags=["URL Scanning"],
    )
    application.include_router(
        email_router,
        prefix=f"{api_prefix}/emails",
        tags=["Email Scanning"],
    )
    application.include_router(
        threat_router,
        prefix=f"{api_prefix}/threats",
        tags=["Threat Intelligence"],
    )
    application.include_router(
        dashboard_router,
        prefix=f"{api_prefix}/dashboard",
        tags=["Dashboard"],
    )
    application.include_router(
        report_router,
        prefix=f"{api_prefix}/reports",
        tags=["Reports"],
    )
    application.include_router(
        extension_router,
        prefix=f"{api_prefix}/extension",
        tags=["Browser Extension"],
    )

    # -------------------------------------------------------------------------
    # Health check endpoints
    # -------------------------------------------------------------------------
    @application.get("/health", tags=["Health"])
    async def health_check():
        return {
            "status": "healthy",
            "version": settings.APP_VERSION,
            "environment": settings.APP_ENV,
        }

    @application.get("/health/ready", tags=["Health"])
    async def readiness_check():
        """Check if all dependencies are available."""
        checks = {"api": True, "database": False, "redis": False}

        # Database check
        try:
            from app.database import engine

            async with engine.connect() as conn:
                await conn.execute("SELECT 1")
            checks["database"] = True
        except Exception:
            pass

        # Redis check
        try:
            import redis.asyncio as aioredis

            r = aioredis.from_url(settings.REDIS_URL)
            await r.ping()
            await r.close()
            checks["redis"] = True
        except Exception:
            pass

        all_healthy = all(checks.values())
        return {
            "status": "ready" if all_healthy else "degraded",
            "checks": checks,
        }

    return application


app = create_app()
