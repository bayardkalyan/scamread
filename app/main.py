"""Create and configure the FastAPI application."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app import config
from app.analysis import patterns as pattern_store
from app.routes.admin import router as admin_router
from app.routes.api import APP_VERSION, router as api_router
from app.routes.intelligence import router as intelligence_router
from app.routes.web import router as web_router
from app.security.headers import SecurityHeadersMiddleware
from app.services import campaign_store, observations
from app.services.database import ensure_schema

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Everything slow happens once here, not on each check.
    ensure_schema()
    pattern_store.seed_database()
    pattern_store.reload_now()
    campaign_store.refresh_index()
    observations.start()
    yield
    observations.stop()


app = FastAPI(
    title="ScamRead",
    description="A deterministic scam-risk analyzer for suspicious messages and links.",
    version=APP_VERSION,
    lifespan=lifespan,
    # API docs are only shown when running locally in development mode.
    docs_url=None if config.IS_PRODUCTION else "/docs",
    redoc_url=None,
    openapi_url=None if config.IS_PRODUCTION else "/openapi.json",
)

app.add_middleware(SecurityHeadersMiddleware, hsts=config.IS_PRODUCTION)
app.mount("/static", StaticFiles(directory=config.PROJECT_ROOT / "static"), name="static")

app.include_router(web_router)
app.include_router(api_router)
app.include_router(intelligence_router)
app.include_router(admin_router)
