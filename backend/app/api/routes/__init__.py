# app/api/routes/__init__.py
from fastapi import APIRouter
from app.api.routes.incidents import router as incidents_router
from app.api.routes.rules import router as rules_router

# Create main router
router = APIRouter()

# Include all routers
router.include_router(incidents_router, prefix="/api")
router.include_router(rules_router, prefix="/api")