# app/api/routes/__init__.py
from fastapi import APIRouter
from .incidents import router as incidents_router
from .evidence import router as evidence_router  
from .rules import router as rules_router

router = APIRouter()
router.include_router(incidents_router)
router.include_router(evidence_router)  
router.include_router(rules_router)