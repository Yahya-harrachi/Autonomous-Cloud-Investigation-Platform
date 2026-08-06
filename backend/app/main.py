from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import asyncio

load_dotenv()

from .api.routes import ingestion
from .api.routes import incidents
from .api.routes import rules  
from .api.routes.debug import cloudtrail, cloudtrail_normalized
from .api.routes import sqs
from .api.routes import websocket  # Add this
from .core.database import engine, Base
from .models.incident import IncidentModel
from .domain.models.risk_rule import RuleModel


# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="ACIP - Autonomous Cloud Investigation Platform",
    description="Automated cloud incident investigation system",
    version="0.1.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(ingestion.router)
app.include_router(incidents.router)
app.include_router(rules.router)  
app.include_router(cloudtrail.router)
app.include_router(cloudtrail_normalized.router)
app.include_router(sqs.router)
app.include_router(websocket.router)  # Add this

@app.get("/")
async def root():
    return {
        "message": "ACIP API is running",
        "status": "healthy",
        "version": "0.1.0"
    }

@app.get("/health")
async def health_check():
    return {"status": "healthy", "database": "connected"}


# Startup event to ensure event loop is running
from .services.sqs_consumer import start_consumer

@app.on_event("startup")
async def startup_event():
    # Start SQS consumer automatically
    start_consumer()
    print("✅ SQS Consumer auto-started"),