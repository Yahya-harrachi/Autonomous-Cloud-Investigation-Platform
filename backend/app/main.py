from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .api.routes import ingestion
from .api.routes import incidents  # Existing incident endpoints
from .core.database import engine, Base
from .models.incident import IncidentModel  # Import to create table
from .api.routes.debug import cloudtrail, cloudtrail_normalized

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
app.include_router(cloudtrail.router)
app.include_router(cloudtrail_normalized.router)  


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