from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .api import incidents
from .core.database import engine, Base

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
    allow_origins=["*"],  # For development only
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(incidents.router)

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