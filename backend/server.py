from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from database import init_db
import os

# Import routes
from routes import auth_routes, station_routes, report_routes, alert_routes, collaboration_routes, analytics_routes

app = FastAPI(
    title="WaterWatch API",
    description="Water Quality Monitoring Platform",
    version="1.0.0"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create uploads directory
os.makedirs("uploads", exist_ok=True)
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")

# Initialize database
@app.on_event("startup")
def startup_event():
    init_db()

# Include routers
app.include_router(auth_routes.router)
app.include_router(station_routes.router)
app.include_router(report_routes.router)
app.include_router(alert_routes.router)
app.include_router(collaboration_routes.router)
app.include_router(analytics_routes.router)

@app.get("/")
def root():
    return {
        "message": "WaterWatch API",
        "version": "1.0.0",
        "status": "running"
    }

@app.get("/api/health")
def health_check():
    return {"status": "healthy"}
