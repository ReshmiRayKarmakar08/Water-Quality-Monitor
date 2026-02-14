


from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlmodel import Session, select
from database import create_db_and_tables, get_session
# --- FIX: Added Alert to imports ---
from models import User, Report, Alert 
from auth import create_access_token, get_current_user
from pydantic import BaseModel
import hashlib
import requests
import urllib3
from typing import Dict, Any, Optional, List
import time
from datetime import datetime # --- FIX: Added datetime ---
from cachetools import TTLCache
# Disable SSL warnings (CPCB SSL issue)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = FastAPI()

# ---------- CORS MIDDLEWARE ----------
# ---------- CORS MIDDLEWARE ----------
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",     # React app
        "http://127.0.0.1:3000",     # React app (alternative)
        "http://localhost:5173",      # Vite app (agar Vite use kar rahe ho)
        "http://127.0.0.1:5173",      # Vite app (alternative)
        "*"                           # Allow all (temporary for development)
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- CACHE SETUP ----------
# Cache stations data for 1 hour to avoid hitting the API too frequently
stations_cache = TTLCache(maxsize=1, ttl=3600)

# ---------- STARTUP ----------
@app.on_event("startup")
def on_startup():
    create_db_and_tables()

# ---------- HOME ----------
@app.get("/api")
def home():
    return {"message": "Backend is running successfully"}

# ---------- LOGIN SCHEMA ----------
class LoginRequest(BaseModel):
    email: str
    password: str

# ---------- SIGNUP ----------
@app.post("/api/signup")
def signup(user: User, session: Session = Depends(get_session)):
    existing_user = session.exec(
        select(User).where(User.email == user.email)
    ).first()

    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    user.password = hashlib.sha256(user.password.encode()).hexdigest()
    session.add(user)
    session.commit()
    session.refresh(user)

    return {"message": "User registered successfully"}

# ---------- LOGIN ----------
@app.post("/api/login")
def login(data: LoginRequest, session: Session = Depends(get_session)):
    hashed_password = hashlib.sha256(data.password.encode()).hexdigest()

    user = session.exec(
        select(User).where(User.email == data.email)
    ).first()

    if not user or user.password != hashed_password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token({"user_id": user.id})
    return {"accessToken": token}

# ---------- PROFILE (PROTECTED) ----------
@app.post("/api/profile")
def profile(
    current_user: dict = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    user = session.get(User, current_user["user_id"])
    return {
        "id": user.id,
        "name": user.name,
        "email": user.email
    }

# ---------- REPORTS ----------
@app.post("/api/reports")
def create_report(
    report: Report,
    current_user: dict = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    session.add(report)
    session.commit()
    session.refresh(report)
    return report

@app.get("/api/reports")
def get_reports(session: Session = Depends(get_session)):
    return session.exec(select(Report)).all()

@app.put("/api/reports/{report_id}")
def update_report_status(
    report_id: int,
    status: str,
    session: Session = Depends(get_session)
):
    report = session.get(Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    report.status = status
    session.add(report)
    session.commit()
    session.refresh(report)
    return report

@app.get("/api/stations")
def get_cpcb_stations(force_refresh: bool = False):
    """
    Backend proxy for CPCB stations API with caching.
    Always returns an array of stations.
    """
    
    # Check cache first (unless force refresh is requested)
    if not force_refresh and 'stations_data' in stations_cache:
        print("Returning cached stations data")
        return stations_cache['stations_data']
    
    # Real CPCB API endpoint
    url = "https://rtwqmsdb1.cpcb.gov.in/data/internet/stations/stations.json"
    
    # Additional headers to mimic a browser request
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Referer': 'https://rtwqmsdb1.cpcb.gov.in/',
        'Origin': 'https://rtwqmsdb1.cpcb.gov.in'
    }

    try:
        print("Fetching real data from CPCB API...")
        
        response = requests.get(
            url, 
            timeout=15, 
            verify=False,
            headers=headers
        )
        
        response.raise_for_status()
        data = response.json()
        
        # Convert to array if it's an object
        if isinstance(data, dict):
            stations_array = list(data.values())
        elif isinstance(data, list):
            stations_array = data
        else:
            stations_array = []
        
        if stations_array and len(stations_array) > 0:
            print(f"Successfully fetched {len(stations_array)} stations from CPCB")
            # Cache the successful response
            stations_cache['stations_data'] = stations_array
            return stations_array
        else:
            print("Received empty data from CPCB API")
            return get_mock_stations_array()
            
    except Exception as e:
        print(f"Error fetching CPCB data: {e}")
        return get_mock_stations_array()

def get_mock_stations_array():
    """Return mock data as an array"""
    print("Serving mock data as array")
    
    # Check if we have cached mock data
    if 'mock_data_array' in stations_cache:
        return stations_cache['mock_data_array']
    
    # Mock data as array
    mock_stations = [
        {
            "station_code": "UK53",
            "station_name": "UK53_D/s of Tehri Dam",
            "latitude": "30.3807",
            "longitude": "78.4834",
            "city": "Tehri",
            "state": "Uttarakhand"
        },
        {
            "station_code": "UP20",
            "station_name": "UP20_Ghazipur",
            "latitude": "25.5881",
            "longitude": "83.5819",
            "city": "Ghazipur",
            "state": "Uttar Pradesh"
        },
        {
            "station_code": "WB12",
            "station_name": "WB12_Kolkata",
            "latitude": "22.5726",
            "longitude": "88.3639",
            "city": "Kolkata",
            "state": "West Bengal"
        },
        {
            "station_code": "DL05",
            "station_name": "DL05_Yamuna at Delhi",
            "latitude": "28.7041",
            "longitude": "77.1025",
            "city": "Delhi",
            "state": "Delhi"
        },
        {
            "station_code": "MH15",
            "station_name": "MH15_Mumbai",
            "latitude": "19.0760",
            "longitude": "72.8777",
            "city": "Mumbai",
            "state": "Maharashtra"
        },
        {
            "station_code": "KA08",
            "station_name": "KA08_Bangalore",
            "latitude": "12.9716",
            "longitude": "77.5946",
            "city": "Bangalore",
            "state": "Karnataka"
        },
        {
            "station_code": "TN10",
            "station_name": "TN10_Chennai",
            "latitude": "13.0827",
            "longitude": "80.2707",
            "city": "Chennai",
            "state": "Tamil Nadu"
        },
        {
            "station_code": "GJ07",
            "station_name": "GJ07_Ahmedabad",
            "latitude": "23.0225",
            "longitude": "72.5714",
            "city": "Ahmedabad",
            "state": "Gujarat"
        },
        {
            "station_code": "RJ05",
            "station_name": "RJ05_Jaipur",
            "latitude": "26.9124",
            "longitude": "75.7873",
            "city": "Jaipur",
            "state": "Rajasthan"
        },
        {
            "station_code": "PB03",
            "station_name": "PB03_Ludhiana",
            "latitude": "30.9010",
            "longitude": "75.8573",
            "city": "Ludhiana",
            "state": "Punjab"
        }
    ]
    
    # Cache the mock data
    stations_cache['mock_data_array'] = mock_stations
    
    return mock_stations
# ---------- STATION DETAILS ENDPOINT ----------
@app.get("/api/stations/{station_code}")
def get_station_details(station_code: str):
    """
    Get details for a specific station
    """
    stations = get_cpcb_stations()
    
    # Handle both list and dict responses
    if isinstance(stations, dict):
        if station_code in stations:
            return stations[station_code]
        else:
            # Search in dict values
            for station in stations.values():
                if station.get('station_code') == station_code:
                    return station
    elif isinstance(stations, list):
        for station in stations:
            if station.get('station_code') == station_code:
                return station
    
    raise HTTPException(status_code=404, detail=f"Station {station_code} not found")

# ---------- HEALTH CHECK ENDPOINT ----------
@app.get("/api/health")
def health_check():
    """Check if the API is healthy and CPCB connection is working"""
    try:
        # Try to connect to CPCB API
        response = requests.get(
            "https://rtwqmsdb1.cpcb.gov.in",
            timeout=5,
            verify=False
        )
        cpcb_status = "up" if response.status_code < 500 else "down"
    except:
        cpcb_status = "down"
    
    return {
        "status": "healthy",
        "cpcb_api": cpcb_status,
        "cache_size": len(stations_cache),
        "timestamp": time.time()
    }

# ---------------- ALERT THRESHOLDS ----------------
# ---------------- ALERT THRESHOLDS ----------------
THRESHOLDS = {
    "ph": (6.5, 8.5),
    "do": (4, 14),
    "turbidity": (0, 5)
}

def check_threshold_and_create_alert(station_name, parameter, value, session):
    if parameter.lower() not in THRESHOLDS:
        return

    low, high = THRESHOLDS[parameter.lower()]

    if value < low or value > high:
        # Check if an identical alert was already created recently to avoid spam
        # This is optional but good practice
        alert = Alert(
            type="contamination",
            message=f"{parameter.upper()} abnormal ({value}) at {station_name}",
            location=station_name,
            issued_at=datetime.utcnow()
        )
        session.add(alert)
        session.commit()

# ---------------- GET ALERTS ----------------
@app.get("/api/alerts")
def get_alerts(session: Session = Depends(get_session)):
    # Returns all alerts from the database
    return session.exec(select(Alert).order_by(Alert.created_at.desc())).all()

# ---------------- READINGS FOR CHARTS ----------------
@app.get("/api/readings")
def get_readings(
    station_code: Optional[str] = "UK53",
    session: Session = Depends(get_session)
):
    """
    Returns readings for a specific station.
    Auto-generates alerts if thresholds are crossed.
    """

    all_readings = [
        {"station_code": "UK53", "time": "08:00", "ph": 7.2, "do": 6.5, "turbidity": 2.1},
        {"station_code": "UK53", "time": "10:00", "ph": 7.8, "do": 6.2, "turbidity": 2.4},
        {"station_code": "UK53", "time": "12:00", "ph": 9.3, "do": 3.5, "turbidity": 6.8},
        {"station_code": "WB12", "time": "08:00", "ph": 7.1, "do": 6.0, "turbidity": 2.2},
    ]

    filtered_readings = [
        r for r in all_readings if r["station_code"] == station_code
    ]

    # SAFE threshold check
    for reading in filtered_readings:
        try:
            for param in ["ph", "do", "turbidity"]:
                check_threshold_and_create_alert(
                    reading["station_code"],
                    param,
                    reading[param],
                    session
                )
        except Exception as e:
            print("Threshold error:", e)

    return filtered_readings


























































