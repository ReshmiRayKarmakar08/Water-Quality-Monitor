from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import desc
from database import get_db
from models import WaterStation, StationReading
from schemas import WaterStationResponse, StationReadingResponse
import requests
from typing import List
import urllib3

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

router = APIRouter(prefix="/api", tags=["Stations"])

STATIONS_API = "https://rtwqmsdb1.cpcb.gov.in/data/internet/stations/stations.json"
READINGS_API = "https://rtwqmsdb1.cpcb.gov.in/data/internet/layers/10/index.json"

@router.get("/stations", response_model=List[WaterStationResponse])
def get_stations(db: Session = Depends(get_db)):
    """Get all water stations with their latest readings"""
    try:
        # Fetch from government API
        response = requests.get(STATIONS_API, timeout=10, verify=False)
        stations_data = response.json()
        
        # Store/update in database
        for station_data in stations_data:
            existing = db.query(WaterStation).filter(
                WaterStation.station_id == str(station_data.get('id', ''))
            ).first()
            
            if not existing:
                station = WaterStation(
                    station_id=str(station_data.get('id', '')),
                    station_name=station_data.get('name', ''),
                    state=station_data.get('state', ''),
                    city=station_data.get('city', ''),
                    latitude=station_data.get('latitude'),
                    longitude=station_data.get('longitude')
                )
                db.add(station)
        
        db.commit()
        
        # Return all stations with latest readings
        stations = db.query(WaterStation).all()
        result = []
        for station in stations:
            latest_reading = db.query(StationReading).filter(
                StationReading.station_id == station.id
            ).order_by(desc(StationReading.reading_date)).first()
            
            station_dict = {
                "id": station.id,
                "station_id": station.station_id,
                "station_name": station.station_name,
                "state": station.state,
                "city": station.city,
                "latitude": station.latitude,
                "longitude": station.longitude,
                "latest_reading": latest_reading
            }
            result.append(station_dict)
        
        return result
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching stations: {str(e)}")

@router.get("/readings")
def get_readings(db: Session = Depends(get_db)):
    """Get water quality readings from government API"""
    try:
        response = requests.get(READINGS_API, timeout=10, verify=False)
        readings_data = response.json()
        
        # Process and store readings
        for reading_data in readings_data:
            station_id_str = str(reading_data.get('station_id', ''))
            station = db.query(WaterStation).filter(
                WaterStation.station_id == station_id_str
            ).first()
            
            if station:
                reading = StationReading(
                    station_id=station.id,
                    ph=reading_data.get('ph'),
                    turbidity=reading_data.get('turbidity'),
                    lead=reading_data.get('lead'),
                    arsenic=reading_data.get('arsenic'),
                    dissolved_oxygen=reading_data.get('dissolved_oxygen'),
                    conductivity=reading_data.get('conductivity'),
                    temperature=reading_data.get('temperature')
                )
                db.add(reading)
        
        db.commit()
        return {"message": "Readings updated successfully", "count": len(readings_data)}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching readings: {str(e)}")