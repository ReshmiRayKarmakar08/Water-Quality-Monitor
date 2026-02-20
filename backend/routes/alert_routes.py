from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from database import get_db
from models import Alert, WaterStation, StationReading, User
from schemas import AlertCreate, AlertResponse
from auth import get_current_user_id
from typing import List
from sqlalchemy import desc

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])

# Water quality thresholds
PH_MIN = 6.0
PH_MAX = 8.5
LEAD_MAX = 0.01  # mg/L
ARSENIC_MAX = 0.01  # mg/L

def check_and_create_alerts(db: Session):
    """Check water quality readings and create alerts if thresholds are exceeded"""
    stations = db.query(WaterStation).all()
    alerts_created = 0
    
    for station in stations:
        latest_reading = db.query(StationReading).filter(
            StationReading.station_id == station.id
        ).order_by(desc(StationReading.reading_date)).first()
        
        if not latest_reading:
            continue
        
        # Check pH levels
        if latest_reading.ph and (latest_reading.ph < PH_MIN or latest_reading.ph > PH_MAX):
            existing_alert = db.query(Alert).filter(
                Alert.station_id == station.id,
                Alert.alert_type == "pH",
                Alert.is_read == False
            ).first()
            
            if not existing_alert:
                severity = "high" if (latest_reading.ph < 5.5 or latest_reading.ph > 9) else "medium"
                alert = Alert(
                    station_id=station.id,
                    alert_type="pH",
                    severity=severity,
                    message=f"pH level {latest_reading.ph} at {station.station_name} is outside safe range ({PH_MIN}-{PH_MAX})"
                )
                db.add(alert)
                alerts_created += 1
        
        # Check lead levels
        if latest_reading.lead and latest_reading.lead > LEAD_MAX:
            existing_alert = db.query(Alert).filter(
                Alert.station_id == station.id,
                Alert.alert_type == "lead",
                Alert.is_read == False
            ).first()
            
            if not existing_alert:
                severity = "critical" if latest_reading.lead > (LEAD_MAX * 2) else "high"
                alert = Alert(
                    station_id=station.id,
                    alert_type="lead",
                    severity=severity,
                    message=f"Lead level {latest_reading.lead} mg/L at {station.station_name} exceeds safe limit ({LEAD_MAX} mg/L)"
                )
                db.add(alert)
                alerts_created += 1
        
        # Check arsenic levels
        if latest_reading.arsenic and latest_reading.arsenic > ARSENIC_MAX:
            existing_alert = db.query(Alert).filter(
                Alert.station_id == station.id,
                Alert.alert_type == "arsenic",
                Alert.is_read == False
            ).first()
            
            if not existing_alert:
                severity = "critical" if latest_reading.arsenic > (ARSENIC_MAX * 2) else "high"
                alert = Alert(
                    station_id=station.id,
                    alert_type="arsenic",
                    severity=severity,
                    message=f"Arsenic level {latest_reading.arsenic} mg/L at {station.station_name} exceeds safe limit ({ARSENIC_MAX} mg/L)"
                )
                db.add(alert)
                alerts_created += 1
    
    db.commit()
    return alerts_created

@router.post("", response_model=AlertResponse, status_code=status.HTTP_201_CREATED)
def create_alert(
    alert_data: AlertCreate,
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db)
):
    alert = Alert(
        user_id=user_id,
        station_id=alert_data.station_id,
        alert_type=alert_data.alert_type,
        severity=alert_data.severity,
        message=alert_data.message
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert

@router.get("", response_model=List[AlertResponse])
def get_alerts(
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db)
):
    # First, check and create any new alerts
    check_and_create_alerts(db)
    
    # Return all unread alerts
    alerts = db.query(Alert).filter(
        Alert.is_read == False
    ).order_by(desc(Alert.created_at)).all()
    return alerts

@router.put("/{alert_id}/read")
def mark_alert_read(
    alert_id: int,
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db)
):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found"
        )
    
    alert.is_read = True
    db.commit()
    return {"message": "Alert marked as read"}