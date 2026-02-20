from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from database import get_db
from models import StationReading, WaterStation, Report, Alert, ReportStatus
from auth import get_current_user_id
from datetime import datetime, timedelta

router = APIRouter(prefix="/api/analytics", tags=["Analytics"])

@router.get("")
def get_analytics(
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db)
):
    """Get analytics data for dashboard"""
    
    # Get pH trends (last 30 days average by day)
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    ph_trends = db.query(
        func.date(StationReading.reading_date).label('date'),
        func.avg(StationReading.ph).label('avg_ph')
    ).filter(
        StationReading.reading_date >= thirty_days_ago,
        StationReading.ph.isnot(None)
    ).group_by(
        func.date(StationReading.reading_date)
    ).order_by('date').all()
    
    # Get contamination trends
    contamination_trends = db.query(
        func.date(StationReading.reading_date).label('date'),
        func.avg(StationReading.lead).label('avg_lead'),
        func.avg(StationReading.arsenic).label('avg_arsenic')
    ).filter(
        StationReading.reading_date >= thirty_days_ago
    ).group_by(
        func.date(StationReading.reading_date)
    ).order_by('date').all()
    
    # Station comparisons (top 10 stations by average pH)
    station_comparisons = db.query(
        WaterStation.station_name,
        func.avg(StationReading.ph).label('avg_ph'),
        func.avg(StationReading.turbidity).label('avg_turbidity')
    ).join(
        StationReading, WaterStation.id == StationReading.station_id
    ).filter(
        StationReading.reading_date >= thirty_days_ago
    ).group_by(
        WaterStation.station_name
    ).order_by(
        desc('avg_ph')
    ).limit(10).all()
    
    # Overall statistics
    total_stations = db.query(WaterStation).count()
    total_reports = db.query(Report).count()
    pending_reports = db.query(Report).filter(Report.status == ReportStatus.pending).count()
    active_alerts = db.query(Alert).filter(Alert.is_read == False).count()
    
    # Latest readings summary
    latest_readings = db.query(
        func.avg(StationReading.ph).label('avg_ph'),
        func.avg(StationReading.turbidity).label('avg_turbidity'),
        func.avg(StationReading.lead).label('avg_lead'),
        func.avg(StationReading.arsenic).label('avg_arsenic')
    ).filter(
        StationReading.reading_date >= thirty_days_ago
    ).first()
    
    return {
        "overview": {
            "total_stations": total_stations,
            "total_reports": total_reports,
            "pending_reports": pending_reports,
            "active_alerts": active_alerts
        },
        "latest_averages": {
            "ph": round(latest_readings.avg_ph, 2) if latest_readings.avg_ph else None,
            "turbidity": round(latest_readings.avg_turbidity, 2) if latest_readings.avg_turbidity else None,
            "lead": round(latest_readings.avg_lead, 4) if latest_readings.avg_lead else None,
            "arsenic": round(latest_readings.avg_arsenic, 4) if latest_readings.avg_arsenic else None
        },
        "ph_trends": [
            {"date": str(item.date), "avg_ph": round(item.avg_ph, 2)}
            for item in ph_trends
        ],
        "contamination_trends": [
            {
                "date": str(item.date),
                "avg_lead": round(item.avg_lead, 4) if item.avg_lead else 0,
                "avg_arsenic": round(item.avg_arsenic, 4) if item.avg_arsenic else 0
            }
            for item in contamination_trends
        ],
        "station_comparisons": [
            {
                "station": item.station_name,
                "avg_ph": round(item.avg_ph, 2) if item.avg_ph else 0,
                "avg_turbidity": round(item.avg_turbidity, 2) if item.avg_turbidity else 0
            }
            for item in station_comparisons
        ]
    }