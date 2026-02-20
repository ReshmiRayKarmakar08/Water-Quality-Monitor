from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File
from sqlalchemy.orm import Session
from database import get_db
from models import Report, User, ReportStatus, UserRole
from schemas import ReportCreate, ReportResponse
from auth import get_current_user_id
from typing import List, Optional
import shutil
import os
from datetime import datetime

router = APIRouter(prefix="/api/reports", tags=["Reports"])

UPLOAD_DIR = os.getenv("UPLOAD_DIR", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

@router.post("", response_model=ReportResponse, status_code=status.HTTP_201_CREATED)
def create_report(
    report_data: ReportCreate,
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db)
):
    report = Report(
        user_id=user_id,
        title=report_data.title,
        description=report_data.description,
        location=report_data.location,
        latitude=report_data.latitude,
        longitude=report_data.longitude,
        water_source=report_data.water_source,
        image_url=report_data.image_url,
        status=ReportStatus.pending
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return report

@router.get("", response_model=List[ReportResponse])
def get_reports(
    status: Optional[str] = None,
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    
    query = db.query(Report)
    
    # If citizen, only show their own reports
    if user.role == UserRole.citizen:
        query = query.filter(Report.user_id == user_id)
    
    # Filter by status if provided
    if status:
        query = query.filter(Report.status == status)
    
    reports = query.order_by(Report.created_at.desc()).all()
    return reports

@router.put("/{report_id}/verify", response_model=ReportResponse)
def verify_report(
    report_id: int,
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if user.role not in [UserRole.authority, UserRole.admin]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only authorities can verify reports"
        )
    
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found"
        )
    
    report.status = ReportStatus.verified
    report.verified_by = user_id
    report.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(report)
    return report

@router.put("/{report_id}/reject", response_model=ReportResponse)
def reject_report(
    report_id: int,
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if user.role not in [UserRole.authority, UserRole.admin]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only authorities can reject reports"
        )
    
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found"
        )
    
    report.status = ReportStatus.rejected
    report.verified_by = user_id
    report.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(report)
    return report