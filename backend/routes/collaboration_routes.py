from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from database import get_db
from models import Collaboration, User, UserRole
from schemas import CollaborationCreate, CollaborationResponse
from auth import get_current_user_id
from typing import List

router = APIRouter(prefix="/api/collaborations", tags=["Collaborations"])

@router.post("", response_model=CollaborationResponse, status_code=status.HTTP_201_CREATED)
def create_collaboration(
    collab_data: CollaborationCreate,
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if user.role != UserRole.ngo:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only NGOs can create collaborations"
        )
    
    collaboration = Collaboration(
        user_id=user_id,
        title=collab_data.title,
        description=collab_data.description,
        location=collab_data.location,
        start_date=collab_data.start_date,
        end_date=collab_data.end_date
    )
    db.add(collaboration)
    db.commit()
    db.refresh(collaboration)
    return collaboration

@router.get("", response_model=List[CollaborationResponse])
def get_collaborations(
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    
    # NGOs see only their collaborations
    if user.role == UserRole.ngo:
        collaborations = db.query(Collaboration).filter(
            Collaboration.user_id == user_id
        ).order_by(Collaboration.created_at.desc()).all()
    else:
        # Others see all active collaborations
        collaborations = db.query(Collaboration).filter(
            Collaboration.status == "active"
        ).order_by(Collaboration.created_at.desc()).all()
    
    return collaborations

@router.put("/{collab_id}/status")
def update_collaboration_status(
    collab_id: int,
    new_status: str,
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db)
):
    collaboration = db.query(Collaboration).filter(
        Collaboration.id == collab_id,
        Collaboration.user_id == user_id
    ).first()
    
    if not collaboration:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Collaboration not found or you don't have permission"
        )
    
    collaboration.status = new_status
    db.commit()
    return {"message": "Status updated successfully"}