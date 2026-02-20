from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime
from models import UserRole, ReportStatus

# User Schemas
class UserBase(BaseModel):
    email: EmailStr
    name: str
    role: UserRole = UserRole.citizen

class UserCreate(UserBase):
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(UserBase):
    id: int
    created_at: datetime
    
    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

# Station Schemas
class StationReadingBase(BaseModel):
    ph: Optional[float] = None
    turbidity: Optional[float] = None
    lead: Optional[float] = None
    arsenic: Optional[float] = None
    dissolved_oxygen: Optional[float] = None
    conductivity: Optional[float] = None
    temperature: Optional[float] = None

class StationReadingResponse(StationReadingBase):
    id: int
    station_id: int
    reading_date: datetime
    
    class Config:
        from_attributes = True

class WaterStationResponse(BaseModel):
    id: int
    station_id: str
    station_name: str
    state: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    latest_reading: Optional[StationReadingResponse] = None
    
    class Config:
        from_attributes = True

# Report Schemas
class ReportCreate(BaseModel):
    title: str
    description: str
    location: str
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    water_source: Optional[str] = None
    image_url: Optional[str] = None

class ReportResponse(ReportCreate):
    id: int
    user_id: int
    status: ReportStatus
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True

# Alert Schemas
class AlertCreate(BaseModel):
    station_id: Optional[int] = None
    alert_type: str
    severity: str
    message: str

class AlertResponse(AlertCreate):
    id: int
    user_id: Optional[int] = None
    is_read: bool
    created_at: datetime
    
    class Config:
        from_attributes = True

# Collaboration Schemas
class CollaborationCreate(BaseModel):
    title: str
    description: str
    location: Optional[str] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None

class CollaborationResponse(CollaborationCreate):
    id: int
    user_id: int
    status: str
    created_at: datetime
    
    class Config:
        from_attributes = True