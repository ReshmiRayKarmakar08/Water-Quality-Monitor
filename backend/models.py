from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Enum, Text, Boolean
from sqlalchemy.orm import relationship
from database import Base
from datetime import datetime
import enum

class UserRole(str, enum.Enum):
    citizen = "citizen"
    ngo = "ngo"
    authority = "authority"
    admin = "admin"

class ReportStatus(str, enum.Enum):
    pending = "pending"
    verified = "verified"
    rejected = "rejected"

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=False)
    role = Column(Enum(UserRole), default=UserRole.citizen, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    reports = relationship("Report", back_populates="user")
    alerts = relationship("Alert", back_populates="user")
    collaborations = relationship("Collaboration", back_populates="user")

class WaterStation(Base):
    __tablename__ = "water_stations"
    
    id = Column(Integer, primary_key=True, index=True)
    station_id = Column(String, unique=True, index=True)
    station_name = Column(String)
    state = Column(String)
    city = Column(String)
    latitude = Column(Float)
    longitude = Column(Float)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    readings = relationship("StationReading", back_populates="station")

class StationReading(Base):
    __tablename__ = "station_readings"
    
    id = Column(Integer, primary_key=True, index=True)
    station_id = Column(Integer, ForeignKey("water_stations.id"))
    ph = Column(Float)
    turbidity = Column(Float)
    lead = Column(Float)
    arsenic = Column(Float)
    dissolved_oxygen = Column(Float)
    conductivity = Column(Float)
    temperature = Column(Float)
    reading_date = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    station = relationship("WaterStation", back_populates="readings")

class Report(Base):
    __tablename__ = "reports"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    location = Column(String, nullable=False)
    latitude = Column(Float)
    longitude = Column(Float)
    water_source = Column(String)
    image_url = Column(String)
    status = Column(Enum(ReportStatus), default=ReportStatus.pending)
    verified_by = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    user = relationship("User", back_populates="reports")

class Alert(Base):
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    station_id = Column(Integer, ForeignKey("water_stations.id"), nullable=True)
    alert_type = Column(String, nullable=False)  # pH, lead, arsenic, etc.
    severity = Column(String, nullable=False)  # low, medium, high, critical
    message = Column(Text, nullable=False)
    is_read = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    user = relationship("User", back_populates="alerts")
    station = relationship("WaterStation")

class Collaboration(Base):
    __tablename__ = "collaborations"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))  # NGO user
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    location = Column(String)
    start_date = Column(DateTime)
    end_date = Column(DateTime, nullable=True)
    status = Column(String, default="active")  # active, completed, cancelled
    created_at = Column(DateTime, default=datetime.utcnow)
    
    user = relationship("User", back_populates="collaborations")