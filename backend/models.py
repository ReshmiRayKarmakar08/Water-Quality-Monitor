from sqlmodel import SQLModel, Field
from typing import Optional
from datetime import datetime


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    email: str
    password: str


class Report(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    title: str
    description: str
    status: str = "pending"
    created_at: datetime = Field(default_factory=datetime.utcnow)


class Alert(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    station_id: str
    parameter: str
    value: float
    threshold: str
    status: str = "ACTIVE"
    created_at: datetime = Field(default_factory=datetime.utcnow)


class StationReading(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    station_name: str
    parameter: str
    value: float
    recorded_at: datetime = Field(default_factory=datetime.utcnow)
