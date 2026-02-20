"""
Seed script to populate database with sample data
"""
from database import SessionLocal, init_db
from models import User, WaterStation, StationReading, Report, Alert, Collaboration, UserRole, ReportStatus
from auth import get_password_hash
from datetime import datetime, timedelta
import random

def seed_database():
    print("Initializing database...")
    init_db()
    
    db = SessionLocal()
    
    try:
        # Check if data already exists
        if db.query(User).count() > 0:
            print("Database already has data. Skipping seed.")
            return
        
        print("Seeding users...")
        # Create users with different roles
        users = [
            User(
                name="John Citizen",
                email="citizen@waterwatch.com",
                password=get_password_hash("password123"),
                role=UserRole.citizen
            ),
            User(
                name="Green NGO",
                email="ngo@waterwatch.com",
                password=get_password_hash("password123"),
                role=UserRole.ngo
            ),
            User(
                name="Water Authority",
                email="authority@waterwatch.com",
                password=get_password_hash("password123"),
                role=UserRole.authority
            ),
            User(
                name="Admin User",
                email="admin@waterwatch.com",
                password=get_password_hash("password123"),
                role=UserRole.admin
            ),
        ]
        
        for user in users:
            db.add(user)
        db.commit()
        print(f"Created {len(users)} users")
        
        # Create sample water stations
        print("Seeding water stations...")
        stations_data = [
            {"station_id": "ST001", "name": "Delhi Yamuna Station", "state": "Delhi", "city": "Delhi", "lat": 28.6139, "lon": 77.2090},
            {"station_id": "ST002", "name": "Mumbai Coastal Station", "state": "Maharashtra", "city": "Mumbai", "lat": 19.0760, "lon": 72.8777},
            {"station_id": "ST003", "name": "Bangalore Lake Station", "state": "Karnataka", "city": "Bangalore", "lat": 12.9716, "lon": 77.5946},
            {"station_id": "ST004", "name": "Chennai Marina Station", "state": "Tamil Nadu", "city": "Chennai", "lat": 13.0827, "lon": 80.2707},
            {"station_id": "ST005", "name": "Kolkata Hooghly Station", "state": "West Bengal", "city": "Kolkata", "lat": 22.5726, "lon": 88.3639},
        ]
        
        stations = []
        for s_data in stations_data:
            station = WaterStation(
                station_id=s_data["station_id"],
                station_name=s_data["name"],
                state=s_data["state"],
                city=s_data["city"],
                latitude=s_data["lat"],
                longitude=s_data["lon"]
            )
            db.add(station)
            stations.append(station)
        db.commit()
        print(f"Created {len(stations)} water stations")
        
        # Create sample readings for each station
        print("Seeding station readings...")
        readings_count = 0
        for station in stations:
            # Create readings for last 30 days
            for i in range(30):
                reading_date = datetime.utcnow() - timedelta(days=i)
                reading = StationReading(
                    station_id=station.id,
                    ph=round(random.uniform(6.5, 8.0), 2),
                    turbidity=round(random.uniform(1, 10), 2),
                    lead=round(random.uniform(0, 0.02), 4),
                    arsenic=round(random.uniform(0, 0.015), 4),
                    dissolved_oxygen=round(random.uniform(5, 10), 2),
                    conductivity=round(random.uniform(200, 800), 2),
                    temperature=round(random.uniform(20, 30), 2),
                    reading_date=reading_date
                )
                db.add(reading)
                readings_count += 1
        db.commit()
        print(f"Created {readings_count} station readings")
        
        # Create sample reports
        print("Seeding reports...")
        reports_data = [
            {
                "title": "Foul smell in local water supply",
                "description": "The tap water in our area has been smelling bad for the past week. Residents are concerned about water quality.",
                "location": "Sector 15, Delhi",
                "latitude": 28.5355,
                "longitude": 77.3910,
                "water_source": "Tap Water",
                "status": ReportStatus.pending
            },
            {
                "title": "Discolored water in community well",
                "description": "The water from the community well appears yellowish. We suspect contamination.",
                "location": "Andheri, Mumbai",
                "latitude": 19.1136,
                "longitude": 72.8697,
                "water_source": "Well",
                "status": ReportStatus.verified
            },
            {
                "title": "Lake pollution near residential area",
                "description": "Industrial waste is being discharged into the lake. Urgent action needed.",
                "location": "Whitefield, Bangalore",
                "latitude": 12.9698,
                "longitude": 77.7499,
                "water_source": "Lake",
                "status": ReportStatus.pending
            },
        ]
        
        for rep_data in reports_data:
            report = Report(
                user_id=users[0].id,
                title=rep_data["title"],
                description=rep_data["description"],
                location=rep_data["location"],
                latitude=rep_data["latitude"],
                longitude=rep_data["longitude"],
                water_source=rep_data["water_source"],
                status=rep_data["status"]
            )
            db.add(report)
        db.commit()
        print(f"Created {len(reports_data)} reports")
        
        # Create sample alerts
        print("Seeding alerts...")
        alert = Alert(
            station_id=stations[0].id,
            alert_type="pH",
            severity="high",
            message=f"pH level 5.2 at {stations[0].station_name} is outside safe range (6.0-8.5)"
        )
        db.add(alert)
        
        alert2 = Alert(
            station_id=stations[1].id,
            alert_type="lead",
            severity="critical",
            message=f"Lead level 0.025 mg/L at {stations[1].station_name} exceeds safe limit (0.01 mg/L)"
        )
        db.add(alert2)
        db.commit()
        print("Created 2 alerts")
        
        # Create sample collaboration
        print("Seeding collaborations...")
        collab = Collaboration(
            user_id=users[1].id,
            title="Clean Water Initiative 2026",
            description="Community-driven water quality improvement program focusing on local water bodies.",
            location="Delhi NCR",
            start_date=datetime.utcnow(),
            status="active"
        )
        db.add(collab)
        db.commit()
        print("Created 1 collaboration")
        
        print("\n✅ Database seeding completed successfully!")
        print("\n📧 Test user credentials:")
        print("  Citizen: citizen@waterwatch.com / password123")
        print("  NGO: ngo@waterwatch.com / password123")
        print("  Authority: authority@waterwatch.com / password123")
        print("  Admin: admin@waterwatch.com / password123")
        
    except Exception as e:
        print(f"❌ Error seeding database: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    seed_database()
