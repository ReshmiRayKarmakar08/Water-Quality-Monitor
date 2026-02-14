import { MapContainer, TileLayer, Marker, Popup } from "react-leaflet";
import { useEffect, useState } from "react";
import "leaflet/dist/leaflet.css";
import L from "leaflet";

/* ---------------- FIX LEAFLET MARKER ICON ISSUE ---------------- */
delete L.Icon.Default.prototype._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl:
    "https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon-2x.png",
  iconUrl:
    "https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon.png",
  shadowUrl:
    "https://unpkg.com/leaflet@1.9.4/dist/images/marker-shadow.png",
});

function MapView() {
  const [stations, setStations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    console.log("🔍 Starting to fetch stations...");
    
    fetch("http://127.0.0.1:8000/api/stations")
      .then((res) => {
        console.log("📡 Response status:", res.status);
        if (!res.ok) {
          throw new Error(`HTTP error! status: ${res.status}`);
        }
        return res.json();
      })
      .then((data) => {
        console.log("✅ Raw data from backend:", data);
        
        // Handle different data formats
        let stationArray = [];
        if (Array.isArray(data)) {
          stationArray = data;
        } else if (data && typeof data === 'object') {
          stationArray = Object.values(data);
        }
        
        console.log(`📊 Total stations: ${stationArray.length}`);
        
        // Check first station to see its structure
        if (stationArray.length > 0) {
          console.log("📋 First station structure:", stationArray[0]);
          console.log("📋 Available fields:", Object.keys(stationArray[0]));
        }
        
        // Process stations with CORRECT field names
        const validStations = stationArray.filter(station => {
          // Use station_latitude and station_longitude (from console output)
          const lat = parseFloat(station.station_latitude);
          const lng = parseFloat(station.station_longitude);
          
          const isValid = !isNaN(lat) && !isNaN(lng) && 
                         lat >= -90 && lat <= 90 && 
                         lng >= -180 && lng <= 180;
          
          if (!isValid && station.station_latitude) {
            console.log("⚠️ Invalid coordinates for:", station.station_name, 
                      "lat:", station.station_latitude, 
                      "lng:", station.station_longitude);
          }
          
          return isValid;
        }).map(station => ({
          ...station,
          // Add parsed coordinates for easy access
          parsed_lat: parseFloat(station.station_latitude),
          parsed_lng: parseFloat(station.station_longitude)
        }));
        
        console.log(`📍 Found ${validStations.length} stations with valid coordinates out of ${stationArray.length}`);
        
        if (validStations.length > 0) {
          console.log("✅ First valid station:", validStations[0]);
        } else {
          console.log("⚠️ No valid coordinates found. Available fields:", 
            stationArray.length > 0 ? Object.keys(stationArray[0]) : 'No stations');
        }
        
        setStations(validStations);
        setLoading(false);
      })
      .catch((err) => {
        console.error("❌ Error fetching stations:", err);
        setError(err.message);
        setLoading(false);
      });
  }, []);

  if (loading) {
    return (
      <div style={{ height: "90vh", width: "100%", display: "flex", justifyContent: "center", alignItems: "center" }}>
        <div>Loading stations...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div style={{ height: "90vh", width: "100%", display: "flex", justifyContent: "center", alignItems: "center" }}>
        <div style={{ color: "red" }}>Error: {error}</div>
      </div>
    );
  }

  return (
    <div style={{ height: "90vh", width: "100%" }}>
      {stations.length === 0 ? (
        <div style={{ height: "100%", display: "flex", justifyContent: "center", alignItems: "center", flexDirection: "column" }}>
          <div style={{ fontSize: "18px", marginBottom: "10px" }}>❌ No stations with valid coordinates</div>
          <div style={{ color: "gray", maxWidth: "600px", textAlign: "center" }}>
            <p>Debug Info:</p>
            <p>Check console for details. Looking for fields: station_latitude, station_longitude</p>
          </div>
        </div>
      ) : (
        <MapContainer
          center={[22.5726, 88.3639]}
          zoom={5}
          style={{ height: "100%", width: "100%" }}
        >
          <TileLayer
            url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
            attribution="© OpenStreetMap contributors"
          />

          {stations.map((station, index) => {
            return (
              <Marker
                key={station.station_id || station.station_no || index}
                position={[station.parsed_lat, station.parsed_lng]}
              >
                <Popup>
                  <div style={{ minWidth: "200px" }}>
                    <strong>{station.station_name || "Unknown Station"}</strong>
                    <br />
                    <br />
                    <div>Station Code: {station.station_no || station.station_code || 'N/A'}</div>
                    <div>Station ID: {station.station_id || 'N/A'}</div>
                    <div>Site: {station.site_name || 'N/A'}</div>
                    <div>Latitude: {station.station_latitude}</div>
                    <div>Longitude: {station.station_longitude}</div>
                    <div>Status: {station.station_status_remark || 'N/A'}</div>
                  </div>
                </Popup>
              </Marker>
            );
          })}
        </MapContainer>
      )}
    </div>
  );
}

export default MapView;