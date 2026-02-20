import { useEffect, useState } from 'react';
import { MapContainer, TileLayer, Marker, Popup } from 'react-leaflet';
import { stationAPI } from '../services/api';
import 'leaflet/dist/leaflet.css';
import L from 'leaflet';

// Fix for default marker icons
delete L.Icon.Default.prototype._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon-2x.png',
  iconUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon.png',
  shadowUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-shadow.png',
});

function MapView() {
  const [stations, setStations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    fetchStations();
  }, []);

  const fetchStations = async () => {
    try {
      const response = await stationAPI.getStations();
      setStations(response.data.filter(s => s.latitude && s.longitude));
      setLoading(false);
    } catch (err) {
      setError('Failed to load stations');
      setLoading(false);
    }
  };

  if (loading) {
    return <div className="flex items-center justify-center h-screen" data-testid="map-loading">Loading map...</div>;
  }

  if (error) {
    return <div className="flex items-center justify-center h-screen text-red-600" data-testid="map-error">{error}</div>;
  }

  return (
    <div className="h-screen w-full" data-testid="map-container">
      <MapContainer
        center={[20.5937, 78.9629]} // India center
        zoom={5}
        style={{ height: '100%', width: '100%' }}
      >
        <TileLayer
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
        />
        {stations.map((station) => (
          <Marker
            key={station.id}
            position={[station.latitude, station.longitude]}
          >
            <Popup>
              <div className="p-2" data-testid={`station-popup-${station.id}`}>
                <h3 className="font-bold text-lg">{station.station_name}</h3>
                <p className="text-sm text-gray-600">
                  {station.city}, {station.state}
                </p>
                {station.latest_reading && (
                  <div className="mt-2 space-y-1 text-sm">
                    <p data-testid="station-ph"><strong>pH:</strong> {station.latest_reading.ph?.toFixed(2) || 'N/A'}</p>
                    <p data-testid="station-turbidity"><strong>Turbidity:</strong> {station.latest_reading.turbidity?.toFixed(2) || 'N/A'}</p>
                    <p data-testid="station-lead"><strong>Lead:</strong> {station.latest_reading.lead?.toFixed(4) || 'N/A'} mg/L</p>
                    <p data-testid="station-arsenic"><strong>Arsenic:</strong> {station.latest_reading.arsenic?.toFixed(4) || 'N/A'} mg/L</p>
                  </div>
                )}
              </div>
            </Popup>
          </Marker>
        ))}
      </MapContainer>
    </div>
  );
}

export default MapView;