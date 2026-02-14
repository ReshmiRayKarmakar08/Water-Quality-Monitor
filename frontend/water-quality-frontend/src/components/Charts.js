import React, { useEffect, useState } from "react";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
  Radar,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
} from "recharts";

const Charts = () => {
  const [stations, setStations] = useState([]);
  const [selectedStation, setSelectedStation] = useState("");
  const [historyData, setHistoryData] = useState([]);

  // 🔹 Fetch stations list
  useEffect(() => {
    fetch("http://127.0.0.1:8000/cpcb/stations")
      .then((res) => res.json())
      .then((data) => {
        setStations(Object.values(data));
      });
  }, []);

  // 🔹 Fetch readings when station changes
  useEffect(() => {
    if (!selectedStation) return;

    fetch("http://127.0.0.1:8000/cpcb/readings")
      .then((res) => res.json())
      .then((data) => {
        // Filter readings for selected station
        const filtered = data.filter(
          (r) => r.station_name === selectedStation
        );

        setHistoryData(filtered);
      });
  }, [selectedStation]);

  // Latest reading for radar chart
  const latest = historyData.length > 0 ? historyData[historyData.length - 1] : null;

  const radarData = latest
    ? [
        { subject: "pH", A: latest.ph || 0, fullMark: 14 },
        { subject: "DO", A: latest.do || 0, fullMark: 10 },
        { subject: "Turbidity", A: latest.turbidity || 0, fullMark: 10 },
      ]
    : [];

  return (
    <div style={{ width: "100%" }}>
      {/* 🔹 Station Dropdown */}
      <div style={{ marginBottom: "20px" }}>
        <select
          onChange={(e) => setSelectedStation(e.target.value)}
          value={selectedStation}
        >
          <option value="">Select Station</option>
          {stations.map((station) => (
            <option
              key={station.station_code}
              value={station.station_name}
            >
              {station.station_name}
            </option>
          ))}
        </select>
      </div>

      <div
        className="charts-wrapper"
        style={{ display: "flex", gap: "20px", width: "100%" }}
      >
        {/* 🔹 Line Chart */}
        <div
          className="glass-card"
          style={{ flex: 2, minHeight: "400px" }}
        >
          <h4 style={{ marginBottom: "20px" }}>
            {selectedStation
              ? `${selectedStation} - Parameter History`
              : "Select a station"}
          </h4>

          <ResponsiveContainer width="100%" height={350}>
            <LineChart data={historyData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="time" />
              <YAxis />
              <Tooltip />
              <Legend />

              <Line type="monotone" dataKey="ph" stroke="#0081ff" />
              <Line type="monotone" dataKey="turbidity" stroke="#ff4b5c" />
              <Line type="monotone" dataKey="do" stroke="#05cd99" />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* 🔹 Radar Chart */}
        <div
          className="glass-card"
          style={{ flex: 1, minHeight: "400px" }}
        >
          <h4>Current Quality Snapshot</h4>

          <ResponsiveContainer width="100%" height={350}>
            <RadarChart data={radarData}>
              <PolarGrid />
              <PolarAngleAxis dataKey="subject" />
              <PolarRadiusAxis />
              <Radar
                name="Readings"
                dataKey="A"
                stroke="#0081ff"
                fill="#0081ff"
                fillOpacity={0.6}
              />
              <Tooltip />
            </RadarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
};

export default Charts;
