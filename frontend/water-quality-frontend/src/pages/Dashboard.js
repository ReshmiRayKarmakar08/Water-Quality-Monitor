import React, { useState } from 'react';
import Charts from '../components/Charts'; 

const Dashboard = () => {
  const [selectedStation, setSelectedStation] = useState("UK53");

  return (
    <div className="dashboard-view">
      {/* 1. Top Section: Header and Dropdown */}
      <div className="dashboard-header">
        <div className="header-text">
          <h2>Water Station : {selectedStation}_D/s of Tehri Dam</h2>
          <p className="last-update">Real-time Environmental Monitoring</p>
        </div>
        
        <div className="selector-container">
          <label>Station Name</label>
          <select 
            value={selectedStation} 
            onChange={(e) => setSelectedStation(e.target.value)}
            className="station-select-box"
          >
            <option value="UK53">UK53</option>
            <option value="UP20">UP20</option>
            <option value="WB12">WB12</option>
          </select>
        </div>
      </div>

      {/* 2. Bottom Section: The Charts Grid */}
      <div className="charts-section">
        <Charts stationId={selectedStation} />
      </div>
    </div>
  );
};

export default Dashboard;