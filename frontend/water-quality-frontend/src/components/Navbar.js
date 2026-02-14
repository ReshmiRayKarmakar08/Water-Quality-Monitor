import React from 'react';
import { Link } from 'react-router-dom';

const Navbar = () => {
  // This matches the "User loggedin: admin (admin@123)" in your screenshot
  const user = { name: "admin", email: "admin@123" };

  return (
    <nav className="navbar glass-card">
      <div className="logo-section">
        <div className="logo-circle">
          <img src="/logo192.png" alt="React Logo" />
        </div>
        <div>
          <h1 className="nav-title">Water Quality Monitor</h1>
          <p className="nav-subtitle">Environmental Intelligence</p>
        </div>
      </div>

      <div className="user-info">
        User loggedin: {user.name} ({user.email})
      </div>

      <div className="nav-actions">
        <Link to="/map"><button className="nav-btn">Map</button></Link>
        <Link to="/reports"><button className="nav-btn">NGO</button></Link>
        <Link to="/report"><button className="nav-btn">Create Report</button></Link>
        <button className="alert-btn">Alert</button>
      </div>
    </nav>
  );
};

export default Navbar;