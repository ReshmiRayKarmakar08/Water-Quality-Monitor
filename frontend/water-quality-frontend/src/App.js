import React from "react";
import { BrowserRouter, Routes, Route, useLocation } from "react-router-dom";

// IMPORT YOUR COMPONENTS HERE
import Navbar from "./components/Navbar";
import Login from "./pages/Login";
import Signup from "./pages/signup"; // Ensure the 's' matches your filename
import Dashboard from "./pages/Dashboard";
import Report from "./pages/Report";
import Reports from "./pages/Reports";
import MapView from "./pages/MapView";

import "./index.css";

function AppContent() {
  const location = useLocation();
  const isAuthPage = location.pathname === "/" || location.pathname === "/signup";

  return (
    <div className="dashboard-container">
      {!isAuthPage && <Navbar />}
      <main className={isAuthPage ? "auth-area" : "content-area"}>
        <Routes>
          <Route path="/" element={<Login />} />
          <Route path="/signup" element={<Signup />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/map" element={<MapView />} />
          <Route path="/report" element={<Report />} />
          <Route path="/reports" element={<Reports />} />
        </Routes>
      </main>
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AppContent />
    </BrowserRouter>
  );
}