import React from "react";
import { useNavigate } from "react-router-dom";

const Login = () => {
  const navigate = useNavigate();

  return (
    <div className="login-screen">
      <div className="login-card glass-card">
        <div className="login-brand">
          <img src="/logo192.png" alt="Logo" className="brand-logo" />
          <h1>Water Quality Monitor</h1>
          <p className="brand-tagline">Environmental Intelligence</p>
        </div>
        
        <form className="login-form" onSubmit={(e) => { e.preventDefault(); navigate('/dashboard'); }}>
          <h3>Login</h3>
          <div className="form-group">
            <label>Your email</label>
            <input type="email" placeholder="admin@123" required />
          </div>
          <div className="form-group">
            <label>Your password</label>
            <input type="password" placeholder="••••••••" required />
          </div>
          <button type="submit" className="blue-submit-btn">Submit</button>
        </form>
      </div>
    </div>
  );
};

export default Login;