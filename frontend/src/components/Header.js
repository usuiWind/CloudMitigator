import React from 'react';
import { Shield } from 'lucide-react';
import './Header.css';

const Header = () => {
  return (
    <header className="header">
      <div className="header-content">
        <div className="logo-section">
          <Shield className="logo-icon" size={28} />
          <div className="logo-text">
            <h1>CloudMitigator</h1>
            <span className="tagline">AWS Security Automation</span>
          </div>
        </div>
        <div className="header-actions">
          <span className="status-indicator">
            <span className="status-dot"></span>
            Connected
          </span>
        </div>
      </div>
    </header>
  );
};

export default Header;
