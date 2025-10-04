import React from 'react';
import { Cloud, Filter, Database, Shield, Lock, AlertTriangle } from 'lucide-react';
import './Sidebar.css';

const serviceIcons = {
  iam: Lock,
  secretsmanager: Database,
  wafv2: Shield,
  cloudtrail: AlertTriangle,
};

const Sidebar = ({ services, selectedService, onServiceSelect, ttpCount }) => {
  return (
    <aside className="sidebar">
      <div className="sidebar-section">
        <div className="sidebar-header">
          <Filter size={18} />
          <h3>Filters</h3>
        </div>
        
        <div className="filter-group">
          <label className="filter-label">AWS Service</label>
          <button
            className={`service-item ${selectedService === 'all' ? 'active' : ''}`}
            onClick={() => onServiceSelect('all')}
          >
            <Cloud size={18} />
            <span>All Services</span>
            <span className="count">{ttpCount}</span>
          </button>
          
          {services.map((service) => {
            const Icon = serviceIcons[service] || Cloud;
            return (
              <button
                key={service}
                className={`service-item ${selectedService === service ? 'active' : ''}`}
                onClick={() => onServiceSelect(service)}
              >
                <Icon size={18} />
                <span>{service}</span>
              </button>
            );
          })}
        </div>
      </div>

      <div className="sidebar-footer">
        <div className="info-card">
          <h4>About CloudMitigator</h4>
          <p>Automated AWS security mitigations mapped to MITRE ATT&CK TTPs.</p>
        </div>
      </div>
    </aside>
  );
};

export default Sidebar;
