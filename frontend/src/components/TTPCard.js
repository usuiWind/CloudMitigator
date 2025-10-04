import React, { useState, useEffect, useCallback } from 'react';
import { Shield, AlertCircle, CheckCircle, Loader } from 'lucide-react';
import { getTTPStatus } from '../services/api';
import './TTPCard.css';

const TTPCard = ({ id, ttp, onMitigate, credentialsValid = true, refreshTrigger }) => {
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState(null);
  const [statusLoading, setStatusLoading] = useState(true);

  const handleMitigate = async () => {
    setLoading(true);
    try {
      const result = await onMitigate(id);
      // Only refresh this card's status after successful mitigation
      if (result && result.success) {
        fetchStatus();
      }
    } finally {
      setLoading(false);
    }
  };

  const fetchStatus = useCallback(async () => {
    try {
      setStatusLoading(true);
      const statusData = await getTTPStatus(id);
      setStatus(statusData);
    } catch (error) {
      console.error('Error fetching TTP status:', error);
      setStatus(null);
    } finally {
      setStatusLoading(false);
    }
  }, [id]);

  useEffect(() => {
    fetchStatus();
  }, [fetchStatus]);

  return (
    <div className="ttp-card">
      <div className="ttp-card-header">
        <div className="ttp-id-badge">
          <AlertCircle size={16} />
          <span>{id}</span>
        </div>
        <div className="service-badge">{ttp.aws_service}</div>
      </div>

      <div className="ttp-card-body">
        <h3 className="ttp-name">{ttp.name}</h3>
        {ttp.description && (
          <p className="ttp-description">{ttp.description}</p>
        )}
        
        <div className="mitigation-info">
          <div className="mitigation-label">
            <Shield size={16} />
            <span>Mitigation</span>
          </div>
          <p className="mitigation-text">{ttp.mitigation}</p>
        </div>
      </div>

      <div className="ttp-card-footer">
        {status && status.instances_needing_mitigation > 0 && (
          <div className="instances-warning">
            <AlertCircle size={14} />
            <span>
              {status.instances_needing_mitigation} instance{status.instances_needing_mitigation > 1 ? 's' : ''} need{status.instances_needing_mitigation === 1 ? 's' : ''} mitigation
            </span>
          </div>
        )}
        <button
          className={`mitigate-button ${
            status && status.instances_needing_mitigation > 0 ? 'needs-mitigation' : 'no-mitigation'
          }`}
          onClick={handleMitigate}
          disabled={loading || statusLoading}
        >
          {loading ? (
            <>
              <Loader className="button-spinner" size={16} />
              Applying...
            </>
          ) : (
            <>
              <CheckCircle size={16} />
              Apply Mitigation
            </>
          )}
        </button>
      </div>
    </div>
  );
};

export default TTPCard;
