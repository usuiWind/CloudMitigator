import React, { useState, useEffect } from 'react';
import { AlertCircle, CheckCircle, RefreshCw } from 'lucide-react';
import { checkCredentials } from '../services/api';
import './CredentialsStatus.css';

const CredentialsStatus = () => {
  const [credentialsStatus, setCredentialsStatus] = useState(null);
  const [loading, setLoading] = useState(true);

  const checkCredentialsStatus = async () => {
    try {
      setLoading(true);
      const status = await checkCredentials();
      setCredentialsStatus(status);
    } catch (error) {
      setCredentialsStatus({
        valid: false,
        error: 'Failed to check credentials',
        details: error.message
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    checkCredentialsStatus();
  }, []);

  if (loading) {
    return (
      <div className="credentials-status loading">
        <RefreshCw className="icon spinning" size={16} />
        <span>Checking AWS credentials...</span>
      </div>
    );
  }

  if (credentialsStatus?.valid) {
    return (
      <div className="credentials-status valid">
        <CheckCircle className="icon" size={16} />
        <span>AWS credentials valid</span>
        <div className="credentials-details">
          <small>Account: {credentialsStatus.account_id}</small>
          <small>Region: {credentialsStatus.region}</small>
        </div>
      </div>
    );
  }

  return (
    <div className="credentials-container">
      <div className="credentials-status invalid">
        <AlertCircle className="icon" size={16} />
        <span>AWS credentials not configured (Demo Mode)</span>
        <div className="credentials-error">
          <small>Mitigations will simulate actions - {credentialsStatus?.error || 'Unknown error'}</small>
        </div>
        <button 
          className="retry-button" 
          onClick={checkCredentialsStatus}
          disabled={loading}
        >
          <RefreshCw className={`icon ${loading ? 'spinning' : ''}`} size={14} />
          Retry
        </button>
      </div>
    </div>
  );
};

export default CredentialsStatus;
