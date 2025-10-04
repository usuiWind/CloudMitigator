import React from 'react';
import TTPCard from './TTPCard';
import { Loader } from 'lucide-react';
import './TTPList.css';

const TTPList = ({ ttps, loading, onMitigate, credentialsValid = true }) => {
  if (loading) {
    return (
      <div className="loading-container">
        <Loader className="spinner" size={48} />
        <p>Loading TTPs...</p>
      </div>
    );
  }

  const ttpEntries = Object.entries(ttps);

  if (ttpEntries.length === 0) {
    return (
      <div className="empty-state">
        <p>No TTPs found matching your criteria.</p>
      </div>
    );
  }

  return (
    <div className="ttp-list">
      <div className="ttp-list-header">
        <h2>Found {ttpEntries.length} TTP{ttpEntries.length !== 1 ? 's' : ''}</h2>
      </div>
      <div className="ttp-grid">
        {ttpEntries.map(([id, ttp]) => (
          <TTPCard
            key={id}
            id={id}
            ttp={ttp}
            onMitigate={onMitigate}
            credentialsValid={credentialsValid}
          />
        ))}
      </div>
    </div>
  );
};

export default TTPList;
