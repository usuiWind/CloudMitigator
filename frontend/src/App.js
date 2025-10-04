import React, { useState, useEffect, useCallback } from 'react';
import { ToastContainer, toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import './App.css';
import Header from './components/Header';
import Sidebar from './components/Sidebar';
import SearchBar from './components/SearchBar';
import TTPList from './components/TTPList';
import CredentialsStatus from './components/CredentialsStatus';
import LogsViewer from './components/LogsViewer';
import { fetchTTPs, mitigateTTP, checkCredentials } from './services/api';

function App() {
  const [ttps, setTtps] = useState({});
  const [filteredTtps, setFilteredTtps] = useState({});
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedService, setSelectedService] = useState('all');
  const [credentialsValid, setCredentialsValid] = useState(false);

  const loadTTPs = useCallback(async () => {
    try {
      setLoading(true);
      const data = await fetchTTPs();
      setTtps(data);
      setFilteredTtps(data);
    } catch (error) {
      toast.error('Failed to load TTPs: ' + error.message);
    } finally {
      setLoading(false);
    }
  }, []);

  const checkCredentialsStatus = useCallback(async () => {
    try {
      const status = await checkCredentials();
      setCredentialsValid(status.valid);
    } catch (error) {
      setCredentialsValid(false);
    }
  }, []);

  const filterTTPs = useCallback(() => {
    let filtered = { ...ttps };

    // Filter by search query
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      filtered = Object.fromEntries(
        Object.entries(filtered).filter(([id, ttp]) =>
          id.toLowerCase().includes(query) ||
          ttp.name.toLowerCase().includes(query) ||
          (ttp.description && ttp.description.toLowerCase().includes(query))
        )
      );
    }

    // Filter by AWS service
    if (selectedService !== 'all') {
      filtered = Object.fromEntries(
        Object.entries(filtered).filter(([_, ttp]) =>
          ttp.aws_service === selectedService
        )
      );
    }

    setFilteredTtps(filtered);
  }, [ttps, searchQuery, selectedService]);

  const handleMitigate = async (ttpId) => {
    try {
      const result = await mitigateTTP(ttpId);
      if (result.success) {
        const isDemo = result.details?.demo_mode;
        const icon = isDemo ? '🎭' : '✓';
        toast.success(`${icon} ${result.message}`);
        return result; // Return result so TTPCard can check success
      } else {
        toast.error(`✗ ${result.error || 'Mitigation failed'}`);
        return result;
      }
    } catch (error) {
      toast.error('Failed to apply mitigation: ' + error.message);
      return { success: false, error: error.message };
    }
  };

  const getUniqueServices = () => {
    const services = new Set(Object.values(ttps).map(ttp => ttp.aws_service));
    return Array.from(services).sort();
  };

  useEffect(() => {
    loadTTPs();
    checkCredentialsStatus();
  }, [loadTTPs, checkCredentialsStatus]);

  useEffect(() => {
    filterTTPs();
  }, [filterTTPs]);

  return (
    <div className="app">
      <Header />
      <div className="app-container">
        <Sidebar
          services={getUniqueServices()}
          selectedService={selectedService}
          onServiceSelect={setSelectedService}
          ttpCount={Object.keys(ttps).length}
        />
        <main className="main-content">
          <div className="content-header">
            <h1>MITRE ATT&CK TTP Mitigations</h1>
            <p className="subtitle">Automated AWS security mitigations for detected threats</p>
          </div>
          <CredentialsStatus />
          <LogsViewer />
          <SearchBar
            value={searchQuery}
            onChange={setSearchQuery}
            placeholder="Search by TTP ID, name, or description..."
          />
          <TTPList
            ttps={filteredTtps}
            loading={loading}
            onMitigate={handleMitigate}
            credentialsValid={credentialsValid}
          />
        </main>
      </div>
      <ToastContainer
        position="top-right"
        autoClose={5000}
        hideProgressBar={false}
        newestOnTop
        closeOnClick
        rtl={false}
        pauseOnFocusLoss
        draggable
        pauseOnHover
        theme="light"
      />
    </div>
  );
}

export default App;
