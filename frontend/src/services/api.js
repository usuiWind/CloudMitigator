import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const fetchTTPs = async (searchQuery = '') => {
  try {
    const params = searchQuery ? { search: searchQuery } : {};
    const response = await api.get('/ttps', { params });
    return response.data;
  } catch (error) {
    console.error('Error fetching TTPs:', error);
    throw error;
  }
};

export const fetchTTP = async (ttpId) => {
  try {
    const response = await api.get(`/ttps/${ttpId}`);
    return response.data;
  } catch (error) {
    console.error(`Error fetching TTP ${ttpId}:`, error);
    throw error;
  }
};

export const mitigateTTP = async (ttpId, params = {}) => {
  try {
    const response = await api.post(`/mitigate/${ttpId}`, params);
    return response.data;
  } catch (error) {
    console.error(`Error mitigating TTP ${ttpId}:`, error);
    if (error.response && error.response.data) {
      throw new Error(error.response.data.error || 'Mitigation failed');
    }
    throw error;
  }
};

export const fetchLogs = async () => {
  try {
    const response = await api.get('/logs');
    return response.data;
  } catch (error) {
    console.error('Error fetching logs:', error);
    throw error;
  }
};

export const checkHealth = async () => {
  try {
    const response = await api.get('/status');
    return response.data;
  } catch (error) {
    console.error('Error checking health:', error);
    throw error;
  }
};

export const checkCredentials = async () => {
  try {
    const response = await api.get('/credentials/status');
    return response.data;
  } catch (error) {
    console.error('Error checking credentials:', error);
    throw error;
  }
};

export const getTTPStatus = async (ttpId) => {
  try {
    const response = await api.get(`/ttps/${ttpId}/status`);
    return response.data;
  } catch (error) {
    console.error(`Error getting TTP status ${ttpId}:`, error);
    throw error;
  }
};

export default api;
