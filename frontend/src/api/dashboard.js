import client from './client';

export const getDashboardStats = () =>
  client.get('/dashboard/stats').then((r) => r.data);

export const getThreatTrend = (days = 7) =>
  client.get('/dashboard/trend', { params: { days } }).then((r) => r.data);

export const getTopThreats = (limit = 10) =>
  client.get('/dashboard/top-threats', { params: { limit } }).then((r) => r.data);

export const getRecentScans = (limit = 20) =>
  client.get('/dashboard/recent', { params: { limit } }).then((r) => r.data);

export const generateReport = (data) =>
  client.post('/reports/generate', data).then((r) => r.data);
