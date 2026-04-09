import client from './client';

export const listThreats = (page = 1, pageSize = 20, params = {}) =>
  client.get('/threats', { params: { page, page_size: pageSize, ...params } }).then((r) => r.data);

export const getThreat = (id) =>
  client.get(`/threats/${id}`).then((r) => r.data);

export const createThreat = (data) =>
  client.post('/threats', data).then((r) => r.data);

export const updateThreat = (id, data) =>
  client.patch(`/threats/${id}`, data).then((r) => r.data);

export const deleteThreat = (id) =>
  client.delete(`/threats/${id}`).then((r) => r.data);

export const lookupThreat = (value, indicatorType) =>
  client.post('/threats/lookup', { value, indicator_type: indicatorType }).then((r) => r.data);
