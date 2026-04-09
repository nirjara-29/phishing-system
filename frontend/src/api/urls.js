import client from './client';

export const scanUrl = (url, asyncMode = false) =>
  client.post('/urls/scan', { url, async_mode: asyncMode }).then((r) => r.data);

export const scanUrlBatch = (urls) =>
  client.post('/urls/batch', { urls, async_mode: true }).then((r) => r.data);

export const getScanResult = (scanId) =>
  client.get(`/urls/${scanId}`).then((r) => r.data);

export const listUrlScans = (page = 1, pageSize = 20) =>
  client.get('/urls', { params: { page, page_size: pageSize } }).then((r) => r.data);

export const quickCheck = (url) =>
  client.post('/extension/check', { url, check_cache: true }).then((r) => r.data);
