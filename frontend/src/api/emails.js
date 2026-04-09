import client from './client';

export const scanEmail = (data) =>
  client.post('/emails/scan', data).then((r) => r.data);

export const getEmailScanResult = (scanId) =>
  client.get(`/emails/${scanId}`).then((r) => r.data);

export const listEmailScans = (page = 1, pageSize = 20) =>
  client.get('/emails', { params: { page, page_size: pageSize } }).then((r) => r.data);
