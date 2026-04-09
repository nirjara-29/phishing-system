import client from './client';

export const loginUser = (credentials) =>
  client.post('/auth/login', credentials).then((r) => r.data);

export const registerUser = (data) =>
  client.post('/auth/register', data).then((r) => r.data);

export const refreshTokens = (refreshToken) =>
  client.post('/auth/refresh', { refresh_token: refreshToken }).then((r) => r.data);

export const changePassword = (data) =>
  client.post('/auth/change-password', data).then((r) => r.data);

export const generateApiKey = () =>
  client.post('/auth/api-key').then((r) => r.data);

export const getProfile = () =>
  client.get('/auth/me').then((r) => r.data);
