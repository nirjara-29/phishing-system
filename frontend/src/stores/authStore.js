import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { loginUser, registerUser, getProfile } from '../api/auth';

export const useAuthStore = create(
  persist(
    (set, get) => ({
      user: null,
      accessToken: null,
      refreshToken: null,
      isAuthenticated: false,
      isLoading: false,
      error: null,

      setTokens: (accessToken, refreshToken) =>
        set({ accessToken, refreshToken, isAuthenticated: true }),

      login: async (credentials) => {
        set({ isLoading: true, error: null });
        try {
          const data = await loginUser(credentials);
          set({
            accessToken: data.access_token,
            refreshToken: data.refresh_token,
            isAuthenticated: true,
            isLoading: false,
          });
          // Fetch profile after login
          try {
            const profile = await getProfile();
            set({ user: profile });
          } catch {
            // Profile fetch is optional
          }
          return data;
        } catch (err) {
          const message =
            err.response?.data?.message || err.response?.data?.detail || 'Login failed';
          set({ error: message, isLoading: false });
          throw err;
        }
      },

      register: async (data) => {
        set({ isLoading: true, error: null });
        try {
          const result = await registerUser(data);
          // If registration returns tokens, auto-login
          if (result.access_token) {
            set({
              accessToken: result.access_token,
              refreshToken: result.refresh_token,
              isAuthenticated: true,
            });
          }
          set({ isLoading: false });
          return result;
        } catch (err) {
          const message =
            err.response?.data?.message || err.response?.data?.detail || 'Registration failed';
          set({ error: message, isLoading: false });
          throw err;
        }
      },

      logout: () =>
        set({
          user: null,
          accessToken: null,
          refreshToken: null,
          isAuthenticated: false,
          error: null,
        }),

      clearError: () => set({ error: null }),
    }),
    {
      name: 'phishnet-auth',
      partialize: (state) => ({
        accessToken: state.accessToken,
        refreshToken: state.refreshToken,
        isAuthenticated: state.isAuthenticated,
        user: state.user,
      }),
    }
  )
);
