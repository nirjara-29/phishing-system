import { create } from 'zustand';
import { listThreats, getThreat, createThreat, deleteThreat } from '../api/threats';

export const useThreatStore = create((set) => ({
  threats: [],
  totalThreats: 0,
  currentThreat: null,
  loading: false,
  error: null,

  fetchThreats: async (page = 1, filters = {}) => {
    set({ loading: true, error: null });
    try {
      const data = await listThreats(page, 20, filters);
      set({
        threats: data.items || data,
        totalThreats: data.total || 0,
        loading: false,
      });
    } catch (err) {
      set({ error: 'Failed to load threats', loading: false });
    }
  },

  fetchThreatDetail: async (id) => {
    set({ loading: true, error: null });
    try {
      const data = await getThreat(id);
      set({ currentThreat: data, loading: false });
    } catch {
      set({ error: 'Threat not found', loading: false });
    }
  },

  addThreat: async (data) => {
    set({ loading: true, error: null });
    try {
      const result = await createThreat(data);
      set((state) => ({
        threats: [result, ...state.threats],
        loading: false,
      }));
      return result;
    } catch (err) {
      const msg = err.response?.data?.message || 'Failed to create threat';
      set({ error: msg, loading: false });
      throw err;
    }
  },

  removeThreat: async (id) => {
    try {
      await deleteThreat(id);
      set((state) => ({
        threats: state.threats.filter((t) => t.id !== id),
      }));
    } catch {
      set({ error: 'Failed to delete threat' });
    }
  },

  clearError: () => set({ error: null }),
}));
