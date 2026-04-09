import { create } from 'zustand';
import { getScanResult, listUrlScans } from '../api/urls';
import { getEmailScanResult, listEmailScans } from '../api/emails';
import { checkUrl, scanEmail } from '../services/api';

export const useScanStore = create((set, get) => ({
  // Current scan
  currentScan: null,
  scanLoading: false,
  scanError: null,

  // Scan history
  urlScans: [],
  emailScans: [],
  urlTotal: 0,
  emailTotal: 0,

  // URL scanning
  scanUrlAction: async (url) => {
    set({ scanLoading: true, scanError: null, currentScan: null });
    try {
      const result = await checkUrl(url);
      set({ currentScan: result, scanLoading: false });
      return result;
    } catch (err) {
      const msg = err.message || 'Unable to analyze. Please try again.';
      set({ scanError: msg, scanLoading: false });
      throw err;
    }
  },

  // Email scanning
  scanEmailAction: async (emailText) => {
    set({ scanLoading: true, scanError: null, currentScan: null });
    try {
      const result = await scanEmail(emailText);
      set({ currentScan: result, scanLoading: false });
      return result;
    } catch (err) {
      const msg = err.message || 'Unable to analyze. Please try again.';
      set({ scanError: msg, scanLoading: false });
      throw err;
    }
  },

  // Fetch scan result by ID
  fetchScanResult: async (scanId, type = 'url') => {
    set({ scanLoading: true, scanError: null });
    try {
      const fetcher = type === 'url' ? getScanResult : getEmailScanResult;
      const result = await fetcher(scanId);
      set({ currentScan: result, scanLoading: false });
      return result;
    } catch (err) {
      set({ scanError: 'Failed to fetch scan result', scanLoading: false });
      throw err;
    }
  },

  // List scans
  fetchUrlScans: async (page = 1) => {
    try {
      const data = await listUrlScans(page);
      set({ urlScans: data.items || data, urlTotal: data.total || 0 });
    } catch {
      // silently fail
    }
  },

  fetchEmailScans: async (page = 1) => {
    try {
      const data = await listEmailScans(page);
      set({ emailScans: data.items || data, emailTotal: data.total || 0 });
    } catch {
      // silently fail
    }
  },

  clearScan: () => set({ currentScan: null, scanError: null }),
}));
