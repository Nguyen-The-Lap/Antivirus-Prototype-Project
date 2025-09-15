import { create } from 'zustand';
import { devtools, persist } from 'zustand/middleware';
import { api } from '../services/api';

export interface ScanResult {
  scan_id: string;
  filename: string;
  infected: boolean;
  threats?: string[];
  scan_time: string;
  [key: string]: any;
}

interface AppState {
  // State
  isScanning: boolean;
  scanResults: ScanResult[];
  recentScans: ScanResult[];
  stats: {
    totalScans: number;
    infectedFiles: number;
    cleanFiles: number;
  };
  error: string | null;
  
  // Actions
  scanFile: (file: File) => Promise<ScanResult>;
  getRecentScans: (limit?: number) => Promise<void>;
  getScanResult: (scanId: string) => Promise<ScanResult>;
  getStats: () => Promise<void>;
  clearError: () => void;
}

export const useStore = create<AppState>()(
  devtools(
    persist(
      (set, get) => ({
        // Initial state
        isScanning: false,
        scanResults: [],
        recentScans: [],
        stats: {
          totalScans: 0,
          infectedFiles: 0,
          cleanFiles: 0,
        },
        error: null,

        // Scan a file
        scanFile: async (file: File) => {
          set({ isScanning: true, error: null });
          try {
            const result = await api.scanFile(file);
            
            // Update recent scans
            await get().getRecentScans();
            
            // Update stats
            await get().getStats();
            
            return result;
          } catch (error: any) {
            const errorMessage = error.response?.data?.error || error.message || 'Failed to scan file';
            set({ error: errorMessage });
            throw new Error(errorMessage);
          } finally {
            set({ isScanning: false });
          }
        },

        // Get recent scans
        getRecentScans: async (limit = 10) => {
          try {
            const data = await api.getRecentScans(limit);
            set({ recentScans: data.results || [] });
          } catch (error: any) {
            const errorMessage = error.response?.data?.error || error.message || 'Failed to fetch recent scans';
            set({ error: errorMessage });
          }
        },

        // Get scan result by ID
        getScanResult: async (scanId: string) => {
          try {
            const result = await api.getScanResult(scanId);
            return result;
          } catch (error: any) {
            const errorMessage = error.response?.data?.error || error.message || 'Failed to fetch scan result';
            set({ error: errorMessage });
            throw error;
          }
        },

        // Get statistics
        getStats: async () => {
          try {
            const data = await api.getStats();
            set({
              stats: {
                totalScans: data.total_scans || 0,
                infectedFiles: data.infected_files || 0,
                cleanFiles: data.clean_files || 0,
              },
            });
          } catch (error: any) {
            console.error('Failed to fetch stats:', error);
          }
        },

        // Clear error
        clearError: () => set({ error: null }),
      }),
      {
        name: 'antivirus-storage', // name of the item in the storage (must be unique)
        partialize: (state) => ({
          // Only persist these fields
          recentScans: state.recentScans,
          stats: state.stats,
        }),
      }
    ),
    {
      name: 'antivirus-devtools',
    }
  )
);
