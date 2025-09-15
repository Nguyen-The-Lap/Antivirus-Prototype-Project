import axios from 'axios';
import type { AxiosInstance } from 'axios';

const API_BASE_URL = 'http://localhost:5000/api';

class ApiService {
  private static instance: ApiService;
  private axiosInstance: AxiosInstance;

  private constructor() {
    this.axiosInstance = axios.create({
      baseURL: API_BASE_URL,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    // Add request interceptor
    this.axiosInstance.interceptors.request.use(
      (config) => {
        // You can add auth token here if needed
        // const token = localStorage.getItem('token');
        // if (token) {
        //   config.headers.Authorization = `Bearer ${token}`;
        // }
        return config;
      },
      (error) => {
        return Promise.reject(error);
      }
    );

    // Add response interceptor
    this.axiosInstance.interceptors.response.use(
      (response) => response,
      (error) => {
        // Handle errors globally
        if (error.response) {
          // The request was made and the server responded with a status code
          // that falls out of the range of 2xx
          console.error('API Error:', error.response.data);
          console.error('Status:', error.response.status);
          console.error('Headers:', error.response.headers);
        } else if (error.request) {
          // The request was made but no response was received
          console.error('API Error:', error.request);
        } else {
          // Something happened in setting up the request that triggered an Error
          console.error('Error:', error.message);
        }
        return Promise.reject(error);
      }
    );
  }

  public static getInstance(): ApiService {
    if (!ApiService.instance) {
      ApiService.instance = new ApiService();
    }
    return ApiService.instance;
  }

  // File scanning
  public async scanFile(file: File): Promise<any> {
    const formData = new FormData();
    formData.append('file', file);

    const response = await this.axiosInstance.post('/scan', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });

    return response.data;
  }

  // Get scan result by ID
  public async getScanResult(scanId: string): Promise<any> {
    const response = await this.axiosInstance.get(`/scan/${scanId}`);
    return response.data;
  }

  // Get recent scans
  public async getRecentScans(limit: number = 10): Promise<any> {
    const response = await this.axiosInstance.get('/recent-scans', {
      params: { limit },
    });
    return response.data;
  }

  // Get statistics
  public async getStats(): Promise<any> {
    const response = await this.axiosInstance.get('/stats');
    return response.data;
  }

  // Scan directory (admin only)
  public async scanDirectory(directory: string): Promise<any> {
    const response = await this.axiosInstance.post('/scan/directory', { directory });
    return response.data;
  }
}

export const api = ApiService.getInstance();
