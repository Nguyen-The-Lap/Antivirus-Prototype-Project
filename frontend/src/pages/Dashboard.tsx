import { useEffect } from 'react';
import { useStore } from '../store/useStore';
import { FileUploadCard } from '../components/scan/FileUploadCard';
import { ScanStats } from '../components/dashboard/ScanStats';
import { RecentScans } from '../components/dashboard/RecentScans';
import { SystemStatus } from '../components/dashboard/SystemStatus';

export const Dashboard = () => {
  const { getRecentScans, getStats } = useStore();

  useEffect(() => {
    getRecentScans(5);
    getStats();
  }, [getRecentScans, getStats]);

  return (
    <div className="space-y-6">
      <div className="flex flex-col lg:flex-row gap-6">
        <div className="lg:w-2/3">
          <FileUploadCard />
        </div>
        <div className="lg:w-1/3">
          <SystemStatus />
        </div>
      </div>
      
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <ScanStats />
      </div>
      
      <div className="mt-8">
        <RecentScans />
      </div>
    </div>
  );
};
