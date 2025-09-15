import { useEffect, useState } from 'react';
import { useStore } from '../../store/useStore';

const statuses = {
  online: 'text-green-400 bg-green-400/10',
  error: 'text-rose-400 bg-rose-400/10',
  warning: 'text-yellow-400 bg-yellow-400/10',
  offline: 'text-gray-500 bg-gray-100 dark:bg-gray-800',
};

const statusList = [
  {
    id: 1,
    name: 'Scanner Engine',
    status: 'online',
    description: 'Real-time scanning engine is operational',
  },
  {
    id: 2,
    name: 'Virus Definitions',
    status: 'online',
    description: 'Virus definitions are up to date',
  },
  {
    id: 3,
    name: 'Machine Learning Model',
    status: 'online',
    description: 'AI threat detection is active',
  },
  {
    id: 4,
    name: 'Cloud Protection',
    status: 'online',
    description: 'Cloud-based threat intelligence connected',
  },
];

export const SystemStatus = () => {
  const [lastUpdated, setLastUpdated] = useState(new Date());
  const { stats } = useStore();

  // Update the last updated time every minute
  useEffect(() => {
    const timer = setInterval(() => {
      setLastUpdated(new Date());
    }, 60000);

    return () => clearInterval(timer);
  }, []);

  // Calculate system health (simple example)
  const systemHealth = (stats?.totalScans || 0) > 0
    ? Math.max(0, 100 - ((stats?.infectedFiles || 0) / (stats?.totalScans || 1)) * 100)
    : 100;

  return (
    <div className="bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden">
      <div className="p-6">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-medium text-gray-900 dark:text-white">System Status</h2>
          <div className="flex items-center">
            <span className="text-sm text-gray-500 dark:text-gray-400">
              Last updated: {lastUpdated.toLocaleTimeString()}
            </span>
          </div>
        </div>

        <div className="mt-6">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400">Overall Health</h3>
            <span className="text-sm font-medium text-gray-900 dark:text-white">
              {Math.round(systemHealth)}%
            </span>
          </div>
          <div className="mt-2 h-2 w-full bg-gray-200 rounded-full overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-green-500 via-yellow-500 to-red-500"
              style={{ width: `${systemHealth}%` }}
            />
          </div>
        </div>

        <div className="mt-6">
          <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-3">
            Component Status
          </h3>
          <ul className="divide-y divide-gray-200 dark:divide-gray-700">
            {statusList.map((item) => (
              <li key={item.id} className="py-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center">
                    <span
                      className={`flex-none w-2.5 h-2.5 rounded-full ${statuses[item.status as keyof typeof statuses]}`}
                      aria-hidden="true"
                    />
                    <p className="ml-3 text-sm font-medium text-gray-900 dark:text-white">
                      {item.name}
                    </p>
                  </div>
                  <p className="text-sm text-gray-500 dark:text-gray-400">
                    {item.status === 'online' ? 'Operational' : 'Offline'}
                  </p>
                </div>
                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400 ml-5">
                  {item.description}
                </p>
              </li>
            ))}
          </ul>
        </div>

        <div className="mt-6 border-t border-gray-200 dark:border-gray-700 pt-4">
          <div className="flex items-center justify-between">
            <p className="text-sm font-medium text-gray-500 dark:text-gray-400">
              Last System Scan
            </p>
            <p className="text-sm text-gray-900 dark:text-white">
              {stats?.totalScans ? 'A few seconds ago' : 'Never'}
            </p>
          </div>
          <div className="mt-2 flex items-center justify-between">
            <p className="text-sm font-medium text-gray-500 dark:text-gray-400">
              Threats Blocked (24h)
            </p>
            <p className="text-sm text-rose-600 dark:text-rose-400 font-medium">
              {stats?.infectedFiles || 0}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
