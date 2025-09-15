import { NavLink, useLocation } from 'react-router-dom';
import { useStore } from '../../store/useStore';

const navigation = [
  { name: 'Dashboard', href: '/', icon: 'M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6' },
  { name: 'Scan File', href: '/scan', icon: 'M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12' },
  { name: 'Recent Scans', href: '/recent', icon: 'M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z' },
  { name: 'Threats', href: '/threats', icon: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z' },
  { name: 'Settings', href: '/settings', icon: 'M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z' },
];

export const Sidebar = () => {
  const location = useLocation();
  const { stats } = useStore();

  return (
    <div className="hidden md:flex md:flex-shrink-0">
      <div className="flex flex-col w-64 border-r border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800">
        <div className="flex flex-col flex-grow pt-5 pb-4 overflow-y-auto">
          <div className="flex items-center flex-shrink-0 px-4">
            <h2 className="text-xl font-bold text-gray-900 dark:text-white">Menu</h2>
          </div>
          
          <div className="mt-5 flex-1 flex flex-col">
            <nav className="flex-1 px-2 space-y-1">
              {navigation.map((item) => (
                <NavLink
                  key={item.name}
                  to={item.href}
                  className={({ isActive }) =>
                    `group flex items-center px-2 py-2 text-sm font-medium rounded-md ${
                      isActive
                        ? 'bg-indigo-50 text-indigo-700 dark:bg-gray-700 dark:text-white'
                        : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900 dark:text-gray-300 dark:hover:bg-gray-700 dark:hover:text-white'
                    }`
                  }
                >
                  <svg
                    className={`mr-3 h-6 w-6 ${
                      location.pathname === item.href
                        ? 'text-indigo-500 dark:text-indigo-400'
                        : 'text-gray-400 group-hover:text-gray-500 dark:group-hover:text-gray-300'
                    }`}
                    xmlns="http://www.w3.org/2000/svg"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                    aria-hidden="true"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth="2"
                      d={item.icon}
                    />
                  </svg>
                  {item.name}
                </NavLink>
              ))}
            </nav>
          </div>
          
          <div className="p-4 mt-auto">
            <div className="bg-indigo-50 dark:bg-gray-700 rounded-lg p-4">
              <h3 className="text-sm font-medium text-indigo-800 dark:text-indigo-200">Scan Statistics</h3>
              <dl className="mt-2 grid grid-cols-1 gap-2">
                <div className="flex items-center justify-between">
                  <dt className="text-xs text-indigo-600 dark:text-indigo-300">Total Scans</dt>
                  <dd className="text-sm font-medium text-gray-900 dark:text-white">{stats?.totalScans || 0}</dd>
                </div>
                <div className="flex items-center justify-between">
                  <dt className="text-xs text-indigo-600 dark:text-indigo-300">Threats Detected</dt>
                  <dd className="text-sm font-medium text-red-600 dark:text-red-400">{stats?.infectedFiles || 0}</dd>
                </div>
                <div className="flex items-center justify-between">
                  <dt className="text-xs text-indigo-600 dark:text-indigo-300">Clean Files</dt>
                  <dd className="text-sm font-medium text-green-600 dark:text-green-400">
                    {Math.max(0, (stats?.totalScans || 0) - (stats?.infectedFiles || 0))}
                  </dd>
                </div>
              </dl>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
