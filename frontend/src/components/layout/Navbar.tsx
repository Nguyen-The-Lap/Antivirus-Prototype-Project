import { Link, useNavigate } from 'react-router-dom';
import { useState, useEffect } from 'react';
import { useStore } from '../../store/useStore';
import { toast } from 'react-toastify';

export const Navbar = () => {
  const [isScrolled, setIsScrolled] = useState(false);
  const { stats, getStats } = useStore();
  const navigate = useNavigate();

  useEffect(() => {
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 10);
    };

    window.addEventListener('scroll', handleScroll);
    getStats();

    return () => {
      window.removeEventListener('scroll', handleScroll);
    };
  }, [getStats]);

  const handleLogout = () => {
    // Implement logout logic here
    toast.success('Logged out successfully');
    navigate('/login');
  };

  return (
    <header 
      className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
        isScrolled 
          ? 'bg-white/80 dark:bg-gray-800/80 backdrop-blur-md shadow-md' 
          : 'bg-white dark:bg-gray-800'
      }`}
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between h-16">
          <div className="flex items-center">
            <Link to="/" className="flex-shrink-0 flex items-center">
              <div className="h-8 w-8 text-indigo-600 dark:text-indigo-400">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor">
                  <path 
                    fillRule="evenodd" 
                    d="M12.516 2.17a.75.75 0 00-1.032 0 11.209 11.209 0 01-7.877 3.08.75.75 0 00-.722.515A12.74 12.74 0 002.25 9.75c0 5.942 4.064 10.933 9.563 12.348a.749.749 0 00.374 0c5.499-1.415 9.563-6.406 9.563-12.348 0-1.39-.223-2.73-.635-3.985a.75.75 0 00-.722-.516l-.143.001c-2.996 0-5.717-1.17-7.734-3.08zm3.094 8.016a.75.75 0 10-1.22-.872l-3.236 4.53L9.53 12.22a.75.75 0 00-1.06 1.06l2.25 2.25a.75.75 0 001.14-.094l3.75-5.25z" 
                    clipRule="evenodd" 
                  />
                </svg>
              </div>
              <span className="ml-2 text-xl font-bold text-gray-900 dark:text-white">
                Antivirus Scanner
              </span>
            </Link>
            <nav className="hidden md:ml-10 md:flex space-x-8">
              <Link 
                to="/" 
                className="inline-flex items-center px-1 pt-1 border-b-2 border-indigo-500 text-sm font-medium text-gray-900 dark:text-white"
              >
                Dashboard
              </Link>
              <Link 
                to="/scan" 
                className="inline-flex items-center px-1 pt-1 border-b-2 border-transparent text-sm font-medium text-gray-500 hover:border-gray-300 hover:text-gray-700 dark:text-gray-300 dark:hover:text-white"
              >
                Scan File
              </Link>
              <Link 
                to="/recent" 
                className="inline-flex items-center px-1 pt-1 border-b-2 border-transparent text-sm font-medium text-gray-500 hover:border-gray-300 hover:text-gray-700 dark:text-gray-300 dark:hover:text-white"
              >
                Recent Scans
              </Link>
              <Link 
                to="/threats" 
                className="inline-flex items-center px-1 pt-1 border-b-2 border-transparent text-sm font-medium text-gray-500 hover:border-gray-300 hover:text-gray-700 dark:text-gray-300 dark:hover:text-white"
              >
                Threats
              </Link>
            </nav>
          </div>
          
          <div className="hidden md:ml-4 md:flex md:items-center md:space-x-4">
            <div className="flex items-center space-x-2">
              <div className="flex items-center">
                <span className="h-2 w-2 rounded-full bg-green-500 mr-2"></span>
                <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
                  {stats?.totalScans || 0} Scans
                </span>
              </div>
              <div className="h-5 w-px bg-gray-300 dark:bg-gray-600"></div>
              <div className="flex items-center">
                <span className="h-2 w-2 rounded-full bg-red-500 mr-2"></span>
                <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
                  {stats?.infectedFiles || 0} Threats
                </span>
              </div>
            </div>
            
            <div className="ml-4 flex items-center md:ml-6">
              <button
                type="button"
                onClick={handleLogout}
                className="ml-4 inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
              >
                Logout
              </button>
            </div>
          </div>
          
          <div className="-mr-2 flex items-center md:hidden">
            <button
              type="button"
              className="inline-flex items-center justify-center p-2 rounded-md text-gray-400 hover:text-gray-500 hover:bg-gray-100 focus:outline-none focus:ring-2 focus:ring-inset focus:ring-indigo-500"
              aria-expanded="false"
            >
              <span className="sr-only">Open main menu</span>
              <svg
                className="block h-6 w-6"
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
                  d="M4 6h16M4 12h16M4 18h16"
                />
              </svg>
            </button>
          </div>
        </div>
      </div>
    </header>
  );
};
