import React from 'react';
import { Link } from 'react-router-dom';

const Header = () => {
  return (
    <header className="bg-gray-800 text-white shadow-lg">
      <div className="container mx-auto px-4 py-4">
        <div className="flex items-center justify-between">
          <Link to="/" className="flex items-center space-x-2">
            <span className="text-2xl font-bold">🔍 ACIP</span>
            <span className="text-sm text-gray-400">Autonomous Cloud Investigation Platform</span>
          </Link>
          
          <nav className="flex space-x-6">
            <Link to="/" className="hover:text-gray-300">Dashboard</Link>
            <Link to="/incidents" className="hover:text-gray-300">Incidents</Link>
            <Link to="/events" className="hover:text-gray-300">Events</Link>
            <Link to="/realtime-events" className="hover:text-gray-300">Live Events</Link>
            <Link to="/rules" className="hover:text-gray-300">Rules</Link>
            <Link
              to="/ai-assistant"
              className={`hover:text-gray-300`}
            >
              
              <span>AI Assistant</span>
            </Link>
          </nav>
        </div>
      </div>
    </header>
  );
};

export default Header;