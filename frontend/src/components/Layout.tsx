import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import {
  LayoutDashboard, Zap, Bell, Shield, Map, Plug, LogOut, Ghost,
} from 'lucide-react';
import { useAuthStore } from '../store/authStore';

const NAV = [
  { to: '/',            label: 'Dashboard',   icon: LayoutDashboard },
  { to: '/events',      label: 'Events',      icon: Zap },
  { to: '/alerts',      label: 'Alerts',      icon: Bell },
  { to: '/decoys',      label: 'Decoys',      icon: Shield },
  { to: '/mitre',       label: 'MITRE ATT&CK',icon: Map },
  { to: '/integrations',label: 'Integrations',icon: Plug },
];

export default function Layout() {
  const logout = useAuthStore((s) => s.logout);
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  return (
    <div className="flex h-full">
      {/* Sidebar */}
      <aside className="w-56 flex-shrink-0 bg-gray-950 border-r border-gray-800 flex flex-col">
        <div className="flex items-center gap-2 px-4 py-5 border-b border-gray-800">
          <Ghost className="text-indigo-400" size={22} />
          <span className="font-bold text-lg tracking-tight text-white">PhantomGrid</span>
        </div>
        <nav className="flex-1 px-2 py-3 space-y-0.5">
          {NAV.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) =>
                `flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm transition-colors ${
                  isActive
                    ? 'bg-indigo-600/20 text-indigo-300 font-medium'
                    : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800'
                }`
              }
            >
              <Icon size={16} />
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="px-2 py-3 border-t border-gray-800">
          <button
            onClick={handleLogout}
            className="flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm text-gray-400 hover:text-gray-200 hover:bg-gray-800 transition-colors w-full"
          >
            <LogOut size={16} />
            Sign out
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-auto bg-gray-950 p-6">
        <Outlet />
      </main>
    </div>
  );
}
