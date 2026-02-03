import { NavLink } from 'react-router-dom';
import { clsx } from 'clsx';

const navItems = [
  { path: '/', label: 'Dashboard', icon: 'H' },
  { path: '/servers', label: 'Servers', icon: 'S' },
  { path: '/keys', label: 'Keys', icon: 'K' },
  { path: '/graph', label: 'Graph', icon: 'G' },
  { path: '/scanner', label: 'Scanner', icon: 'R' },
  { path: '/watcher', label: 'Watcher', icon: 'W' },
  { path: '/alerts', label: 'Alerts', icon: 'A' },
  { path: '/reports', label: 'Reports', icon: 'P' },
  { path: '/settings', label: 'Settings', icon: 'C' },
];

export default function Sidebar() {
  return (
    <aside className="flex w-56 flex-col bg-gray-900 border-r border-gray-800">
      <div className="flex h-14 items-center px-4 border-b border-gray-800">
        <span className="text-lg font-bold text-blue-400">Keyspider</span>
      </div>
      <nav className="flex-1 overflow-y-auto py-4">
        {navItems.map((item) => (
          <NavLink
            key={item.path}
            to={item.path}
            end={item.path === '/'}
            className={({ isActive }) =>
              clsx(
                'flex items-center gap-3 px-4 py-2.5 text-sm transition-colors',
                isActive
                  ? 'bg-blue-500/10 text-blue-400 border-r-2 border-blue-400'
                  : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800'
              )
            }
          >
            <span className="flex h-6 w-6 items-center justify-center rounded bg-gray-800 text-xs font-bold">
              {item.icon}
            </span>
            {item.label}
          </NavLink>
        ))}
      </nav>
    </aside>
  );
}
