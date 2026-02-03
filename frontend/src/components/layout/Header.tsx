import { useNavigate } from 'react-router-dom';

export default function Header() {
  const navigate = useNavigate();

  const handleLogout = () => {
    localStorage.removeItem('token');
    navigate('/login');
  };

  return (
    <header className="flex h-14 items-center justify-between border-b border-gray-800 bg-gray-900 px-6">
      <div className="text-sm text-gray-400">SSH Key Usage Monitor</div>
      <button
        onClick={handleLogout}
        className="text-sm text-gray-400 hover:text-gray-200 transition-colors"
      >
        Logout
      </button>
    </header>
  );
}
