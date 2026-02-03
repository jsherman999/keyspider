import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useServers, useCreateServer } from '../api/queries/servers';
import { Table } from '../components/common/Table';
import { Badge } from '../components/common/Badge';
import type { Server } from '../api/types';
import { formatDistanceToNow } from 'date-fns';

export default function Servers() {
  const navigate = useNavigate();
  const [search, setSearch] = useState('');
  const [showAdd, setShowAdd] = useState(false);
  const { data, isLoading } = useServers({ search: search || undefined });
  const createServer = useCreateServer();
  const [newServer, setNewServer] = useState({ hostname: '', ip_address: '', ssh_port: 22, os_type: 'linux' });

  const handleAdd = () => {
    createServer.mutate(newServer, {
      onSuccess: () => {
        setShowAdd(false);
        setNewServer({ hostname: '', ip_address: '', ssh_port: 22, os_type: 'linux' });
      },
    });
  };

  const columns = [
    { key: 'hostname', header: 'Hostname' },
    { key: 'ip_address', header: 'IP Address' },
    { key: 'os_type', header: 'OS' },
    { key: 'ssh_port', header: 'Port' },
    {
      key: 'is_reachable',
      header: 'Status',
      render: (s: Server) => (
        <Badge variant={s.is_reachable ? 'success' : 'danger'}>
          {s.is_reachable ? 'Reachable' : 'Unreachable'}
        </Badge>
      ),
    },
    {
      key: 'last_scanned_at',
      header: 'Last Scanned',
      render: (s: Server) => s.last_scanned_at ? formatDistanceToNow(new Date(s.last_scanned_at), { addSuffix: true }) : '-',
    },
  ];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-gray-100">Servers</h1>
        <button
          onClick={() => setShowAdd(!showAdd)}
          className="rounded bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700"
        >
          Add Server
        </button>
      </div>

      {showAdd && (
        <div className="rounded-lg border border-gray-800 bg-gray-900 p-4">
          <div className="grid grid-cols-4 gap-4">
            <input
              placeholder="Hostname"
              value={newServer.hostname}
              onChange={(e) => setNewServer({ ...newServer, hostname: e.target.value })}
              className="rounded border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-gray-100"
            />
            <input
              placeholder="IP Address"
              value={newServer.ip_address}
              onChange={(e) => setNewServer({ ...newServer, ip_address: e.target.value })}
              className="rounded border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-gray-100"
            />
            <input
              type="number"
              placeholder="Port"
              value={newServer.ssh_port}
              onChange={(e) => setNewServer({ ...newServer, ssh_port: Number(e.target.value) })}
              className="rounded border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-gray-100"
            />
            <div className="flex gap-2">
              <select
                value={newServer.os_type}
                onChange={(e) => setNewServer({ ...newServer, os_type: e.target.value })}
                className="flex-1 rounded border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-gray-100"
              >
                <option value="linux">Linux</option>
                <option value="aix">AIX</option>
              </select>
              <button onClick={handleAdd} className="rounded bg-green-600 px-4 py-2 text-sm text-white hover:bg-green-700">
                Save
              </button>
            </div>
          </div>
        </div>
      )}

      <input
        type="text"
        placeholder="Search servers..."
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        className="w-full rounded border border-gray-700 bg-gray-800 px-4 py-2 text-sm text-gray-100 focus:border-blue-500 focus:outline-none"
      />

      <div className="rounded-lg border border-gray-800 bg-gray-900">
        {isLoading ? (
          <div className="p-8 text-center text-gray-500">Loading...</div>
        ) : (
          <Table
            columns={columns}
            data={(data?.items || []) as unknown as Record<string, unknown>[]}
            onRowClick={(item) => navigate(`/servers/${(item as unknown as Server).id}`)}
          />
        )}
      </div>

      {data && (
        <div className="text-sm text-gray-500">
          Showing {data.items.length} of {data.total} servers
        </div>
      )}
    </div>
  );
}
