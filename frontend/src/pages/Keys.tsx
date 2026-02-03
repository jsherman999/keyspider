import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useKeys } from '../api/queries/keys';
import { Table } from '../components/common/Table';
import { Badge } from '../components/common/Badge';
import type { SSHKey } from '../api/types';

export default function Keys() {
  const navigate = useNavigate();
  const [search, setSearch] = useState('');
  const [keyType, setKeyType] = useState('');
  const { data, isLoading } = useKeys({ search: search || undefined, key_type: keyType || undefined });

  const columns = [
    {
      key: 'fingerprint_sha256',
      header: 'Fingerprint',
      render: (k: SSHKey) => <span className="font-mono text-xs">{k.fingerprint_sha256}</span>,
    },
    {
      key: 'key_type',
      header: 'Type',
      render: (k: SSHKey) => <Badge variant="info">{k.key_type}</Badge>,
    },
    { key: 'key_bits', header: 'Bits' },
    { key: 'comment', header: 'Comment' },
    {
      key: 'is_host_key',
      header: 'Host Key',
      render: (k: SSHKey) => k.is_host_key ? <Badge variant="warning">Host</Badge> : <span className="text-gray-500">-</span>,
    },
  ];

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-bold text-gray-100">SSH Keys</h1>

      <div className="flex gap-4">
        <input
          type="text"
          placeholder="Search keys..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="flex-1 rounded border border-gray-700 bg-gray-800 px-4 py-2 text-sm text-gray-100 focus:border-blue-500 focus:outline-none"
        />
        <select
          value={keyType}
          onChange={(e) => setKeyType(e.target.value)}
          className="rounded border border-gray-700 bg-gray-800 px-4 py-2 text-sm text-gray-100"
        >
          <option value="">All Types</option>
          <option value="rsa">RSA</option>
          <option value="ed25519">Ed25519</option>
          <option value="ecdsa">ECDSA</option>
          <option value="dsa">DSA</option>
        </select>
      </div>

      <div className="rounded-lg border border-gray-800 bg-gray-900">
        {isLoading ? (
          <div className="p-8 text-center text-gray-500">Loading...</div>
        ) : (
          <Table
            columns={columns}
            data={(data?.items || []) as unknown as Record<string, unknown>[]}
            onRowClick={(item) => navigate(`/keys/${(item as unknown as SSHKey).id}`)}
          />
        )}
      </div>

      {data && (
        <div className="text-sm text-gray-500">
          Showing {data.items.length} of {data.total} keys
        </div>
      )}
    </div>
  );
}
