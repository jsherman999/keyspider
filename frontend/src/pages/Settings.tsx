import { useState, FormEvent } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import api from '../api/client';
import { Card } from '../components/common/Card';
import type { User } from '../api/types';

interface APIKeyInfo {
  id: number;
  key_prefix: string;
  name: string;
  permissions: string[];
  expires_at: string | null;
  last_used_at: string | null;
  created_at: string;
}

export default function Settings() {
  const qc = useQueryClient();

  const { data: user } = useQuery({
    queryKey: ['me'],
    queryFn: () => api.get<User>('/auth/me').then((r) => r.data),
  });

  const { data: apiKeys } = useQuery({
    queryKey: ['api-keys'],
    queryFn: () => api.get<APIKeyInfo[]>('/auth/api-keys').then((r) => r.data),
  });

  const [keyName, setKeyName] = useState('');
  const [newKey, setNewKey] = useState<string | null>(null);

  const createKey = useMutation({
    mutationFn: (name: string) =>
      api.post('/auth/api-keys', { name, permissions: ['read', 'write'] }).then((r) => r.data),
    onSuccess: (data) => {
      setNewKey(data.key);
      setKeyName('');
      qc.invalidateQueries({ queryKey: ['api-keys'] });
    },
  });

  const deleteKey = useMutation({
    mutationFn: (id: number) => api.delete(`/auth/api-keys/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['api-keys'] }),
  });

  const handleCreateKey = (e: FormEvent) => {
    e.preventDefault();
    if (keyName) createKey.mutate(keyName);
  };

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-bold text-gray-100">Settings</h1>

      {/* User Info */}
      {user && (
        <Card title="Current User">
          <div className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-gray-400">Username</span>
              <span className="text-gray-200">{user.username}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Role</span>
              <span className="text-gray-200">{user.role}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Display Name</span>
              <span className="text-gray-200">{user.display_name || '-'}</span>
            </div>
          </div>
        </Card>
      )}

      {/* API Keys */}
      <Card title="API Keys">
        <form onSubmit={handleCreateKey} className="mb-4 flex gap-2">
          <input
            type="text"
            placeholder="Key name..."
            value={keyName}
            onChange={(e) => setKeyName(e.target.value)}
            className="flex-1 rounded border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-gray-100"
          />
          <button type="submit" className="rounded bg-blue-600 px-4 py-2 text-sm text-white hover:bg-blue-700">
            Create
          </button>
        </form>

        {newKey && (
          <div className="mb-4 rounded bg-green-900/30 border border-green-700 p-3">
            <div className="text-xs text-green-400 mb-1">New API Key (copy now — shown only once):</div>
            <code className="text-sm text-green-300 break-all">{newKey}</code>
          </div>
        )}

        <div className="space-y-2">
          {apiKeys?.map((k) => (
            <div key={k.id} className="flex items-center justify-between rounded bg-gray-800 px-3 py-2">
              <div>
                <span className="text-sm text-gray-200">{k.name}</span>
                <span className="ml-2 font-mono text-xs text-gray-500">{k.key_prefix}...</span>
              </div>
              <button
                onClick={() => deleteKey.mutate(k.id)}
                className="text-xs text-red-400 hover:text-red-300"
              >
                Revoke
              </button>
            </div>
          ))}
          {!apiKeys?.length && <div className="text-sm text-gray-500">No API keys</div>}
        </div>
      </Card>
    </div>
  );
}
