import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import api from '../api/client';
import { Card } from '../components/common/Card';
import { Badge } from '../components/common/Badge';
import type { SummaryReport } from '../api/types';

interface KeyExposure {
  ssh_key_id: number;
  fingerprint_sha256: string;
  key_type: string;
  comment: string | null;
  server_count: number;
  servers: string[];
}

interface StaleKey {
  ssh_key_id: number;
  fingerprint_sha256: string;
  key_type: string;
  server_hostname: string;
  file_path: string;
  days_since_use: number | null;
}

export default function Reports() {
  const [activeTab, setActiveTab] = useState<'summary' | 'exposure' | 'stale'>('summary');

  const { data: summary } = useQuery({
    queryKey: ['report-summary'],
    queryFn: () => api.get<SummaryReport>('/reports/summary').then((r) => r.data),
    enabled: activeTab === 'summary',
  });

  const { data: exposure } = useQuery({
    queryKey: ['report-exposure'],
    queryFn: () => api.get<KeyExposure[]>('/reports/key-exposure').then((r) => r.data),
    enabled: activeTab === 'exposure',
  });

  const { data: stale } = useQuery({
    queryKey: ['report-stale'],
    queryFn: () => api.get<StaleKey[]>('/reports/stale-keys').then((r) => r.data),
    enabled: activeTab === 'stale',
  });

  const tabs = [
    { key: 'summary' as const, label: 'Summary' },
    { key: 'exposure' as const, label: 'Key Exposure' },
    { key: 'stale' as const, label: 'Stale Keys' },
  ];

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-bold text-gray-100">Reports</h1>

      <div className="flex gap-2 border-b border-gray-800 pb-1">
        {tabs.map((tab) => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            className={`px-4 py-2 text-sm rounded-t ${
              activeTab === tab.key
                ? 'bg-gray-800 text-gray-100'
                : 'text-gray-400 hover:text-gray-200'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {activeTab === 'summary' && summary && (
        <div className="grid grid-cols-2 gap-4 md:grid-cols-3">
          <Card><div className="text-xs text-gray-400">Total Servers</div><div className="text-2xl font-bold">{summary.total_servers}</div></Card>
          <Card><div className="text-xs text-gray-400">Reachable</div><div className="text-2xl font-bold text-green-400">{summary.reachable_servers}</div></Card>
          <Card><div className="text-xs text-gray-400">Unreachable</div><div className="text-2xl font-bold text-red-400">{summary.unreachable_servers}</div></Card>
          <Card><div className="text-xs text-gray-400">SSH Keys</div><div className="text-2xl font-bold">{summary.total_keys}</div></Card>
          <Card><div className="text-xs text-gray-400">Key Locations</div><div className="text-2xl font-bold">{summary.total_key_locations}</div></Card>
          <Card><div className="text-xs text-gray-400">Access Events</div><div className="text-2xl font-bold">{summary.total_access_events}</div></Card>
          <Card><div className="text-xs text-gray-400">Access Paths</div><div className="text-2xl font-bold">{summary.total_access_paths}</div></Card>
          <Card><div className="text-xs text-gray-400">Active Watchers</div><div className="text-2xl font-bold text-blue-400">{summary.active_watchers}</div></Card>
          <Card><div className="text-xs text-gray-400">Unreachable Alerts</div><div className="text-2xl font-bold text-red-400">{summary.unreachable_sources}</div></Card>
        </div>
      )}

      {activeTab === 'exposure' && (
        <div className="space-y-3">
          {exposure?.map((item) => (
            <div key={item.ssh_key_id} className="rounded-lg border border-gray-800 bg-gray-900 p-4">
              <div className="flex items-center justify-between">
                <div>
                  <span className="font-mono text-xs text-gray-200">{item.fingerprint_sha256}</span>
                  <div className="mt-1 flex gap-2">
                    <Badge variant="info">{item.key_type}</Badge>
                    {item.comment && <span className="text-xs text-gray-400">{item.comment}</span>}
                  </div>
                </div>
                <Badge variant="warning">{item.server_count} servers</Badge>
              </div>
              <div className="mt-2 flex flex-wrap gap-1">
                {item.servers.map((s) => (
                  <span key={s} className="rounded bg-gray-800 px-2 py-0.5 text-xs text-gray-300">{s}</span>
                ))}
              </div>
            </div>
          ))}
          {exposure?.length === 0 && (
            <div className="text-center text-sm text-gray-500 py-8">No keys found on multiple servers</div>
          )}
        </div>
      )}

      {activeTab === 'stale' && (
        <div className="space-y-3">
          {stale?.map((item, i) => (
            <div key={i} className="rounded-lg border border-gray-800 bg-gray-900 p-4">
              <div className="flex items-center justify-between">
                <div>
                  <span className="font-mono text-xs text-gray-200">{item.fingerprint_sha256}</span>
                  <div className="mt-1 text-xs text-gray-400">
                    {item.server_hostname} — {item.file_path}
                  </div>
                </div>
                <Badge variant="warning">
                  {item.days_since_use ? `${item.days_since_use} days` : 'Never used'}
                </Badge>
              </div>
            </div>
          ))}
          {stale?.length === 0 && (
            <div className="text-center text-sm text-gray-500 py-8">No stale keys found</div>
          )}
        </div>
      )}
    </div>
  );
}
