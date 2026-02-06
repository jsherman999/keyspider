import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useUnreachable } from '../api/queries/graph';
import { Badge, SeverityBadge } from '../components/common/Badge';
import api from '../api/client';
import { formatDistanceToNow } from 'date-fns';
import type { UnreachableSource, MysteryKey } from '../api/types';

type AlertTab = 'unreachable' | 'mystery';

export default function Alerts() {
  const [activeTab, setActiveTab] = useState<AlertTab>('unreachable');
  const [severity, setSeverity] = useState('');
  const { data, isLoading } = useUnreachable({ severity: severity || undefined });
  const qc = useQueryClient();

  const { data: mysteryKeys, isLoading: mysteryLoading } = useQuery({
    queryKey: ['mystery-keys-alerts'],
    queryFn: () => api.get<MysteryKey[]>('/reports/mystery-keys').then((r) => r.data),
    enabled: activeTab === 'mystery',
  });

  const acknowledge = useMutation({
    mutationFn: (id: number) => api.put(`/reports/alerts/${id}/acknowledge`, { acknowledged: true }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['unreachable'] }),
  });

  const tabs: { key: AlertTab; label: string }[] = [
    { key: 'unreachable', label: 'Unreachable Sources' },
    { key: 'mystery', label: 'Mystery Keys' },
  ];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-gray-100">Alerts</h1>
        {activeTab === 'unreachable' && (
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            className="rounded border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-gray-100"
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        )}
      </div>

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

      {activeTab === 'unreachable' && (
        <div className="space-y-3">
          {isLoading && <div className="text-center text-gray-500">Loading...</div>}
          {data?.items?.map((alert: UnreachableSource) => (
            <div
              key={alert.id}
              className="rounded-lg border border-gray-800 bg-gray-900 p-4"
            >
              <div className="flex items-start justify-between">
                <div className="space-y-2">
                  <div className="flex items-center gap-3">
                    <SeverityBadge severity={alert.severity} />
                    <span className="font-mono text-sm text-gray-200">{alert.source_ip}</span>
                    {alert.reverse_dns && (
                      <span className="text-xs text-gray-400">({alert.reverse_dns})</span>
                    )}
                  </div>
                  <div className="flex gap-4 text-xs text-gray-400">
                    <span>Target: Server #{alert.target_server_id}</span>
                    {alert.username && <span>User: {alert.username}</span>}
                    <span>{alert.event_count} events</span>
                    <span>Last seen: {formatDistanceToNow(new Date(alert.last_seen_at), { addSuffix: true })}</span>
                  </div>
                  {alert.fingerprint && (
                    <div className="font-mono text-xs text-blue-400">{alert.fingerprint}</div>
                  )}
                  {alert.notes && (
                    <div className="text-xs text-gray-300 italic">{alert.notes}</div>
                  )}
                </div>
                <div>
                  {!alert.acknowledged && (
                    <button
                      onClick={() => acknowledge.mutate(alert.id)}
                      className="rounded bg-green-600/20 px-3 py-1 text-xs text-green-400 hover:bg-green-600/30"
                    >
                      Acknowledge
                    </button>
                  )}
                </div>
              </div>
            </div>
          ))}
          {data?.items?.length === 0 && !isLoading && (
            <div className="text-center text-sm text-gray-500 py-8">No unreachable source alerts</div>
          )}
          {data && (
            <div className="text-sm text-gray-500">
              Showing {data.items.length} of {data.total} alerts
            </div>
          )}
        </div>
      )}

      {activeTab === 'mystery' && (
        <div className="space-y-3">
          {mysteryLoading && <div className="text-center text-gray-500">Loading...</div>}
          {mysteryKeys?.map((item, i) => (
            <div key={i} className="rounded-lg border border-red-800/30 bg-gray-900 p-4">
              <div className="flex items-center justify-between">
                <div>
                  <span className="font-mono text-xs text-red-300">{item.fingerprint || 'Unknown fingerprint'}</span>
                  <div className="mt-1 text-xs text-gray-400">
                    {item.server_hostname} — from {item.last_source_ip} as {item.last_username}
                  </div>
                  <div className="mt-1 text-xs text-gray-500">
                    Last seen: {formatDistanceToNow(new Date(item.last_seen_at), { addSuffix: true })}
                  </div>
                </div>
                <Badge variant="danger">{item.event_count} events</Badge>
              </div>
            </div>
          ))}
          {mysteryKeys?.length === 0 && !mysteryLoading && (
            <div className="text-center text-sm text-gray-500 py-8">
              No mystery keys found — all used keys are in authorized_keys
            </div>
          )}
        </div>
      )}
    </div>
  );
}
