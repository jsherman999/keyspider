import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useUnreachable } from '../api/queries/graph';
import { SeverityBadge } from '../components/common/Badge';
import api from '../api/client';
import { formatDistanceToNow } from 'date-fns';
import type { UnreachableSource } from '../api/types';

export default function Alerts() {
  const [severity, setSeverity] = useState('');
  const { data, isLoading } = useUnreachable({ severity: severity || undefined });
  const qc = useQueryClient();

  const acknowledge = useMutation({
    mutationFn: (id: number) => api.put(`/reports/alerts/${id}/acknowledge`, { acknowledged: true }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['unreachable'] }),
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-gray-100">Alerts — Unreachable Sources</h1>
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
      </div>

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
      </div>

      {data && (
        <div className="text-sm text-gray-500">
          Showing {data.items.length} of {data.total} alerts
        </div>
      )}
    </div>
  );
}
