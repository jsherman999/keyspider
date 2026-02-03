import { useSummary, useUnreachable } from '../api/queries/graph';
import { useScans } from '../api/queries/scans';
import { useWatchSessions } from '../api/queries/watch';
import { StatCard } from '../components/common/Card';
import { StatusBadge, SeverityBadge } from '../components/common/Badge';
import type { SummaryReport } from '../api/types';

export default function Dashboard() {
  const { data: summary } = useSummary() as { data: SummaryReport | undefined };
  const { data: scans } = useScans({ limit: 5 });
  const { data: watches } = useWatchSessions();
  const { data: unreachable } = useUnreachable({ limit: 5 });

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-bold text-gray-100">Dashboard</h1>

      {summary && (
        <div className="grid grid-cols-2 gap-4 md:grid-cols-4 lg:grid-cols-6">
          <StatCard label="Servers" value={summary.total_servers} />
          <StatCard label="Reachable" value={summary.reachable_servers} variant="success" />
          <StatCard label="SSH Keys" value={summary.total_keys} />
          <StatCard label="Access Events" value={summary.total_access_events} />
          <StatCard label="Active Watchers" value={summary.active_watchers} variant="success" />
          <StatCard label="Critical Alerts" value={summary.critical_alerts} variant={summary.critical_alerts > 0 ? 'danger' : 'default'} />
        </div>
      )}

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Recent Scans */}
        <div className="rounded-lg border border-gray-800 bg-gray-900">
          <div className="border-b border-gray-800 px-4 py-3">
            <h2 className="text-sm font-medium text-gray-200">Recent Scans</h2>
          </div>
          <div className="divide-y divide-gray-800">
            {scans?.items.map((scan) => (
              <div key={scan.id} className="flex items-center justify-between px-4 py-3">
                <div>
                  <span className="text-sm text-gray-300">{scan.job_type}</span>
                  <span className="ml-2 text-xs text-gray-500">#{scan.id}</span>
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-xs text-gray-500">
                    {scan.servers_scanned} servers, {scan.keys_found} keys
                  </span>
                  <StatusBadge status={scan.status} />
                </div>
              </div>
            ))}
            {!scans?.items.length && (
              <div className="px-4 py-6 text-center text-sm text-gray-500">No scans yet</div>
            )}
          </div>
        </div>

        {/* Active Watchers */}
        <div className="rounded-lg border border-gray-800 bg-gray-900">
          <div className="border-b border-gray-800 px-4 py-3">
            <h2 className="text-sm font-medium text-gray-200">Active Watchers</h2>
          </div>
          <div className="divide-y divide-gray-800">
            {watches?.items.filter((w) => w.status === 'active').map((w) => (
              <div key={w.id} className="flex items-center justify-between px-4 py-3">
                <span className="text-sm text-gray-300">Server #{w.server_id}</span>
                <div className="flex items-center gap-3">
                  <span className="text-xs text-gray-500">{w.events_captured} events</span>
                  <StatusBadge status={w.status} />
                </div>
              </div>
            ))}
            {!watches?.items.filter((w) => w.status === 'active').length && (
              <div className="px-4 py-6 text-center text-sm text-gray-500">No active watchers</div>
            )}
          </div>
        </div>
      </div>

      {/* Alerts */}
      {unreachable?.items && unreachable.items.length > 0 && (
        <div className="rounded-lg border border-red-900/50 bg-gray-900">
          <div className="border-b border-gray-800 px-4 py-3">
            <h2 className="text-sm font-medium text-red-400">Top Alerts</h2>
          </div>
          <div className="divide-y divide-gray-800">
            {unreachable.items.map((ur: { id: number; source_ip: string; severity: string; event_count: number; username: string | null }) => (
              <div key={ur.id} className="flex items-center justify-between px-4 py-3">
                <div>
                  <span className="text-sm text-gray-300">{ur.source_ip}</span>
                  {ur.username && <span className="ml-2 text-xs text-gray-500">({ur.username})</span>}
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-xs text-gray-500">{ur.event_count} events</span>
                  <SeverityBadge severity={ur.severity} />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
