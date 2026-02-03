import { useState } from 'react';
import { useScans, useCreateScan, useCancelScan } from '../api/queries/scans';
import { useServers } from '../api/queries/servers';
import { StatusBadge } from '../components/common/Badge';
import { formatDistanceToNow } from 'date-fns';

export default function Scanner() {
  const { data: scans, isLoading } = useScans();
  const { data: servers } = useServers({ limit: 200 });
  const createScan = useCreateScan();
  const cancelScan = useCancelScan();
  const [scanType, setScanType] = useState('full_scan');
  const [selectedServer, setSelectedServer] = useState<number | undefined>();
  const [depth, setDepth] = useState(10);

  const handleLaunch = () => {
    createScan.mutate({
      job_type: scanType,
      seed_server_id: scanType !== 'full_scan' ? selectedServer : undefined,
      max_depth: scanType === 'spider_crawl' ? depth : undefined,
    });
  };

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-bold text-gray-100">Scanner</h1>

      {/* Launch Scan */}
      <div className="rounded-lg border border-gray-800 bg-gray-900 p-4">
        <h2 className="mb-4 text-sm font-medium text-gray-200">Launch Scan</h2>
        <div className="flex flex-wrap gap-4">
          <select
            value={scanType}
            onChange={(e) => setScanType(e.target.value)}
            className="rounded border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-gray-100"
          >
            <option value="full_scan">Full Scan</option>
            <option value="server_scan">Server Scan</option>
            <option value="spider_crawl">Spider Crawl</option>
          </select>

          {scanType !== 'full_scan' && (
            <select
              value={selectedServer || ''}
              onChange={(e) => setSelectedServer(Number(e.target.value) || undefined)}
              className="rounded border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-gray-100"
            >
              <option value="">Select server...</option>
              {servers?.items.map((s) => (
                <option key={s.id} value={s.id}>{s.hostname} ({s.ip_address})</option>
              ))}
            </select>
          )}

          {scanType === 'spider_crawl' && (
            <input
              type="number"
              value={depth}
              onChange={(e) => setDepth(Number(e.target.value))}
              min={1}
              max={50}
              className="w-24 rounded border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-gray-100"
              placeholder="Depth"
            />
          )}

          <button
            onClick={handleLaunch}
            disabled={scanType !== 'full_scan' && !selectedServer}
            className="rounded bg-blue-600 px-6 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
          >
            Launch
          </button>
        </div>
      </div>

      {/* Scan Jobs */}
      <div className="rounded-lg border border-gray-800 bg-gray-900">
        <div className="border-b border-gray-800 px-4 py-3">
          <h2 className="text-sm font-medium text-gray-200">Scan Jobs</h2>
        </div>
        <div className="divide-y divide-gray-800">
          {isLoading && <div className="p-8 text-center text-gray-500">Loading...</div>}
          {scans?.items.map((scan) => (
            <div key={scan.id} className="flex items-center justify-between px-4 py-3">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-gray-200">{scan.job_type}</span>
                  <StatusBadge status={scan.status} />
                  <span className="text-xs text-gray-500">#{scan.id}</span>
                </div>
                <div className="flex gap-4 text-xs text-gray-500">
                  <span>{scan.servers_scanned} servers</span>
                  <span>{scan.keys_found} keys</span>
                  <span>{scan.events_parsed} events</span>
                  <span>{scan.unreachable_found} unreachable</span>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-xs text-gray-500">
                  {formatDistanceToNow(new Date(scan.created_at), { addSuffix: true })}
                </span>
                {['pending', 'running'].includes(scan.status) && (
                  <button
                    onClick={() => cancelScan.mutate(scan.id)}
                    className="rounded bg-red-600/20 px-3 py-1 text-xs text-red-400 hover:bg-red-600/30"
                  >
                    Cancel
                  </button>
                )}
              </div>
            </div>
          ))}
          {!scans?.items.length && !isLoading && (
            <div className="p-8 text-center text-sm text-gray-500">No scans yet</div>
          )}
        </div>
      </div>
    </div>
  );
}
