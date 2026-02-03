import { useState } from 'react';
import { useWatchSessions, useWatchEvents, useStartWatch, useStopWatch } from '../api/queries/watch';
import { useServers } from '../api/queries/servers';
import { useWebSocket } from '../hooks/useWebSocket';
import { StatusBadge, Badge } from '../components/common/Badge';
import type { AccessEvent } from '../api/types';
import { format } from 'date-fns';

export default function Watcher() {
  const { data: sessions } = useWatchSessions();
  const { data: servers } = useServers({ limit: 200 });
  const startWatch = useStartWatch();
  const stopWatch = useStopWatch();
  const [selectedServer, setSelectedServer] = useState<number | undefined>();
  const [activeSession, setActiveSession] = useState<number | null>(null);
  const { data: events } = useWatchEvents(activeSession || 0, { limit: 100 });
  const { messages } = useWebSocket(
    activeSession ? `/api/ws/watch/${activeSession}` : '',
    !!activeSession,
  );

  const handleStart = () => {
    if (!selectedServer) return;
    startWatch.mutate({ server_id: selectedServer });
  };

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-bold text-gray-100">Watcher</h1>

      {/* Start Watcher */}
      <div className="rounded-lg border border-gray-800 bg-gray-900 p-4">
        <h2 className="mb-4 text-sm font-medium text-gray-200">Start New Watcher</h2>
        <div className="flex gap-4">
          <select
            value={selectedServer || ''}
            onChange={(e) => setSelectedServer(Number(e.target.value) || undefined)}
            className="flex-1 rounded border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-gray-100"
          >
            <option value="">Select server...</option>
            {servers?.items.map((s) => (
              <option key={s.id} value={s.id}>{s.hostname} ({s.ip_address})</option>
            ))}
          </select>
          <button
            onClick={handleStart}
            disabled={!selectedServer}
            className="rounded bg-green-600 px-6 py-2 text-sm font-medium text-white hover:bg-green-700 disabled:opacity-50"
          >
            Start Watching
          </button>
        </div>
      </div>

      {/* Active Sessions */}
      <div className="rounded-lg border border-gray-800 bg-gray-900">
        <div className="border-b border-gray-800 px-4 py-3">
          <h2 className="text-sm font-medium text-gray-200">Watch Sessions</h2>
        </div>
        <div className="divide-y divide-gray-800">
          {sessions?.items.map((s) => (
            <div key={s.id} className="flex items-center justify-between px-4 py-3">
              <div className="flex items-center gap-3">
                <span className="text-sm text-gray-300">Server #{s.server_id}</span>
                <StatusBadge status={s.status} />
                <span className="text-xs text-gray-500">{s.events_captured} events</span>
              </div>
              <div className="flex gap-2">
                <button
                  onClick={() => setActiveSession(s.id)}
                  className="rounded bg-blue-600/20 px-3 py-1 text-xs text-blue-400 hover:bg-blue-600/30"
                >
                  View Events
                </button>
                {s.status === 'active' && (
                  <button
                    onClick={() => stopWatch.mutate(s.id)}
                    className="rounded bg-red-600/20 px-3 py-1 text-xs text-red-400 hover:bg-red-600/30"
                  >
                    Stop
                  </button>
                )}
              </div>
            </div>
          ))}
          {!sessions?.items.length && (
            <div className="p-8 text-center text-sm text-gray-500">No watch sessions</div>
          )}
        </div>
      </div>

      {/* Live Event Log */}
      {activeSession && (
        <div className="rounded-lg border border-gray-800 bg-gray-900">
          <div className="border-b border-gray-800 px-4 py-3 flex justify-between items-center">
            <h2 className="text-sm font-medium text-gray-200">
              Live Events — Session #{activeSession}
            </h2>
            <button
              onClick={() => setActiveSession(null)}
              className="text-xs text-gray-400 hover:text-gray-200"
            >
              Close
            </button>
          </div>
          <div className="max-h-96 overflow-y-auto font-mono text-xs">
            {/* Real-time messages */}
            {messages
              .filter((m) => m.type !== 'keepalive' && m.type !== 'pong')
              .map((m, i) => (
                <div key={`ws-${i}`} className="flex gap-4 border-b border-gray-800/50 px-4 py-1.5 text-green-400">
                  <span>{JSON.stringify(m)}</span>
                </div>
              ))}
            {/* Historical events */}
            {events?.items.map((e: AccessEvent) => (
              <div key={e.id} className="flex gap-4 border-b border-gray-800/50 px-4 py-1.5">
                <span className="text-gray-500">{format(new Date(e.event_time), 'HH:mm:ss')}</span>
                <Badge variant={e.event_type === 'accepted' ? 'success' : 'danger'}>{e.event_type}</Badge>
                <span className="text-gray-300">{e.source_ip}</span>
                <span className="text-gray-400">{e.username}</span>
                <span className="text-gray-500">{e.auth_method}</span>
                {e.fingerprint && <span className="text-blue-400">{e.fingerprint}</span>}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
