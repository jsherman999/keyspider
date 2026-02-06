import { useState } from 'react';
import { useAgents, useDeployAgentBatch } from '../api/queries/agents';
import { useQuery } from '@tanstack/react-query';
import api from '../api/client';
import { Badge } from '../components/common/Badge';
import { Card } from '../components/common/Card';
import type { Server, AgentStatus } from '../api/types';
import { formatDistanceToNow } from 'date-fns';

function AgentStatusBadge({ status }: { status: string }) {
  const variants: Record<string, 'success' | 'warning' | 'danger' | 'info'> = {
    active: 'success',
    deploying: 'info',
    inactive: 'warning',
    error: 'danger',
    not_deployed: 'info',
  };
  return <Badge variant={variants[status] || 'info'}>{status}</Badge>;
}

export default function Agents() {
  const { data: agents, isLoading } = useAgents();
  const { data: servers } = useQuery({
    queryKey: ['servers'],
    queryFn: () => api.get<Server[]>('/servers').then((r) => r.data),
  });
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [filter, setFilter] = useState('');
  const deployBatch = useDeployAgentBatch();

  const agentMap = new Map<number, AgentStatus>();
  agents?.forEach((a) => agentMap.set(a.server_id, a));

  const filteredServers = servers?.filter((s) => {
    if (!filter) return true;
    const agent = agentMap.get(s.id);
    return agent?.deployment_status === filter || (!agent && filter === 'not_deployed');
  });

  const toggleSelect = (id: number) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const handleBulkDeploy = () => {
    const apiUrl = window.location.origin;
    deployBatch.mutate({ serverIds: Array.from(selected), apiUrl });
    setSelected(new Set());
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-gray-100">Agents</h1>
        <div className="flex gap-2">
          <select
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="rounded border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-gray-100"
          >
            <option value="">All Statuses</option>
            <option value="active">Active</option>
            <option value="inactive">Inactive</option>
            <option value="deploying">Deploying</option>
            <option value="error">Error</option>
            <option value="not_deployed">Not Deployed</option>
          </select>
          {selected.size > 0 && (
            <button
              onClick={handleBulkDeploy}
              className="rounded bg-blue-600 px-4 py-2 text-sm text-white hover:bg-blue-700"
            >
              Deploy to {selected.size} servers
            </button>
          )}
        </div>
      </div>

      {isLoading && <div className="text-center text-gray-500">Loading...</div>}

      <div className="space-y-2">
        {filteredServers?.map((server) => {
          const agent = agentMap.get(server.id);
          return (
            <div
              key={server.id}
              className="flex items-center justify-between rounded-lg border border-gray-800 bg-gray-900 p-4"
            >
              <div className="flex items-center gap-4">
                <input
                  type="checkbox"
                  checked={selected.has(server.id)}
                  onChange={() => toggleSelect(server.id)}
                  className="rounded border-gray-600"
                />
                <div>
                  <div className="text-sm font-medium text-gray-100">{server.hostname}</div>
                  <div className="text-xs text-gray-400">{server.ip_address}</div>
                </div>
              </div>
              <div className="flex items-center gap-4">
                {agent ? (
                  <>
                    <AgentStatusBadge status={agent.deployment_status} />
                    {agent.last_heartbeat_at && (
                      <span className="text-xs text-gray-400">
                        Last heartbeat:{' '}
                        {formatDistanceToNow(new Date(agent.last_heartbeat_at), { addSuffix: true })}
                      </span>
                    )}
                    {agent.agent_version && (
                      <span className="text-xs text-gray-500">v{agent.agent_version}</span>
                    )}
                    {agent.error_message && (
                      <span className="text-xs text-red-400" title={agent.error_message}>
                        Error
                      </span>
                    )}
                  </>
                ) : (
                  <span className="text-xs text-gray-500">No agent</span>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {filteredServers?.length === 0 && (
        <div className="text-center text-sm text-gray-500 py-8">No servers match the filter</div>
      )}
    </div>
  );
}
