import { useState } from 'react';
import { useParams } from 'react-router-dom';
import { useServer, useServerKeys, useServerEvents, useServerPaths } from '../api/queries/servers';
import { useServerGraph } from '../api/queries/graph';
import { useAgentStatus, useDeployAgent, useUninstallAgent, useSudoEvents } from '../api/queries/agents';
import { Card } from '../components/common/Card';
import { Badge } from '../components/common/Badge';
import { Table } from '../components/common/Table';
import GraphViewer from '../components/graph/GraphViewer';
import type { AccessEvent, AccessPath, SudoEvent } from '../api/types';
import { format, formatDistanceToNow } from 'date-fns';

export default function ServerDetail() {
  const { id } = useParams<{ id: string }>();
  const serverId = Number(id);
  const { data: server } = useServer(serverId);
  const { data: keys } = useServerKeys(serverId);
  const { data: events } = useServerEvents(serverId, { limit: 20 });
  const { data: paths } = useServerPaths(serverId);
  const { data: graph } = useServerGraph(serverId);
  const { data: agentStatus } = useAgentStatus(serverId);
  const { data: sudoEvents } = useSudoEvents(serverId, { limit: 20 });
  const deployAgent = useDeployAgent();
  const uninstallAgent = useUninstallAgent();
  const [activeTab, setActiveTab] = useState<'keys' | 'events' | 'paths' | 'agent' | 'sudo'>('keys');

  if (!server) return <div className="text-gray-500">Loading...</div>;

  const keyColumns = [
    { key: 'file_path', header: 'File Path' },
    { key: 'file_type', header: 'Type' },
    { key: 'unix_owner', header: 'Owner' },
    { key: 'unix_permissions', header: 'Perms' },
  ];

  const eventColumns = [
    {
      key: 'event_time',
      header: 'Time',
      render: (e: AccessEvent) => format(new Date(e.event_time), 'MMM d HH:mm:ss'),
    },
    { key: 'source_ip', header: 'Source IP' },
    { key: 'username', header: 'User' },
    { key: 'auth_method', header: 'Method' },
    {
      key: 'event_type',
      header: 'Status',
      render: (e: AccessEvent) => (
        <Badge variant={e.event_type === 'accepted' ? 'success' : 'danger'}>{e.event_type}</Badge>
      ),
    },
  ];

  const tabs = [
    { key: 'keys' as const, label: `Keys (${keys?.length || 0})` },
    { key: 'events' as const, label: `Events (${events?.total || 0})` },
    { key: 'paths' as const, label: `Paths (${paths?.length || 0})` },
    { key: 'agent' as const, label: 'Agent' },
    { key: 'sudo' as const, label: `Sudo (${sudoEvents?.total || 0})` },
  ];

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-bold text-gray-100">{server.hostname}</h1>

      <div className="grid grid-cols-2 gap-6 lg:grid-cols-4">
        <Card>
          <div className="text-xs text-gray-400">IP Address</div>
          <div className="text-sm text-gray-100">{server.ip_address}</div>
        </Card>
        <Card>
          <div className="text-xs text-gray-400">OS</div>
          <div className="text-sm text-gray-100">{server.os_type} {server.os_version || ''}</div>
        </Card>
        <Card>
          <div className="text-xs text-gray-400">SSH Port</div>
          <div className="text-sm text-gray-100">{server.ssh_port}</div>
        </Card>
        <Card>
          <div className="text-xs text-gray-400">Status</div>
          <Badge variant={server.is_reachable ? 'success' : 'danger'}>
            {server.is_reachable ? 'Reachable' : 'Unreachable'}
          </Badge>
        </Card>
      </div>

      {/* Mini Graph */}
      {graph && (
        <Card title="Access Graph">
          <div className="h-80">
            <GraphViewer data={graph} />
          </div>
        </Card>
      )}

      {/* Tabs */}
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

      {activeTab === 'keys' && (
        <Table columns={keyColumns} data={(keys || []) as unknown as Record<string, unknown>[]} />
      )}

      {activeTab === 'events' && (
        <Table columns={eventColumns} data={(events?.items || []) as unknown as Record<string, unknown>[]} />
      )}

      {activeTab === 'paths' && (
        <div className="space-y-2">
          {paths?.map((p: AccessPath) => (
            <div key={p.id} className="flex items-center justify-between rounded bg-gray-800 px-3 py-2 text-sm">
              <span className="text-gray-300">
                {p.source_server_id ? `Server #${p.source_server_id}` : 'Unknown'} → Server #{p.target_server_id}
              </span>
              <div className="flex items-center gap-2">
                {p.is_authorized && <Badge variant="success">Authorized</Badge>}
                {p.is_used && <Badge variant="info">Used</Badge>}
                <span className="text-gray-500">{p.event_count} events | {p.username}</span>
              </div>
            </div>
          ))}
          {!paths?.length && <div className="text-sm text-gray-500">No access paths found.</div>}
        </div>
      )}

      {activeTab === 'agent' && (
        <Card title="Agent Status">
          {agentStatus ? (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <div className="text-xs text-gray-400">Status</div>
                  <Badge
                    variant={
                      agentStatus.deployment_status === 'active'
                        ? 'success'
                        : agentStatus.deployment_status === 'error'
                        ? 'danger'
                        : 'warning'
                    }
                  >
                    {agentStatus.deployment_status}
                  </Badge>
                </div>
                <div>
                  <div className="text-xs text-gray-400">Version</div>
                  <div className="text-sm text-gray-100">{agentStatus.agent_version || 'N/A'}</div>
                </div>
                <div>
                  <div className="text-xs text-gray-400">Last Heartbeat</div>
                  <div className="text-sm text-gray-100">
                    {agentStatus.last_heartbeat_at
                      ? formatDistanceToNow(new Date(agentStatus.last_heartbeat_at), { addSuffix: true })
                      : 'Never'}
                  </div>
                </div>
                <div>
                  <div className="text-xs text-gray-400">Installed</div>
                  <div className="text-sm text-gray-100">
                    {agentStatus.installed_at
                      ? format(new Date(agentStatus.installed_at), 'MMM d, yyyy HH:mm')
                      : 'N/A'}
                  </div>
                </div>
              </div>
              {agentStatus.error_message && (
                <div className="rounded bg-red-900/20 border border-red-800 p-3 text-sm text-red-300">
                  {agentStatus.error_message}
                </div>
              )}
              <button
                onClick={() => uninstallAgent.mutate(serverId)}
                className="rounded bg-red-600/20 px-4 py-2 text-sm text-red-400 hover:bg-red-600/30"
              >
                Uninstall Agent
              </button>
            </div>
          ) : (
            <div className="space-y-4">
              <p className="text-sm text-gray-400">No agent deployed on this server.</p>
              <button
                onClick={() => deployAgent.mutate({ serverId, apiUrl: window.location.origin })}
                className="rounded bg-blue-600 px-4 py-2 text-sm text-white hover:bg-blue-700"
              >
                Deploy Agent
              </button>
            </div>
          )}
        </Card>
      )}

      {activeTab === 'sudo' && (
        <div className="space-y-2">
          {sudoEvents?.items?.map((e: SudoEvent) => (
            <div key={e.id} className="rounded bg-gray-800 px-3 py-2 text-sm">
              <div className="flex items-center justify-between">
                <span className="text-gray-200">
                  <span className="text-yellow-400">{e.username}</span> → {e.target_user}
                </span>
                <span className="text-xs text-gray-400">
                  {format(new Date(e.event_time), 'MMM d HH:mm:ss')}
                </span>
              </div>
              <div className="mt-1 font-mono text-xs text-gray-400 truncate">{e.command}</div>
            </div>
          ))}
          {!sudoEvents?.items?.length && (
            <div className="text-sm text-gray-500">No sudo events recorded.</div>
          )}
        </div>
      )}
    </div>
  );
}
