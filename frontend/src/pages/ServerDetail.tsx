import { useParams } from 'react-router-dom';
import { useServer, useServerKeys, useServerEvents, useServerPaths } from '../api/queries/servers';
import { useServerGraph } from '../api/queries/graph';
import { Card } from '../components/common/Card';
import { Badge, StatusBadge } from '../components/common/Badge';
import { Table } from '../components/common/Table';
import GraphViewer from '../components/graph/GraphViewer';
import type { KeyLocation, AccessEvent, AccessPath } from '../api/types';
import { format } from 'date-fns';

export default function ServerDetail() {
  const { id } = useParams<{ id: string }>();
  const serverId = Number(id);
  const { data: server } = useServer(serverId);
  const { data: keys } = useServerKeys(serverId);
  const { data: events } = useServerEvents(serverId, { limit: 20 });
  const { data: paths } = useServerPaths(serverId);
  const { data: graph } = useServerGraph(serverId);

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

      {/* Keys */}
      <Card title={`Keys (${keys?.length || 0})`}>
        <Table columns={keyColumns} data={(keys || []) as unknown as Record<string, unknown>[]} />
      </Card>

      {/* Events */}
      <Card title={`Recent Events (${events?.total || 0})`}>
        <Table columns={eventColumns} data={(events?.items || []) as unknown as Record<string, unknown>[]} />
      </Card>

      {/* Paths */}
      <Card title={`Access Paths (${paths?.length || 0})`}>
        <div className="space-y-2">
          {paths?.map((p: AccessPath) => (
            <div key={p.id} className="flex items-center justify-between rounded bg-gray-800 px-3 py-2 text-sm">
              <span className="text-gray-300">
                {p.source_server_id ? `Server #${p.source_server_id}` : 'Unknown'} → Server #{p.target_server_id}
              </span>
              <span className="text-gray-500">{p.event_count} events | {p.username}</span>
            </div>
          ))}
          {!paths?.length && <div className="text-sm text-gray-500">No access paths found.</div>}
        </div>
      </Card>
    </div>
  );
}
