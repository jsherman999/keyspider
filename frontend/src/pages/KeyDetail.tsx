import { useParams } from 'react-router-dom';
import { useKey, useKeyLocations, useKeyEvents } from '../api/queries/keys';
import { useKeyGraph } from '../api/queries/graph';
import { Card } from '../components/common/Card';
import { Badge } from '../components/common/Badge';
import { Table } from '../components/common/Table';
import GraphViewer from '../components/graph/GraphViewer';
import type { KeyLocation, AccessEvent } from '../api/types';
import { format } from 'date-fns';

export default function KeyDetail() {
  const { id } = useParams<{ id: string }>();
  const keyId = Number(id);
  const { data: key } = useKey(keyId);
  const { data: locations } = useKeyLocations(keyId);
  const { data: events } = useKeyEvents(keyId, { limit: 20 });
  const { data: graph } = useKeyGraph(keyId);

  if (!key) return <div className="text-gray-500">Loading...</div>;

  const locationColumns = [
    { key: 'server_hostname', header: 'Server' },
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
    { key: 'source_ip', header: 'Source' },
    { key: 'username', header: 'User' },
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
      <h1 className="text-xl font-bold text-gray-100">SSH Key Detail</h1>

      <div className="grid grid-cols-2 gap-6 lg:grid-cols-4">
        <Card>
          <div className="text-xs text-gray-400">Fingerprint (SHA256)</div>
          <div className="font-mono text-xs text-gray-100 break-all">{key.fingerprint_sha256}</div>
        </Card>
        <Card>
          <div className="text-xs text-gray-400">Type</div>
          <div className="text-sm text-gray-100">{key.key_type} {key.key_bits ? `(${key.key_bits} bits)` : ''}</div>
        </Card>
        <Card>
          <div className="text-xs text-gray-400">Locations</div>
          <div className="text-sm text-gray-100">{key.location_count}</div>
        </Card>
        <Card>
          <div className="text-xs text-gray-400">Events</div>
          <div className="text-sm text-gray-100">{key.event_count}</div>
        </Card>
      </div>

      {graph && (
        <Card title="Key Usage Graph">
          <div className="h-80">
            <GraphViewer data={graph} />
          </div>
        </Card>
      )}

      <Card title={`File Locations (${locations?.length || 0})`}>
        <Table columns={locationColumns} data={(locations || []) as unknown as Record<string, unknown>[]} />
      </Card>

      <Card title={`Access Events (${events?.total || 0})`}>
        <Table columns={eventColumns} data={(events?.items || []) as unknown as Record<string, unknown>[]} />
      </Card>
    </div>
  );
}
