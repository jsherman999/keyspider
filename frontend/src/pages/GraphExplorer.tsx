import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import api from '../api/client';
import GraphViewer from '../components/graph/GraphViewer';
import type { GraphData } from '../api/types';

export default function GraphExplorer() {
  const navigate = useNavigate();
  const [layer, setLayer] = useState('');
  const [selectedNode, setSelectedNode] = useState<string | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ['graph', layer],
    queryFn: () =>
      api.get<GraphData>('/graph', { params: layer ? { layer } : undefined }).then((r) => r.data),
  });

  const handleNodeClick = (nodeId: string) => {
    setSelectedNode(nodeId);
    if (nodeId.startsWith('server-')) {
      const serverId = nodeId.replace('server-', '');
      navigate(`/servers/${serverId}`);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-gray-100">Graph Explorer</h1>
        <div className="flex items-center gap-4">
          <select
            value={layer}
            onChange={(e) => setLayer(e.target.value)}
            className="rounded border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-gray-100"
          >
            <option value="">All Layers</option>
            <option value="authorization">Authorization Only</option>
            <option value="usage">Usage Only</option>
          </select>
          {data && (
            <span className="text-sm text-gray-400">
              {data.node_count} nodes, {data.edge_count} edges
            </span>
          )}
        </div>
      </div>

      <div className="flex gap-4 text-xs text-gray-400">
        <span className="flex items-center gap-1">
          <span className="h-3 w-3 rounded-full bg-blue-500"></span> Server
        </span>
        <span className="flex items-center gap-1">
          <span className="h-3 w-3 rounded-full bg-red-500"></span> Unreachable
        </span>
        <span className="flex items-center gap-1">
          <span className="h-3 w-3 rounded-full bg-gray-500"></span> Offline
        </span>
        <span className="flex items-center gap-1">
          <span className="h-3 w-3 border-2 border-dashed border-orange-400 rounded-full"></span> Dormant
        </span>
        <span className="flex items-center gap-1">
          <span className="h-3 w-3 border-2 border-red-500 rounded-full"></span> Mystery
        </span>
      </div>

      <div className="h-[calc(100vh-200px)] rounded-lg border border-gray-800 bg-gray-900">
        {isLoading ? (
          <div className="flex h-full items-center justify-center text-gray-500">Loading graph...</div>
        ) : data ? (
          <GraphViewer data={data} onNodeClick={handleNodeClick} />
        ) : (
          <div className="flex h-full items-center justify-center text-gray-500">No graph data available</div>
        )}
      </div>
    </div>
  );
}
