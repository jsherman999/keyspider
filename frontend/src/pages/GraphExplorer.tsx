import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useGraph } from '../api/queries/graph';
import GraphViewer from '../components/graph/GraphViewer';

export default function GraphExplorer() {
  const navigate = useNavigate();
  const { data, isLoading } = useGraph();
  const [selectedNode, setSelectedNode] = useState<string | null>(null);

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
        {data && (
          <span className="text-sm text-gray-400">
            {data.node_count} nodes, {data.edge_count} edges
          </span>
        )}
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
