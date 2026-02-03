import CytoscapeComponent from 'react-cytoscapejs';
import { useCytoscapeElements, cytoscapeStylesheet } from '../../hooks/useGraph';
import type { GraphData } from '../../api/types';

interface GraphViewerProps {
  data: GraphData;
  onNodeClick?: (nodeId: string) => void;
}

export default function GraphViewer({ data, onNodeClick }: GraphViewerProps) {
  const elements = useCytoscapeElements(data);

  if (!elements.length) {
    return <div className="flex h-full items-center justify-center text-gray-500">No graph data</div>;
  }

  return (
    <CytoscapeComponent
      elements={elements}
      stylesheet={cytoscapeStylesheet}
      layout={{ name: 'cose', animate: false, nodeOverlap: 20, padding: 30 }}
      style={{ width: '100%', height: '100%' }}
      cy={(cy) => {
        cy.on('tap', 'node', (evt) => {
          onNodeClick?.(evt.target.id());
        });
      }}
    />
  );
}
