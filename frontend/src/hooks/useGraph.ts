import { useMemo } from 'react';
import type { GraphData } from '../api/types';
import type { ElementDefinition } from 'cytoscape';

export function useCytoscapeElements(data: GraphData | undefined) {
  return useMemo(() => {
    if (!data) return [];

    const elements: ElementDefinition[] = [];

    for (const node of data.nodes) {
      elements.push({
        data: {
          id: node.id,
          label: node.label,
          type: node.type,
          ip_address: node.ip_address,
          os_type: node.os_type,
          is_reachable: node.is_reachable,
        },
        classes: node.type === 'unreachable' ? 'unreachable' : node.is_reachable ? 'reachable' : 'offline',
      });
    }

    for (const edge of data.edges) {
      elements.push({
        data: {
          id: edge.id,
          source: edge.source,
          target: edge.target,
          label: edge.label || '',
          event_count: edge.event_count,
          is_active: edge.is_active,
        },
        classes: edge.is_active ? 'active' : 'inactive',
      });
    }

    return elements;
  }, [data]);
}

export const cytoscapeStylesheet = [
  {
    selector: 'node',
    style: {
      'background-color': '#3b82f6',
      label: 'data(label)',
      color: '#e5e7eb',
      'font-size': '11px',
      'text-valign': 'bottom' as const,
      'text-margin-y': 6,
      width: 40,
      height: 40,
    },
  },
  {
    selector: 'node.unreachable',
    style: {
      'background-color': '#ef4444',
      shape: 'diamond' as const,
    },
  },
  {
    selector: 'node.offline',
    style: {
      'background-color': '#6b7280',
    },
  },
  {
    selector: 'edge',
    style: {
      'line-color': '#4b5563',
      'target-arrow-color': '#4b5563',
      'target-arrow-shape': 'triangle' as const,
      'curve-style': 'bezier' as const,
      width: 2,
      label: 'data(label)',
      'font-size': '9px',
      color: '#9ca3af',
      'text-rotation': 'autorotate' as const,
    },
  },
  {
    selector: 'edge.active',
    style: {
      'line-color': '#3b82f6',
      'target-arrow-color': '#3b82f6',
    },
  },
  {
    selector: ':selected',
    style: {
      'background-color': '#f59e0b',
      'line-color': '#f59e0b',
      'target-arrow-color': '#f59e0b',
    },
  },
];
