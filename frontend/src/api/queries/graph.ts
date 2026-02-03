import { useQuery } from '@tanstack/react-query';
import api from '../client';
import type { GraphData } from '../types';

export function useGraph() {
  return useQuery({
    queryKey: ['graph'],
    queryFn: () => api.get<GraphData>('/graph').then((r) => r.data),
  });
}

export function useServerGraph(serverId: number, depth = 2) {
  return useQuery({
    queryKey: ['graph', 'server', serverId, depth],
    queryFn: () => api.get<GraphData>(`/graph/server/${serverId}`, { params: { depth } }).then((r) => r.data),
    enabled: !!serverId,
  });
}

export function useKeyGraph(keyId: number) {
  return useQuery({
    queryKey: ['graph', 'key', keyId],
    queryFn: () => api.get<GraphData>(`/graph/key/${keyId}`).then((r) => r.data),
    enabled: !!keyId,
  });
}

export function useSummary() {
  return useQuery({
    queryKey: ['summary'],
    queryFn: () => api.get('/reports/summary').then((r) => r.data),
  });
}

export function useUnreachable(params?: { offset?: number; limit?: number; severity?: string }) {
  return useQuery({
    queryKey: ['unreachable', params],
    queryFn: () => api.get('/reports/unreachable', { params }).then((r) => r.data),
  });
}
