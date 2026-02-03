import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import api from '../client';
import type { WatchSession, PaginatedResponse, AccessEvent } from '../types';

export function useWatchSessions() {
  return useQuery({
    queryKey: ['watch-sessions'],
    queryFn: () => api.get<{ items: WatchSession[]; total: number }>('/watch').then((r) => r.data),
  });
}

export function useWatchSession(id: number) {
  return useQuery({
    queryKey: ['watch-session', id],
    queryFn: () => api.get<WatchSession>(`/watch/${id}`).then((r) => r.data),
    enabled: !!id,
  });
}

export function useWatchEvents(id: number, params?: { offset?: number; limit?: number }) {
  return useQuery({
    queryKey: ['watch-events', id, params],
    queryFn: () => api.get<PaginatedResponse<AccessEvent>>(`/watch/${id}/events`, { params }).then((r) => r.data),
    enabled: !!id,
    refetchInterval: 5000,
  });
}

export function useStartWatch() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: { server_id: number; auto_spider?: boolean; spider_depth?: number }) =>
      api.post<WatchSession>('/watch', data).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['watch-sessions'] }),
  });
}

export function useStopWatch() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => api.post(`/watch/${id}/stop`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['watch-sessions'] }),
  });
}
