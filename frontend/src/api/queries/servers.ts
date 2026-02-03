import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import api from '../client';
import type { Server, PaginatedResponse, AccessEvent, AccessPath, KeyLocation } from '../types';

export function useServers(params?: { offset?: number; limit?: number; search?: string; os_type?: string }) {
  return useQuery({
    queryKey: ['servers', params],
    queryFn: () => api.get<PaginatedResponse<Server>>('/servers', { params }).then((r) => r.data),
  });
}

export function useServer(id: number) {
  return useQuery({
    queryKey: ['server', id],
    queryFn: () => api.get<Server>(`/servers/${id}`).then((r) => r.data),
    enabled: !!id,
  });
}

export function useServerKeys(id: number) {
  return useQuery({
    queryKey: ['server-keys', id],
    queryFn: () => api.get<KeyLocation[]>(`/servers/${id}/keys`).then((r) => r.data),
    enabled: !!id,
  });
}

export function useServerEvents(id: number, params?: { offset?: number; limit?: number }) {
  return useQuery({
    queryKey: ['server-events', id, params],
    queryFn: () => api.get<PaginatedResponse<AccessEvent>>(`/servers/${id}/access-events`, { params }).then((r) => r.data),
    enabled: !!id,
  });
}

export function useServerPaths(id: number) {
  return useQuery({
    queryKey: ['server-paths', id],
    queryFn: () => api.get<AccessPath[]>(`/servers/${id}/access-paths`).then((r) => r.data),
    enabled: !!id,
  });
}

export function useCreateServer() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: Partial<Server>) => api.post<Server>('/servers', data).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['servers'] }),
  });
}

export function useDeleteServer() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => api.delete(`/servers/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['servers'] }),
  });
}
