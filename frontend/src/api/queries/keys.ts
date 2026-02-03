import { useQuery } from '@tanstack/react-query';
import api from '../client';
import type { SSHKey, SSHKeyDetail, KeyLocation, PaginatedResponse, AccessEvent } from '../types';

export function useKeys(params?: { offset?: number; limit?: number; key_type?: string; search?: string }) {
  return useQuery({
    queryKey: ['keys', params],
    queryFn: () => api.get<PaginatedResponse<SSHKey>>('/keys', { params }).then((r) => r.data),
  });
}

export function useKey(id: number) {
  return useQuery({
    queryKey: ['key', id],
    queryFn: () => api.get<SSHKeyDetail>(`/keys/${id}`).then((r) => r.data),
    enabled: !!id,
  });
}

export function useKeyLocations(id: number) {
  return useQuery({
    queryKey: ['key-locations', id],
    queryFn: () => api.get<KeyLocation[]>(`/keys/${id}/locations`).then((r) => r.data),
    enabled: !!id,
  });
}

export function useKeyEvents(id: number, params?: { offset?: number; limit?: number }) {
  return useQuery({
    queryKey: ['key-events', id, params],
    queryFn: () => api.get<PaginatedResponse<AccessEvent>>(`/keys/${id}/access-events`, { params }).then((r) => r.data),
    enabled: !!id,
  });
}
