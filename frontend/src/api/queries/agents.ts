import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import api from '../client';
import type { AgentStatus, SudoEvent, PaginatedResponse } from '../types';

export function useAgents() {
  return useQuery({
    queryKey: ['agents'],
    queryFn: () => api.get<AgentStatus[]>('/agents').then((r) => r.data),
  });
}

export function useAgentStatus(serverId: number) {
  return useQuery({
    queryKey: ['agents', serverId],
    queryFn: () => api.get<AgentStatus>(`/agents/${serverId}`).then((r) => r.data),
    enabled: !!serverId,
  });
}

export function useDeployAgent() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ serverId, apiUrl }: { serverId: number; apiUrl: string }) =>
      api.post(`/agents/deploy/${serverId}`, { api_url: apiUrl }).then((r) => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['agents'] });
    },
  });
}

export function useDeployAgentBatch() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ serverIds, apiUrl }: { serverIds: number[]; apiUrl: string }) =>
      api.post('/agents/deploy-batch', { server_ids: serverIds, api_url: apiUrl }).then((r) => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['agents'] });
    },
  });
}

export function useUninstallAgent() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (serverId: number) =>
      api.post(`/agents/${serverId}/uninstall`).then((r) => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['agents'] });
    },
  });
}

export function useSudoEvents(serverId: number, params?: { offset?: number; limit?: number }) {
  return useQuery({
    queryKey: ['sudo-events', serverId, params],
    queryFn: () =>
      api.get<PaginatedResponse<SudoEvent>>(`/agents/${serverId}/sudo-events`, { params }).then((r) => r.data),
    enabled: !!serverId,
  });
}
