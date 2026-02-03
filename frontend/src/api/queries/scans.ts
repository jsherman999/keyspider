import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import api from '../client';
import type { ScanJob, PaginatedResponse } from '../types';

export function useScans(params?: { offset?: number; limit?: number; status?: string }) {
  return useQuery({
    queryKey: ['scans', params],
    queryFn: () => api.get<PaginatedResponse<ScanJob>>('/scans', { params }).then((r) => r.data),
  });
}

export function useScan(id: number) {
  return useQuery({
    queryKey: ['scan', id],
    queryFn: () => api.get<ScanJob>(`/scans/${id}`).then((r) => r.data),
    enabled: !!id,
    refetchInterval: (query) => {
      const data = query.state.data;
      return data && ['pending', 'running'].includes(data.status) ? 2000 : false;
    },
  });
}

export function useCreateScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: { job_type: string; seed_server_id?: number; max_depth?: number }) =>
      api.post<ScanJob>('/scans', data).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scans'] }),
  });
}

export function useCancelScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => api.post(`/scans/${id}/cancel`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scans'] }),
  });
}
