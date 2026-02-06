// Shared API types

export interface Server {
  id: number;
  hostname: string;
  ip_address: string;
  os_type: string;
  os_version: string | null;
  ssh_port: number;
  is_reachable: boolean;
  last_scanned_at: string | null;
  discovered_via: string | null;
  prefer_agent: boolean;
  created_at: string;
  updated_at: string;
}

export interface SSHKey {
  id: number;
  fingerprint_sha256: string;
  fingerprint_md5: string | null;
  key_type: string;
  key_bits: number | null;
  comment: string | null;
  is_host_key: boolean;
  file_mtime: string | null;
  estimated_age_days: number | null;
  first_seen_at: string;
  created_at: string;
}

export interface SSHKeyDetail extends SSHKey {
  public_key_data: string | null;
  location_count: number;
  event_count: number;
}

export interface KeyLocation {
  id: number;
  ssh_key_id: number;
  server_id: number;
  file_path: string;
  file_type: string;
  unix_owner: string | null;
  unix_permissions: string | null;
  graph_layer: string;
  file_mtime: string | null;
  file_size: number | null;
  last_verified_at: string | null;
  server_hostname: string | null;
}

export interface AccessEvent {
  id: number;
  target_server_id: number;
  source_ip: string;
  source_server_id: number | null;
  ssh_key_id: number | null;
  fingerprint: string | null;
  username: string;
  auth_method: string | null;
  event_type: string;
  event_time: string;
  raw_log_line: string | null;
  log_source: string | null;
}

export interface AccessPath {
  id: number;
  source_server_id: number | null;
  target_server_id: number;
  ssh_key_id: number | null;
  username: string | null;
  first_seen_at: string;
  last_seen_at: string;
  event_count: number;
  is_active: boolean;
  is_authorized: boolean;
  is_used: boolean;
}

export interface ScanJob {
  id: number;
  job_type: string;
  status: string;
  initiated_by: string;
  seed_server_id: number | null;
  max_depth: number | null;
  servers_scanned: number;
  keys_found: number;
  events_parsed: number;
  unreachable_found: number;
  error_message: string | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
}

export interface WatchSession {
  id: number;
  server_id: number;
  status: string;
  last_event_at: string | null;
  events_captured: number;
  auto_spider: boolean;
  spider_depth: number;
  error_message: string | null;
  started_at: string;
  stopped_at: string | null;
}

export interface GraphNode {
  id: string;
  label: string;
  type: string;
  ip_address: string | null;
  os_type: string | null;
  is_reachable: boolean;
  key_count: number;
  event_count: number;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  label: string | null;
  key_type: string | null;
  username: string | null;
  event_count: number;
  is_active: boolean;
  is_authorized: boolean | null;
  is_used: boolean | null;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
  node_count: number;
  edge_count: number;
}

export interface UnreachableSource {
  id: number;
  source_ip: string;
  reverse_dns: string | null;
  fingerprint: string | null;
  ssh_key_id: number | null;
  target_server_id: number;
  username: string | null;
  first_seen_at: string;
  last_seen_at: string;
  event_count: number;
  severity: string;
  notes: string | null;
  acknowledged: boolean;
  acknowledged_by: number | null;
}

export interface SummaryReport {
  total_servers: number;
  reachable_servers: number;
  unreachable_servers: number;
  total_keys: number;
  total_key_locations: number;
  total_access_events: number;
  total_access_paths: number;
  active_watchers: number;
  unreachable_sources: number;
  critical_alerts: number;
  high_alerts: number;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  offset: number;
  limit: number;
}

export interface User {
  id: number;
  username: string;
  display_name: string | null;
  role: string;
  is_active: boolean;
  last_login_at: string | null;
  created_at: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
}

export interface AgentStatus {
  id: number;
  server_id: number;
  agent_version: string | null;
  deployment_status: string;
  last_heartbeat_at: string | null;
  last_event_at: string | null;
  installed_at: string | null;
  error_message: string | null;
  created_at: string;
  updated_at: string;
}

export interface SudoEvent {
  id: number;
  server_id: number;
  username: string;
  command: string | null;
  target_user: string | null;
  working_dir: string | null;
  tty: string | null;
  event_time: string;
  success: boolean;
  created_at: string;
}

export interface DormantKey {
  ssh_key_id: number;
  fingerprint_sha256: string;
  key_type: string;
  comment: string | null;
  server_id: number;
  server_hostname: string;
  file_path: string;
  first_seen_at: string;
  days_since_first_seen: number;
}

export interface MysteryKey {
  fingerprint: string | null;
  last_source_ip: string | null;
  last_username: string | null;
  server_id: number;
  server_hostname: string;
  event_count: number;
  last_seen_at: string;
}
