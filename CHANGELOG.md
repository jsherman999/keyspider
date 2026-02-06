# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-02-05

Major update: agent system, SFTP-based scanning, graph layers, sudo monitoring, and expanded test coverage.

### Added

#### Agent System
- **Agent script** (`agent/keyspider_agent.py`): Standalone stdlib-only Python agent deployed to target servers via SSH. Runs as systemd service with heartbeat, incremental SSH auth log collection, sudo event monitoring, key inventory scanning, and bearer token auth.
- **Agent manager** (`core/agent_manager.py`): Deploys/uninstalls agents via SSH+SFTP. Generates unique tokens (SHA256 hashed), renders agent config, uploads systemd unit, manages lifecycle.
- **Agent receiver API** (`api/agent_receiver.py`): Endpoints for agents to report data -- `POST /api/agent/heartbeat`, `/events`, `/sudo-events`, `/keys`. Token-based auth with SHA256 verification.
- **Agent management API** (`api/agents.py`): Operator endpoints -- `GET /api/agents`, `GET/POST /api/agents/{server_id}`, deploy, deploy-batch, uninstall, sudo-events.
- **AgentStatus model** (`models/agent_status.py`): Tracks deployment status, heartbeat, version, token hash per server.
- **SudoEvent model** (`models/sudo_event.py`): Records sudo command executions with username, command, target user, working directory, TTY, and success status.
- **Agent schemas** (`schemas/agent.py`): Request/response schemas for all agent endpoints.

#### SFTP-based File Operations
- **SFTP reader** (`core/sftp_reader.py`): Secure file operations via asyncssh SFTP client -- `read_file`, `read_file_tail`, `stat_file`, `list_dir`, `file_exists`. Eliminates all shell command injection vectors.
- Key scanner rewritten to use SFTP instead of `cat`/shell commands.
- Spider engine log reading uses SFTP with bounded line limits.

#### Authorization vs Usage Graph Layers
- `KeyLocation.graph_layer` field: classifies keys as `"authorization"` (in authorized_keys) or `"usage"` (seen in logs).
- `AccessPath.is_authorized` and `is_used` flags for dormant/mystery key detection.
- `GraphBuilder.build_layered_graph()` method with `show_dormant` and `show_mystery` toggles.
- `GET /api/graph` now accepts optional `layer` query parameter.
- `GET /api/graph/layered` endpoint for layered graph views.

#### Reports
- `GET /api/reports/dormant-keys` -- Authorized keys that have never been used.
- `GET /api/reports/mystery-keys` -- Keys used in authentication but not found in any authorized_keys file.
- `GET /api/reports/stale-keys` now accepts optional `age_days` filter parameter.

#### Journalctl Support
- `parse_journalctl_json()` and `parse_journalctl_output()` in log parser for structured systemd journal parsing.
- Spider engine tries journalctl first, falls back to syslog file reading.
- Accurate timestamps from journald (avoids syslog year ambiguity).

#### Sudo Event Parsing
- `parse_sudo_line()` in log parser for extracting sudo events from auth logs.
- Captures: username, target user, command, working directory, TTY, success/failure.

#### Key Age Tracking
- `SSHKey.file_mtime` and `estimated_age_days` fields.
- `KeyLocation.file_mtime` and `file_size` fields.
- File modification times captured via SFTP stat during key scanning.

#### Frontend
- **Agents page** (`pages/Agents.tsx`): Server table with agent status, deploy/uninstall actions, health indicators.
- **Server detail**: Added Agent tab (status, heartbeat, version, deploy/uninstall) and Sudo tab (sudo event history).
- **Alerts page**: Tabbed interface with "Unreachable Sources" and "Mystery Keys" tabs.
- **Reports page**: Added "Dormant Keys" and "Mystery Keys" tabs.
- **Graph Explorer**: Layer filter dropdown (All/Authorization/Usage), dormant and mystery edge highlighting.
- **Sidebar**: Added Agents navigation item.
- **Agent query hooks** (`api/queries/agents.ts`): `useAgents`, `useAgentStatus`, `useDeployAgent`, `useUninstallAgent`, `useSudoEvents`.

### Changed

#### SSH Connection Pool
- Renamed internal connection tracking to use `wrapper_id` (UUID) for unambiguous release/close.
- Health checks run outside the connection lock to prevent pool stalls.
- Lazy singleton initialization via `get_ssh_pool()` / `set_ssh_pool()` (replaces module-level global).

#### Incremental Scanning
- `Server.scan_watermark` field for tracking last processed event timestamp.
- Log parsing filters events before watermark on incremental scans.
- Log rotation detection via file size comparison.
- Configurable line limits: `LOG_MAX_LINES_INITIAL` (50000), `LOG_MAX_LINES_INCREMENTAL` (50000).

#### Syslog Year Handling
- Log parser accepts `reference_time` parameter (file mtime from SFTP stat).
- Sequential timestamp tracking with year rollover detection (>300 day backward jump triggers year decrement).

#### Batch Database Operations
- Spider engine pre-fetches fingerprint→key_id and source_ip→server_id mappings in bulk queries.
- Bulk `session.add_all()` for access events instead of individual inserts.

#### Watcher Callback Cleanup
- Event queues tracked in `_event_queues` list for cleanup.
- `stop()` sends None sentinel to unblock all waiting generators.
- `events()` generator uses try/finally to remove callback on exit.

#### Scan Tasks
- Servers with active agents (heartbeat < 5 min) skip SSH scanning automatically.
- `prefer_agent` flag on Server model controls scan behavior.

### Fixed
- Shell command injection vectors eliminated by replacing all `run_command(f"cat {path}")` with SFTP reads.
- Connection pool health check no longer blocks under lock.
- Watcher callback leak on generator abandonment.

### Testing
- **135 tests** (all passing), up from 54 in v0.1.0.
- New test files: `test_sftp_reader.py`, `test_connection_pool.py`, `test_agent_manager.py`, `test_agent_receiver.py`, `test_graph_layers.py`, `test_sudo_parser.py`.
- Updated: `test_log_parser.py` (journalctl, sudo, year rollover), `test_scan_workflow.py` (new model fields, agent status, sudo events), `test_api.py` (new endpoint auth tests).

---

## [0.1.0] - 2026-02-03

Initial implementation of Keyspider SSH key monitoring application.

### Added

#### Core Engine
- **SSH Connection Pool** (`core/ssh_connector.py`): asyncssh-based connection pooling with configurable max connections (default 50), per-server limits (default 3), automatic retry with exponential backoff, connection health checking, and timeout handling.
- **Auth Log Parser** (`core/log_parser.py`): Regex-based parsing for SSH authentication events from Debian/Ubuntu (`/var/log/auth.log`), RHEL/CentOS (`/var/log/secure`), and AIX (`/var/adm/syslog`, `/var/log/syslog`). Extracts timestamp, source IP, username, auth method, key fingerprint (SHA256/MD5), accept/reject status, and disconnect events.
- **Key Scanner** (`core/key_scanner.py`): Remote SSH key discovery across all user home directories. Scans `authorized_keys`, identity files (`id_rsa`, `id_ed25519`, etc.), and host keys. Parses `/etc/passwd` to enumerate home directories. Never reads or stores private key content.
- **Fingerprint Calculator** (`core/fingerprint.py`): SHA256 and MD5 fingerprint computation from public key data, key type detection (RSA, Ed25519, ECDSA, DSA), comment extraction, fingerprint normalization, and cross-format matching.
- **Spider Engine** (`core/spider_engine.py`): Recursive BFS crawler that starts from a seed server and discovers the full SSH access graph. Processes each server by parsing logs, scanning keys, storing results, and following source IPs. Depth-limited (default 10) with cycle detection via visited-set. Reports progress via callback.
- **Real-time Watcher** (`core/watcher.py`): Persistent SSH connections running `tail -F` on auth logs for live event monitoring. Auto-reconnects with exponential backoff. Supports async iteration over parsed events and optional callbacks per event.
- **Unreachable Detector** (`core/unreachable_detector.py`): Tests SSH reachability of source IPs from the jump server. Caches results with TTL. Performs reverse DNS lookups. Classifies severity (critical/high/medium/low) based on key usage, RFC1918 status, and root access.
- **Graph Builder** (`core/graph_builder.py`): Constructs Cytoscape-compatible graph responses from database records. Supports full graph, server-centered subgraph (configurable depth), key-centered subgraph, and BFS path-finding between servers.

#### Database
- **10 SQLAlchemy ORM models** (initial set): `Server`, `SSHKey`, `KeyLocation`, `AccessEvent`, `AccessPath`, `ScanJob`, `WatchSession`, `UnreachableSource`, `User`, `APIKey`.
- **Async session factory** with `asyncpg` driver for PostgreSQL 13.
- **Query helpers**: `paginate()` for list endpoints with offset/limit/total, `get_or_create()` for upsert patterns.
- **Alembic migration environment** configured for async engine.

#### Pydantic Schemas
- Request and response schemas for all API resources: `ServerCreate`, `ServerResponse`, `SSHKeyResponse`, `KeyLocationResponse`, `AccessEventResponse`, `ScanJobCreate`, `ScanJobResponse`, `WatchSessionCreate`, `WatchSessionResponse`, `GraphResponse`, `LoginRequest`, `TokenResponse`, `UserCreate`, `APIKeyCreate`, `ReportSummary`, and paginated list wrappers.

#### REST API (FastAPI)
- **Auth endpoints**: Login (JWT issuance), logout, current user info, API key CRUD.
- **Server endpoints**: Full CRUD, server detail with stats, keys/events/paths per server, bulk CSV import.
- **Key endpoints**: List all keys (paginated), key detail with locations, access events per key, lookup by fingerprint.
- **Scan endpoints**: Launch scans (full_scan, server_scan, spider_crawl), list scan jobs, scan status and results, cancel running scans.
- **Watch endpoints**: Start/stop/pause/resume watch sessions, list active sessions, paginated events per session.
- **Graph endpoints**: Full access graph, server-centered subgraph, key-centered subgraph, path finding between servers.
- **Report endpoints**: Unreachable sources (filterable by severity), key exposure (keys on multiple servers), stale keys (authorized but unused), environment summary, report export (CSV/JSON).

#### WebSocket
- `WS /api/ws/watch/{session_id}`: Stream real-time authentication events for a watch session.
- `WS /api/ws/scan/{job_id}`: Stream scan progress updates.

#### Authentication & Authorization
- JWT authentication with configurable expiry (default 60 minutes) and HS256 signing.
- API key authentication with bcrypt hashing, 8-character prefix identification, scoped permissions, and optional expiry.
- Role-based access control: `admin` (full access), `operator` (scan + watch), `viewer` (read-only).
- FastAPI dependency injection with `DbSession`, `CurrentUser`, `AdminUser`, `OperatorUser` type aliases.

#### Celery Workers
- **Celery configuration** with 4 task queues: `scan`, `key`, `spider`, `watcher`.
- **Beat schedule**: Daily full scan at 2:00 AM UTC, watcher health check every 5 minutes.
- **Scan tasks**: `scan_single_server` (connect, parse logs, scan keys, store results).
- **Key tasks**: `scan_server_keys_task` (key discovery for a single server).
- **Spider tasks**: `run_spider_crawl` (recursive crawl with progress tracking).
- **Watch tasks**: `start_watcher` and `stop_watcher` for managing persistent log tail sessions.

#### CLI (Typer)
- `keyspider server` -- Server management: list, add, show, import from CSV.
- `keyspider scan` -- Scan operations: full, server, spider, status, cancel.
- `keyspider keys` -- Key management: list, show, locate by fingerprint.
- `keyspider watch` -- Watcher control: start, stop, list, stream events.
- `keyspider report` -- Reports: unreachable sources, key exposure, summary, export.
- `keyspider user` -- User management: create users, generate API keys.
- `keyspider db` -- Database operations: init (create tables), migrate (run Alembic).

#### Frontend (React 18 + TypeScript)
- **Build tooling**: Vite 5, TypeScript 5, Tailwind CSS 3, PostCSS.
- **API layer**: Axios HTTP client with JWT auth interceptor, TanStack Query v5 hooks for all resources (servers, keys, scans, watch, graph), WebSocket client with auto-reconnect.
- **12 pages**:
  - `Dashboard` -- Summary statistics, recent events, active watchers, top alerts.
  - `GraphExplorer` -- Interactive Cytoscape.js graph with search, depth control, and node click navigation.
  - `Servers` -- Searchable server table with add server form, status badges, last scan timestamps.
  - `ServerDetail` -- Server info, keys found, access events timeline, inbound/outbound access paths.
  - `Keys` -- Searchable key table with type and location count filters.
  - `KeyDetail` -- Key metadata, all file locations, access events using this key.
  - `Scanner` -- Scan launcher (full/server/spider), active/completed scan list with progress display.
  - `Watcher` -- Start/stop watchers, live scrollable event log with search/filter.
  - `Alerts` -- Unreachable sources sorted by severity, acknowledge and add notes.
  - `Reports` -- Generate and view unreachable/exposure/stale-keys/summary reports.
  - `Settings` -- User management, API key management, system configuration.
  - `Login` -- Authentication page.
- **Reusable components**: `Table` (sortable, clickable rows), `Card`, `Badge` (success/warning/danger/info variants), `Sidebar` layout, `Header`.
- **Graph visualization**: Cytoscape.js integration with dagre layout, server/unreachable node styling, edge labels.

#### Infrastructure
- **Docker Compose** with 7 services: `postgres`, `redis`, `api`, `worker`, `watcher`, `beat`, `frontend`.
- **Dockerfile.api**: Python 3.11-slim with openssh-client, non-root user, uvicorn entrypoint.
- **Dockerfile.worker**: Python 3.11-slim with openssh-client and gevent, non-root user, Celery entrypoint.
- **Dockerfile.frontend**: Multi-stage build with Node 20 (build) and nginx:alpine (serve).
- **nginx.conf**: Reverse proxy config with `/api` and `/ws` proxy pass to FastAPI, WebSocket upgrade support.
- Health checks for PostgreSQL (`pg_isready`) and Redis (`redis-cli ping`).
- SSH keys mounted read-only from host into API, worker, and watcher containers.

#### Configuration
- `pydantic-settings` based configuration with environment variable support.
- All settings configurable: database URL, Redis URL, SSH parameters (key path, timeouts, connection limits), JWT settings (secret key, expiry, algorithm), CORS origins, spider depth, watcher reconnect delays.

#### Testing
- **54 tests** (all passing) across unit and integration suites.
- **Unit tests**:
  - `test_log_parser.py` -- Parsing of accepted/failed/disconnect events for Debian, RHEL, and AIX formats; full log parsing; log path detection.
  - `test_fingerprint.py` -- SHA256/MD5 calculation, key type detection, comment extraction, fingerprint normalization, cross-format matching.
  - `test_key_scanner.py` -- `authorized_keys` option stripping for plain keys, command-restricted keys, from-restricted keys, ECDSA keys.
  - `test_spider_engine.py` -- Spider progress tracking, visited-set cycle detection, queue management.
- **Integration tests**:
  - `test_api.py` -- Health check endpoint, auth requirement enforcement, login with invalid credentials (401 response).
  - `test_scan_workflow.py` -- Server creation, scan job creation, SSH key and location creation via ORM.
  - `test_ssh_connector.py` -- Connection pool initialization, server key generation, empty pool cleanup.
- **Test fixtures**: Sample auth logs for Debian, RHEL, and AIX; sample `authorized_keys` with options.
- **SQLite test adapter**: `before_create` event listener that patches PostgreSQL `INET` to `String(45)` and `JSONB` to `JSON()` for in-memory SQLite test database.

[0.2.0]: https://github.com/jsherman999/keyspider/releases/tag/v0.2.0
[0.1.0]: https://github.com/jsherman999/keyspider/releases/tag/v0.1.0
