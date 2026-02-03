# Keyspider

SSH key usage monitoring and tracking application. Keyspider operates from a central Linux jump server to recursively discover, map, and monitor all SSH access relationships across an environment of 500-5,000 servers (Linux + AIX). It builds a spider-web graph of access paths, maps fingerprints to actual key files, and flags unreachable sources as security concerns.

## Architecture

```
                    ┌─────────────┐
                    │  Frontend   │  React 18 + TypeScript
                    │  :3000      │  Cytoscape.js graph viz
                    └──────┬──────┘
                           │
                    ┌──────┴──────┐
                    │  FastAPI    │  REST API + WebSocket
                    │  :8000      │  JWT / API key auth
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
       ┌──────┴──────┐ ┌──┴───┐ ┌──────┴──────┐
       │   Workers   │ │ Beat │ │   Watcher   │
       │  (Celery)   │ │      │ │  (Celery)   │
       │  scan/key/  │ │ cron │ │  tail -F    │
       │  spider     │ │      │ │  100 conns  │
       └──────┬──────┘ └──┬───┘ └──────┬──────┘
              │           │            │
       ┌──────┴───────────┴────────────┴──────┐
       │          PostgreSQL 13 + Redis        │
       └──────────────────────────────────────┘
```

### Technology Stack

| Component    | Technology                          |
|-------------|-------------------------------------|
| Backend     | Python 3.11+ / FastAPI (async)      |
| SSH         | asyncssh                            |
| Task Queue  | Celery + Redis                      |
| Database    | PostgreSQL 13                       |
| ORM         | SQLAlchemy 2.0 (async)              |
| Migrations  | Alembic                             |
| Frontend    | React 18 + TypeScript + Vite        |
| Graph Viz   | Cytoscape.js                        |
| Real-time   | WebSocket (FastAPI native)          |
| CLI         | Typer + Rich                        |
| Auth        | JWT + API keys (bcrypt + bearer)    |
| Deployment  | Docker Compose (7 services)         |

## Features

### Spider Engine
Recursive BFS crawler that starts from a seed server and automatically discovers the full SSH access graph:

1. Connects to seed server, parses auth logs to extract source IPs and key fingerprints
2. Scans for SSH key files (`authorized_keys`, identity keys, host keys) across all user home directories
3. Matches fingerprints from logs to discovered key files
4. For each source IP: tests reachability from the jump server
   - **Reachable** -- adds to crawl queue, continues spider
   - **Unreachable** -- flags as security concern with severity classification
5. Follows outbound keys to discover what servers each host can access
6. Recurses with configurable depth limit (default 10) and cycle detection

### Log Parsing
Parses SSH authentication events from multiple log formats:

| OS             | Log Path                           |
|----------------|------------------------------------|
| Debian/Ubuntu  | `/var/log/auth.log`                |
| RHEL/CentOS    | `/var/log/secure`                  |
| AIX            | `/var/adm/syslog`, `/var/log/syslog` |

Extracts: timestamp, source IP, username, auth method, key fingerprint (SHA256/MD5), accept/reject status, disconnect events.

### Key Scanner
Discovers SSH key material on remote servers:
- `~/.ssh/authorized_keys` for all users (parses `/etc/passwd` for home directories)
- `~/.ssh/id_*` identity keys (public keys only -- private key content is never stored)
- `/etc/ssh/ssh_host_*_key.pub` host keys
- Calculates SHA256 and MD5 fingerprints
- Records file ownership and permissions

### Real-time Watcher
Persistent SSH connections that `tail -F` auth logs for live monitoring:
- Parses each new log line through the log parser
- Stores events in the database immediately
- Optionally triggers spider crawls for new source IPs (`auto_spider` mode)
- Broadcasts events via WebSocket to connected frontend clients
- Auto-reconnects with exponential backoff on connection drops

### Unreachable Source Detection
Identifies and classifies SSH access from sources the jump server cannot reach:

| Severity   | Condition                                          |
|------------|----------------------------------------------------|
| Critical   | Root key fingerprint used from unreachable source  |
| High       | Any key from unreachable non-RFC1918 source        |
| Medium     | Key from unreachable RFC1918 (internal) source     |
| Low        | Failed auth attempts from unreachable source       |

### Access Graph
Interactive Cytoscape.js visualization of all SSH access relationships:
- Full environment graph (nodes = servers, edges = access paths)
- Server-centered subgraphs with configurable depth
- Key-centered views showing everywhere a specific key is used
- Path finding between any two servers (BFS)
- Unreachable sources highlighted in red

## Project Structure

```
keyspider/
├── docker-compose.yml              # 7-service deployment
├── Dockerfile.api                   # FastAPI server
├── Dockerfile.worker                # Celery workers
├── Dockerfile.frontend              # React build + nginx
├── alembic.ini                      # Migration config
├── pyproject.toml                   # Python project config
│
├── src/keyspider/
│   ├── main.py                      # FastAPI app entry point
│   ├── config.py                    # pydantic-settings config
│   ├── dependencies.py              # Auth, DB, role-based access
│   │
│   ├── models/                      # SQLAlchemy ORM (10 tables)
│   │   ├── server.py                # Servers inventory
│   │   ├── ssh_key.py               # Discovered SSH keys
│   │   ├── key_location.py          # Key file locations on servers
│   │   ├── access_event.py          # Auth log events
│   │   ├── access_path.py           # Aggregated access relationships
│   │   ├── scan_job.py              # Scan job tracking
│   │   ├── watch_session.py         # Watcher sessions
│   │   ├── unreachable_source.py    # Flagged unreachable sources
│   │   ├── user.py                  # App users
│   │   └── api_key.py               # API keys
│   │
│   ├── schemas/                     # Pydantic request/response
│   ├── api/                         # FastAPI route handlers
│   │   ├── auth.py                  # Login, API key management
│   │   ├── servers.py               # Server CRUD + detail
│   │   ├── keys.py                  # Key lookup + locations
│   │   ├── scans.py                 # Scan launch + status
│   │   ├── watch.py                 # Watcher management
│   │   ├── graph.py                 # Graph queries
│   │   ├── reports.py               # Reports + exports
│   │   └── ws.py                    # WebSocket endpoints
│   │
│   ├── core/                        # Business logic
│   │   ├── ssh_connector.py         # asyncssh connection pool
│   │   ├── log_parser.py            # Auth log parsing
│   │   ├── key_scanner.py           # Key file discovery
│   │   ├── fingerprint.py           # SHA256/MD5 fingerprinting
│   │   ├── spider_engine.py         # Recursive BFS crawler
│   │   ├── watcher.py               # Real-time log tailing
│   │   ├── unreachable_detector.py  # Reachability + severity
│   │   └── graph_builder.py         # Graph construction
│   │
│   ├── workers/                     # Celery tasks
│   │   ├── celery_app.py            # Config + beat schedule
│   │   ├── scan_tasks.py            # Server scan tasks
│   │   ├── key_tasks.py             # Key discovery tasks
│   │   ├── spider_tasks.py          # Spider crawl tasks
│   │   └── watch_tasks.py           # Watcher management
│   │
│   ├── db/                          # Database layer
│   │   ├── session.py               # Async engine + session factory
│   │   └── queries.py               # paginate(), get_or_create()
│   │
│   └── cli/                         # Typer CLI
│       ├── main.py                  # Entry point
│       ├── server_commands.py
│       ├── scan_commands.py
│       ├── key_commands.py
│       ├── watch_commands.py
│       ├── report_commands.py
│       ├── user_commands.py
│       └── db_commands.py
│
├── frontend/
│   └── src/
│       ├── api/                     # Axios client + TanStack Query hooks
│       ├── components/              # Layout, graph, common UI
│       └── pages/                   # 12 pages (see below)
│
└── tests/
    ├── unit/                        # log_parser, fingerprint, key_scanner, spider
    ├── integration/                 # API, scan workflow, SSH connector
    └── fixtures/                    # Sample logs (Debian, RHEL, AIX), keys
```

## Getting Started

### Prerequisites
- Docker and Docker Compose
- SSH key pair on the jump server (the server running Keyspider)
- SSH access from the jump server to target servers

### Quick Start with Docker Compose

```bash
git clone https://github.com/jsherman999/keyspider.git
cd keyspider

# Edit environment variables (database password, secret key, etc.)
vim docker-compose.yml

# Start all services
docker compose up -d

# Initialize the database
docker compose exec api keyspider db init

# Create an admin user
docker compose exec api keyspider user create admin --role admin
```

The frontend will be available at `http://localhost:3000` and the API at `http://localhost:8000`.

### Local Development

```bash
# Backend
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Requires PostgreSQL and Redis running locally
keyspider db init
uvicorn keyspider.main:app --reload

# Frontend
cd frontend
npm install
npm run dev
```

### Running Tests

```bash
source .venv/bin/activate
pip install -e ".[dev]"
python -m pytest tests/ -v
```

Tests use an in-memory SQLite database with automatic PostgreSQL type adaptation (INET, JSONB).

## Docker Compose Services

| Service    | Image/Build     | Purpose                           | Ports  |
|------------|----------------|-----------------------------------|--------|
| `postgres` | postgres:13     | Primary database                  | 5432   |
| `redis`    | redis:7-alpine  | Celery broker + result backend    | 6379   |
| `api`      | Dockerfile.api  | FastAPI server                    | 8000   |
| `worker`   | Dockerfile.worker | Celery workers (scan/key/spider) | -      |
| `watcher`  | Dockerfile.worker | Celery watcher queue (100 conns) | -      |
| `beat`     | Dockerfile.worker | Celery Beat scheduler            | -      |
| `frontend` | Dockerfile.frontend | React app via nginx             | 3000   |

SSH keys from the jump server are mounted read-only into the `api`, `worker`, and `watcher` containers.

## CLI Usage

```bash
# Server management
keyspider server list
keyspider server add <hostname> --port 22
keyspider server import servers.csv
keyspider server show <hostname>

# Scanning
keyspider scan full                        # Full environment scan
keyspider scan server <hostname>           # Single server scan
keyspider scan spider <hostname> --depth 5 # Spider crawl from seed
keyspider scan status [job_id]
keyspider scan cancel <job_id>

# SSH keys
keyspider keys list
keyspider keys show <fingerprint>
keyspider keys locate <fingerprint>

# Real-time watching
keyspider watch start <hostname> --depth 3
keyspider watch stop <session_id>
keyspider watch list
keyspider watch events <session_id>

# Reports
keyspider report unreachable
keyspider report exposure
keyspider report summary
keyspider report export --format csv

# Administration
keyspider user create <username> --role admin
keyspider user apikey create <name>
keyspider db init
keyspider db migrate
```

## API Endpoints

All endpoints are prefixed with `/api`. Authentication required unless noted.

### Auth
| Method | Path                    | Description          |
|--------|------------------------|----------------------|
| POST   | `/api/auth/login`      | Login, returns JWT   |
| POST   | `/api/auth/logout`     | Invalidate token     |
| GET    | `/api/auth/me`         | Current user info    |
| POST   | `/api/auth/api-keys`   | Create API key       |
| GET    | `/api/auth/api-keys`   | List API keys        |
| DELETE | `/api/auth/api-keys/{id}` | Revoke API key    |

### Servers
| Method | Path                              | Description               |
|--------|----------------------------------|---------------------------|
| GET    | `/api/servers`                    | List servers (paginated)  |
| POST   | `/api/servers`                    | Add server                |
| GET    | `/api/servers/{id}`               | Server detail + stats     |
| PUT    | `/api/servers/{id}`               | Update server             |
| DELETE | `/api/servers/{id}`               | Remove server             |
| GET    | `/api/servers/{id}/keys`          | Keys on this server       |
| GET    | `/api/servers/{id}/access-events` | Access events             |
| GET    | `/api/servers/{id}/access-paths`  | Access paths to/from      |
| POST   | `/api/servers/import`             | Bulk import from CSV      |

### SSH Keys
| Method | Path                             | Description               |
|--------|----------------------------------|---------------------------|
| GET    | `/api/keys`                      | List all keys (paginated) |
| GET    | `/api/keys/{id}`                 | Key detail + locations    |
| GET    | `/api/keys/{id}/locations`       | Key file locations        |
| GET    | `/api/keys/{id}/access-events`   | Events involving this key |
| GET    | `/api/keys/by-fingerprint/{fp}`  | Lookup by fingerprint     |

### Scans
| Method | Path                     | Description          |
|--------|-------------------------|----------------------|
| POST   | `/api/scans`             | Launch a scan        |
| GET    | `/api/scans`             | List scan jobs       |
| GET    | `/api/scans/{id}`        | Scan status/results  |
| POST   | `/api/scans/{id}/cancel` | Cancel running scan  |

### Watcher
| Method | Path                       | Description          |
|--------|---------------------------|----------------------|
| POST   | `/api/watch`               | Start watching       |
| GET    | `/api/watch`               | List watch sessions  |
| GET    | `/api/watch/{id}`          | Session detail       |
| POST   | `/api/watch/{id}/stop`     | Stop watching        |
| POST   | `/api/watch/{id}/pause`    | Pause watching       |
| POST   | `/api/watch/{id}/resume`   | Resume watching      |
| GET    | `/api/watch/{id}/events`   | Paginated events     |

### Graph
| Method | Path                          | Description                    |
|--------|------------------------------|--------------------------------|
| GET    | `/api/graph`                  | Full access graph              |
| GET    | `/api/graph/server/{id}`      | Server-centered subgraph       |
| GET    | `/api/graph/key/{id}`         | Key usage subgraph             |
| GET    | `/api/graph/path?from=&to=`   | Find paths between servers     |

### Reports
| Method | Path                          | Description                |
|--------|------------------------------|----------------------------|
| GET    | `/api/reports/unreachable`    | Unreachable sources        |
| GET    | `/api/reports/key-exposure`   | Keys on multiple servers   |
| GET    | `/api/reports/stale-keys`     | Unused authorized keys     |
| GET    | `/api/reports/summary`        | Environment summary stats  |
| POST   | `/api/reports/generate`       | Export report (CSV/JSON)   |

### WebSocket
| Path                           | Description                    |
|-------------------------------|--------------------------------|
| `/api/ws/watch/{session_id}`   | Stream real-time watcher events |
| `/api/ws/scan/{job_id}`        | Stream scan progress updates    |

## Frontend Pages

| Page              | Description                                                    |
|-------------------|----------------------------------------------------------------|
| Dashboard         | Summary stats, recent events, active watchers, top alerts      |
| Graph Explorer    | Interactive Cytoscape.js graph with filtering and drill-down   |
| Servers           | Searchable server table with status badges                     |
| Server Detail     | Server info, keys, events timeline, mini access graph          |
| Keys              | Searchable key table filtered by type and location count       |
| Key Detail        | Key info, all file locations, access events, servers           |
| Scanner           | Launch scans, monitor progress, view results                   |
| Watcher           | Start/stop watchers, live scrollable log view with search      |
| Alerts            | Unreachable sources sorted by severity, acknowledge and notes  |
| Reports           | Generate and view reports                                      |
| Settings          | User management, API keys, system configuration                |
| Login             | Authentication page                                            |

## Configuration

All settings are configurable via environment variables:

| Variable                    | Default                          | Description                      |
|----------------------------|----------------------------------|----------------------------------|
| `DATABASE_URL`             | `postgresql+asyncpg://...`       | PostgreSQL connection string     |
| `REDIS_URL`                | `redis://localhost:6379/0`       | Redis URL                        |
| `CELERY_BROKER_URL`        | `redis://localhost:6379/0`       | Celery broker URL                |
| `CELERY_RESULT_BACKEND`    | `redis://localhost:6379/1`       | Celery result backend            |
| `SSH_KEY_PATH`             | `/root/.ssh/id_rsa`              | Path to SSH private key          |
| `SSH_KNOWN_HOSTS`          | `None`                           | Path to known_hosts file         |
| `SSH_CONNECT_TIMEOUT`      | `10`                             | SSH connection timeout (seconds) |
| `SSH_COMMAND_TIMEOUT`      | `30`                             | SSH command timeout (seconds)    |
| `SSH_MAX_CONNECTIONS`      | `50`                             | Max total SSH connections        |
| `SSH_PER_SERVER_LIMIT`     | `3`                              | Max connections per server       |
| `SECRET_KEY`               | `change-me-in-production`        | JWT signing key                  |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `60`                          | JWT token expiry                 |
| `CORS_ORIGINS`             | `["http://localhost:3000"]`      | Allowed CORS origins (JSON)      |
| `SPIDER_DEFAULT_DEPTH`     | `10`                             | Default spider crawl depth       |
| `SPIDER_MAX_DEPTH`         | `50`                             | Maximum allowed crawl depth      |
| `WATCHER_RECONNECT_DELAY`  | `5`                              | Initial reconnect delay (seconds)|
| `WATCHER_MAX_RECONNECT_DELAY` | `300`                         | Max reconnect delay (seconds)    |

## Security

- SSH private keys are mounted read-only into containers -- never copied or written to
- Private key **content** is never stored in the database -- only fingerprints, file paths, and metadata
- JWT authentication with configurable expiry and HS256 signing
- API key authentication with bcrypt hashing and scoped permissions
- Role-based access control: `admin` (full), `operator` (scan/watch), `viewer` (read-only)
- All scan and watch operations logged with initiator for audit trail
- Non-root container users in all Dockerfiles
- API should be bound to internal interfaces or placed behind a reverse proxy with TLS

## Database

PostgreSQL 13 with 10 tables:

- `servers` -- Server inventory with OS type, SSH port, reachability status
- `ssh_keys` -- Discovered keys indexed by SHA256 fingerprint
- `key_locations` -- Where key files exist (server, path, owner, permissions)
- `access_events` -- Individual auth log events (source IP, fingerprint, accept/reject)
- `access_paths` -- Aggregated access relationships with event counts
- `scan_jobs` -- Scan job tracking (type, status, progress counters)
- `watch_sessions` -- Active watcher sessions with auto-spider config
- `unreachable_sources` -- Flagged unreachable sources with severity
- `users` -- Application users with roles
- `api_keys` -- API keys with scoped permissions and expiry

Migrations are managed with Alembic. Run `keyspider db migrate` to apply.

## License

MIT
