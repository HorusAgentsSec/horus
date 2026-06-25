# Iris

Iris is the Horus host monitoring daemon. It runs on your own Linux servers, watches kernel-level security events in real time, and ships them to the Horus API where they are triaged and turned into findings.

Iris is written in Rust (`iris-rs`, v0.2). It replaces a previous Python implementation that was retired after chronic memory-leak issues caused by unbounded inotify watches and procfs polling. The current design delegates all watching to the kernel (auditd and journald) and uses zero application-level polling.

---

## Architecture

```
Linux kernel
  ├── auditd subsystem  ──► /var/log/audit/audit.log  ──► AuditdMonitor
  └── journal           ──► journalctl -f -o json      ──► JournaldMonitor
                                          │
                                   mpsc channel (cap 10 000)
                                          │
                                     Daemon loop (every interval_seconds)
                                          │
                                     IrisReporter
                                          │
                              POST /api/iris/events
                                          │
                                    Horus API
                                          │
                             ┌────────────┴────────────┐
                        iris_events             deterministic alerts
                             │                  (brute-force, C2, tamper)
                      AI triage scheduler
                             │
                           findings
```

The daemon spawns one async task per monitor. Each task pushes `serde_json::Value` objects into a shared in-memory channel. The main loop drains the channel on every tick and POSTs the batch to the server. If the server is unreachable, events are written to a local JSON queue (`/var/lib/horus/iris/queue.json`), capped at 5,000 events to prevent OOM. On the next successful flush, the backlog is replayed.

Iris handles `SIGTERM` and `SIGINT` gracefully: it aborts monitor tasks, drains any remaining in-channel events, and sends one final batch before exiting.

---

## Monitors

### JournaldMonitor

**Source:** `journalctl -f -o json --output-fields=MESSAGE,SYSLOG_IDENTIFIER,_COMM,PRIORITY,_PID,_UID`

The journald monitor streams structured journal entries in real time. It filters to a known set of security identifiers (`sshd`, `sudo`, `su`, `su-l`, `login`, `passwd`, `useradd`, `userdel`, `usermod`, `groupadd`, `chpasswd`) and to any entry with priority 3 or lower (error/critical/alert/emergency).

**What it detects:**

| Condition | Event type | Severity |
|---|---|---|
| Successful SSH login | `auth_event` | `low` |
| Failed SSH login | `auth_event` | `medium` |
| Invalid SSH username | `auth_event` | `medium` |
| SSH brute force (>=5 failures in 60 s from the same IP) | `auth_event` | `high` |
| sudo command execution | `auth_event` | `low` |
| sudo command that stops/disables/removes the Iris agent | `auth_event` | `high` |
| su/su-l session open | `auth_event` | `low` |
| useradd / userdel / usermod / groupadd / chpasswd | `auth_event` | `high` |
| Any journal entry at priority <=3 (error or worse) | `log_anomaly` | `medium` or `high` |

**Brute-force detection:** the monitor keeps a sliding 60-second window of failed SSH attempts per source IP in memory. When a single IP crosses 5 failures, one `brute_force` event is emitted. A 5-minute cooldown prevents alert storms from a sustained attacker. Old IP state is pruned on every record so an attacker rotating source addresses cannot grow the in-memory map without bound.

**Agent tamper detection:** any sudo command that contains `horus-iris` or `horus_iris` and includes a destructive verb (`stop`, `disable`, `mask`, `kill`, `rm`, `remove`, `uninstall`) triggers an `agent_tamper` event at `high` severity. This maps to MITRE ATT&CK T1562.001 (Impair Defenses: Disable or Modify Tools).

### AuditdMonitor

**Source:** `/var/log/audit/audit.log` (tailed with `tail -f -n 0`)

The auditd monitor reads raw audit records from the kernel audit subsystem. Records arrive in multi-line groups identified by a serial number; the monitor accumulates them until it sees an `EOE` (End of Event) record, then processes the complete group. To prevent unbounded memory use from groups that never close (e.g. a process that crashes before the kernel writes EOE), the monitor evicts the oldest 100 open groups whenever the map exceeds 500 entries.

The monitor only acts on records whose `key` field starts with `horus_`. These keys are written by the audit rules the installer places at `/etc/audit/rules.d/horus.rules`.

**Audit rules installed:**

```
# File Integrity Monitoring; /etc and /root only (low volume, high value)
-w /etc -p wa -k horus_fim
-w /root -p wa -k horus_fim

# Exec from world-writable paths only
-a always,exit -F arch=b64 -S execve -F dir=/tmp -k horus_exec
-a always,exit -F arch=b64 -S execve -F dir=/dev/shm -k horus_exec
-a always,exit -F arch=b64 -S execve -F dir=/var/tmp -k horus_exec
```

Network auditing (`-S connect`) is intentionally excluded: auditing every outbound TCP connection floods the log on busy hosts and belongs at the network layer rather than the host agent.

**What it detects:**

| Audit key | Condition | Event type | Severity |
|---|---|---|---|
| `horus_exec` | Binary name matches a blacklist (`nc`, `ncat`, `netcat`, `socat`, `mimikatz`, `msfconsole`, `msfvenom`) | `new_process` | `high` |
| `horus_exec` | Executable path is inside `/tmp/`, `/dev/shm/`, or `/var/tmp/` | `new_process` | `medium` |
| `horus_exec` | All other execs from watched dirs | (suppressed) | |
| `horus_fim` | Write or attribute change under `/etc/` or `/root/` | `file_change` | `high` |
| `horus_fim` | Write or attribute change elsewhere | `file_change` | `medium` |
| `horus_net` | Outbound connection to a known high-risk port (4444, 5555, 1337, 31337, 6666, 9001) | `new_connection` | `high` |

Only successful syscalls (`success=yes`) are processed. Failed attempts are silently discarded.

The backlog wait time is set to 0 (`--backlog_wait_time 0`) in the audit rules, with a large buffer (`-b 16384`). If the audit backlog fills, the kernel drops events rather than stalling syscalls; this ensures Iris never introduces latency into the monitored system.

---

## Configuration

Iris is configured with a YAML file. The default search path is:

1. `--config <path>` (command-line flag)
2. `$HORUS_IRIS_CONFIG` (environment variable)
3. `/etc/horus/iris.yaml`
4. `~/.horus/iris.yaml`

**Minimal `iris.yaml`:**

```yaml
server_url: https://your-horus-server
api_key: irs_<your-api-key>
agent_id: <uuid-from-horus-ui>

interval_seconds: 30
log_level: INFO
```

**Fields:**

| Field | Type | Default | Description |
|---|---|---|---|
| `server_url` | string | (required) | Base URL of the Horus API server, without trailing slash |
| `api_key` | string | (required) | Agent API key from the Horus dashboard; must start with `irs_` |
| `agent_id` | string | (required) | UUID of the registered agent, from the Horus dashboard |
| `interval_seconds` | integer | `30` | How often the daemon flushes the event channel and POSTs to the server |
| `log_level` | string | `INFO` | Passed to `tracing-subscriber`; valid values: `TRACE`, `DEBUG`, `INFO`, `WARN`, `ERROR` |

The log level can also be overridden at runtime with the `RUST_LOG` environment variable, which takes precedence.

**Note:** there are no `watch_paths` or `ignore_patterns` fields. All file, process, and network monitoring is delegated to the kernel audit subsystem. This is intentional: application-level recursive inotify watches were the cause of the OOM issues in the previous Python implementation.

---

## Event schema

Every event Iris sends to the API is a JSON object with the following top-level fields:

```json
{
  "event_type": "auth_event",
  "severity": "high",
  "title": "Brute-force SSH from 1.2.3.4",
  "payload": { ... }
}
```

| Field | Type | Values |
|---|---|---|
| `event_type` | string | `file_change`, `new_process`, `new_listener`, `new_connection`, `auth_event`, `log_anomaly` |
| `severity` | string | `info`, `low`, `medium`, `high`, `critical` |
| `title` | string | Human-readable one-line summary |
| `payload` | object | Event-specific fields (see below) |

**Payload shapes by event type:**

`auth_event` (SSH, sudo, su, user changes):
```json
{
  "subtype": "ssh_login_success | ssh_login_failure | ssh_invalid_user | brute_force | sudo_command | su_session | user_change | agent_tamper",
  "user": "alice",
  "source_ip": "1.2.3.4",
  "method": "publickey",
  "command": "/usr/bin/apt upgrade"
}
```

`new_process` (auditd exec):
```json
{
  "exe": "/tmp/evil",
  "comm": "evil",
  "cmdline": "/tmp/evil -l 0.0.0.0 -p 4444",
  "uid": "1000"
}
```

`file_change` (auditd FIM):
```json
{
  "path": "/etc/passwd",
  "exe": "/usr/sbin/usermod",
  "uid": "0"
}
```

`new_connection` (auditd network):
```json
{
  "exe": "/usr/bin/nc",
  "comm": "nc",
  "uid": "1000",
  "dest_port": 4444
}
```

`log_anomaly` (high-priority journal entry):
```json
{
  "identifier": "kernel",
  "priority": 2,
  "pid": "1"
}
```

The wire format sent to the API wraps these in a batch envelope:

```json
{
  "agent_id": "<uuid>",
  "hostname": "web-01",
  "ip": "10.0.0.5",
  "events": [ ... ]
}
```

---

## AI triage

Events accumulate in `iris_events` with `processed = false`. The triage engine runs on a per-org schedule (default: every 60 minutes) and processes pending events in a token-economical way.

**How it works:**

1. Fetch up to 2,000 pending events for the org (only `id`, `event_type`, `severity`, `title` — no payloads).
2. Group events by `(event_type, severity)`. For each group, collect the event titles.
3. Filter out groups whose finding fingerprint is already recorded as a false positive in the verdict memory (org-level and community-level).
4. Build a compact prompt: one line per group, showing the count and two representative titles. Typically 200-400 input tokens regardless of event volume.
5. Call the LLM with `temperature=0` and instruct it to return a JSON array of flagged groups with `risk: CRITICAL|HIGH` and a one-sentence reason.
6. For each flagged group: create a summary finding (source `iris_ai`), then trigger the full scan pipeline for every agent that contributed events to that group.
7. Mark all analyzed events as `processed = true`, including benign ones, so they do not accumulate for re-analysis.

**Deterministic threats** (agent tamper, SSH brute force, connections to known C2 ports) bypass the triage interval entirely. They are detected synchronously at event ingestion and immediately create findings and in-app notifications for `admin` and `analyst` users.

**Offline agent detection:** separately, the triage scheduler checks whether any previously-online agent has not reported within a configurable window (default from `settings.iris_offline_after_minutes`). On first detection it flips the agent status to `offline`, creates a medium-severity finding, and sends an in-app notification. The status field acts as a latch so the alert fires only once per offline transition.

---

## Database tables

### `iris_agents`

Stores registered agent instances. Each agent has a unique API key (stored as SHA-256); only the first 12 characters are stored in plaintext for display.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | Primary key |
| `org_id` | `uuid` | FK to `organizations` |
| `name` | `text` | Human label assigned at registration |
| `hostname` | `text` | Updated by the daemon on each heartbeat |
| `platform` | `text` | `linux` or `darwin` |
| `ip` | `text` | Last known IP, updated by the daemon |
| `api_key_hash` | `text` | SHA-256 of the `irs_` key |
| `key_prefix` | `text` | First 12 characters, for display only |
| `asset_id` | `uuid` | Optional FK to `assets`; auto-created if absent |
| `last_seen_at` | `timestamptz` | Updated on every event batch |
| `status` | `text` | `online`, `offline`, `degraded` |
| `config` | `jsonb` | Reserved for future per-agent overrides |
| `created_at` | `timestamptz` | |
| `created_by` | `uuid` | FK to `auth.users` |

Row-level security is enabled. All queries are scoped to `current_org_id()`.

### `iris_events`

Stores raw events received from agents. Events remain with `processed = false` until the triage pipeline consumes them.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | Primary key |
| `agent_id` | `uuid` | FK to `iris_agents` |
| `org_id` | `uuid` | FK to `organizations` |
| `event_type` | `text` | Constrained to the six valid types |
| `severity` | `text` | `info`, `low`, `medium`, `high`, `critical` |
| `title` | `text` | Human-readable summary |
| `payload` | `jsonb` | Event-specific data |
| `received_at` | `timestamptz` | Set at insertion by the server |
| `processed` | `boolean` | `false` until triage has run |
| `scan_id` | `uuid` | FK to `scans`; filled when batched into a scan |

Indexes: `(agent_id, processed)` for pending-event queries; `(org_id, received_at desc)` for org-wide time-ordered queries.

---

## API endpoints

All endpoints are under `/api/iris`.

### Agent-authenticated endpoints

These use the `X-Iris-Key: irs_<token>` header. No JWT is required.

---

**`POST /api/iris/events`**

The primary endpoint the daemon calls. Stores a batch of events, updates the agent heartbeat, and triggers deterministic alerts for high-confidence threats.

Request body:
```json
{
  "agent_id": "<uuid>",
  "hostname": "web-01",
  "ip": "10.0.0.5",
  "events": [
    {
      "event_type": "auth_event",
      "severity": "high",
      "title": "Brute-force SSH from 1.2.3.4",
      "payload": { "subtype": "brute_force", "source_ip": "1.2.3.4" }
    }
  ]
}
```

Response: `202 Accepted`, `{"received": <count>}`.

---

**`GET /api/iris/ping`**

Connectivity and credential check. The daemon calls this with `--test-connection`.

Response: `200 OK`, `{"ok": true, "agent": "<name>", "agent_id": "<uuid>"}`.

---

### User-authenticated endpoints

These require a valid user session (Bearer JWT or `hrs_` API key).

---

**`POST /api/iris/agents/register`**

Register a new agent. Returns the `api_key` exactly once; it cannot be retrieved again.

Request body:
```json
{ "name": "prod-web-01", "asset_id": "<optional-uuid>" }
```

Response: `201 Created`
```json
{
  "agent_id": "<uuid>",
  "key_prefix": "irs_xxxxxxxx",
  "api_key": "irs_<full-token>"
}
```

---

**`GET /api/iris/agents`**

List all agents for the authenticated org, with pending and total event counts.

---

**`GET /api/iris/agents/{agent_id}/events`**

Return the most recent events for an agent (default limit 50, max 200).

---

**`DELETE /api/iris/agents/{agent_id}`**

Soft-delete an agent. Its events are preserved in the database and remain queryable.

---

**`POST /api/iris/agents/{agent_id}/process`**

Batch all pending events for an agent into a scan and submit it to the AI pipeline. Returns immediately; processing is asynchronous.

Response: `202 Accepted`, `{"scan_id": "<uuid>", "events_processed": <count>}`.

---

**`GET /api/iris/agents/{agent_id}/ai-analysis`**

Live read-only preview of what the AI triage analyst sees for this agent. Builds the same grouped summary and calls the LLM, but writes nothing to the database. The result is cached for 30 seconds to limit LLM calls under rapid UI polling.

Response includes the system prompt, the user prompt sent to the model, the raw model response, token counts, and the number of event groups analyzed.

---

### Public endpoints (no auth)

| Endpoint | Description |
|---|---|
| `GET /api/iris/install.sh` | Bash installer with the server URL pre-baked |
| `GET /api/iris/binary` | Compiled `horus-iris` binary (built at deploy time) |
| `GET /api/iris/package` | `iris-rs` source as `.tar.gz` (build-from-source fallback) |
| `GET /api/iris/uninstall.sh` | Uninstall script |

---

## Installation

### Requirements

- Linux (x86_64 or aarch64)
- systemd
- `auditd` (installed by the script if not present)
- Root privileges for install

### One-liner from the dashboard

The Horus dashboard shows a curl command that downloads the installer with the server URL pre-baked. Run it as root:

```bash
curl -sSL https://your-horus-server/api/iris/install.sh | sudo bash
```

The installer will:

1. Download the pre-built binary from `/api/iris/binary`, or build from source if `HORUS_URL` is not set.
2. Install the binary to `/usr/local/bin/horus-iris`.
3. Create `/etc/horus/iris.yaml` with placeholder values (skipped if the file already exists).
4. Create `/var/lib/horus/iris/` for the offline event queue.
5. Write audit rules to `/etc/audit/rules.d/horus.rules` and load them.
6. Install and reload the `horus-iris.service` systemd unit.
7. Remove the legacy Python install at `/opt/horus/iris/` if present.

### Build from source

```bash
git clone <repo>
cd iris-rs
cargo build --release
sudo cp target/release/horus-iris /usr/local/bin/horus-iris
```

Requires Rust 1.70+ (edition 2021). The release profile enables LTO and strips the binary.

### Post-install configuration

Edit `/etc/horus/iris.yaml` and set the three required fields:

```yaml
server_url: https://your-horus-server
api_key: irs_<key-from-dashboard>
agent_id: <uuid-from-dashboard>
```

The API key and agent UUID are obtained from **Settings > Iris Agents > Register agent** in the Horus dashboard. The key is shown only once.

### Enable and start

```bash
sudo systemctl enable --now horus-iris
```

### Verify connectivity

```bash
sudo horus-iris --test-connection
```

### Check status and logs

```bash
sudo systemctl status horus-iris
sudo journalctl -u horus-iris -f
```

### Offline queue location

When the server is unreachable, events are written to `/var/lib/horus/iris/queue.json`. Writes are atomic (write to `.json.tmp`, then rename). The queue is capped at 5,000 events; when the cap is reached, the oldest events are dropped. The maximum queue file size Iris will read on startup is 16 MiB; a larger file is discarded to protect the host from OOM on boot.

### Uninstall

```bash
curl -sSL https://your-horus-server/api/iris/uninstall.sh | sudo bash
```
