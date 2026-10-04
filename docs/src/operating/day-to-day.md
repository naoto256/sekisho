# Operation

This chapter covers running Sekisho day-to-day on a Debian/Ubuntu
host: the systemd unit, where logs go, and how to back up state. When
something is actually broken, see [Troubleshooting](./troubleshooting.md).

## systemd

The `.deb` package ships `/usr/lib/systemd/system/sekishod.service`:

```ini
[Unit]
Description=Sekisho Identity-Aware Proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=sekisho
Group=sekisho
EnvironmentFile=-/etc/default/sekishod
UnsetEnvironment=SEKISHO_MASTER_KEY
LoadCredential=sekisho-master-key:/etc/sekisho/master-key
Environment=SEKISHO_MASTER_KEY_FILE=%d/sekisho-master-key
ExecStart=/usr/bin/sekishod --instance-config /var/lib/sekisho/instance_config.db
Restart=on-failure
RestartSec=5

# Graceful shutdown: sekishod drains HTTP, then WebSockets, then closes
# DB pools. If that has not finished after 90s it aborts itself, so
# TimeoutStopSec must stay at 90s or above — any lower and systemd
# sends SIGKILL before the daemon reaches its own deadline.
KillSignal=SIGTERM
TimeoutStopSec=90s

# Allow binding to privileged ports (443, etc.)
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# Security hardening
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
LockPersonality=yes

StateDirectory=sekisho
RuntimeDirectory=sekisho
ReadWritePaths=/var/lib/sekisho

StandardOutput=journal
StandardError=journal
SyslogIdentifier=sekishod

[Install]
WantedBy=multi-user.target
```

Notable choices:

- Runs as the unprivileged `sekisho` user.
- Binds privileged ports through `CAP_NET_BIND_SERVICE` rather than
  running as root.
- `ProtectSystem=strict` and `PrivateTmp=yes` mean the daemon sees
  its own private `/tmp` and cannot write outside `/var/lib/sekisho`
  and `/run/sekisho`. This affects how you collect debug dumps; see
  [Troubleshooting](./troubleshooting.md).

## Common commands

```bash
sudo systemctl status sekishod           # current state
sudo systemctl restart sekishod          # apply listener-related config changes
sudo journalctl -u sekishod -f           # follow logs
sudo journalctl -u sekishod --since today
sudo journalctl -u sekishod -p warning   # warnings and above
```

The packaged `sekisho-webui.service` is independent of the daemon because the
Web UI can manage a remote Sekisho host. If this host instead uses Web UI
`local_auth`, add the following with
`sudo systemctl edit sekisho-webui.service`:

```ini
[Unit]
Requires=sekishod.service
After=sekishod.service
PartOf=sekishod.service
```

After `sudo systemctl daemon-reload`, restart the Web UI. The drop-in makes a
daemon restart restart an active Web UI as well, renewing its in-memory
local-auth credential. Without it, restart the Web UI manually after the
daemon. A separate daemon stop followed by a later start leaves the Web UI
stopped even with the drop-in; systemd does not infer a reverse start
dependency.

## Environment file

`/etc/default/sekishod` (mode 0600, owned by root:root) holds runtime
environment settings. The master key is deliberately separate:
`LoadCredential=` copies `/etc/sekisho/master-key` into a protected,
read-only service credential and passes only its `%d/...` path to the daemon.
The key bytes never enter the daemon through an ordinary environment value.

```bash
# Optional overrides
SEKISHO_INSTANCE_CONFIG=/var/lib/sekisho/instance_config.db
SEKISHO_LOG_LEVEL=info
SEKISHO_LOG_FORMAT=json          # json (default) or text
SEKISHO_CONTROL_SOCKET=/run/sekisho/control.sock
SEKISHO_NODE_ID=proxy-a          # identity used for ACME leader election;
                                 # defaults to the OS hostname

# Listen addresses (proxy_listen / api_listen / http_listen) live in
# the per-instance SQLite, managed via
# `PATCH /instance`, or `configure` -> `edit instance` inside a
# `sekisho-cli` session (the shell has no one-shot subcommands). Defaults:
# proxy 0.0.0.0:443, api localhost-only, http 0.0.0.0:80.

# Operational database — leave unset to keep everything in the
# per-instance SQLite (single-node default). Point at a shared
# Postgres for HA:
# SEKISHO_SERVICE_DB=postgres://sekisho:<password>@db.example.com:5432/sekisho
```

## Encrypted secret format

Secrets stored at rest (cookie signing key, JWT signing key, OIDC client
secrets, TLS private keys, ACME account keys, session id_tokens) are
wrapped with XChaCha20-Poly1305. Two on-disk blob shapes ship today:

- **v2** (`0x02 || nonce(24) || ct+tag`) — KEK-direct. Used by
  `instance_config` (per-node, encrypts the service DB URL before
  the DEK ring is loadable) and the in-flight handoff token. The
  ring-routed columns hold v3 only; a v2 blob in one of them is
  rejected rather than KEK-decrypted.
- **v3** (`0x03 || key_id(1) || nonce(24) || ct+tag`) — DEK-routed
  via the `master_keys` ring. Every new write to a ring-routed
  column produces v3. The `key_id` byte lets the daemon decrypt with
  the right DEK without consulting the DB.

Operators don't have to reason about the formats; standard API calls
read and write transparently. To rotate the underlying DEK without
touching the master-key credential, and for KEK compromise response,
see [Encryption keys](./encryption-keys.md).

## Backups

In the single-node default everything Sekisho knows is in
`/var/lib/sekisho/instance_config.db` plus the master-key credential in
`/etc/sekisho/master-key`. To back up:

```bash
# Hot copy via SQLite's online backup (safe with WAL mode):
sudo sqlite3 /var/lib/sekisho/instance_config.db ".backup '/var/backups/sekisho-$(date +%F).db'"

# And the master-key credential:
sudo cp /etc/sekisho/master-key /var/backups/sekisho-master-key-$(date +%F)
```

Restoring requires both files. The database without the master key
is mostly opaque (encrypted secrets cannot be decrypted; routes,
IdPs minus client secrets, and config are still readable).

When `SEKISHO_SERVICE_DB` points at a shared Postgres, operational
state lives there instead — back up via `pg_dump`. The instance config
SQLite still needs the same treatment on each node: it is small,
but it holds the encrypted `cluster_db_url` pointer and any future
per-instance config state.

## Health and metrics

| Endpoint                   | Auth      | Returns                                |
|----------------------------|-----------|----------------------------------------|
| `GET /health`              | none      | `{"status":"ok"}` as long as the daemon is listening. Suitable for a liveness probe. |
| `GET /healthz`             | none      | Alias of `/health` using the Kubernetes / Docker convention. Instant `200 {"status":"ok"}`, no DB dependency. |
| `GET /ready`               | none      | `200 {"status":"ready"}` when the service DB was reachable at boot; `503 {"status":"degraded", ...}` when the daemon booted but could not reach its service DB. |
| `GET /readyz`              | none      | Stricter readiness probe for k8s / Docker HEALTHCHECK. Returns `200 {"status":"ready"}` only when all of: the service DB answers a live `SELECT 1`, a valid route generation is current, the cert cache has completed its initial load, and graceful shutdown has not been signalled. Returns `503 {"status":"not_ready"}` otherwise — body is deliberately opaque; diagnose via logs / metrics, not probe output. |
| `GET /metrics`             | none      | Prometheus exposition format. See [Metrics](#metrics) below for the metric set and the recommended scrape topology. |

All are on the management API port (`127.0.0.1:9443` by default,
plus any additional address set via `instance.api_listen`). The public
proxy port never serves these: exposing liveness / readiness on the
public side would let unauthenticated callers fingerprint the daemon
and its subsystems.

### Metrics

Sekisho exposes Prometheus-format metrics on
`/.sekisho/api/v1/metrics` (mgmt port only, no auth). The endpoint
follows the standard `text/plain; version=0.0.4` exposition format,
so any Prometheus-compatible agent can scrape it as-is.

The metric set is intentionally low-cardinality. Per-user and
per-session labels are never emitted; route ids and IdP ids are the
highest-cardinality labels you will see, and both are bounded by
configuration.

| Metric                                       | Type      | Labels                  | Use |
|----------------------------------------------|-----------|-------------------------|-----|
| `sekisho_proxy_requests_total`               | counter   | route, status           | RPS, error rate per route. Unmatched traffic is bucketed under `route="_unrouted"`. |
| `sekisho_proxy_response_headers_duration_seconds` | histogram | route, status           | Request start through response headers, including upstream selection and response-header latency. |
| `sekisho_proxy_response_body_duration_seconds` | histogram | route, status, outcome  | Response headers through EOF, body error, or downstream drop. `outcome` is exactly one of `eof`, `error`, or `dropped`. |
| `sekisho_proxy_upstream_errors_total`        | counter   | route, kind             | `kind` ∈ {`timeout`, `route_client_build`, `upstream_send`}. |
| `sekisho_proxy_policy_denied_total`          | counter   | route, reason           | Policy-deny path; reason currently `policy_deny` (will subdivide as the DSL surfaces structured failure). |
| `sekisho_auth_login_total`                   | counter   | idp_id, kind, result    | `kind` ∈ {`oidc`, `saml`}; `result` ∈ {`success`, `failure`}. Login attempts that never reach IdP context get `idp_id="unknown"`. |
| `sekisho_auth_logout_total`                  | counter   | kind                    | `kind` ∈ {`idp_redirect`, `local_only`, `saml_slo`}. |
| `sekisho_session_active`                     | gauge     | —                       | Process-local active session count. Resets to 0 on restart; for an authoritative number query the DB. |
| `sekisho_session_create_total`               | counter   | —                       | Cumulative session creates. |
| `sekisho_session_revoke_total`               | counter   | —                       | Cumulative session revocations. |
| `sekisho_session_access_update_total`        | counter   | result                  | `result` ∈ {`persisted`, `skipped`}. `skipped / (persisted + skipped)` is the coalescing hit rate — high values mean the `last_accessed_at` write storm is being absorbed in-process. |
| `sekisho_ws_active`                          | gauge     | —                       | Active WebSocket tunnels. RAII-decremented, so the count cannot leak on tunnel error. |
| `sekisho_ws_tunnels_total`                   | counter   | route, result           | Tunnel starts; `result="started"` today (`closed` / `error` may be added later). |
| `sekisho_control_budget_in_flight`            | gauge     | budget                  | Process-local permits or reservations currently in use. `budget` is exactly one of `proxy_http`, `proxy_websocket`, `management`, `probe`, or `challenge`. |
| `sekisho_control_budget_limit`                | gauge     | budget                  | Process-local limit for the same five budget labels. |
| `sekisho_control_budget_rejected_total`       | counter   | budget                  | Immediate rejections observed by this process. `budget` is exactly one of `proxy_websocket`, `probe`, `challenge`, or `acme_queue`; the queue label counts only new-domain `Full` outcomes returned to this process. |
| `sekisho_acme_queue_active`                   | gauge     | —                       | Cluster-wide active queue rows (`pending` plus all `in_progress`, including rows old enough to be recycled by a later picker). |
| `sekisho_acme_queue_capacity`                 | gauge     | —                       | Live cluster-wide active-row capacity from `GlobalConfig`; a database with no persisted config row reports the default `1000` without writing it. |
| `sekisho_acme_issuance_in_progress`           | gauge     | —                       | Cluster-wide durable `in_progress` rows that the next picker would count after excluding stale rows. The scrape does not recycle them. |
| `sekisho_acme_issuance_limit`                 | gauge     | —                       | Startup queue-worker limit for the scraped target. Nodes can report different values during a rolling restart; this is not a single effective-leader or cluster-wide limit. |
| `sekisho_acme_issuance_total`                | counter   | result                  | `result` ∈ {`success`, `failure`}. |
| `sekisho_cert_cache_reloads_total`           | counter   | —                       | Cert cache reloads. The `trigger` (peer bump / explicit / boot) is in the audit log, not on this metric. |
| `sekisho_cert_expiry_seconds`                | gauge     | domain                  | Signed seconds until expiry. Alert on `< 7*86400` for renew-imminent without computing `now` in PromQL. |
| `sekisho_build_info`                         | gauge     | version, git_commit     | Always `1`. Standard pattern for filtering dashboards by build. |

Three of the four durable ACME gauges — queue active, queue capacity, and
issuance in_progress — come from one read-only service-database statement per
scrape. The target-local startup issuance limit is appended to the same
response block only after that snapshot succeeds. If the backend is
unavailable, the query fails, or the persisted global configuration cannot be
decoded, the endpoint still returns HTTP 200 with the existing process metrics
but omits all four durable metric families together. Their absence therefore
means that the durable snapshot was unavailable, not that its values were
zero; PromQL's `absent()` can distinguish that state. The endpoint does not
emit `NaN`, cached values, or synthetic zeroes. It adds no outer query
timeout: backend pool-acquisition and lock settings plus caller cancellation
remain the only bounds, and no total query deadline is claimed.

Issuance staleness uses the scraped node's clock and the same ten-minute cutoff
as its queue worker. Around the cutoff, clock skew can make two node-local
scrapes temporarily disagree. The durable row count also does not claim that an
external ACME call is exactly-once before lease fencing exists.

#### Scrape topology

The mgmt port is loopback-bound by default, which is the right
posture for this metric — it is unauthenticated, and the trust
boundary is the host. To get metrics into a remote Prometheus,
run a local agent on each Sekisho node that scrapes 127.0.0.1
and `remote_write`s outbound:

```
┌─ proxy-a ─────────────────────┐         ┌─ central ─────────┐
│ sekishod  → 127.0.0.1:9443   │         │                   │
│   /.sekisho/api/v1/metrics   │ ◀ scrape│  Prometheus /     │
│         ▲                    │         │  Mimir /          │
│         │                    │  remote_│  VictoriaMetrics  │
│   grafana-agent / vmagent    │ write ▶ │                   │
└──────────────────────────────┘         └───────────────────┘
```

Recommended agents:

- **grafana-agent** / **alloy** — Grafana stack
- **vmagent** — VictoriaMetrics
- **otel-collector** — if you are standardising on OTel

The management listener uses an Ed25519 TLS raw public key rather than X.509.
Only use a collector whose TLS stack supports RFC 7250 and configure the
canonical pin obtained with `sekishod --print-management-rpk`. A collector
that supports only CA certificates cannot scrape this endpoint directly; do
not replace pin verification with an insecure TLS mode.

If you must scrape Sekisho directly from a remote Prometheus
(skipping the local agent), you have to expose the mgmt port beyond
loopback. In that case it is your responsibility to put the port
behind a network ACL / mTLS — Sekisho's metric endpoint itself does
not authenticate the caller, by design.

### Container HEALTHCHECK

For Docker:

```dockerfile
ENV SEKISHO_MANAGEMENT_RPK_PIN=sekisho-rpk-v1:ed25519:<base64url-SPKI-DER>
HEALTHCHECK --interval=10s --timeout=3s --start-period=30s --retries=3 \
  CMD sekisho-cli --healthz https://127.0.0.1:9443
```

For Kubernetes:

```yaml
livenessProbe:
  exec:
    command: ["sekisho-cli", "--healthz", "https://127.0.0.1:9443"]
  periodSeconds: 10
  timeoutSeconds: 3
readinessProbe:
  exec:
    command: ["sekisho-cli", "--healthz", "https://127.0.0.1:9443"]
  periodSeconds: 5
  timeoutSeconds: 3
```

Inject `SEKISHO_MANAGEMENT_RPK_PIN` into the probe container from an
out-of-band-managed Secret. `sekisho-cli --healthz` verifies the exact RPK,
wraps the `/readyz` call, and exits `0` on ready / `1` otherwise.

### Degraded mode

When `SEKISHO_SERVICE_DB` points at a database the daemon cannot reach
at startup, Sekisho does _not_ fail to start. Instead:

- `/health` continues to return `200` (daemon is alive).
- `/ready` returns `503` (daemon is not serving traffic).
- Every operational request (`/routes`, `/idps`, `/sessions`, …)
  returns `503 SERVICE_UNAVAILABLE` with
  `{"error": {"code": "SERVICE_UNAVAILABLE", "message": "…"}}`.
- `/instance` stays reachable, so the operator can correct the DSN
  and restart:

  ```bash
  # from a host with local access to the daemon — the control
  # socket only accepts the sekishod service user, so run as that
  # user explicitly (root is rejected by SO_PEERCRED):
  export SEKISHO_MANAGEMENT_RPK_PIN="$(sudo -u sekisho sekishod --print-management-rpk)"
  sudo -u sekisho sekisho-cli --local-auth
  sekisho@iap> show instance
  sekisho@iap> configure
  sekisho@iap# edit instance
  sekisho@iap edit instance> set cluster-db-url postgres://…
  sekisho@iap edit instance> commit
  sekisho@iap edit instance> exit
  sekisho@iap# exit
  # then:
  sudo systemctl restart sekishod
  ```

There is no auto-reconnect: a daemon that boots into degraded mode
stays degraded until restarted. This is deliberate — the failure
mode we care about is "operator typo in the DSN" or "Postgres is
really down", and silently reconnecting would hide either. Fix and
restart.

## Inspecting the runtime

The `sekisho-cli` shell, used in `--local-auth` mode, requires no API
key — it uses a Unix socket challenge to prove local access:

```bash
export SEKISHO_MANAGEMENT_RPK_PIN="$(sudo -u sekisho sekishod --print-management-rpk)"
sudo -u sekisho sekisho-cli --local-auth
```

> The control socket at `/run/sekisho/control.sock` is mode `0660`
> and owned by the `sekisho` group, but the daemon additionally
> checks `SO_PEERCRED` and rejects any peer whose UID is not its
> own. **Do not add non-privileged users to the `sekisho` group**:
> the group is a safety net for files the daemon writes, not an
> admin group. Only the `sekisho` daemon user itself can redeem a
> challenge — `root` is rejected by the UID check just like any
> other user, so use `sudo -u sekisho` rather than plain `sudo`.
>
> The management pin is public but trust-sensitive. Distribute it through an
> authenticated channel; the clients have no TOFU or insecure fallback.

Useful read-only commands:

```text
sekisho@iap> show config
sekisho@iap> show route
sekisho@iap> show idp
sekisho@iap> show certificate
sekisho@iap> show session
sekisho@iap> show api-key
```

`show route` also prints each route's enable status
(`enabled` / `disabled`). Flip individual routes with
`enable route <name>` / `disable route <name>`.

`show session` follows paginated responses (`limit=100`, starting `offset=0`) until `has_more` is false.

## Upgrading

`sekishod`, `sekisho-cli`, and `sekisho-webui` are released together and
should normally be upgraded together. Product-version skew is allowed with a
warning; management API-version skew is rejected. Read the release notes for
version-specific steps. In an HA deployment, upgrade one node at a time and
confirm that it is ready before moving to the next node.

## Restart costs

Most config changes take effect immediately:

- Routes, IdPs, certificates, API keys, sessions, policies: live reload.
  Route mutations synchronously withdraw the old route generation before the
  API response, then rebuild in the background; the mutation response does not
  wait for refresh completion. A database observation error fails readiness
  immediately and permits a previous valid route generation for less than 30
  seconds only. Invalid route data and intentional local mutations have no
  grace period.

These require a restart:

- Listener addresses (`instance.proxy_listen` / `api_listen` / `http_listen`).
- the `/etc/sekisho/master-key` service credential (clearly).
- `acme_issuance_concurrency_limit` and `acme_renewal_scan_interval_hours`.
- `--no-tls` and other CLI-only flags.

`acme_queue_capacity` is live. Lowering it below the current number of
pending plus in-progress rows admits no new domains until the queue drains;
deduplicated requests for an already-active domain still return that row.

## Proxy limits

The proxy layer ships with conservative in-process DoS guards:

- Request body cap: **10 MiB**. Bodies above this are rejected with
  `413 Payload Too Large`.
- Concurrency cap: **500 in-flight proxied requests**. A request
  arriving over the cap is not refused — it waits for a slot and is
  served when one frees. There is no timeout on that wait, and the
  cap does not turn overload into `503`s: sustained overload shows up
  as latency. A slot is held until the response body reaches EOF,
  errors, or the client goes away — not merely until the upstream
  replies — so slow readers occupy slots too.

  There is no separate queue-wait metric. The wait is included in
  `sekisho_proxy_response_headers_duration_seconds`, so saturation
  appears as that histogram shifting right, and
  `sekisho_control_budget_in_flight` against
  `sekisho_control_budget_limit` for the `proxy_http` budget shows how
  close to the cap the process is running.

  WebSocket upgrades behave the opposite way: over
  `websocket_concurrency_limit` an upgrade is refused immediately with
  `503` rather than queued, because a tunnel is long-lived and there is
  no honest estimate of how long a wait would be.

These are sensible defaults for a jump-host proxy. Both are fixed at
build time: neither has a runtime setting, and no configuration value
raises them, so a deployment that regularly serves larger uploads or
higher concurrency needs a custom build of Sekisho. Per-route
concurrency is a different matter and is configured normally, with
`concurrency_limit`; per-client limits are a planned follow-up.
