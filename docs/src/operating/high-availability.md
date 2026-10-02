# High Availability

Sekisho runs as a stateless proxy on each node and delegates all shared
state to one database that every node reads and writes. That is the
whole of what the product requires.

## What Sekisho requires, and what it does not

Sekisho itself asks for two things from an HA deployment:

- **Every node points at the same service database.** Set
  `cluster_db_url` on each node's `instance` resource to the same
  PostgreSQL. Each node keeps its own per-instance SQLite for the
  settings that describe that machine — see
  [Per-instance settings](../configuration/instance.md).
- **Certificate issuance has a single owner.** Only the elected leader
  runs ACME orders, because Let's Encrypt rate-limits per FQDN and two
  nodes racing the same order burns the quota. Election is automatic
  unless `acme_leader` pins a node.

One consequence is worth stating plainly: **cross-node guarantees hold
only when the shared database is PostgreSQL.** Cross-host session
handoff tokens are single-use because redeeming one inserts its nonce
into a uniquely-constrained table that every node shares. With a SQLite
service database that table is node-local, so the single-use property
is local to that node — SQLite is a single-node configuration.

Sekisho does not require, ship, or manage a cluster manager. How you
make one PostgreSQL highly available is your choice.

## A reference topology

The rest of this page describes one arrangement that the project uses:
Patroni for PostgreSQL primary election, etcd as Patroni's lock store,
and a node-local HAProxy so Sekisho always connects to whichever
PostgreSQL is currently writable. It is written out concretely for
Ubuntu 24.04 with stock packages.

Treat it as a worked example rather than a requirement. Any setup that
presents one writable PostgreSQL endpoint to every node satisfies what
Sekisho asks for.

## Topology

```
+----------+   +----------+       +-------------+
|  proxy-a  |   |  proxy-b  |       |  arbiter  |
|          |   |          |       |             |
| sekishod |   | sekishod |       |    etcd     |
|sekisho-webui |   |sekisho-webui |       | (quorum 3rd)|
|  haproxy |   |  haproxy |       |             |
|  etcd    |   |  etcd    |       +-------------+
|  patroni |   |  patroni |
|    PG    |   |    PG    |
+----------+   +----------+
```

- **proxy-a / proxy-b**: identical nodes running the full Sekisho
  stack plus Patroni-managed PostgreSQL. Exactly one is the
  PostgreSQL primary at any time; the other streams as an
  asynchronous replica.
- **arbiter**: runs only etcd. It exists so the etcd cluster has
  three members and can survive the loss of either proxy node
  without losing quorum. It holds no PostgreSQL data and is not
  reachable from the public internet.
- Private network `192.0.2.0/24` carries the etcd peer traffic,
  PostgreSQL replication, and HAProxy health checks. The public
  IAP traffic lands on the proxy nodes' Sekisho interface
  (`198.51.100.0/24` in the reference setup).

## Components and Roles

| Component  | Role                                                                                  | Hosts            |
|------------|---------------------------------------------------------------------------------------|------------------|
| etcd       | Distributed lock + config store used by Patroni (leader election, cluster state).     | proxy-a, proxy-b, arbiter |
| Patroni    | Supervises PostgreSQL: runs `initdb` / `pg_basebackup`, elects leader, writes `pg_hba`/`postgresql.conf`, promotes/demotes on failover. | proxy-a, proxy-b   |
| PostgreSQL | Sekisho's operational data (routes, policies, IdPs, sessions, certificates, audit).    | proxy-a, proxy-b   |
| HAProxy    | Node-local TCP forwarder to whichever PostgreSQL is currently primary. Polls Patroni's REST API for health. | proxy-a, proxy-b   |
| sekishod / sekisho-webui | Stateless; connect to `127.0.0.1:5433` (the local HAProxy).                 | proxy-a, proxy-b   |

## Why HAProxy?

Sekisho takes a **single** PostgreSQL endpoint. Its DSN names one
host, and it does not try several and pick the writable one. To keep
that DSN valid while still surviving a primary flip, the reference
topology pushes primary-selection one layer down: each node runs an
HAProxy that listens on `127.0.0.1:5433` and only marks a backend
"up" when Patroni's `/primary` REST endpoint returns 200 on that
backend. Sekisho's DSN is therefore the trivial
`postgres://sekisho:…@127.0.0.1:5433/sekisho` — the HAProxy layer
hides which physical node is writable today.

If Sekisho ever accepts several endpoints and selects the writable
one itself, this layer becomes optional, at the cost of losing the
flexibility to expose secondary endpoints (read-only reads directed
at the replica, etc.) the same way.

## Replication Mode

The reference setup uses **asynchronous** streaming replication.
Reasoning:

- `sekisho`'s write workload is small (session last-accessed bumps,
  route CRUD, audit events). Commit latency matters for UX, so the
  primary should not wait on replica acks.
- A **clean shutdown** of the primary (`systemctl stop patroni`,
  OS reboot for patches, etc.) flushes all outstanding WAL to the
  replica as part of the shutdown checkpoint — that is, async does
  **not** mean "lose the last second of traffic during a reboot".
  Data loss is only possible if the primary dies abruptly (kernel
  panic, power loss) before the replica received the latest WAL.
- Planned reboots are the dominant downtime source (daily OS patch
  window, typically staggered an hour apart across the two nodes).
  For this pattern, async + Patroni auto-failover is enough.

Switch to synchronous replication by setting Patroni's
`synchronous_mode: true` in the DCS config if the workload justifies
the commit-latency / single-standby-block trade-off.

## Setup

The steps below assume two fresh proxy nodes running Ubuntu
24.04 with sudo access and a third small VM for `arbiter`. The
reference setup also assumes you already have single-node Sekisho
running on `proxy-a` with a local PostgreSQL you want to keep
(this guide takes the existing data over into the Patroni-managed
cluster rather than starting from empty).

### 1. etcd

Install etcd on all three nodes:

```bash
sudo apt-get install -y etcd-server etcd-client
```

On Ubuntu the service runs as `etcd` and reads `/etc/default/etcd`.
Stop the auto-started single-node daemon, wipe its data, and replace
the config with the cluster form. Example for `proxy-a`
(`192.0.2.254`):

```bash
sudo systemctl stop etcd
sudo rm -rf /var/lib/etcd/default
sudo tee /etc/default/etcd >/dev/null <<'CFG'
ETCD_LISTEN_CLIENT_URLS=http://192.0.2.254:2379,http://127.0.0.1:2379
ETCD_ADVERTISE_CLIENT_URLS=http://192.0.2.254:2379
ETCD_LISTEN_PEER_URLS=http://192.0.2.254:2380
ETCD_INITIAL_ADVERTISE_PEER_URLS=http://192.0.2.254:2380
ETCD_INITIAL_CLUSTER=proxy-a=http://192.0.2.254:2380,proxy-b=http://192.0.2.253:2380,arbiter=http://192.0.2.252:2380
ETCD_INITIAL_CLUSTER_TOKEN=sekisho-ha-etcd
ETCD_INITIAL_CLUSTER_STATE=new
CFG
sudo systemctl daemon-reload
```

Write the equivalent file on `proxy-b` and `arbiter`, adjusting
only the three `*_URL` values to the local IP. Start the three
daemons concurrently:

```bash
for h in proxy-a proxy-b arbiter; do
  ssh "$h" 'sudo systemctl start etcd' &
done; wait
```

Verify:

```bash
etcdctl --endpoints=http://192.0.2.254:2379 member list
```

All three members should print `started`. No TLS is configured —
the peer and client traffic stays on the private segment. Add TLS
if your network assumption differs.

### 2. PostgreSQL and Patroni (both proxy nodes)

```bash
sudo apt-get install -y postgresql-16 postgresql-contrib-16 patroni python3-psycopg2
```

The PostgreSQL package auto-initialises a single-node cluster
under `/var/lib/postgresql/16/main`. Keep that on `proxy-a` (it
holds the existing data) and **wipe** it on `proxy-b` (Patroni
will re-populate it via `pg_basebackup`). Disable and mask the
stock systemd unit on both nodes so nothing competes with Patroni
for control of the process:

```bash
sudo systemctl stop postgresql@16-main 2>/dev/null || sudo systemctl stop postgresql
sudo systemctl disable postgresql@16-main postgresql
sudo systemctl mask postgresql@16-main
```

On `proxy-b` only:

```bash
sudo rm -rf /var/lib/postgresql/16/main
sudo mkdir -p /var/lib/postgresql/16/main
sudo chown postgres:postgres /var/lib/postgresql/16/main
sudo chmod 700 /var/lib/postgresql/16/main
```

#### Patroni config

Ubuntu's `patroni.service` reads `/etc/patroni/config.yml`. A
minimal config that matches the topology above (substitute the
local IP in `name`, `restapi.*`, `postgresql.connect_address`):

```yaml
scope: sekisho-ha
namespace: /db/
name: proxy-a

restapi:
  listen: 192.0.2.254:8008
  connect_address: 192.0.2.254:8008

etcd3:
  hosts: 192.0.2.254:2379,192.0.2.253:2379,192.0.2.252:2379

bootstrap:
  dcs:
    ttl: 30
    loop_wait: 10
    retry_timeout: 10
    maximum_lag_on_failover: 1048576
    postgresql:
      use_pg_rewind: true
      parameters:
        wal_level: replica
        hot_standby: 'on'
        max_wal_senders: 10
        max_replication_slots: 10
        wal_log_hints: 'on'
  pg_hba:
    - local all all peer
    - host all all 127.0.0.1/32 scram-sha-256
    - host all all ::1/128 scram-sha-256
    - host all all 192.0.2.0/24 scram-sha-256
    - host replication replicator 192.0.2.0/24 scram-sha-256

postgresql:
  listen: 0.0.0.0:5432
  connect_address: 192.0.2.254:5432
  data_dir: /var/lib/postgresql/16/main
  bin_dir: /usr/lib/postgresql/16/bin
  pgpass: /var/lib/postgresql/.pgpass_patroni
  authentication:
    replication:
      username: replicator
      password: "…generate and keep in sync across nodes…"
    superuser:
      username: postgres
      password: "…generate and keep in sync across nodes…"
    rewind:
      username: postgres
      password: "…same as superuser above…"
  parameters:
    unix_socket_directories: '/var/run/postgresql'

tags:
  nofailover: false
  noloadbalance: false
  clonefrom: false
  nosync: false
```

Ubuntu's PostgreSQL keeps its config under `/etc/postgresql/16/main/`
rather than inside `data_dir`. Patroni expects `postgresql.conf` to
live inside `data_dir` (it rewrites it in-place on start). On
`proxy-a`, before starting Patroni for the first time, copy the
three config files and create an empty `conf.d` directory so
Patroni's initial rewrite doesn't trip on the `include_dir`
directive the Ubuntu config file ends with:

```bash
for f in postgresql.conf pg_hba.conf pg_ident.conf; do
  sudo -u postgres cp /etc/postgresql/16/main/$f /var/lib/postgresql/16/main/$f
done
sudo -u postgres mkdir -p /var/lib/postgresql/16/main/conf.d
```

Before starting Patroni on `proxy-a`, set a password on the
`postgres` superuser and create a `replicator` user — Patroni's
config only applies `bootstrap.pg_hba` on fresh clusters, so a
takeover of existing data needs the users to pre-exist:

```bash
sudo -u postgres psql <<SQL
ALTER USER postgres WITH PASSWORD '<superuser_pw>';
CREATE USER replicator WITH REPLICATION PASSWORD '<replicator_pw>';
SQL
```

Also append the HA entries to `pg_hba.conf` by hand on `proxy-a` —
Patroni will not overwrite `pg_hba` on takeover, and the Ubuntu
default has no entries for replication from other hosts:

```bash
sudo -u postgres tee -a /var/lib/postgresql/16/main/pg_hba.conf >/dev/null <<'HBA'

# HA replication
host    replication     replicator      192.0.2.0/24   scram-sha-256
host    all             all             192.0.2.0/24   scram-sha-256
HBA
```

#### Bring Patroni up

Start on `proxy-a` first — it has the existing data and will
promote itself to leader once it sees an empty etcd namespace:

```bash
sudo systemctl enable --now patroni
sudo patronictl -c /etc/patroni/config.yml list
```

Expected output (`proxy-a` as leader, no replicas yet):

```
+ Cluster: sekisho-ha (…) ---------+----+-----------+
| Member | Host         | Role   | State   | TL | Lag in MB |
+--------+--------------+--------+---------+----+-----------+
| proxy-a | 192.0.2.254 | Leader | running |  2 |           |
+--------+--------------+--------+---------+----+-----------+
```

Then start Patroni on `proxy-b`. With the data dir empty, Patroni
runs `pg_basebackup` against the current leader and begins
streaming:

```bash
sudo systemctl enable --now patroni
```

Re-run `patronictl list` on either node until the state reads
`streaming` and `Lag in MB` is `0`.

### 3. HAProxy (both proxy nodes)

```bash
sudo apt-get install -y haproxy
```

Replace `/etc/haproxy/haproxy.cfg` on both nodes with the config
below. It's identical on both nodes — HAProxy queries the Patroni
REST API (`/primary`: returns 200 if the backend is the current
primary, 503 otherwise) and only routes to the 200-returning node:

```
global
    maxconn 100
    log /dev/log local0
    log /dev/log local1 notice

defaults
    log global
    mode tcp
    retries 2
    timeout client 30m
    timeout connect 4s
    timeout server 30m
    timeout check 5s

listen sekisho-pg-rw
    bind 127.0.0.1:5433
    option httpchk GET /primary
    http-check expect status 200
    default-server inter 3s fall 3 rise 2 on-marked-down shutdown-sessions
    server proxy-a 192.0.2.254:5432 maxconn 100 check port 8008
    server proxy-b 192.0.2.253:5432 maxconn 100 check port 8008

listen stats
    mode http
    bind 127.0.0.1:7000
    stats enable
    stats uri /
    stats refresh 5s
```

Validate and start:

```bash
sudo haproxy -c -f /etc/haproxy/haproxy.cfg
sudo systemctl restart haproxy
```

Confirm the backend state (the primary should show `UP`, the
replica `DOWN`):

```bash
curl -s 'http://127.0.0.1:7000/;csv' | awk -F, '/sekisho-pg-rw,proxy-/ {print $1, $2, $18}'
```

### 4. sekishod / sekisho-webui

With Patroni + HAProxy in place, each node's Sekisho connects to
its local HAProxy. Install the same 64-hex master key at
`/etc/sekisho/master-key` on both nodes, then point the DSN at
`127.0.0.1:5433` in `/etc/default/sekishod`:

```
SEKISHO_INSTANCE_CONFIG=/var/lib/sekisho/instance_config.db
SEKISHO_SERVICE_DB=postgres://sekisho:<pw>@127.0.0.1:5433/sekisho
SEKISHO_LOG_LEVEL=info
```

Listen addresses (proxy / management-API / HTTP-redirect) are
configured via `PATCH /instance` per-node, not env. Defaults are
`0.0.0.0:443` for the proxy and `0.0.0.0:80` for HTTP; the
management API is localhost-only out of the box. Each peer in HA
sets its own values if it needs to bind to a specific NIC.

The master-key credential must be identical across both nodes —
every operational secret that moves through PostgreSQL (cookie
signing key, JWT signing key, ACME account key, TLS private keys,
the encrypted `cluster_db_url`) is encrypted with it. The sekisho
user's password is stored in the DSN and rotated with a plain
`ALTER USER sekisho WITH PASSWORD 'newpw'` on the primary; it
replicates to the standby automatically.

`SEKISHO_SERVICE_DB` is imported into the encrypted
`instance_config` on **first boot only**: once the row is
populated, later changes to the env variable are logged and
ignored, and the DSN must be updated via the management API
(`PATCH /.sekisho/api/v1/instance`). To rebuild a node from a
clean state, stop Sekisho, remove `/var/lib/sekisho/instance_config.db*`,
set the env, and start again.

Enable the units:

```bash
sudo systemctl enable --now sekishod sekisho-webui
```

Both nodes should now show the same routes / policies / etc. via
`sekisho-cli` or `sekisho-webui`, because they all read the same
(Patroni-managed) PostgreSQL.

## Verifying a Failover

Force a leader switch from `proxy-a` to `proxy-b`:

```bash
sudo patronictl -c /etc/patroni/config.yml \
    switchover --leader proxy-a --candidate proxy-b --force
```

- `patronictl list` on either node should show `proxy-b` as Leader
  with an incremented timeline (`TL`), and `proxy-a` streaming as
  Replica with `Lag in MB: 0`.
- HAProxy stats on both nodes should flip: `proxy-b` reads `UP`,
  `proxy-a` reads `DOWN`, within one `inter` interval (~3–10 s).
- `sudo systemctl is-active sekishod sekisho-webui` remains `active` on
  both nodes. Existing in-flight connections to the old primary
  are reset by HAProxy's `on-marked-down shutdown-sessions`, and
  Sekisho reconnects through HAProxy to the new primary on the
  next query.
- `show route` via `sekisho-cli --local-auth` on both nodes returns
  the same list as before.

Switch back to confirm bidirectional failover:

```bash
sudo patronictl -c /etc/patroni/config.yml \
    switchover --leader proxy-b --candidate proxy-a --force
```

A planned OS patch reboot on the primary is fine to do with or
without a prior switchover — `systemctl stop patroni` shuts
PostgreSQL down cleanly, which flushes all WAL to the replica
before the service exits. `patronictl switchover` before the
reboot buys a second or two of continuous-writes by avoiding the
~30 s leader lock TTL, but nothing more.

## Per-node state that is **not** replicated

- `/var/lib/sekisho/instance_config.db` — SQLite, each node's own encrypted
  `cluster_db_url`.
- `/etc/sekisho/master-key` — must be the same byte-for-byte on every
  node, but it lives on each node's local filesystem and is loaded through a
  systemd service credential, not the shared database. Lose the
  master key on a node and everything that node reads from
  PostgreSQL becomes undecryptable gibberish.
- HAProxy / Patroni / etcd configuration — mostly identical across
  nodes, with the obvious per-node `name` / `listen` / `IP`
  substitutions.

Everything else — routes, policies, IdPs, sessions, certificates
(including operator-uploaded ones; the private key is encrypted
with the master key before being written to
the `certificates` table), API keys, global config, audit — lives
in the shared PostgreSQL and is streamed to the replica via
Patroni.
