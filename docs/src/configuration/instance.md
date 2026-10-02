# Per-instance settings

Most configuration is cluster-shared: change a route on one node and
every node serves it. A handful of settings are not, because they
describe *this* machine — which addresses it binds, and which database
it reads the shared configuration from. Those live on the `instance`
resource.

An HA peer therefore has its own `instance` and shares everything else.

## The two databases

Sekisho distinguishes two databases:

- **Instance config DB** (`--instance-config` / `SEKISHO_INSTANCE_CONFIG`,
  default `/var/lib/sekisho/instance_config.db`): a per-instance SQLite
  file that is always opened. In single-node mode it also hosts the
  operational tables; in HA mode (a separate `SEKISHO_SERVICE_DB`) it
  stays config-only — the operational schema is never created here.
  Existing dev installs that were provisioned before 2.5c may still
  carry empty operational tables in this file; they are harmless.
- **Cluster (service) DB** (optional): where operational data —
  routes, IdPs, policies, config, sessions, certs, secrets, api_keys
  — actually lives. Accepts `postgres://…`, `postgresql://…` for a
  shared RDBMS (the HA topology), or a SQLite URL / path for a
  separate SQLite file (rarely useful). Set through the management
  API at `/instance` (encrypted at rest with the master key); on
  first boot the `SEKISHO_SERVICE_DB` environment variable is
  imported as a one-shot provisioning convenience. When unset, the
  per-instance SQLite doubles as the cluster DB — the single-node
  default.

Running HA means pointing every node's `SEKISHO_SERVICE_DB` at the same
Postgres while each node keeps its own `SEKISHO_INSTANCE_CONFIG` file.

## The fields

`show instance` prints the whole object. The fields are:

| Field               | Default        | Purpose                                                 |
|---------------------|----------------|---------------------------------------------------------|
| `cluster_db_url`    | `""`           | Where the shared operational data lives. Empty means the per-instance SQLite doubles as the cluster DB — the single-node default. Encrypted at rest. |
| `proxy_listen`      | `0.0.0.0:443`  | TLS proxy bind address.                                 |
| `api_listen`        | `""`           | An **additional** address for the management API. `127.0.0.1:9443` is always bound whatever this says, so leave it empty unless another interface has to reach the API. |
| `http_listen`       | `0.0.0.0:80`   | HTTP listener: ACME http-01 challenges and the redirect to HTTPS. Empty disables it. |
| `proxy_accept_from` | `""`           | Source-IP allow-list for the proxy listener. Empty means any source. |
| `api_accept_from`   | `""`           | Same, for the extra management API address. The always-on loopback bind is not filtered. |
| `http_accept_from`  | `""`           | Same, for the HTTP listener.                            |

Every one of these is read at startup, so a change takes effect on
restart — see [Restarts](#restarts) below.

### Source-IP allow-lists

Each listener can carry a comma-separated list of CIDRs or bare IPs.
A bare IP is widened to a host route in the canonical stored form, so
saving `10.0.0.5` and reloading displays `10.0.0.5/32`:

```
proxy_accept_from = "127.0.0.1/32,10.0.0.0/8"
api_accept_from   = "10.0.0.5"        # stored as 10.0.0.5/32
http_accept_from  = "::1/128,fe80::/10"
```

An empty list means "any source". There is no "deny all" value — bind
the listener to `127.0.0.1:<port>` if that is what you want.

Where the filter runs differs by listener, which matters when you are
reading logs. On the TLS proxy listener the check happens immediately
after `accept()` and before the handshake: the connection is closed with
no TLS round-trip and only a debug-level line, because once a scanner
finds the address the denial is high-volume by design. The HTTP listener
and the management API filter at the request layer instead.

## Editing it

`instance` is a configuration-mode resource like any other:

```text
sekisho@iap> configure
sekisho@iap# edit instance
sekisho@iap edit instance> set http-listen 0.0.0.0:80
sekisho@iap edit instance> commit
sekisho@iap edit instance> exit
sekisho@iap# exit
```

To clear a field rather than set it, use `unset`. `set` with no value is
a usage error, not a way to empty a field:

```text
sekisho@iap edit instance> unset http-listen
```

Clearing `http_listen` disables the HTTP listener, and with it ACME —
see [TLS and certificates](./tls.md).

## Restarts

Listener addresses and the cluster database URL are read at startup.
Committing a change stages it in the database; the running process keeps
its current sockets until it is restarted:

```bash
sudo systemctl restart sekishod
```
