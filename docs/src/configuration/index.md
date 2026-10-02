# Configuration

Sekisho has no configuration files. Every runtime setting lives in a
database. You change it from a terminal with the `sekisho-cli` shell,
or in a browser with the web UI that `sekisho-webui` serves.

Two databases are involved. Node-local settings — bind addresses above all —
live in a per-instance SQLite file that every node always has. Everything
else lives in the cluster database, which is that same SQLite file in the
single-node default and a shared PostgreSQL in HA. See
[Per-instance settings](./instance.md).

There are five top-level configuration objects:

| Object                             | Cardinality | Purpose                                                  |
|------------------------------------|-------------|----------------------------------------------------------|
| [Global Config](./global.md)       | Singleton   | Cluster-wide: auth domain, cookie name, session lifetime, ACME settings. |
| [Per-instance Settings](./instance.md) | Singleton per node | Node-local: `proxy_listen`, `api_listen`, `http_listen`, their source ACLs, and the cluster DB pointer. Managed through `/instance`. |
| [Routes](./routes.md)              | 0..N        | One per hostname/path served by the proxy.               |
| [Identity Providers](./idps.md)    | 0..N        | OIDC and SAML IdP definitions referenced by routes.      |
| [Policies](./policies.md)          | 0..N        | Named boolean expressions referenced by routes for authorization. |

Listen addresses are **not** in Global Config. They are per-node, so an HA
peer can bind its own address; putting them in the shared object would force
every node to agree on one.

Three operational object types are also exposed through the same API but are
not authored by hand: **sessions**, **certificates**, and
[**API keys**](./api-keys.md).

## Changing things

Everything on this page is edited with `sekisho-cli` or the web UI, and
both are covered where each object is described. Neither needs you to
know anything about HTTP.

If you are automating instead — CI that publishes a route, a script
that rotates a key — the same objects are reachable over the management
API, documented in
[Management API](../design/management-api.md).

## Two shell modes

`sekisho-cli` distinguishes between **operational** and **configuration**
commands:

| Mode          | Prompt     | Available commands                                                                         |
|---------------|------------|--------------------------------------------------------------------------------------------|
| Operational   | `sekisho@iap>`  | `show`, `create api-key`, `delete <route|idp|certificate|api-key|session>`, `enable/disable route`, `upload certificate`, `add/activate/retire/rotate encryption-key`, `export`, `import` |
| Configuration | `sekisho@iap#`  | `show`, `edit <route|idp|policy|sekisho|instance>`, `create <route|idp|policy>`, `delete <route|idp|policy>`, `export`, `import` |

Enter configuration mode with `configure`, leave with `exit`.

Within `edit`, changes are staged locally until you `commit` or
`rollback`. A `commit` sends every staged `set` and `delete` as one
update, so a half-typed resource never reaches the data plane.

### Enabling routes

`create route` leaves the route disabled so that you can land
policies, IdP bindings and DNS before traffic flows. When everything
is staged, `enable route <name>` flips the flag — and if the route's
`tls_downstream` is `acme` and no certificate exists for the
hostname yet, `sekisho-cli` enqueues one and polls the durable ACME
queue before enabling. `disable route <name>` takes a route out of service while
keeping its configuration and certificate around for a later
re-enable.

## Tab completion

Tab completion covers every resource and every field, and works
offline — it does not round-trip the daemon, so it is as fast on a
slow link as on localhost.

It is only correct if the shell and the daemon are the same version.
They ship together and `sekisho-cli` checks at startup, refusing to
connect to a daemon that does not match rather than completing fields
that may not exist. See
[Architecture](../design/architecture.md#3-version-locked-clients).
