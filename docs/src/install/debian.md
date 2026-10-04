# Debian and Ubuntu

Sekisho ships as three packages rather than one, so a host can take only
what it needs.

| Package         | Contains                                   | Install it on                          |
|-----------------|--------------------------------------------|----------------------------------------|
| `sekishod`      | The daemon: proxy, management API, ACME.   | Every node that serves traffic.        |
| `sekisho-cli`   | The management shell.                      | Wherever you administer from.          |
| `sekisho-webui` | The admin web UI.                          | Only where you want an admin UI.       |

A proxy peer in an HA pair needs `sekishod` alone. The shell can live on
an admin workstation and talk to the daemon over the management API.

## Installing

Release `.deb` artifacts are currently published for `amd64`. On
`arm64`, use the Linux tarball or the multi-architecture container image.

The packages are independent. Install only the programs needed on that host;
neither management client installs the daemon as a dependency. For example,
an admin workstation can take only the CLI:

```bash
sudo apt install ./sekisho-cli_<version>_amd64.deb
```

To install all three programs on one proxy host:

```bash
sudo apt install ./sekishod_<version>_amd64.deb \
                 ./sekisho-cli_<version>_amd64.deb \
                 ./sekisho-webui_<version>_amd64.deb
```

Installing all three packages together will:

- create a system user `sekisho`,
- install `/usr/bin/sekishod`, `/usr/bin/sekisho-cli`, and
  `/usr/bin/sekisho-webui`,
- create `/var/lib/sekisho/` (state directory) and `/run/sekisho/`
  (control socket),
- install and **enable** `sekishod.service`.

## The web UI is installed disabled

`sekisho-webui.service` ships disabled. An admin UI is not something
every proxy peer should be listening on, so opting in is per host:

```bash
sudo systemctl enable --now sekisho-webui
```

When upgrading an enabled Web UI from 0.1.0 to 0.1.1, run that command once
after the upgrade. The 0.1.0 removal script stopped and disabled the unit.
Starting with 0.1.1, package upgrades restart the Web UI only when it was
already active and preserve its enabled or disabled state. Fresh installs
remain disabled and stopped.

Nothing else has to change for the daemon to work without it — the shell
and the management API are the same surface.

On first install, the package creates `/etc/sekisho-webui/webui.yaml` as
`root:sekisho` with mode `0640`, because the YAML can contain an API key. The
service runs as `sekisho` and reads the file through its `sekisho` group
membership. On each configure, an existing non-symlink regular file whose
numeric owner, group, and mode are exactly `0:0:644` is treated as the legacy
default and changed to `root:sekisho` mode `0640`; its contents are not
rewritten. Other existing owner, group, and mode combinations remain
operator-managed and unchanged. An API key entered through the setup form
stays in process memory instead of being written to this file.

The Web UI can instead manage a remote daemon. Before enabling its service,
set `sekisho_api_url` and `management_rpk_pin`, remove the `local_auth` block,
and either configure an API key or enter one through the setup form.
Local-socket authentication is the only mode that requires the Web UI and
daemon to share a host and service user; the packaged units both run as
`sekisho`. The packaged Web UI unit is otherwise independent of
`sekishod.service`, so a daemon restart does not affect a remote-management
Web UI on the same machine.

For a co-located Web UI that uses `local_auth`, opt into lifecycle coupling
with a systemd drop-in instead of editing the packaged unit:

```bash
sudo systemctl edit sekisho-webui.service
```

```ini
[Unit]
Requires=sekishod.service
After=sekishod.service
PartOf=sekishod.service
```

Then run `sudo systemctl daemon-reload` and restart the Web UI. With this
drop-in, restarting `sekishod.service` also restarts an active Web UI so it
re-establishes its in-memory local-auth credential and API compatibility
state. Stopping and later starting the daemon as two separate operations does
not start the Web UI again; start it explicitly. A `sekishod` package upgrade
also performs separate stop and start operations, so run
`sudo systemctl start sekisho-webui` after upgrading the daemon on a coupled
host. Without the drop-in, a daemon restart invalidates the Web UI's local-auth
credential until the Web UI is restarted manually or credential refresh
succeeds. The first refresh attempt is scheduled about 55 minutes after token
issuance; after a failed attempt, the Web UI retries every 30 seconds.

## Keeping the three in step

Both clients check the daemon's `/version` at startup. A product-version
difference produces a warning, while an incompatible management API version
stops the client before it issues management operations.
If `/version` is unreachable or malformed, the client exits rather than
operating without a compatibility verdict. The Web UI systemd unit retries
startup under its existing `Restart=on-failure` policy.

The Debian packages do not enforce a product-version match. Upgrade them
together where practical, but rely on the startup negotiation—not package
co-installation—to decide whether a client and daemon can communicate. See
[Architecture](../design/architecture.md) § API-version-gated clients.

## Next

Continue with [Quick Start](../quick-start.md) § 2, which sets the master
key and brings the daemon up.
