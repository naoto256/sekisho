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

```bash
sudo dpkg -i sekishod_<version>_amd64.deb \
             sekisho-cli_<version>_amd64.deb \
             sekisho-webui_<version>_amd64.deb
sudo apt-get install -f   # pull in any missing dependencies
```

Together they:

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

Nothing else has to change for the daemon to work without it — the shell
and the management API are the same surface.

## Keeping the three in step

All three check the daemon's `/version` at startup. `sekisho-cli` exits
on a mismatch. The web UI loads anyway and shows the mismatch as a
badge, because an operator is often there *because* something is wrong
and refusing would take away the tool they would use to fix it.

Upgrade the three together. See
[Architecture](../design/architecture.md) § Version-locked clients.

## Next

Continue with [Quick Start](../quick-start.md) § 2, which sets the master
key and brings the daemon up.
