# sekisho-webui

`sekisho-webui` is the optional browser-based management client for Sekisho.
It is a server-rendered BFF built with axum, Maud, and HTMX: the browser talks
to the Web UI, and the Web UI talks to the `sekishod` management API. The
management credential is never sent to the browser.

The executable is separate from the `sekishod` IAP process and may connect to
a daemon on another host. Operators who do not want a browser UI can manage
the same API with `sekisho-cli` instead.

## Configuration

Runtime settings live in `webui.yaml`. The default path is
`/etc/sekisho-webui/webui.yaml`; use `--config <path>` to select another file.
The configuration covers:

- the listener and optional TLS certificate;
- the `sekishod` management API URL and its out-of-band RPK pin;
- local-socket or API-key authentication to `sekishod`; and
- access control for the Web UI itself.

The Debian package installs an example configuration and leaves
`sekisho-webui.service` disabled. Enable it explicitly on hosts that should run
the UI after setting its daemon URL, RPK pin, and authentication mode:

```sh
sudo systemctl enable --now sekisho-webui
```

See the [operator documentation](../../docs/src/configuration/index.md) for the
management model and deployment guidance.

## Development

Run with an explicit configuration file:

```sh
cargo run -p sekisho-webui -- --config /path/to/webui.yaml
```

Run the crate tests with:

```sh
cargo test -p sekisho-webui
```
