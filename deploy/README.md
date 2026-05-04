# Talos systemd deployment

Terse install steps for the wheel-install path. The full guide lives in the project README.

## Prerequisites

A Linux host (Raspberry Pi OS or any systemd-based distro), Python 3.11+, and a built `talos-*.whl`. Kismet is optional — talos can run against a fixture for testing.

## Install steps

1. `sudo useradd --system --home /var/lib/talos --shell /usr/sbin/nologin talos`
2. `sudo install -d -o talos -g talos -m 0750 /var/lib/talos /etc/talos`
3. `sudo pip install /path/to/talos-*.whl` (installs `/usr/local/bin/talos`)
4. `sudo install -m 0640 -o root -g talos config/talos.example.yaml /etc/talos/talos.yaml` and edit it
5. `sudo install -m 0644 deploy/talos.env.example /etc/talos/talos.env` (optional; uncomment as needed)
6. `sudo install -m 0644 deploy/talos.service /etc/systemd/system/talos.service`
7. `sudo systemctl daemon-reload && sudo systemctl enable --now talos.service`

## Verify

- `journalctl -u talos.service -f` — should show steady poll activity.
- Trigger an ntfy test: `talos-seed-watchlist --db /var/lib/talos/talos.db --threat-ouis` and confirm an alert lands on your configured topic.

## Web UI (optional)

A read-only dashboard ships as a separate `talos-ui` process. Install with `deploy/talos-ui.service` (mirrors the talos hardening) and reach it on `http://127.0.0.1:8765`. To bind a non-loopback address, set both `ui_bind_host` and `ui_allow_remote: true` in `talos.yaml` — talos has no auth layer in v0.2, so this is a footgun.

**TODO before first deployment:** replace the placeholders in `src/talos/webui/static/` with actual Pico CSS v2.x (https://picocss.com) and HTMX v2.x (https://htmx.org). Both are MIT licensed and small enough to commit. The current files are stubs so the static-file mounts and tests work without internet access.
