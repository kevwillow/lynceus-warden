# Lynceus systemd deployment

Terse install steps for the wheel-install path. The full guide lives in the project README.

## Prerequisites

A Linux host (Raspberry Pi OS or any systemd-based distro), Python 3.11+, and a built `lynceus-*.whl`. Kismet is optional — lynceus can run against a fixture for testing.

## Install steps

1. `sudo useradd --system --home /var/lib/lynceus --shell /usr/sbin/nologin lynceus`
2. `sudo install -d -o lynceus -g lynceus -m 0750 /var/lib/lynceus /etc/lynceus`
3. `sudo pip install /path/to/lynceus-*.whl` (installs `/usr/local/bin/lynceus`)
4. `sudo install -m 0640 -o root -g lynceus config/lynceus.example.yaml /etc/lynceus/lynceus.yaml` and edit it
5. `sudo install -m 0644 deploy/lynceus.env.example /etc/lynceus/lynceus.env` (optional; uncomment as needed)
6. `sudo install -m 0644 deploy/lynceus.service /etc/systemd/system/lynceus.service`
7. `sudo systemctl daemon-reload && sudo systemctl enable --now lynceus.service`

## Verify

- `journalctl -u lynceus.service -f` — should show steady poll activity.
- Trigger an ntfy test: `lynceus-seed-watchlist --db /var/lib/lynceus/lynceus.db --threat-ouis` and confirm an alert lands on your configured topic.

## Web UI (optional)

There is a separate `lynceus-ui` process that serves a small read-only dashboard. Install it with `deploy/lynceus-ui.service` (it uses the same systemd hardening as the main `lynceus` service) and visit `http://127.0.0.1:8765` from the Pi itself. By default it only listens on localhost, on purpose. If you want to reach it from another machine, set both `ui_bind_host` and `ui_allow_remote: true` in `lynceus.yaml` — but be careful: in v0.2 the UI has no login, so anyone who can reach the address can read everything in the database. Don't expose it to a network you don't trust.
