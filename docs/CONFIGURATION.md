# Configuration reference

Lynceus reads a single YAML config file at startup. The path is passed via `--config` (e.g. the systemd unit invokes `lynceus --config /etc/lynceus/lynceus.yaml`). Every field has a default; only override what your environment requires.

The schema is defined in [src/lynceus/config.py](../src/lynceus/config.py) and rejects unknown fields — a typo will fail validation rather than silently being ignored.

## Field reference

| Field | Type | Default | Description | Example |
| --- | --- | --- | --- | --- |
| `kismet_url` | string | `http://127.0.0.1:2501` | Base URL of the Kismet REST API. Must include scheme (`http://` or `https://`); scheme-less values like `127.0.0.1:2501` are rejected at load. | `http://192.168.1.10:2501` |
| `kismet_api_key` | string \| null | `null` | Kismet API key (sent as the `KISMET` cookie). Required for any Kismet instance with auth enabled. | `abc123def456...` |
| `kismet_fixture_path` | string \| null | `null` | Path to a JSON fixture matching the Kismet device-list shape. When set, lynceus uses `FakeKismetClient` and never makes HTTP calls — useful for offline development and tests. | `tests/fixtures/kismet_devices.json` |
| `db_path` | string | `lynceus.db` | Path to the SQLite database file. Override to a stable absolute path on production. | `/var/lib/lynceus/lynceus.db` |
| `location_id` | string | `default` | Identifier recorded on every sighting. Use to distinguish multiple Pis. | `home` |
| `location_label` | string | `Default Location` | Human-readable label paired with `location_id`. | `Living Room` |
| `poll_interval_seconds` | integer | `60` | Seconds between Kismet polls. Minimum `5`; lower values are rejected at load. | `30` |
| `log_level` | string | `INFO` | One of `DEBUG`, `INFO`, `WARNING`, `ERROR`. | `DEBUG` |
| `rules_path` | string \| null | `null` | Path to a `rules.yaml` file. When unset, no rules are evaluated and no alerts fire. | `/etc/lynceus/rules.yaml` |
| `allowlist_path` | string \| null | `null` | Path to an `allowlist.yaml` file. When unset, nothing is allowlisted. | `/etc/lynceus/allowlist.yaml` |
| `alert_dedup_window_seconds` | integer | `3600` | Suppress repeated alerts for the same `(rule_name, mac)` pair within this many seconds. Set to `0` to disable dedup (every hit becomes an alert). Minimum `0`. | `1800` |
| `ntfy_url` | string \| null | `null` | Base URL of the ntfy server. When set, `ntfy_topic` is required. For end-to-end setup including phone app installation, see [NTFY_SETUP.md](NTFY_SETUP.md). | `https://ntfy.sh` |
| `ntfy_topic` | string \| null | `null` | ntfy topic to publish alerts to. When set, `ntfy_url` is required. | `my-lynceus-alerts` |
| `ntfy_auth_token` | string \| null | `null` | Optional bearer token for protected topics. | `tk_...` |
| `ui_bind_host` | string | `127.0.0.1` | Host interface for the web UI (`lynceus-ui`). Loopback by default. Non-loopback values require `ui_allow_remote: true`. | `0.0.0.0` |
| `ui_bind_port` | integer | `8765` | TCP port the UI listens on. Range `[1, 65535]`. | `9000` |
| `ui_allow_remote` | bool | `false` | Permit binding the UI to a non-loopback address. Required `true` to expose the UI off-host; lynceus has no auth layer, so this is gated explicitly. | `true` |
| `kismet_sources` | list[string] \| null | `null` | Inclusive filter on Kismet source (adapter) names. When set, only observations seen by at least one listed source are processed; others are silently dropped (DEBUG-logged). Source names match exactly. Omit or unset to accept every source. | `[alfa-2.4ghz, builtin-bt]` |
| `kismet_source_locations` | dict[string, string] \| null | `null` | Per-source location override. Maps Kismet source names to `location_id` values; sightings observed by a matching source are recorded under that override rather than the global `location_id`. Sources not listed fall back to `location_id`. | `{alfa-2.4ghz: wifi-corner, builtin-bt: bt-corner}` |
| `min_rssi` | integer \| null | `null` | Drop observations weaker than this RSSI threshold (dBm). Range `[-120, 0]`. Observations with no RSSI report are kept regardless. Unset disables RSSI filtering. | `-85` |
| `kismet_timeout_seconds` | float | `10.0` | HTTP timeout (seconds) for all Kismet REST calls. Range `(0, 120]`. | `15.0` |
| `kismet_health_check_on_startup` | bool | `true` | Probe Kismet's `/system/status.json` once at poller startup; on failure, the daemon exits immediately. Set `false` to skip the check (e.g. when starting lynceus before Kismet is ready). | `false` |

### Cross-field validation

- If `kismet_fixture_path` is set together with a non-default `kismet_url`, lynceus logs a warning and the fixture wins.
- `ntfy_url` and `ntfy_topic` must be set as a pair. Setting only one fails validation.
- Setting `ui_bind_host` to anything other than `127.0.0.1` / `localhost` requires `ui_allow_remote: true`. Lynceus has no built-in auth; this gate forces an explicit acknowledgement before exposing the UI off-host.
- Unknown top-level keys cause a load-time error (`extra='forbid'`).

## Worked examples

### 1. Home apartment, one Pi, one ntfy topic

A single Pi watching the apartment, alerts pushed to a personal ntfy topic.

```yaml
kismet_url: http://127.0.0.1:2501
kismet_api_key: paste-from-kismet-ui

db_path: /var/lib/lynceus/lynceus.db

location_id: home
location_label: Apartment

poll_interval_seconds: 60
log_level: INFO

rules_path: /etc/lynceus/rules.yaml
allowlist_path: /etc/lynceus/allowlist.yaml
alert_dedup_window_seconds: 3600

ntfy_url: https://ntfy.sh
ntfy_topic: kev-lynceus-home
```

### 2. Office, allowlist for known coworkers

Same shape as the home install, with an aggressive allowlist for coworker phones, laptops, and headphones to keep the noise down. The allowlist itself lives in `allowlist.yaml`; `lynceus.yaml` just points at it.

```yaml
kismet_url: http://127.0.0.1:2501
kismet_api_key: paste-from-kismet-ui

db_path: /var/lib/lynceus/lynceus.db

location_id: office
location_label: Office (3rd floor)

poll_interval_seconds: 120
log_level: INFO

rules_path: /etc/lynceus/rules.yaml
allowlist_path: /etc/lynceus/allowlist.yaml

# Tighter dedup: in a busy office, repeating every 30 min is enough.
alert_dedup_window_seconds: 1800

ntfy_url: https://ntfy.sh
ntfy_topic: office-lynceus
ntfy_auth_token: tk_replace_me
```

The matching `allowlist.yaml`:

```yaml
entries:
  - pattern: A4:83:E7:11:22:33
    pattern_type: mac
    note: my laptop
  - pattern: AA:BB:CC
    pattern_type: oui
    note: company-issued thinkpads (vendor block)
  - pattern: corp-wifi
    pattern_type: ssid
    note: office SSID — don't alert on the AP itself
```

### 3. Travel mode, elevated severity defaults

A portable Pi for hotel and conference deployments. Faster poll, no dedup, separate ntfy topic so travel alerts don't mix with home traffic. The lynceus config doesn't have a "travel mode" flag — you configure travel posture by tightening the dedup window and pointing at a stricter `rules.yaml`.

```yaml
kismet_url: http://127.0.0.1:2501
kismet_api_key: paste-from-kismet-ui

db_path: /var/lib/lynceus/travel.db

location_id: travel
location_label: Travel Pi

# Faster polling — you may only be in a given location for hours.
poll_interval_seconds: 30
log_level: DEBUG

rules_path: /etc/lynceus/rules.travel.yaml
allowlist_path: /etc/lynceus/allowlist.travel.yaml

# Disable dedup entirely — every hit is interesting on the road.
alert_dedup_window_seconds: 0

ntfy_url: https://ntfy.sh
ntfy_topic: kev-lynceus-travel
```

The companion `rules.travel.yaml` should bump the `new_non_randomized_device` rule from `low` to `med` or `high`, and add aggressive `watchlist_oui` entries for known surveillance vendors. See [RULES.md](RULES.md) for the rule schema.

## Multi-adapter deployments

Two adapters on a single Pi — say a 2.4 GHz Wi-Fi monitor and an internal Bluetooth radio — let you label sightings by which adapter heard them. This is the right shape for a Pi placed in a corner of the room where you want to know whether a device was *seen on Wi-Fi* (so it's at LAN range) versus *seen on Bluetooth* (closer, weaker, more interesting).

Configure Kismet with both `source=` lines first; lynceus doesn't drive Kismet's adapter selection. Then on the lynceus side, list the source names and (optionally) attach a location label per source:

```yaml
kismet_url: http://127.0.0.1:2501
kismet_api_key: paste-from-kismet-ui

db_path: /var/lib/lynceus/lynceus.db

# Default location for sightings whose source isn't listed below.
location_id: living-room
location_label: Living Room

# Only process observations seen by these adapters. Other Kismet sources
# (e.g. an RTL-SDR running for 433 MHz traffic) are silently dropped.
kismet_sources:
  - alfa-2.4ghz
  - builtin-bt

# Per-source override: tag each observation with the adapter's location.
# Useful when the two radios have meaningfully different ranges.
kismet_source_locations:
  alfa-2.4ghz: living-room-wifi
  builtin-bt:  living-room-bt

# Optional: drop weak observations early. -85 dBm is roughly the floor
# below which RSSI is too noisy to be useful for proximity reasoning.
min_rssi: -85

# Tighter than the default 10s, since the local Kismet is on the same Pi.
kismet_timeout_seconds: 5.0

# Default; explicit here for visibility. With multi-adapter setups, a
# misconfigured Kismet (e.g. one of the sources failed to attach) is a
# common cause of "lynceus is silent" — fail fast at startup so you notice.
kismet_health_check_on_startup: true

rules_path: /etc/lynceus/rules.yaml
allowlist_path: /etc/lynceus/allowlist.yaml
```

Verifying the per-source labelling once the daemon is running:

```bash
sudo -u lynceus sqlite3 /var/lib/lynceus/lynceus.db \
  "SELECT location_id, COUNT(*) FROM sightings GROUP BY location_id;"
```

Both `living-room-wifi` and `living-room-bt` should appear with non-zero counts within an hour. If one is missing, the corresponding Kismet `source=` line is probably failing to attach — check `kismet -d` output for that adapter.

## Web UI routes

The `lynceus-ui` server (separate process from the daemon) serves these routes against the same SQLite database. All paths are mounted at the root.

Read-only views:

| Path | What it shows |
| --- | --- |
| `/` | Index: severity counts (24h / 7d / 30d), 30-day sparkline, recent unacknowledged alerts, recent devices, Kismet reachability. |
| `/alerts` | Paginated alerts list with filters for severity, ack state, date range, and free-text search. |
| `/alerts/{id}` | Alert detail with action history (ack/unack audit trail). |
| `/devices` | Paginated devices list with filters for device type and randomization state. |
| `/devices/{mac}` | Device detail with sighting history. |
| `/rules` | Current ruleset (rendered from `rules_path`, read-only). |
| `/allowlist` | Current allowlist (rendered from `allowlist_path`, read-only). |
| `/healthz` | Schema version, table counts, last poll timestamp. |

Mutation endpoints (POST, redirect on success):

| Path | What it does |
| --- | --- |
| `/alerts/{id}/ack` | Acknowledge a single alert; records actor and optional note. |
| `/alerts/{id}/unack` | Reverse a prior acknowledgement; records actor and optional note. |
| `/alerts/bulk-ack` | Acknowledge a list of alert IDs (form field `alert_ids`, capped at 1000). |
| `/alerts/ack-all-visible` | Acknowledge everything matching the current `/alerts` filter (capped at 1000; the cap is enforced via a count read before any write). |

All POST routes require the CSRF token: a cookie set on the first GET, plus the matching token in a hidden form field. The token has an 8-hour TTL and rotates with the cookie. The included templates wire this up automatically; if you build your own forms, see [src/lynceus/webui/csrf.py](../src/lynceus/webui/csrf.py) for the protocol.

## Reload semantics

The config is read **once at startup**. Changes to `lynceus.yaml`, `rules.yaml`, or `allowlist.yaml` require a service restart:

```bash
sudo systemctl restart lynceus
sudo systemctl restart lynceus-ui
```

Live reload (SIGHUP, file-watch, or a control socket) is tracked in [BACKLOG.md](../BACKLOG.md) under web-UI editing — that work needs the validation/rollback machinery first. Until then, plan to bundle config edits and restart deliberately rather than tweaking and hoping.
