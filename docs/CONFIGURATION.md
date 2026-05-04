# Configuration reference

Talos reads a single YAML config file at startup. The path is passed via `--config` (e.g. the systemd unit invokes `talos --config /etc/talos/talos.yaml`). Every field has a default; only override what your environment requires.

The schema is defined in [src/talos/config.py](../src/talos/config.py) and rejects unknown fields — a typo will fail validation rather than silently being ignored.

## Field reference

| Field | Type | Default | Description | Example |
| --- | --- | --- | --- | --- |
| `kismet_url` | string | `http://localhost:2501` | Base URL of the Kismet REST API. | `http://192.168.1.10:2501` |
| `kismet_api_key` | string \| null | `null` | Kismet API key (sent as the `KISMET` cookie). Required for any Kismet instance with auth enabled. | `abc123def456...` |
| `kismet_fixture_path` | string \| null | `null` | Path to a JSON fixture matching the Kismet device-list shape. When set, talos uses `FakeKismetClient` and never makes HTTP calls — useful for offline development and tests. | `tests/fixtures/kismet_devices.json` |
| `db_path` | string | `talos.db` | Path to the SQLite database file. Override to a stable absolute path on production. | `/var/lib/talos/talos.db` |
| `location_id` | string | `default` | Identifier recorded on every sighting. Use to distinguish multiple Pis. | `home` |
| `location_label` | string | `Default Location` | Human-readable label paired with `location_id`. | `Living Room` |
| `poll_interval_seconds` | integer | `60` | Seconds between Kismet polls. Minimum `5`; lower values are rejected at load. | `30` |
| `log_level` | string | `INFO` | One of `DEBUG`, `INFO`, `WARNING`, `ERROR`. | `DEBUG` |
| `rules_path` | string \| null | `null` | Path to a `rules.yaml` file. When unset, no rules are evaluated and no alerts fire. | `/etc/talos/rules.yaml` |
| `allowlist_path` | string \| null | `null` | Path to an `allowlist.yaml` file. When unset, nothing is allowlisted. | `/etc/talos/allowlist.yaml` |
| `alert_dedup_window_seconds` | integer | `3600` | Suppress repeated alerts for the same `(rule_name, mac)` pair within this many seconds. Set to `0` to disable dedup (every hit becomes an alert). Minimum `0`. | `1800` |
| `ntfy_url` | string \| null | `null` | Base URL of the ntfy server. When set, `ntfy_topic` is required. | `https://ntfy.sh` |
| `ntfy_topic` | string \| null | `null` | ntfy topic to publish alerts to. When set, `ntfy_url` is required. | `my-talos-alerts` |
| `ntfy_auth_token` | string \| null | `null` | Optional bearer token for protected topics. | `tk_...` |

### Cross-field validation

- If `kismet_fixture_path` is set together with a non-default `kismet_url`, talos logs a warning and the fixture wins.
- `ntfy_url` and `ntfy_topic` must be set as a pair. Setting only one fails validation.
- Unknown top-level keys cause a load-time error (`extra='forbid'`).

## Worked examples

### 1. Home apartment, one Pi, one ntfy topic

A single Pi watching the apartment, alerts pushed to a personal ntfy topic.

```yaml
kismet_url: http://localhost:2501
kismet_api_key: paste-from-kismet-ui

db_path: /var/lib/talos/talos.db

location_id: home
location_label: Apartment

poll_interval_seconds: 60
log_level: INFO

rules_path: /etc/talos/rules.yaml
allowlist_path: /etc/talos/allowlist.yaml
alert_dedup_window_seconds: 3600

ntfy_url: https://ntfy.sh
ntfy_topic: kev-talos-home
```

### 2. Office, allowlist for known coworkers

Same shape as the home install, with an aggressive allowlist for coworker phones, laptops, and headphones to keep the noise down. The allowlist itself lives in `allowlist.yaml`; `talos.yaml` just points at it.

```yaml
kismet_url: http://localhost:2501
kismet_api_key: paste-from-kismet-ui

db_path: /var/lib/talos/talos.db

location_id: office
location_label: Office (3rd floor)

poll_interval_seconds: 120
log_level: INFO

rules_path: /etc/talos/rules.yaml
allowlist_path: /etc/talos/allowlist.yaml

# Tighter dedup: in a busy office, repeating every 30 min is enough.
alert_dedup_window_seconds: 1800

ntfy_url: https://ntfy.sh
ntfy_topic: office-talos
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

A portable Pi for hotel and conference deployments. Faster poll, no dedup, separate ntfy topic so travel alerts don't mix with home traffic. The talos config doesn't have a "travel mode" flag — you configure travel posture by tightening the dedup window and pointing at a stricter `rules.yaml`.

```yaml
kismet_url: http://localhost:2501
kismet_api_key: paste-from-kismet-ui

db_path: /var/lib/talos/travel.db

location_id: travel
location_label: Travel Pi

# Faster polling — you may only be in a given location for hours.
poll_interval_seconds: 30
log_level: DEBUG

rules_path: /etc/talos/rules.travel.yaml
allowlist_path: /etc/talos/allowlist.travel.yaml

# Disable dedup entirely — every hit is interesting on the road.
alert_dedup_window_seconds: 0

ntfy_url: https://ntfy.sh
ntfy_topic: kev-talos-travel
```

The companion `rules.travel.yaml` should bump the `new_non_randomized_device` rule from `low` to `med` or `high`, and add aggressive `watchlist_oui` entries for known surveillance vendors. See [RULES.md](RULES.md) for the rule schema.

## Reload semantics

In v0.1, the config is read **once at startup**. Changes to `talos.yaml`, `rules.yaml`, or `allowlist.yaml` require a service restart:

```bash
sudo systemctl restart talos
```

Live reload (SIGHUP, file-watch, or a control socket) is on the v0.2 roadmap. Until then, plan to bundle config edits and restart deliberately rather than tweaking and hoping.
