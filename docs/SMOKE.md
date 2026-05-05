# First-run smoke checklist (v0.2)

Run this **after** installing per [deploy/README.md](../deploy/README.md). Each step has an action, a verify command, an expected outcome, and a troubleshooting bullet. If any step fails, **stop and debug** — later steps assume earlier ones passed.

The checklist assumes the standard install paths: config at `/etc/lynceus/lynceus.yaml`, database at `/var/lib/lynceus/lynceus.db`, services running as the `lynceus` system user, both the `lynceus` poller daemon and the `lynceus-ui` web UI installed as systemd units.

For local development without a Pi or a real Kismet — building, testing, exercising the UI — see [docs/WINDOWS_DEV.md](WINDOWS_DEV.md). For deferred features so you don't burn time wondering why something isn't there, see [BACKLOG.md](../BACKLOG.md).

## 0. Pre-flight (sizing guidance)

Read this before deciding how many adapters to attach.

- **Pi 3B+** has 1 GB of RAM. Running Kismet against multiple adapters plus the lynceus daemon plus the lynceus-ui web UI on a 3B+ will pressure memory; you'll see swapping, and capture quality degrades when the kernel starts swapping out Kismet's ring buffers. Recommended on a 3B+: **one adapter, no UI auto-start at boot**. Run `lynceus-ui` on demand (`sudo systemctl start lynceus-ui`) when you want to ack alerts. Multi-adapter on a 3B+ is doable but watch `vmstat 5` for `si`/`so` activity during peak hours.
- **Pi 5** has 4–8 GB. Comfortable with 2–3 adapters plus the web UI running 24/7.
- The systemd units in `deploy/` set `MemoryMax=256M` for `lynceus.service` and `MemoryMax=128M` for `lynceus-ui.service`. These are intentional and roughly correct for both Pi tiers; the variable is Kismet itself, not lynceus. If you see `lynceus` getting OOM-killed (`journalctl -u lynceus | grep -i 'memory cgroup'`), look at what Kismet is doing first.

## 1. Kismet is capturing

**Action:** confirm the Kismet service is up, your monitor adapter is attached, and (if you've configured `kismet_sources` in `lynceus.yaml`) every named source is reporting in.

**Verify:**

```bash
sudo systemctl status kismet
KEY="$(grep -oP '(?<=^kismet_api_key:\s).*' /etc/lynceus/lynceus.yaml | tr -d '"')"
curl -s -b "KISMET=$KEY" http://localhost:2501/system/status.json | head -c 400
curl -s -b "KISMET=$KEY" http://localhost:2501/datasource/all_sources.json \
  | python3 -c 'import sys,json; [print(s["kismet.datasource.name"], s["kismet.datasource.running"]) for s in json.load(sys.stdin)]'
```

**Expected:** `kismet.service` is `active (running)`. `system/status.json` returns a JSON object with a non-zero `kismet.system.devices.count`. The all-sources curl prints one line per attached source, each ending in `1` (running). Every source name in your `kismet_sources:` list must appear here.

**Troubleshoot:**
- Monitor mode not enabled on the capture adapter (`iw dev`, then check Kismet's `kismet_site.conf`).
- Wrong adapter selected — Kismet attached to the host's regular WiFi rather than a dedicated monitor interface.
- Source name mismatch — `kismet_sources:` in `lynceus.yaml` is matched **exactly** against the `kismet.datasource.name` reported above. Typo on either side and observations are silently dropped.

## 2. Lynceus daemon is running

**Action:** confirm the `lynceus` systemd unit is active, steady-state, and that the startup health check passed.

**Verify:**

```bash
sudo systemctl status lynceus
sudo journalctl -u lynceus -n 80 --no-pager | grep -E '(Kismet health check|poll cycle|Traceback)'
```

**Expected:** unit is `active (running)`. The journal shows `Kismet health check passed` near startup (the v0.2 fail-fast probe — if Kismet is unreachable at boot, `Poller.__init__` raises and the daemon exits immediately rather than running blind). After that, you should see one poll-cycle log line per `poll_interval_seconds`. No Python tracebacks.

**Troubleshoot:**
- Missing config file at `/etc/lynceus/lynceus.yaml` (the unit hard-fails on `FileNotFoundError`).
- `Kismet health check failed` line at startup → fix Kismet (step 1) before retrying. If you legitimately want to start lynceus before Kismet is ready, set `kismet_health_check_on_startup: false`.
- Bad permissions on `/var/lib/lynceus` — must be owned by the `lynceus` user with mode `0750`.
- Kismet API key wrong (look for `requests` exceptions or 401s in the journal).

## 3. Lynceus UI is running

**Action:** confirm the `lynceus-ui` systemd unit is active and `/healthz` responds.

**Verify:**

```bash
sudo systemctl status lynceus-ui
curl -sS -i http://127.0.0.1:8765/healthz | head -20
curl -sS http://127.0.0.1:8765/healthz | grep -E 'schema version|devices tracked'
```

**Expected:** unit is `active (running)`. The first curl returns HTTP 200 with `Content-Type: text/html`. The body contains `schema version` and `devices tracked` near the top.

**Troubleshoot:**
- Port 8765 already in use — `sudo ss -ltnp '( sport = :8765 )'`. Pick a different port via `ui_bind_port` in `lynceus.yaml`.
- `ui-bind_host` set to non-loopback without `ui_allow_remote: true` → config load fails. Either revert to `127.0.0.1` or set the flag explicitly (and put real auth in front of it; lynceus has none of its own).
- DB path mismatch — `lynceus-ui` reads the same `db_path` as `lynceus`. If they point at different files, the UI shows zeros while the daemon writes elsewhere.

## 4. Database is being written (and per-source attribution works)

**Action:** confirm new sightings land in the DB, and (if you set `kismet_source_locations`) every configured location_id appears.

**Verify:** run this twice, 60 seconds apart:

```bash
sudo -u lynceus sqlite3 /var/lib/lynceus/lynceus.db "SELECT COUNT(*) FROM sightings;"
sleep 60
sudo -u lynceus sqlite3 /var/lib/lynceus/lynceus.db "SELECT COUNT(*) FROM sightings;"
sudo -u lynceus sqlite3 /var/lib/lynceus/lynceus.db \
  "SELECT location_id, COUNT(*) FROM sightings GROUP BY location_id;"
```

**Expected:** the count increases between the two reads. The per-location query lists every `location_id` you configured under `kismet_source_locations`, each with a non-zero count. (If you didn't set `kismet_source_locations`, you'll see only the global `location_id`.)

**Troubleshoot:**
- `poll_interval_seconds` set high — drop to `5` for the duration of the smoke test.
- Kismet returning no devices since the last poll — re-do step 1, or walk past the Pi with your phone's Wi-Fi on.
- Per-source location row missing → the corresponding source isn't actually capturing. `iw dev` and Kismet's source list (step 1) will tell you which one.
- DB permissions — file must be writable by the `lynceus` user.

## 5. Watchlist seeded

**Action:** confirm `lynceus-seed-watchlist` populated the table.

**Verify:**

```bash
sudo -u lynceus sqlite3 /var/lib/lynceus/lynceus.db \
  "SELECT pattern_type, COUNT(*) FROM watchlist GROUP BY pattern_type;"
```

**Expected:** at least one row for `pattern_type = 'oui'` (from `--threat-ouis`). If you ran `--ble-uuids` you'll also see a row for `pattern_type = 'uuid'`.

**Troubleshoot:**
- Seed step skipped during install — re-run `lynceus-seed-watchlist --db /var/lib/lynceus/lynceus.db --threat-ouis --ble-uuids`.
- Wrong DB path — confirm the seed CLI and the lynceus service point at the same file (`grep db_path /etc/lynceus/lynceus.yaml`).

## 6. Test rule fires

**Action:** temporarily add your own laptop's WiFi MAC to a high-severity `watchlist_mac` rule. Save it to `/etc/lynceus/rules.yaml` and restart lynceus.

```yaml
rules:
  - name: smoke_test
    rule_type: watchlist_mac
    severity: high
    patterns: ["aa:bb:cc:dd:ee:ff"]   # replace with your laptop's MAC
    description: smoke test — remove after step 10
```

```bash
sudo systemctl restart lynceus
```

**Verify:** tail the journal and walk near the Pi with your laptop's WiFi on.

```bash
sudo journalctl -u lynceus -f
```

After at most one `poll_interval_seconds`, also check the web UI:

```bash
curl -sS 'http://127.0.0.1:8765/alerts?search=smoke_test' | grep -c smoke_test
```

**Expected:** within one poll interval, the journal shows an `alert` line for the high-severity hit. The `/alerts?search=smoke_test` curl prints a non-zero count. The line `Failed to write alert` should **not** appear.

**Troubleshoot:**
- Rule YAML syntax — `python3 -c "import yaml; yaml.safe_load(open('/etc/lynceus/rules.yaml'))"`.
- MAC format — lynceus normalizes to lowercase, colon-separated. Hyphens accepted, case-insensitive.
- Allowlist — if you previously allowlisted your laptop, it suppresses this alert. Comment out the relevant entry for the test.

## 7. Acknowledge from the web UI

**Action:** open `http://127.0.0.1:8765/alerts` in a browser (or use SSH port-forwarding if the UI is loopback-only on the Pi). Click the inline **ack** button on the smoke-test alert.

**Verify:** in the browser, the alert row dims and gains an "acknowledged" badge. Check the DB to confirm the write landed:

```bash
sudo -u lynceus sqlite3 /var/lib/lynceus/lynceus.db \
  "SELECT acknowledged, ack_actor FROM alerts WHERE rule_name = 'smoke_test' ORDER BY id DESC LIMIT 1;"
sudo -u lynceus sqlite3 /var/lib/lynceus/lynceus.db \
  "SELECT action, actor FROM alert_actions WHERE alert_id = (SELECT id FROM alerts WHERE rule_name = 'smoke_test' ORDER BY id DESC LIMIT 1);"
```

**Expected:** `acknowledged = 1`, `ack_actor` set to your client IP. The action row records `action = 'ack'` with the same actor — this is the audit trail.

**Troubleshoot:**
- 403 / "missing CSRF token" → cookies disabled in your browser, or you opened the form via `curl` and didn't carry the cookie. The token is set on the first GET and required as a form field on POST.
- 405 → make sure you submitted the form (POST), not just clicked through to the alert detail (GET).
- The row visually didn't change but the DB shows `acknowledged = 1` → hard-refresh the page; the redirect goes back to `/alerts` but a stale tab won't reflect the new state.

## 8. ntfy reaches your phone

**Before you start:** confirm you've completed the ntfy setup in [docs/NTFY_SETUP.md](NTFY_SETUP.md). The phone app must be installed and subscribed to your topic, and `lynceus.yaml` must have `ntfy_url` and `ntfy_topic` set.

**Action:** confirm the alert from step 6 reached the ntfy app on your phone.

**Verify:** your phone should buzz with the lynceus alert within seconds of the journal line in step 6. The high severity is the test here — severity-based priority (`low=2`, `med=3`, `high=5`) means the high-tier alert breaks through Do Not Disturb on iOS and gets critical priority on Android.

**Expected:** notification with title `lynceus: HIGH alert` and body matching the rule message (e.g. `MAC aa:bb:cc:dd:ee:ff on watchlist: smoke test — remove after step 10`).

**Troubleshoot:**
- Wrong topic — `ntfy_topic` in `lynceus.yaml` must exactly match the topic your phone is subscribed to.
- ntfy server unreachable — `curl -I "$NTFY_URL"` from the Pi should return 200.
- Auth token mismatch — if your topic is protected, `ntfy_auth_token` must match.
- DnD overriding the high-priority push → check the ntfy app's notification channel settings, not just the OS.

## 9. Multi-source verification (skip if single adapter)

**Action:** if you configured two adapters via `kismet_sources`, give it an hour of real capture and then verify both are contributing.

**Verify:**

```bash
sudo -u lynceus sqlite3 /var/lib/lynceus/lynceus.db \
  "SELECT location_id, COUNT(*) FROM sightings WHERE first_seen_ts > strftime('%s','now') - 3600 GROUP BY location_id;"
```

**Expected:** every `location_id` you configured under `kismet_source_locations` shows a non-zero count over the last hour.

**Troubleshoot:**
- One adapter missing → step 1 again. The most common cause is a `source=` line in `kismet_site.conf` that fails to attach silently; check `journalctl -u kismet -n 200`.
- Counts heavily skewed (one source 100x the other) is **not** necessarily a bug — Wi-Fi 2.4 GHz at city density vs Bluetooth Classic at one-room range is a 100x density difference in the real world.

## 10. Cleanup

Remove the temporary `smoke_test` rule from `/etc/lynceus/rules.yaml`, restart lynceus, and confirm via the web UI.

```bash
sudo systemctl restart lynceus
sudo journalctl -u lynceus -n 20 --no-pager
curl -sS http://127.0.0.1:8765/rules | grep -c 'smoke_test'
```

**Expected:** the journal shows the ruleset reloading without the `smoke_test` rule listed. The `/rules` curl prints `0`.

## When all 10 pass

You're deployed. Add your own gear (laptop, phone, headphones, smart-home devices) to `allowlist.yaml`, let it run for a week, and treat false positives as allowlist candidates rather than bugs. The first 24–48 hours are the system showing you what it sees, not a defect.

For deferred features the operator should not expect to find — stalking heuristics, Stingray hunter integration, in-UI rule editing, allowlist auto-learn — see [BACKLOG.md](../BACKLOG.md). For development iteration without touching a Pi, see [docs/WINDOWS_DEV.md](WINDOWS_DEV.md).
