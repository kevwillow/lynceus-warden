# First-run smoke checklist

Run this **after** installing per [deploy/README.md](../deploy/README.md). Each step has a verify command and an expected outcome. If any step fails, **stop and debug** — later steps assume earlier ones passed.

The checklist assumes the standard install paths: config at `/etc/talos/talos.yaml`, database at `/var/lib/talos/talos.db`, service running as the `talos` system user.

## 1. Kismet is capturing

**Action:** confirm the Kismet service is up and seeing devices on your monitor adapter.

**Verify:**

```bash
sudo systemctl status kismet
KEY="$(grep -oP '(?<=^kismet_api_key:\s).*' /etc/talos/talos.yaml | tr -d '"')"
curl -s -b "KISMET=$KEY" http://localhost:2501/devices/views/all/devices.json | head -c 200
```

**Expected:** `kismet.service` is `active (running)`. The curl returns HTTP 200 and a JSON array (truncated to the first 200 bytes — you should see a leading `[` and at least one `{`).

**Troubleshoot:**

- Monitor mode not enabled on the capture adapter (check `iw dev` and Kismet's `kismet_site.conf`).
- Wrong adapter selected — Kismet attached to the host's regular WiFi rather than a dedicated monitor interface.
- Missing or wrong API key — regenerate from the Kismet web UI and re-paste into `/etc/talos/talos.yaml`.

## 2. Talos service is running

**Action:** confirm the `talos` systemd unit is active and steady-state.

**Verify:**

```bash
sudo systemctl status talos
sudo journalctl -u talos -n 50 --no-pager
```

**Expected:** unit is `active (running)`. The journal shows config loaded, the poll loop ticking once per `poll_interval_seconds`, and no Python tracebacks.

**Troubleshoot:**

- Missing config file at `/etc/talos/talos.yaml` (the unit hard-fails on `FileNotFoundError`).
- Bad permissions on `/var/lib/talos` — the directory must be owned by the `talos` user with mode `0750`.
- Kismet API key wrong (look for `requests` exceptions or 401s in the journal).

## 3. Database is being written

**Action:** confirm new sightings are landing in the database.

**Verify:** run twice, 60 seconds apart:

```bash
sudo -u talos sqlite3 /var/lib/talos/talos.db "SELECT COUNT(*) FROM sightings;"
sleep 60
sudo -u talos sqlite3 /var/lib/talos/talos.db "SELECT COUNT(*) FROM sightings;"
```

**Expected:** the count increases between the two reads.

**Troubleshoot:**

- `poll_interval_seconds` set too high — drop it to the minimum (`5`) for the duration of the smoke test.
- Kismet returning no devices since the last poll — confirm step 1 again, or check that the capture adapter is actually picking up traffic (walk past it with your phone).
- DB permissions — the file must be writable by the `talos` user.

## 4. Watchlist seeded

**Verify:**

```bash
sudo -u talos sqlite3 /var/lib/talos/talos.db \
  "SELECT pattern_type, COUNT(*) FROM watchlist GROUP BY pattern_type;"
```

**Expected:** at least one row for `pattern_type = 'oui'` (from `talos-seed-watchlist --threat-ouis`).

**Troubleshoot:**

- Seed step skipped during install — re-run `talos-seed-watchlist --db /var/lib/talos/talos.db --threat-ouis`.
- Wrong DB path — check that the seed CLI and the talos service are pointed at the same file.

## 5. Test rule fires (manual injection)

**Action:** temporarily add your own laptop's WiFi MAC to a high-severity `watchlist_mac` rule. Save it to `/etc/talos/rules.yaml` and restart the service so it picks up the new rule.

```yaml
rules:
  - name: smoke_test
    rule_type: watchlist_mac
    severity: high
    patterns: ["aa:bb:cc:dd:ee:ff"]   # replace with your laptop's MAC
    description: smoke test — remove after step 7
```

```bash
sudo systemctl restart talos
```

**Verify:** tail the journal and walk near the Pi with your laptop's WiFi on:

```bash
sudo journalctl -u talos -f
```

**Expected:** within one `poll_interval_seconds` you see an `alert` log line for the high-severity hit. The line `Failed to write alert` should **not** appear.

**Troubleshoot:**

- Rule YAML syntax — re-validate with `python -c "import yaml; yaml.safe_load(open('/etc/talos/rules.yaml'))"`.
- MAC format — talos normalizes to lowercase, colon-separated. Your laptop's MAC must match (case-insensitive, hyphens accepted).
- Allowlist — if you previously allowlisted your laptop, it will suppress this alert. Comment out the relevant allowlist entry for the duration of the test.

## 6. ntfy is reaching your phone

**Action:** confirm the alert from step 5 reached the ntfy app on your phone.

**Verify:** your phone should buzz with the talos alert within seconds of the journal line in step 5.

**Expected:** notification with title `talos: HIGH alert` and body matching the rule's message (in this case, something like `MAC aa:bb:cc:dd:ee:ff on watchlist: smoke test — remove after step 7`).

**Troubleshoot:**

- Wrong topic name — `ntfy_topic` in `talos.yaml` must exactly match the topic your phone is subscribed to.
- ntfy server unreachable — `curl -I "$NTFY_URL"` from the Pi should return 200.
- Auth token mismatch — if your topic is protected, `ntfy_auth_token` must match the bearer token configured on the server.
- Phone subscribed to a different topic, or notifications muted at the OS level.

## 7. Cleanup

Remove the temporary `smoke_test` rule from `/etc/talos/rules.yaml` and restart:

```bash
sudo systemctl restart talos
sudo journalctl -u talos -n 20 --no-pager
```

Confirm the journal shows the ruleset reloading without the `smoke_test` rule listed.

## When all 7 pass

You're deployed. Add your own gear (laptop, phone, headphones, smart-home devices) to `allowlist.yaml` and let it run for a week before tuning further. False positives in the first 24 hours are normal — treat them as allowlist candidates, not bugs.
