# Project status

A snapshot of where talos stands today, for someone who's read the
[README](../README.md) and is asking "should I deploy this on my Pi this
weekend?"

## Current version

**0.2** — feature-complete, awaiting first real-hardware deployment.

## What's shipped

**Daemon (`talos`)**

- Polls Kismet on a configurable interval.
- Filters observations by source, by minimum RSSI, and remaps source
  identifiers to friendlier location IDs.
- Upserts devices and inserts sightings into SQLite.
- Evaluates rules (MAC, OUI, SSID, BLE service UUID, first-sighting of a
  non-randomized device).
- Suppresses allowlisted devices.
- Deduplicates alerts within a configurable window.
- Sends ntfy notifications with severity-based priority and emoji tags.
- Optional Kismet health check on startup, fail-fast if unreachable.
- Clean shutdown on SIGTERM/SIGINT.

**Web UI (`talos-ui`)**

- Read-only dashboard, alerts list and detail, devices list and detail,
  rules and allowlist views.
- Pagination and filtering on alerts and devices.
- Single-alert and bulk acknowledgement with audit trail; "ack all
  visible" capped at 1000 to prevent runaway acks.
- CSRF middleware on POST routes.
- Localhost-bound by default; non-loopback bind requires an explicit
  `ui_allow_remote: true` flag (intentional friction — v0.2 has no auth).

**CLI (`talos-seed-watchlist`)**

- Seeds the watchlist with bundled threat OUIs, bundled BLE tracker
  UUIDs, or a user-supplied YAML file. Re-runnable; duplicates are
  collapsed.

**Deploy**

- Hardened systemd units for daemon and UI (mount restrictions, no
  new privileges, memory and CPU limits).
- Env-file template.
- Wheel-based install path with bundled migrations.

**Configuration**

22 fields covering Kismet connection, polling cadence, source filtering,
RSSI floor, location mapping, alert dedup window, ntfy delivery, web UI
binding, and rules/allowlist paths. Full reference in
[CONFIGURATION.md](CONFIGURATION.md).

## What's deferred

See [BACKLOG.md](../BACKLOG.md) for full detail and trigger conditions.
The headlines:

- Stingray / IMSI-catcher hunter bridge.
- Web UI editing for rules and allowlist (currently read-only; YAML is
  the only edit path).
- Multi-location stalking heuristics (cross-Pi correlation).
- Allowlist auto-learn mode for early-deployment FP suppression.
- BLE 16-bit short-UUID expansion.
- Kismet retry policy with backoff and circuit breaker.
- Kismet-died ntfy alert tier.
- Reverse-proxy path-prefix support.
- Auto-shift-to-now mode for the dev fixture.

## Test coverage at a glance

**437 tests across 15 modules.**

| Module | Tests |
|---|---|
| test_webui.py | 113 |
| test_kismet.py | 65 |
| test_db.py | 64 |
| test_poller.py | 41 |
| test_notify.py | 31 |
| test_config.py | 30 |
| test_rules.py | 30 |
| test_allowlist.py | 17 |
| test_csrf.py | 13 |
| test_seed_watchlist.py | 10 |
| test_integration.py | 9 |
| test_seeds.py | 7 |
| test_static_assets.py | 4 |
| test_smoke.py | 2 |
| test_packaging.py | 1 (slow) |

The `slow` mark is a wheel-build round-trip. Skip with
`pytest -v -m "not slow"` for fast iteration; run the full suite before
release.

## Known limitations

Things talos explicitly does not do today:

- **Does not defeat MAC randomization.** It records each device's
  randomization status, but does not try to correlate across rotations.
  Modern phones rotate often, by design.
- **Does not transmit on the air.** No active probing, no deauths, no
  injection. Passive listen-only.
- **No in-UI editing.** Rules and allowlist are YAML-only. The web UI
  shows them; it cannot change them.
- **No multi-location stalking heuristics.** Single-Pi only. Cross-Pi
  correlation is deferred until baseline data exists.
- **No Stingray / IMSI-catcher detection.** Hunter bridge is on the
  backlog, waiting on the hardware.
- **No Kismet-died ntfy alert.** Health check detects unreachability;
  the infra-alert tier that would ping you is on the backlog.
- **No retry policy on transient Kismet failures.** A failed poll is
  logged and the next one proceeds.
- **No automatic database pruning.** SQLite grows indefinitely; manual
  rotation is the workaround.
- **No web UI authentication.** Localhost-only binding is the security
  boundary. Remote access requires the operator to put their own
  reverse proxy and auth in front.
- **No BLE 16-bit short-UUID expansion.** Shorts are logged at DEBUG
  and skipped.
- **No reverse-proxy path-prefix support.** `/static/` is hardcoded.

## Hardware tested vs untested

- **Tested.** Full pipeline runs on Windows and Linux dev environments
  using the `FakeKismetClient` against a JSON fixture. The 437-test
  suite covers the daemon, the UI, the rules engine, the notifier, the
  database layer, and packaging.
- **Untested.** End-to-end run on a real Raspberry Pi against a real
  Kismet capture from a real adapter. v0.2 is the snapshot you'd
  install for that first run; v0.3 work will be informed by what the
  first deployment turns up.

## Should you deploy this today?

If you're comfortable with a personal-use, self-hosted, "early but
working" project — yes. The code paths are exercised, the docs walk you
through setup and verification, and the failure modes are honest about
what they are. If you want a polished, hardened, audited product, this
isn't that yet.
