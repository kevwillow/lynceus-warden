# Project status

A snapshot of where lynceus stands today, for someone who's read the
[README](../README.md) and is asking "should I deploy this on my Pi this
weekend?"

## Current version

See [`src/lynceus/__init__.py`](../src/lynceus/__init__.py) or
`lynceus --version` for the version actually installed. This document
is a **narrative snapshot, not a version-tracked inventory**. It has
drifted behind the release cadence more than once, so the
[CHANGELOG](../CHANGELOG.md) and the [README](../README.md) feature
list are the authoritative record of what has shipped. A full rewrite
of this doc is on the docs backlog.

Everything below describes the project's shape rather than a specific
tag. Where it names a version, read it as "as of that cycle".

## What's shipped

**Daemon (`lynceus`)**

- Polls Kismet on a configurable interval.
- Filters observations by source, by minimum RSSI, and remaps source
  identifiers to friendlier location IDs.
- Upserts devices and inserts sightings into SQLite.
- Evaluates rules (MAC, OUI, SSID, BLE service UUID, first-sighting of a
  non-randomized device). 16- and 32-bit assigned BLE UUIDs are expanded
  to the 128-bit base form per Core Spec §3.2.1 through one shared
  function, so an operator who watchlists `fd5a` matches an
  advertisement carrying `fd5a`.
- Suppresses allowlisted devices.
- Deduplicates alerts within a configurable window.
- Sends ntfy notifications with severity-based priority and emoji tags.
- Optional Kismet health check on startup, fail-fast if unreachable.
- Clean shutdown on SIGTERM/SIGINT.

**Web UI (`lynceus-ui`)**

- Read-only dashboard, alerts list and detail, devices list and detail,
  rules and allowlist views.
- Pagination and filtering on alerts and devices.
- Single-alert and bulk acknowledgement with audit trail; "ack all
  visible" capped at 1000 to prevent runaway acks.
- Watchful snooze surface: `/watchful` page with filter, pagination,
  per-entry actions (dismiss, promote to permanent allowlist, reset
  escalation, flag for investigation, confirm safe), per-alert "Watch"
  triage button, recurrence digest grouped by ISO week.
- CSRF middleware on POST routes.
- Optional single-operator password + server-side sessions
  (`lynceus-ui-passwd`). Off by default on loopback; **required** on any
  non-loopback bind, which `lynceus-ui` refuses to serve without one.
- Localhost-bound by default; non-loopback bind requires an explicit
  `ui_allow_remote: true` flag (intentional friction).

**Setup (`lynceus-setup`)**

- Interactive CLI wizard that probes Kismet and ntfy, writes
  `lynceus.yaml`, and auto-imports the bundled threat data.
- `lynceus-setup --web` (added in v0.7.0): same wizard, served as
  a loopback-bound multi-page form on port 8766 with a single-use
  setup token. Friendlier for headless / SSH-tunneled hosts and
  operators new to YAML. Validates input through the same
  `Config` constructor the daemon loads from disk, so the wizard
  can't produce a configuration the daemon will refuse.

**CLI (`lynceus-seed-watchlist`)**

- Seeds the watchlist with bundled threat OUIs, bundled BLE tracker
  UUIDs, or a user-supplied YAML file. Re-runnable; duplicates are
  collapsed.

**Deploy**

- Hardened systemd units for daemon and UI (mount restrictions, no
  new privileges, memory and CPU limits).
- Env-file template.
- Wheel-based install path with bundled migrations.

**Configuration**

Fields cover Kismet connection, polling cadence, source filtering,
RSSI floor, location mapping, alert dedup window, evidence capture,
ntfy delivery, web UI binding, and rules/allowlist/severity-override
paths. Full reference in [CONFIGURATION.md](CONFIGURATION.md).

## What's deferred

See [BACKLOG.md](../BACKLOG.md) for full detail and trigger conditions.
The headlines:

- Stingray / IMSI-catcher hunter bridge.
- Web UI editing for the RULESET and for the operator's own
  `allowlist.yaml`; the YAML is the only edit path for both. ⚠️ Not the
  same as "the UI writes nothing": suppressions made from the UI
  (allowlist this device, snooze, promote a watchful entry) are written
  by the daemon to its own `allowlist_ui.yaml`, which does change
  alerting behaviour.
- Multi-location stalking heuristics (cross-Pi correlation).
- Allowlist auto-learn mode for early-deployment FP suppression.
- Kismet retry policy with backoff and circuit breaker.
- Kismet-died ntfy alert tier.
- Reverse-proxy path-prefix support.
- Auto-shift-to-now mode for the dev fixture.

## Test coverage at a glance

Several thousand tests, growing with each cycle. Deliberately not pinned to an exact number here. The count went stale every release and a stale count is worse than none. Coverage spans the daemon, the UI (read-only dashboard + web setup wizard), the rules engine, the notifier, the database layer, the watchlist + Argus import path, the setup core + CLI + web frontends, install.sh, and packaging.

**The suite is maintained outside this repository** and is not part of a clone. See [TESTING.md](TESTING.md) for what that means and why.

The `slow` mark is a wheel-build round-trip. Skip with
`pytest -v -m "not slow"` for fast iteration; run the full suite before
release.

## Known limitations

Things lynceus explicitly does not do today:

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
- **Sightings retention is opt-in and defaults to OFF.** Set
  `sightings_retention_days` to bound the table; while it is unset,
  `sightings` grows without limit and manual rotation is the workaround.
  Evidence retention is different: `evidence_retention_days` defaults to
  **90**, so that half prunes on a stock install. Both run from the poll
  loop at most once a day, not from cron.
- **No web UI authentication.** Localhost-only binding is the security
  boundary. Remote access requires the operator to put their own
  reverse proxy and auth in front.
- **No reverse-proxy path-prefix support.** `/static/` is hardcoded.

## Hardware tested vs untested

- **Tested in software.** Full pipeline runs on Windows and Linux dev
  environments using the `FakeKismetClient` against a JSON fixture. The
  suite covers the daemon, the UI, the rules engine, the notifier, the
  database layer, the Argus import path, the setup core + CLI + web
  frontends, install.sh, and packaging.
- **Tested on hardware.** The end-to-end run on real hardware against a
  real Kismet capture is no longer outstanding. The 0.9.x cycle is
  hardware-verified on-device, and the 0.9.3/0.9.4 Bluetooth fixes came
  out of rig captures rather than reasoning. See the
  [CHANGELOG](../CHANGELOG.md) for what each capture actually settled.
- **Still hardware-blocked.** The drone Remote-ID field path is an
  unverified guess until a live drone is captured, and the passive BLE
  bridge remains off by default behind its enablement gates. Both are
  tracked in [BACKLOG.md](../BACKLOG.md).

## Should you deploy this today?

If you're comfortable with a personal-use, self-hosted, "early but
working" project. Yes. The code paths are exercised, the docs walk you
through setup and verification, and the failure modes are honest about
what they are. If you want a polished, hardened, audited product, this
isn't that yet.
