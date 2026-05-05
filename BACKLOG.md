# lynceus backlog

Deferred features and known followups, captured here so they don't get lost.

## v0.2 release notes

What landed in the v0.2 cycle:

- Project skeleton, packaging, and console scripts (`lynceus`, `lynceus-ui`,
  `lynceus-seed-watchlist`).
- SQLite schema with bundled migrations and a `poller_state` table for
  incremental polling.
- Kismet REST client with multi-source support, startup health check,
  and a fixture-driven fake client for offline development.
- Poll loop with YAML config (pydantic v2 validation), signal handling,
  and a `--once` smoke-test mode.
- Rules engine and allowlist, both YAML-defined, with a configurable
  alert-deduplication window.
- BLE service-UUID extraction and a matching `ble_uuid` rule type for
  AirTag-class trackers.
- ntfy.sh notifier with priority and emoji tags by severity, plus null
  and recording variants for tests.
- Read-only FastAPI web UI: dashboard, alerts list and detail, devices
  list and detail, rules and allowlist views; pagination, filtering,
  single and bulk alert acknowledgement with audit trail; CSRF middleware
  on POST routes; localhost-bound by default.
- Hardened systemd units for the daemon and UI, with env-file template.
- Watchlist seeding CLI with bundled threat OUIs and BLE tracker UUIDs,
  plus user-supplied YAML.
- Documentation: README, configuration reference, rules reference, smoke
  checklist, Windows dev guide, deploy guide, status snapshot.

## Deferred features (revisit when conditions met)

### Argus surveillance-equipment database
A versioned, community-maintainable watchlist of RF signatures for known
surveillance hardware: marked police vehicle WiFi/BT, body-worn cameras,
dashcams, license plate readers, Flock and similar fixed camera systems.
Shipped as a separate YAML dataset consumed via the existing
`lynceus-seed-watchlist --yaml` path — no code change inside lynceus itself,
only data.
- **Trigger**: when a useful baseline of real-world signatures has been
  collected. Data work first; integration is trivial once the data exists.
- **Estimated**: data-gathering effort dominates; lynceus-side work is a
  YAML conversion and a re-seed pass.
- **Notes**: maintain in its own repo or sub-tree so the dataset can
  evolve at its own pace and be forked. Permissive licence on the
  dataset so derivatives are allowed. Detection only — lynceus does not
  jam, spoof, or otherwise interfere with any of the equipment in the
  list, and the project's "passive-only" stance applies to Argus too.

### Stingray hunter bridge
Re-emits hunter alerts to Lynceus ntfy topic. Independent module under
`src/lynceus/bridges/stingray.py`, doesn't touch core.
- **Trigger**: when active SIM is in the hotspot AND hunter is operational.
- **Estimated**: 1 prompt, ~200 LOC + tests.
- **Notes**: ADB workaround NOT recommended — wait for SIM. Building before
  the hunter is operational means the integration drifts out of sync with
  Rayhunter/Crocodile Hunter releases before it's ever exercised.

### BLE 16-bit short UUID expansion
Extend `normalize_uuid` to accept 16-bit shorts and expand to full 128-bit
form via the standard base UUID (`0000XXXX-0000-1000-8000-00805F9B34FB`).
- **Trigger**: when we observe a real-world miss caused by Kismet emitting
  only the short form for a tracker we care about.
- **Estimated**: 1 prompt, ~50 LOC + tests.
- **Notes**: currently parser drops shorts at DEBUG level. If we observe
  meaningful misses, lift this to a real feature.

### Web UI editing for rules and allowlist
Currently read-only views exist; YAML editing is the only path to change them.
- **Trigger**: when YAML editing becomes annoying enough to justify the
  validation/rollback/audit complexity.
- **Estimated**: 3-4 prompts, includes form validation, optimistic-locking
  via a content hash, undo via the existing audit-trail pattern.

### Stalking heuristics (multi-location detection)
Requires real captured baseline data to design well. Postponed until v0.3+
after some weeks of real captures.
- **Trigger**: enough real-world data to know what "normal" looks like in
  your environment.

### Allowlist auto-learn mode
First N hours after install, everything seen goes into a "candidate
allowlist" you review and accept rather than firing alerts on.
- **Trigger**: confirmed false-positive volume in early deployments.

## Followups for technical debt

### CSRF token rotation on session boundaries
v0.2 ships a single token per cookie session (8 hours). Rotation on
auth events comes when auth lands.

### Per-request DB connection pool
v0.2 uses a single shared connection with `check_same_thread=False`.
Safe under WAL + single-writer access pattern. If concurrent UI writes
become real (form-driven rule editing), revisit with a small connection pool.

### Migration packaging revisit on more install paths
Currently tested under editable install + wheel install. If we ever build
a Debian/Arch package, validate migration discovery there too.

### `flake8-bugbear extend-immutable-calls` audit
Currently exempts `fastapi.Form`. Confirm coverage extends to `Query`,
`Depends`, `Path`, `Body`, `Header`, `Cookie` if any are added later.

### Reverse-proxy path prefix support
Currently base.html uses literal /static/ paths. If we ever support
deployment behind a reverse proxy at a non-root path, switch to
url_for('static', path=...) and update tests to assert the resolved
path rather than the literal substring.

### Auto-shift-to-now in FakeKismetClient
The dev fixture (tests/fixtures/dev_kismet.json) currently requires
manual rebumping when its timestamps age out (see scripts/rebump_dev_fixture.py
and docs/WINDOWS_DEV.md). The durable fix:

- Add FakeKismetClient(auto_shift_to_now: bool = False,
  auto_shift_anchor_seconds: float | None = None) constructor params.
- When auto_shift_to_now is True, on first get_devices_since call,
  compute the offset = now - max(last_time across fixture) and apply
  that delta to all timestamps before parsing into observations.
- Surface the flag through Config as kismet_fixture_auto_shift: bool.
- Default to False to preserve current FakeKismetClient behavior for
  integration tests that depend on frozen timestamps.

Trigger: next time someone has to manually rebump the fixture, OR when
v0.3 work touches kismet.py for other reasons (rolling both into one
prompt is cheap).
Estimated: 1 prompt, ~50 LOC + ~15 tests, including a regression test
that proves integration test fixtures are NOT shifted (default off).

## Network capture features

### Per-band filtering (2.4/5/6 GHz)
Currently filtering is per-source (adapter), not per-band. If the same
adapter captures multiple bands and we want to alert differently per band,
we'd need to extract Kismet's frequency field per observation.
Trigger: when one-source-per-band setup proves insufficient.

### Retry policy on Kismet API failures
Currently a single failed poll is silently logged and the next poll
proceeds. If transient failures become noisy, add exponential backoff
with a circuit breaker.

### Kismet-died notification
Lynceus can detect Kismet unreachability (via health_check) but doesn't
currently alert via ntfy when this happens. Add a "lynceus infrastructure
alert" tier that fires on kismet-down, db-locked, etc.

### Per-channel filtering
Same logic as per-band — wait until the simpler primitives prove
insufficient.
