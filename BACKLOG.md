# talos backlog

Deferred features and known followups, captured here so they don't get lost.

## Deferred features (revisit when conditions met)

### Stingray hunter bridge
Re-emits hunter alerts to Talos ntfy topic. Independent module under
`src/talos/bridges/stingray.py`, doesn't touch core.
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
