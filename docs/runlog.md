# Lynceus Run Log

Per-release ship narratives. Companion to `CHANGELOG.md` — the changelog
is the structured user-facing history; this is the engineering ship
report (what was broken, what now works, what departed from spec, what
was deferred).

## v0.3.0-rc3 (2026-05-09)

### Ship-blockers closed

- **C1 — Kismet datasource name probe** (0a55b43): the wizard offered
  kernel interface names (`wlan0`, `wlan1`) from `/sys/class/net`, but
  the poller filters incoming observations against Kismet's configured
  datasource *names* (e.g. `external_wifi`) — every observation in the
  field was silently dropped. The wizard now probes
  `/datasource/all_sources.json` after the health check and presents
  the actual source names; OS enumeration remains as a guarded fallback
  with an explicit "verify against Kismet `name=`" warning so the
  fallback can't silently reintroduce the bug.
- **H1 + H2 — URL scheme validation at config and prompt layers**
  (fec81a0): scheme-less inputs like `127.0.0.1:2501` flowed through
  the wizard into `requests.get` and raised `MissingSchema` /
  `InvalidSchema` at poll time. A pydantic `field_validator` on
  `kismet_url` and `ntfy_url` now rejects bad shapes at config-load
  time (suspenders), and the wizard re-validates the prompts before
  any probe with a 4-attempt cap (belt).
- **Bug 5 — `DEFAULT_KISMET_URL` deduplication and quickstart user-config
  fallback** (fec81a0): `lynceus-quickstart` hardcoded
  `/etc/lynceus/lynceus.yaml`, so a user-mode install couldn't start
  without an explicit `--config` flag; and the default Kismet URL was
  copy-pasted across the wizard and config defaults with subtle
  divergence (`localhost` vs `127.0.0.1`) that broke the
  fixture-vs-non-default-url warning. Now `paths.resolve_existing_config()`
  picks user-mode > system-mode > error-listing-both-paths, and
  `DEFAULT_KISMET_URL` lives once in `lynceus.config` (loopback IP, no
  `/etc/hosts` or v4/v6 ambiguity) with the wizard importing from
  there.
- **M5 / G2 — `Database.__init__` parent-dir creation** (fec81a0): the
  wizard had a local `data_dir.mkdir` patch (rc1.30c) but
  `Database.__init__` itself did not create parent dirs before
  `sqlite3.connect`, so any other caller constructing `Database()` with
  a nested path got "unable to open database file". Now
  `Database.__init__` defensively creates parents (skipping `:memory:`).
- **Bug 6 / S1 / S2 / S5 — system-mode ownership and atomic perms**
  (cdce4a0): rc1 shipped `--system` mode broken-by-default. The daemon
  (`User=lynceus`) couldn't read its config (Bug 6) or write its DB
  (S1); `/etc/lynceus` denied directory traversal so file-level perms
  were moot regardless (S5); and the config write had a race window
  where secret-bearing YAML was briefly world-readable between
  `write_text` and `chmod` (S2, present in user mode too). Replaced
  every `write_text + chmod` pair with an `_atomic_write` helper that
  sets mode at fd-creation time (`os.open` with
  `O_CREAT|O_WRONLY|O_TRUNC` + mode); added scope-gated chown helpers
  (root:lynceus 0640 for files, lynceus:lynceus 0750 for dirs,
  lynceus:lynceus 0640 for the DB plus `-wal`/`-shm` sidecars); and
  patched `install.sh` to chown `/etc/lynceus` to root:lynceus 0750
  after `mkdir` so the daemon's group has explicit traversal rights.
- **H3 — Kismet startup health-check retry** (64fe967): under
  `After=network.target`, Kismet may still be coming up when
  `lynceus.service` starts, and rc1's single-shot health check turned
  a transient probe failure into a daemon crash. The startup probe is
  now wrapped in a 3-attempt retry with `[2.0, 4.0, 8.0]`s backoff
  exposed as `HEALTH_CHECK_RETRY_BACKOFF` (so tests override to zero
  waits); final failure raises the same `RuntimeError` text callers
  depend on.
- **H4 — poll-loop transient-exception catch** (4225c35): a single
  `ConnectionError`, Kismet 5xx, or pydantic `ValidationError` mid-poll
  used to escape `run_forever` and exit the daemon. The per-tick body
  is now wrapped in `try/except Exception` with the traceback logged at
  ERROR (so journalctl shows what happened); `KeyboardInterrupt` and
  `SystemExit` (`BaseException`, not `Exception`) still propagate so
  Ctrl+C and `systemctl stop` actually stop the daemon, and the outer
  `try/finally` keeps `DB.close()` running on the way out.
- **H5 — `KismetClient` transport-level retry** (0f93d9a): mounted a
  urllib3 `Retry` policy on a `requests.Session` so transient 5xx
  (502/503/504), connection errors, and read timeouts no longer
  propagate to the poll loop (3 retries, `backoff_factor=0.5`,
  0.5s/1.0s/2.0s — covers the typical Kismet recovery window; 4xx is
  intentionally out of `status_forcelist` because retrying a bad token
  won't change the answer). All three HTTP-issuing methods on
  `KismetClient` (`health_check`, `get_devices_since`, `list_sources`)
  route through `self._session.get`; a grep-based regression test
  guards against the next method slipping past with a bare
  `requests.get`.
- **Bug 7 — ntfy topic validation** (a415603, with semantics correction
  in 7fa8408): rc1 accepted any non-empty string as the ntfy topic, so
  a fat-fingered `na`/`skip`/`n/a` silently became the topic and
  alerts routed to a topic the operator never subscribed to. Tightened
  to 6–64 alphanumeric/underscore/hyphen with a case-insensitive
  deny-list of cancellation words and a 4-attempt cap before
  `SetupError`. See the "Notable departures" section for the blank-topic
  semantics correction that landed in 7fa8408.

### Test discipline

The diagnostic G-series surfaced a recurring pattern: tests that mocked
the failing call site passed in CI but the production path blew up in
the field. G1 (real `urlsplit` on scheme-less input + real
`requests.get` raising `Invalid/MissingSchema`), G2 (`Database()` on a
deeply nested path), and G3 (`quickstart.main([])` discovering user-mode
config under tmp `HOME`) were each "the test that would have caught the
rc1 field bug" *if* it had exercised the real failure path instead of
the mocked one. The discipline committed to from G1 onward, and
followed by every fix prompt in this cycle (31 through 34 plus the Bug 7
reversal): every regression test must drive the real failure path the
original mock papered over, and where mocks remain (e.g. the conftest
`Retry.increment` short-circuit, see below) they are runtime-perf
workarounds with the contract verified separately by structural tests.

### Notable departures from spec

- **H3 backoff list size**: spec called for an unbounded retry schedule
  with exponential growth; landed with a fixed 3-attempt list
  `[2.0, 4.0, 8.0]` exposed as `HEALTH_CHECK_RETRY_BACKOFF`. Three
  attempts cover the typical Kismet recovery window — an unbounded
  schedule would push visible-failure feedback past the systemd
  start-timeout and look indistinguishable from a hang.
- **H4 outer `KeyboardInterrupt` handler removed**: spec had nested
  `try` blocks (inner `except Exception`, outer `except BaseException`).
  Landed with a single `except Exception` plus `try/finally` for
  `DB.close()`. `BaseException` (KeyboardInterrupt, SystemExit)
  propagates naturally out of the inner block — the outer handler was
  redundant and would have masked unrelated bugs.
- **H5 contract-vs-true behavioural test**: spec described an
  end-to-end retry test with a real loopback server, real failures,
  and real retries. Shipped with a *contract* test (mounted-adapter
  assertions on `total`, `backoff_factor`, `status_forcelist`,
  `allowed_methods`) plus the grep regression. Rationale: the
  real-loopback variant added ~30s to the suite for a property that
  is already expressed declaratively in the urllib3 `Retry` config.
- **H5 `tests/conftest.py` `Retry.increment` patch — DO NOT DELETE AS
  CLEANUP**: a new autouse fixture short-circuits
  `urllib3.Retry.increment` during the suite. This is a **performance
  workaround**, not test scaffolding to be tidied away — the webui
  status header alone contributes ~120 closed-loopback probes per run
  on Windows test machines, each paying 4 connect attempts of
  ECONNREFUSED latency, which adds multiple minutes to suite runtime.
  The structural H5 tests verify the `Retry` attributes are actually
  mounted on the session, so production behaviour is verified
  separately; the runtime retry loop is the only thing bypassed. There
  is no other way to bypass the loop in tests without disabling
  `Retry` entirely (which would defeat the H5 regression coverage).
- **Bug 7 blank-topic semantics correction** (7fa8408 reversed
  a415603): the original Bug 7 fix made blank input at the ntfy *topic*
  prompt skip ntfy entirely (and clear `ntfy_url`). That collapsed two
  distinct paths — skip-ntfy and accept-suggested-default — and was
  operator-hostile: once the URL is set, the operator has committed to
  ntfy and a blank topic should accept the suggested random topic shown
  at the prompt. Final semantics: URL blank → skip ntfy entirely; URL
  set + topic blank → accept suggested random topic; URL set + invalid
  topic → re-prompt against the 4-attempt cap; 4 invalid in a row →
  `SetupError` abort.

### Test counts

900 (rc3 cycle baseline) → 1039 (rc3 ship). +139 tests, every one
closing a real regression path that mock-driven coverage had missed.

### Known issues deferred to v0.3.x or rc4

Diagnostic findings flagged but intentionally not addressed in this
cycle:

- **H6 — migration sort order**: alphabetic sort over `0NN_` prefixes
  works today but breaks at `100_`. Defer until we cross 100 migrations
  or the next migration touches the pre-existing ordering assumptions.
- **H7 through H11 — UI hygiene**: cosmetic and accessibility issues
  in `/watchlist`, `/settings`, and alert detail (focus order, ARIA
  labelling, contrast on dark backgrounds, mobile-viewport overflow).
  Cluster into a single UI-pass commit when there's a clean block of
  time.
- **M-series UI items**: same shape as H7–H11 — paper cuts in the web
  UI that don't block detection or notification.
- **S2 atomic-write coverage gap**: `_atomic_write` replaced every
  `write_text + chmod` pair *in `setup.py`*, but other modules may
  still have unguarded `write_text` followed by `chmod` (or other TOCTOU
  shapes). A wider sweep plus a grep-based regression guard belongs in
  a dedicated S2 follow-up.
- **L-series**: low-priority items from the diagnostic pass, batched
  for a future cleanup commit.
- **Dark-mode toggle**: nice-to-have, explicitly off the v0.3 critical
  path.

After the Kali round-2 shakedown of rc3, if clean, the `-rc3` suffix is
dropped and this becomes `v0.3.0` final.

## v0.4.0-rc1 (2026-05-10)

### Feature: evidence preservation

The headline feature for v0.4.0. On every alert the poller now writes a
full snapshot of what was observed — the complete Kismet device record
as JSON, the RSSI history at the moment the alert fired, and (opt-in)
the operator's GPS fix at capture time — into a new `evidence_snapshots`
table keyed by `alert_id`. Snapshots are pruned by age on each poll
tick per `evidence_retention_days`, and the alert detail page surfaces
the snapshot inline (Kismet record block, RSSI sparkline, optional OSM
link) so an operator triaging a post-hoc alert is no longer staring at
a bare timestamp + MAC. Schema and capture path landed in 6a3f9e2; the
webui surface in b56c7ac.

### Privacy posture

This is the most sensitive feature shipped to date — every dimension of
the privacy posture is called out explicitly here so an operator
deciding whether to enable evidence capture has the full picture in one
place.

- The capture toggles already governing the live observation path
  (`capture.probe_ssids`, `capture.ble_friendly_names`) are now honored
  end-to-end, including in the evidence rows that get written to disk
  and retained for `evidence_retention_days`. Pre-fix, an operator who
  had disabled probe-SSID capture for the alert path was still writing
  probe SSIDs into evidence. Closed in 9debb43 (C-1).
- Operator GPS in evidence rows is opt-in via a new `evidence_store_gps`
  config knob, default `false`. The geopoint Kismet emits is the
  receiver's fix, not the observed device's location — capturing it by
  default would have built a high-resolution operator-movement log into
  the privacy-sensitive evidence path. Closed in f5a8396 (C-2). The
  README privacy section was updated in the same commit to document
  the knob and the rationale.
- Capture failures log only the exception type, not its `repr`. The
  `repr` of common exceptions can include the values that triggered
  them — fragments of MACs, SSIDs, hostnames — and a capture-failure
  log line is exactly the sort of thing operators tail in a terminal
  or pipe to a third-party log shipper. Closed in b0879e2 (H-7).
- `SECURITY.md` documents the data-at-rest threat model for the
  evidence path: the on-disk surface area, what each column can
  contain, the WAL sidecar retention concern (deleted rows linger in
  `*-wal` until checkpoint), and a checkpoint recipe for operators who
  need to flush the WAL before a backup or hand-off. Landed in 2792c56
  (H-8 + M-12).
- The SQLite database file gets `0600` on first creation in user-mode
  installs, so the evidence table is not world-readable on shared
  systems. System-mode is unchanged from the rc3 system-mode work
  (`0640` `root:lynceus`, daemon group has read). Closed in 687051c
  (M-11).

### Hardening

- Bytes / bytearray fields in Kismet records are hex-encoded before
  evidence JSON serialization. Pre-fix, raw bytes raised
  `TypeError: not JSON serializable` mid-capture and dropped the
  snapshot for that alert. H-1, d4f0c16.
- Non-finite floats (`inf`, `-inf`, `nan`) are sanitized to `null`
  before serialization. Same shape as H-1 — Kismet records can carry
  these from upstream sensor noise and the default `json.dumps`
  encoder rejects them. H-2, d4ea850.
- `raw_record` is only carried on observations when
  `evidence_capture_enabled` is true. On busy sites this saves
  multiple MB per poll tick that were otherwise being shuttled
  through the in-memory observation path and discarded. H-3, 40621d6.
- The webui hides the GPS section when coordinates are non-finite,
  even for hand-edited or legacy rows where the row exists but the
  numeric values would render as `inf`/`nan` in the OSM link. H-5,
  39db7b6.
- OSM links open in a new tab (`target="_blank"` with the usual
  `rel="noopener noreferrer"`) so a triage click doesn't navigate
  the operator away from the alert detail page mid-investigation.
  H-6, d04bb0b.
- The `PRAGMA foreign_keys` contract is pinned by a dedicated test —
  the FK-cascade behavior on `evidence_snapshots` (alert delete →
  snapshot delete) silently depends on it being on, and the only
  prior coverage was load-bearing on PRAGMA state set elsewhere.
  H-10, 502d91e.
- The `rssi_history_corrupt` branch in both `db` and `webui` has
  dedicated regression coverage — pre-fix it was a never-exercised
  defensive branch, exactly the shape of bug the rc3 G-series
  pattern was built to catch. H-11, c2859c2.

### Performance

- `captured_at` index added on `evidence_snapshots` for prune
  efficiency at scale. The daily prune (`DELETE WHERE captured_at <
  cutoff`) was a full table scan; at 100K rows that's a multi-second
  stall on a Pi every poll tick. With the index it's an index seek.
  H-4, 7ae6893.

### Forward-compat

- The `evidence_snapshots.do_not_publish` column landed in this cycle
  (default `0`, no producers or consumers in v0.4.0) so that v0.5.0's
  public-feed export work doesn't have to do a destructive migration
  on a table that by then will have meaningful production data in it.
  Adding a column with a default is cheap now and surgical later.
  M-13, 29faf0a.

### Test discipline

The pre-shakedown diagnostic for v0.4.0 surfaced two privacy
criticals (C-1 capture-toggle bypass, C-2 operator GPS leakage) plus
six should-fix items, all of which landed in this rc. Static review
caught what mock-driven tests had missed — the same rc3 G-series
pattern recurred in three distinct places in the v0.4.0 codebase: a
shared Kismet test fixture lacking `signal_rrd`/`location` so the
RSSI-history and GPS paths were exercised against synthetic absence
rather than real presence; an FK-cascade test silently load-bearing
on PRAGMA state set in an unrelated conftest; the
`rssi_history_corrupt` defensive branch never reached by any
existing test. All three are closed by dedicated regression tests in
this rc. The "diagnostic-first, then code" cycle is a pattern worth
keeping for future feature releases — the cost of a static review
pass before the ship-or-not call is small relative to the cost of
shipping a privacy bug.

### Notable departures from spec

- **C-2 GPS default flipped from opt-out to opt-in**: the initial
  evidence-capture implementation in Prompt 35 stored operator GPS
  by default whenever the Kismet record carried a location block.
  The C-2 fix in f5a8396 flipped the default to opt-in
  (`evidence_store_gps` defaults `false`) so the rc1 ship state has
  GPS gated. Operators who pulled an interim commit between Prompt
  35 and the rc1 cycle would have had GPS captured by default; no
  frozen on-disk semantics are affected because v0.4.0-rc1 is the
  first tag with `evidence_snapshots` in the schema, so any interim
  on-disk evidence rows belong to the operator's own dev branch and
  were never part of a tagged release.

### Test counts

1078 (post-Prompt 36, v0.4.0 work-in-progress) → 1107 (v0.4.0-rc1
ship). +29 tests over the privacy/cleanup arc, every one driving a
real failure path the original implementation either missed or only
mock-tested.

### Known issues deferred to v0.4.x or rc2

Diagnostic findings flagged but intentionally not addressed in this
rc:

- **H-9 — replace synthetic Kismet fixture with one captured during
  Kali shakedown**: the highest-value test addition possible —
  every other privacy/hardening fix in this rc would have been
  one-shot caught by exercising the path against a real Kismet
  device record — but it requires real hardware data and so belongs
  to the post-shakedown follow-up, not release prep.
- **M-series remaining**: `last_time` int-only check, RSSI history
  not `:60`-truncated, geopoint length-3 silent accept,
  `isinstance(alt, int|float)` accepts `bool`, clock-jump
  regression in `maybe_prune`, migration 007 missing
  `IF NOT EXISTS`, `<pre>` block size caps, bidi defense on inline
  fields, `alert.message` `<pre>` block sizing, capture-failure log
  lacks evidence row id.
- **L-series**: UI accessibility and operator affordances —
  delete-all-evidence CLI, storage indicator on `/settings`,
  sparkline `aria-label` min/max folding, `focus-visible` on
  details summary.
- **L-8 auth layer**: same forward concern as rc3, deferred to
  v0.5+. The webui still binds loopback-only and assumes a trusted
  local operator; a real auth story is a v0.5 conversation.

After the Kali round-1 shakedown of rc1, if clean, the `-rc1` suffix
is dropped and this becomes `v0.4.0` final.
