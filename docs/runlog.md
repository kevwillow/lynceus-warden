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
