# Testing — pre-0.5.0 audit

A snapshot of the suite captured 2026-05-19, before tag 0.5.0. Sister
doc to [PROJECT_STATUS.md](PROJECT_STATUS.md) — that one gives the
top-line "N tests" headline for the README cross-link; this one is the
release-readiness reference with the counts, the slow profile, and the
caveats that gate the tag.

Read-only audit. No test logic, fixture, or marker changes landed
alongside this document.

## Suite summary

- **Audit date.** 2026-05-19
- **Result.** 2412 passed, 16 skipped, 0 failed.
- **Wall clock.** 326.55s (5:26) on the audit host (Windows 11, Python
  3.14.3, pytest 9.0.2, repo `.venv`).
- **Command.** `pytest --tb=short -q` from the repo root with the
  project's `addopts = "-ra --strict-markers --strict-config"` (per
  [pyproject.toml](../pyproject.toml)).

## Count breakdown

- **Collected items.** 2428 (via `pytest --collect-only -q`).
- **Unique test functions.** 2334 (collected items with `[…]`
  parametrize suffixes folded out).
- **Parametrize-expanded delta.** 94 — items minus functions. The two
  largest contributors are
  `tests/test_migration_rollback.py::test_per_migration_up_down_up`
  (18 IDs, one per reversible migration) and
  `tests/test_migration_rollback.py::test_conditional_rollback_aborts_with_disallowed_row`
  (5 IDs, one per CHECK-relaxation migration that admits a new
  pattern_type or device_type).
- **Suite reconciliation.** 2412 passed + 16 skipped = 2428,
  matching `--collect-only` exactly. No collection-vs-execution gap.

The "items vs functions" distinction matters for narration: prior
sessions surfaced a recurring narration-vs-delta flag where a
parametrized test that adds 18 items reads in commit messages as "+1
test." Both numbers belong on the audit; the headline is the item
count because that's the number pytest reports.

## Slow tests

`pytest --durations=20` from the audit run. Anything over 5s
individually:

| Duration | Test |
| --- | --- |
| 64.59s | `tests/test_bundled_watchlist.py::test_bundled_csv_ssid_rows_land_in_watchlist_db` |
| 64.52s | `tests/test_bundled_watchlist.py::test_bundled_csv_end_to_end_flock_observation_fires_argus_ssid_alert` |
| 16.76s | `tests/test_packaging.py::test_wheel_install_finds_migrations` |

Everything else is sub-2.5s — the next-fastest entries cluster around
the Jinja-template-rendering tests in `test_webui.py` /
`test_webui_theme.py` / `test_ui_watchlist.py`, each at ~2.1-2.3s.

**Rationale per slow test:**

- The two **`test_bundled_csv_*`** tests in `test_bundled_watchlist.py`
  drive the full bundled-Argus-CSV → importer → DB → poller → rule →
  alert chain end-to-end against the shipped `data/argus_export.csv`
  bundle. The cost is dominated by importer normalization +
  per-row writes for a multi-thousand-row CSV. They're the
  load-bearing E2E gates against import-path regressions and the
  rule-firing surface for ssid_pattern (migration 019). Worth their
  cost; not currently a candidate for optimization.
- **`test_wheel_install_finds_migrations`** is `@pytest.mark.slow` and
  builds a real wheel via `python -m build`, installs it into a fresh
  venv, and asserts the packaged data ships the migrations directory.
  Slow setup is intrinsic. The slow marker is on this test (and only
  this test) so `pytest -m "not slow"` removes ~17s from a fast
  iteration loop.

## Test organization

43 test files across `tests/`. By area:

- **Database / migrations / persistence (3).** `test_db.py`,
  `test_migration_rollback.py`, `test_paths.py`.
- **Web UI rendering + routes (10).** `test_webui.py`,
  `test_webui_evidence.py`, `test_webui_theme.py`,
  `test_ui_alert_metadata.py`, `test_ui_settings.py`,
  `test_ui_watchful.py`, `test_ui_watchlist.py`,
  `test_ui_watchlist_filtered.py`, `test_static_assets.py`,
  `test_csrf.py`.
- **Rules / matching / allowlist (4).** `test_rules.py`,
  `test_patterns.py`, `test_alert_linkage.py`,
  `test_severity_overrides.py`. (`test_allowlist.py` straddles this
  area and the daemon side.)
- **Daemon / poller / Kismet (7).** `test_poller.py`, `test_kismet.py`,
  `test_integration.py`, `test_tier1_capture.py`, `test_evidence.py`,
  `test_healthz_json.py`, `test_smoke.py`.
- **Notifier (1).** `test_notify.py`.
- **Watchlist + Argus import (5).** `test_watchlist_metadata.py`,
  `test_bundled_watchlist.py`, `test_import_argus.py`,
  `test_seed_watchlist.py`, `test_seed_metadata.py`, `test_seeds.py`.
- **CLI surfaces (6).** `test_validate.py`, `test_setup_wizard.py`,
  `test_quickstart.py`, `test_bootstrap_kismet.py`,
  `test_export_config.py`, `test_audit_residuals.py`.
- **Other (6).** `test_allowlist.py`, `test_config.py`,
  `test_pagination.py`, `test_redact.py`, `test_install_sh.py`,
  `test_packaging.py`.

The counts above are coarse — several files cross-cut more than one
area. The accurate count is "43 test files." The area labels exist
for operator-facing "where does X coverage live" navigation.

## Known caveats

- **16 platform-skipped tests on Windows.** Twelve are `install.sh`
  bash-driver tests; the remaining four are POSIX-only file-mode
  assertions (two in `test_db.py`, two in `test_setup_wizard.py`).
  All are environment-conditioned skips, not flakes. The same suite
  on Linux runs every one of those tests.
- **`test_wheel_install_finds_migrations` is environment-sensitive.**
  A prior session in this chain surfaced a `FileNotFoundError` looking
  up `lynceus.exe` inside the freshly-built test venv on Windows; the
  audit re-run passes the test cleanly (16.76s). The test is
  `@pytest.mark.slow`-gated, so it's only exercised in full-suite
  runs, not the fast `-m "not slow"` loop. If a future regression
  re-surfaces the FileNotFoundError, the test catches it — but the
  failure may be a Windows venv/symlink quirk rather than a
  packaging-data regression.
- **No flake-prone tests surfaced.** The audit run was a single
  invocation; flake hunting via repeated runs is out of scope. None
  of the slow tests showed signs of duration variance worth tracking.

## Release-readiness note

The suite is **green at 2412 passed / 16 platform-skipped / 0 failed**
as of 2026-05-19, on top of the run-chain's three v0.5.0 prep
commits (H1 migration rollback + H2 deployment runbook, plus CHANGELOG
tidy). The parametrize expansion in the new
`test_migration_rollback.py` lifts the item count by 23 over the
pre-chain baseline; the function count moves by less. No skipped
tests are project-state-conditional — they're all platform-mode skips
that come back in on Linux. Tagging 0.5.0 against this commit is
safe from a test-suite perspective; remaining release work is
operator-side (CHANGELOG section rename, tag, push).
