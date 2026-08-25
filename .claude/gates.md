# Gates

What to run before claiming this repo is clean, and what the numbers should be.

## Commands

| Gate | Command | Expected |
| --- | --- | --- |
| tests | `pytest -q` | pass, 0 failures |
| lint | `ruff check .` | `All checks passed!` |
| build | `python -m build --wheel` | wheel written |
| formatter | `ruff format --check .` | **fails by design**, see below |

`make test`, `make lint`, `make format-check` wrap the first, second, and
fourth. There is no `make build`.

## CI-only gates

Added 2026-08-19. These run in Actions and not in `make`, because each needs a
tool or privilege a checkout does not have. Listed here so a red check is
readable without opening the workflow.

| Gate | Command it amounts to | Note |
| --- | --- | --- |
| `integrity / web-assets` | `node --check` over `git ls-files '*.js'` | 604 lines of `lynceus.js` that nothing had ever parsed |
| `integrity / systemd-units` | `systemd-analyze verify` over the 6 units | stubs the `ExecStart` targets first; see the trap below |
| `integrity / config-examples` | `lynceus-validate` over the shipped `config/*.yaml` | staged under `XDG_CONFIG_HOME` |
| `integrity / workflows` | `actionlint`, pinned + sha256-verified | `SHELLCHECK_OPTS=-S warning`, matching `shellcheck.yml` |
| `ci / test (ubuntu-24.04-arm)` | the suite, on arm64 | the deployment architecture, unexercised until now |
| `ci` coverage leg | `pytest --cov` on the 3.11 x86 leg | HTML report uploaded as an artifact |

⚠️ **`systemd-analyze verify` exits 0 on a malformed directive value.**
Measured: `ProtectSystem=banana` prints "Failed to parse protect system value,
ignoring" and exits **0** — the directive is dropped and the unit runs
unhardened. Only a missing binary exits nonzero. The gate is therefore keyed on
the verifier's OUTPUT being empty, never on its exit status. If you rewrite that
job, keep that property.

⚠️ **The gate stubs `ExecStart` rather than filtering the "not executable"
line.** Filtering would also hide a genuinely typo'd `ExecStart` path, which is
the defect most worth catching. The stub paths are read out of the units, so a
unit that gains a new `Exec*` is covered without editing the workflow.

## Host-only gates

Added 2026-08-22. The mirror image of the section above: these need a real
machine rather than a runner, so they run in neither `make test` nor CI.

| Gate | Marker | File | Needs |
| --- | --- | --- | --- |
| fresh install | `install` | `tests/test_fresh_install.py` | a capture interface |
| browser crawl | `browser` | `tests/test_browser_ui.py` | Chromium and playwright |

⚠️ **The browser half FAILS rather than skips when playwright is missing**, which
is correct for a gate and does mean `make release-gates` is red until you set it
up. playwright is not a lynceus dependency and is not in `.venv`:

```
PW=~/.local/share/lynceus-playwright
python3.11 -m venv $PW && $PW/bin/pip install playwright
$PW/bin/playwright install chromium
LYNCEUS_PLAYWRIGHT_SITE=$PW/lib/python3.11/site-packages make release-gates
```

⛔ **Not `/tmp`.** This block used to say `/tmp/pw-venv`, and on 2026-08-24 that
cost a session the gate: the box had rebooted, `/tmp` was cleared, and
`make release-gates` was therefore RED for a reason that had nothing to do with
the code. Because the browser half FAILS rather than skips, the symptom is a
red release gate at exactly the moment you are trying to cut a release. Put it
somewhere that survives a reboot.

🪤 **The browser cache is versioned, so a surviving cache is not a working one.**
Same session: `~/.cache/ms-playwright` still held `chromium-1228` from a previous
install, but the freshly resolved playwright (1.62.0) wanted `chromium_headless_shell-1234`
and failed with `Executable doesn't exist at .../chromium_headless_shell-1234/...`.
⇒ Re-run `playwright install chromium` after any playwright upgrade; it is a
no-op when the revision already matches.

⚠️ **Build the venv on the same minor as `.venv` (3.11).** `LYNCEUS_PLAYWRIGHT_SITE`
is injected onto the path of the project interpreter, so a `site-packages` built
by another minor is the wrong ABI for anything compiled.

Measured 2026-08-22: browser gate **6 passed in 21.9s**.
Measured 2026-08-24 from the persistent path above: **8 passed in 28.2s**,
sentinel listing all 8 bodies — the same 8 on `main` at `f4dd3da` and on the
combined tree of PRs #215-#221, neither of which adds a browser test.

⇒ The count moved 6 -> 8 because #209 and #211 each added one on top of the six
#204 shipped. ⭐ Derived from `git log -- tests/test_browser_ui.py`, not from
the PR titles: the first attempt at this line credited #217, which touches the
JS-extension gate and adds no browser test at all.
⇒ [[date-every-number-you-publish]] — a dated measurement, not a contract.

## v1.0.0 release baseline

⭐ **Measured 2026-08-24 on `a7a5598`.** That is the release branch commit, not
the tagged commit: `v1.0.0` points at the squash of this branch onto `main`,
whose source tree is identical to `a7a5598` apart from THIS file. So the numbers
below are a statement about the code the tag ships, taken on the release tree
itself rather than carried forward from an earlier SHA.

⚠️ Said precisely because the alternative is the failure this file keeps
recording: a measurement quoted against a SHA it was not taken at. The import
was also asserted to come from the release worktree before the run, because the
shared `.venv` pins the PRIMARY checkout absolutely and a run from a worktree
silently tests the wrong tree without it.

| Gate | Result |
| --- | --- |
| full suite, local | **4847 passed, 4 skipped, 56 deselected**, exit 0, 32m47s |
| `ruff check .` | All checks passed! |
| CI on the PR head | **11/11 success**, 0 non-success, list non-empty |
| browser crawl (host-only) | **8 passed**, 25.4s, sentinel listed all 8 bodies |
| fresh install (host-only) | **1 passed**, 6m15s, sentinel listed the body |

The install gate landed **23,430 watchlist rows, 16 tables, 16.1 MB** from a real
wizard run in a sandboxed venv. ⭐ The same run measured **3m29s / 23,430 rows**
on a quiet box and **6m15s / 23,430 rows** with the full suite running beside it:
the duration moved by a factor of ~1.8 and the row count did not move at all.
⇒ When this gate is fast, check the ROW COUNT, not the clock. It spent a day
passing in 21 seconds by skipping the import entirely.

⚠️ 23,430 is **lower** than the 23,441 this file's install section used to cite,
while `default_watchlist.csv` GAINED 50 rows. Both are #220: it re-cut the
bundled signatures and widened the importer's metacharacter check to drop
identifiers that are still regex-shaped. That is the count becoming honest, not
data going missing.

The 4 skips are environment, checked by name: `test_packaging.py:19` (python not
on PATH), `test_setup_wizard.py:2037` (a real `/sys/class/bluetooth` exists), and
`test_forms_submit_their_own_defaults.py:204` twice (`/watchful` and `/probes`
render no constrained select). The 56 deselected is exactly 47 `diagnostic` plus
9 host-only (8 browser + 1 install).

---

⭐ **Current CI number, measured 2026-08-22 at `c363a01`** (PR head, so 11 checks
rather than the 10 a push SHA gets; CodeQL reports on pull requests only):

| Leg | Result |
| --- | --- |
| `test (ubuntu-latest, py3.11)` | **4582 passed, 1 skipped, 54 deselected**, 8m08s |
| `test (ubuntu-latest, py3.12)` | **4582 passed, 1 skipped, 54 deselected**, 9m11s |
| `test (ubuntu-24.04-arm, py3.11)` | **4582 passed, 1 skipped, 54 deselected**, 10m30s |
| all checks | **11/11 `completed` + `success`**, list non-empty |

At that SHA the 54 deselected was 47 `diagnostic` plus 7 host-only gates.

⛔ **Do not treat that 7 as the number.** It was 8 within the hour, because #209
added a browser gate. A count of gates rots every time somebody adds one, and a
reader who checks the literal will either get a false alarm or start ignoring it.

The invariant worth holding is not a count, it is **no test carrying a host-only
marker may appear in the default collection**. `tests/test_release_gates.py`
asserts exactly that, by collecting `-m "install or browser"` and the default run
and intersecting them, so it grows on its own when a gate is added. That is the
thing to trust; the numbers above are a dated measurement, not a contract.
⇒ [[date-every-number-you-publish]]

`addopts` carries `-m 'not diagnostic and not browser and not install'`, so the
default suite deselects both. `make release-gates` runs them together; a
command-line `-m` overrides the one in `addopts`, measured in both directions.

⏱️ **The install gate takes about nine minutes.** Measured 2026-08-22: 8m40s, of
which 8m00s is `lynceus-setup` importing the bundled `default_watchlist.csv`,
which is 25 MB and 45,663 rows. Load average was 12 throughout, so a quiet
machine is faster and a Pi much slower.

🪤 ⭐ **That import is also how the gate spent a day reporting success in 21
seconds.** The wizard shells out to `lynceus-import-argus` **by name**. The
harness left the ambient `PATH` alone, so the binary was unresolvable from the
clean venv, `import_bundled_watchlist` took its `FileNotFoundError` branch, and
nobody noticed, because the wizard prints "Bundled threat-data import failed"
and then **exits 0**. The gate now counts rows in `watchlist` rather than
trusting an exit code or a printed line.

⚠️ **That 8-minute import runs against a 600-second kill bound**
(`BUNDLED_IMPORT_TIMEOUT_SECONDS`, `setup/core.py:322`). A first-time user on
slower hardware can lose that race and end up with no threat data and a
zero exit status.

🪤 **A clean venv that inherits `PYTHONPATH` is not clean.** `src/lynceus.egg-info`
on that path makes pip resolve `lynceus` as already installed: it pulls every
dependency, skips the package, exits 0 and writes no console scripts. It matters
here because `PYTHONPATH=<worktree>/src` is the only way to test a worktree
against the shared `.venv`, so the people most likely to run the gate are the
people it would mislead.

⚠️ **A deselected test rots and nothing notices**, so `tests/test_release_gates.py`
carries UNMARKED guards that DO run in CI. They collect the gates without
executing them, assert the default run still excludes them, import the audit
script for real and check the API the gate calls, and prove the hermeticity
guard is looking at the real account rather than the per-test HOME. They are
keyed on `HOST_ONLY_MARKERS` in `tests/conftest.py`, so a third gate is covered
by adding its marker there.

⛔ **`make release-gates` does not trust pytest's exit code.** Measured
2026-08-22: `PYTEST_ADDOPTS=--collect-only make release-gates` exited 0 printing
"1/4626 tests collected" and ran nothing, because collecting nothing
successfully is a success. The target clears `PYTEST_ADDOPTS` and then requires
a sentinel file that an autouse fixture writes for every host-only gate that
actually executes.

### Case-file export caps, measured 2026-08-24 at `fb65d27`

⭐ Spec §11.2 required these to be a measurement, not a guess. Built a database
at every cap (1000 sightings, 200 alerts, 200 evidence snapshots of ~4 KB each,
200 named co-observers) and exported it. Desktop, 12 cores, load average 15, so
a Pi is materially slower.

| pairs cap | pairs | artifacts | zipped | peak alloc | wall |
| --- | --- | --- | --- | --- | --- |
| 500 | 100,000 | 18.15 MB | 0.86 MB | 108.7 MB | 35.2s |
| 200 | 40,000 | 8.12 MB | 0.27 MB | 47.1 MB | 29.7s |
| **100** (shipped) | 20,000 | **4.78 MB** | 0.18 MB | **26.3 MB** | 22.5s |
| 50 | 10,000 | 3.11 MB | 0.13 MB | 16.0 MB | 18.9s |

`MAX_PAIRS_PER_CO_OBSERVER = 100` matches `webui/app.py`'s existing
`_CO_PAIRS_LIMIT`, so the document and the co-observation page show the same
depth of drill-down. The DB layer would allow 500.

`MAX_STREAMED_BYTES = 32 MB` is derived from this: peak allocation ran at about
**5.5x the uncompressed artifact size** across the sweep, so 32 MB of artifacts
implies roughly 175 MB peak, which a 2 GB Pi running the daemon can absorb.

⚠️ **The query cost does not move with the pairs cap: 17 to 21 seconds at every
row of that table.** It is 200 separate per-co-observer queries and that count
is fixed by `MAX_CO_OBSERVERS`, so lowering the pairs cap buys memory, not time.
A worst-case export is therefore a ~20 second HTTP request on this box and
longer on a Pi. ⇒ The CLI is the right tool for a large record, and the UI
refusal names it.

⚠️ **The byte ceiling exists for EVIDENCE, not for the rest.** At the caps the
bundle is 4.78 MB, nowhere near 32 MB. A stored Kismet record has no size limit,
so 200 large snapshots is the only realistic way an export reaches the ceiling.
⇒ [[find-the-threshold-before-inventing-one]]

### Coverage baseline

⭐ **Measured in CI on 2026-08-19 at `d2a1c3d`: 86.86%** — 1534 of 11675
statements unreached, across 58 modules. `--cov-fail-under=85`.

The threshold was taken from the CI job rather than a local run on purpose:
this box skips the Bluetooth-directory test and CI skips the live-Argus one, so
the two measure slightly different line sets.

Least-covered modules at that commit, which is where new tests buy the most:

| module | covered |
| --- | --- |
| `setup/web/steps_kismet.py` | 38% |
| `cli/bootstrap_kismet.py` | 48% |
| `_adapter_descriptors.py` | 60% |
| `webui/server.py` | 68% |
| `bridges/ble.py` | 71% |
| `cli/quickstart.py` | 74% |

⚠️ **The floor catches collapse, not erosion.** A large module falling out of
the run (`app.py`, `poller.py`) moves the total by many points and trips it. A
small module going dark moves it by a fraction of a point and does not — the
per-module table in the run summary is what shows you that.

⚠️ **A covered line is not a tested one.** This file records several guards that
matched a spelling rather than a behaviour, and every one of them counts as
covered.

## Baseline

Taken on 2026-08-02, on Windows with Python 3.11, on the full local suite.

| Gate | Result |
| --- | --- |
| `pytest -q` | 3508 passed, 28 skipped, 50 deselected, ~11 min |
| `ruff check .` | clean |
| `python -m build --wheel` | `lynceus-0.9.4-py3-none-any.whl` |
| `ruff format --check .` | 93 files (22 under `src/`, 70 under `tests/`) |

**From a clone**, measured at `db62433` in a throwaway worktree, which is
what CI and a contributor see:

| Gate | Result |
| --- | --- |
| `pytest -q` | 3024 passed, 27 skipped, 47 deselected, ~11 min |
| `ruff check .` | clean |
| `python -m build --wheel` | wheel written |

The 484-test gap is the eleven withheld files. Quote the clone number when
reporting on anything a reader could reproduce, and say so when you quote the
local one.

**On Linux**, measured at `ef1f566` in a throwaway worktree, on the clone
(118 files), Python 3.11.14, BlueZ 5.72, kernel 7.0.0:

| Gate | Result |
| --- | --- |
| `pytest -q` | 3048 passed, 3 skipped, 47 deselected, 27m09s |
| `pytest -m diagnostic` | 47 passed, 0 failed, 4m54s (was 46 passed / **1 failed**, see below) |
| `ruff check .` | clean |
| `python -m build --wheel` | `lynceus-0.9.5-py3-none-any.whl` |
| `ruff format --check .` | 94 files (22 `src/`, 70 `tests/`, 1 `scripts/`, 1 `docs/`) |

This was the first execution of the suite on Linux, and it is the number to
beat here. Against the Windows clone run it is **+24 passed / -24 skipped**:
the POSIX-only `install.sh`, file-mode and symlink tests converted one-for-one
into live passes. Eleven tests failed on that very first run. All eleven were
test defects that Windows could not structurally expose, fixed in `9b2636c`;
**no product bugs were found**. See that commit message for the mechanisms.

A drop below 3508 (local) or 3048 (Linux clone) is a regression. A **rise** in
skips is usually one too — but not always, and the exceptions are below.

⭐ **Current CI number — measured 2026-08-20 at `416bad5`, the MERGED `main`** that carries
v1.0.0's contents (#182). Published here because a baseline taken on a branch head is how this line
rotted three times; this one is `main` itself.

| Leg | Result |
| --- | --- |
| `test (ubuntu-latest, py3.11)` | **4447 passed, 1 skipped, 47 deselected** — 9m56s |
| `test (ubuntu-latest, py3.12)` | **4447 passed, 1 skipped, 47 deselected** — 7m31s |
| `test (ubuntu-24.04-arm, py3.11)` | **4447 passed, 1 skipped, 47 deselected** — 7m05s |
| all checks at that SHA | **10/10 `completed`+`success`**, 0 cancelled, 0 neutral, list non-empty |

⚠️ **10, not the 11 a PR head gets** — CodeQL reports on pull requests, so it is absent from a
push-to-`main` SHA. Absent is not failed; the conclusions present were enumerated, not counted.

⭐ **Current LOCAL Linux number — measured 2026-08-19 at `754f388`** (this box,
worktree `/home/kev/lw-s3-clock`, `.venv/bin` on `PATH`). ⚠️ `754f388` is the branch head that
squash-merged as **`de46f81`**; the source tree is identical, and `6f24a45` on top of it is
docs-only. Named precisely rather than reported as "main", because the SHA is the whole point of
this table.

| Gate | Result |
| --- | --- |
| `pytest -q` | **4416 passed, 1 skipped, 47 deselected, 0 failed** — 36m48s |
| `ruff check .` | `All checks passed!` |

⚠️ **The 26m20s below and the 36m48s above are the same suite under different contention**, not a
regression: three sessions plus other projects were running on this box. **Do not read the wall
clock as the suite's cost.**

<details><summary>Superseded — <code>2ccbc92</code>, 2026-08-19 (kept: the rate of rot is the lesson)</summary>

| Gate | Result |
| --- | --- |
| `pytest -q` | **4334 passed, 1 skipped, 47 deselected, 0 failed** — 26m20s |
| `pytest -m diagnostic` | **47 passed**, 0 failed, 4335 deselected — 3m37s |
| `ruff check .` | `All checks passed!` |
| `python -m build --wheel` | `lynceus-0.9.5-py3-none-any.whl` |

</details>

The one skip is the good one: `test_setup_wizard.py:2018` — it skips *because* a
real `/sys/class/bluetooth` is present. **Skip count 1, and check WHICH test.**

⭐ **Local and CI both totalled 4416 — identical, and that is the expected
result, not a coincidence.** They trade one skip for one run: CI skips the live
Argus test, this box skips the missing-Bluetooth-dir branch. **That the local
skip was the Bluetooth one is the proof the Argus cross-repo gate actually ran**
— which only happens because the worktree sat at `/home/kev/lw-gate`, so
`parents[1].parent` resolved to `/home/kev/argus`. Under `.claude/worktrees/` it
would have skipped and the total would have read 4333.

⚠️ **26m20s against CI's 8m46s is contention, not the suite.** Measured during
this run: another project's Go test suite at 90–108% CPU across many processes,
`/proc/pressure/io` full avg60 ≈7–12%, pytest in `D` on `jbd2_log_wait_commit`.
It sat at 9% for 22 minutes and then did 165 tests in 30 seconds. **A slow run
here is not a hung one.**

**Previous:** 3281 passed at `feat/csp` (2026-08-13, 19m46s), skip
`test_setup_wizard.py:1955`.

Previous: 3249 at `d5c27e2` (2026-08-07). The +32 is the CSP guards
(`test_webui_csp.py`, `test_setup_web_csp.py`), the delivery-failure suite
(`test_notify_delivery.py`), and migration 024's roundtrip parametrization.

⚠️ **Do not run delegates or other heavy I/O alongside a gate.** Measured
2026-08-13 while three `codex exec` packets ran concurrently: pytest sat in
`D` state at 6.6% CPU with `/proc/pressure/io` at ~7% full stall and took
18m09s against a quiet-box 19m04s — but got only 8% through in the first 4.5
minutes, which reads exactly like a hang and is not one. A later run stalled
at 8% for over 5 minutes with `jbd2/nvme0n1p2-8` (the ext4 journal) blocked in
`D`, caused by other sessions on the same disk. **Check `grep full
/proc/pressure/io` and the process state before diagnosing a slow run.**

⭐ **CURRENT BASELINE — always quoted WITH the SHA it was measured at.**

| | |
|---|---|
| SHA | **`acd8ace`** (2026-08-18) |
| local `pytest -q`, Linux, Python 3.11 | **4225 passed, 2 skipped, 47 deselected** — 39m03s |
| `ruff check .` | clean |

Measured in a **throwaway worktree at a committed SHA**, `git status` clean, on
the local tree (not the clone). Both skips print a reason and are expected here:
`test_packaging.py:19` (python not on PATH) and `test_setup_wizard.py:2018`
(a real `/sys/class/bluetooth` is present). **Skip count 2 — check WHICH tests.**

⚠️ The wall-clock is not comparable to earlier entries: this box was running
another project's delegate fleet throughout, at load 7–36. See the I/O-pressure
trap above before reading 39m as a regression.

⛔ **The entry below sat here from 2026-08-02 to 2026-08-18 while the suite grew
by 717 tests**, so anything checking "did we drop below the baseline" was
comparing against a number that had been meaningless for two weeks. A stale
baseline does not fail loudly; it silently stops being able to detect anything.
⇒ **Re-measure when you notice the gap, not when something breaks.**

### Previous baseline (superseded 2026-08-18)

| | |
|---|---|
| SHA | **`6f24a45`** |
| CI, Python 3.11 (x86-64) | **4416 passed, 1 skipped, 47 deselected** |
| CI, Python 3.12 (x86-64) | **4416 passed, 1 skipped, 47 deselected** |
| CI, Python 3.11 (**arm64**) | **4416 passed, 1 skipped, 47 deselected** |
| run | <https://github.com/kevwillow/lynceus-warden/actions/runs/32325722053> |

⚠️ **Superseded numbers kept below rather than deleted**, because the rate of rot is the lesson:
`2ccbc92` read **4334** and was published on 2026-08-19; five merges later the same day it read
**4416**. A SHA-stamped number does not become false, it becomes *old* — which is why the SHA is
there and why a bare total is not.

Measured 2026-08-19. The one CI skip is the expected one and was **read, not counted**:
`tests/test_import_argus.py:3364` — *"live Argus CSV not found"*. CI does not and should not have it.

⚠️ **CI is no longer a 4-minute job.** It was 4m22s at `63aa497` and is **8m01s–8m46s** at `2ccbc92`;
the suite grew by **811 tests** over the same stretch. The old "CI is 3-4× faster than this box"
note below is still directionally right but its absolute figures are history.

**Previous baseline:** 3523 passed, 1 skipped at `63aa497`
(<https://github.com/kevwillow/lynceus-warden/actions/runs/31844656916>), CI 4m26s / 4m22s.

⛔ **A bare total is a claim that quietly stops being true at the next merge.**
This line has now rotted three times — 3024 → 3508 → 3294 — and the 3294 stood
here for twelve days while main was at 3518, in the file everyone cites *before*
trusting a green run. So the SHA is not decoration: **if the SHA above is not
`origin/main`, this number is history, not a baseline.** Re-measure rather than
quoting it.

⇒ **Expect the current total to be HIGHER than the figure above.** A lower one
is worth asking about before it is worth explaining. Same treatment the README
now uses for the same number, for the same reason.

**Historical, for the drift record:** `3294 passed, 1 skipped` at PR #24
(2026-08-14, local ~19m39s / CI 4m06s+4m04s); `3283 passed` on main before #24;
`3281` at `feat/csp`; `3249` at `d5c27e2`.

🪤 **Local and CI both report skip count 1, and it is a DIFFERENT TEST each
time.** This is the sharpest form of the skip-count trap:

| | the one skip |
|---|---|
| Local (this box) | `test_setup_wizard.py:1955` — real `/sys/class/bluetooth` is present, so the missing-dir branch cannot be exercised |
| CI (clean runner) | `test_import_argus.py:3333` — no live Argus CSV, which CI does not and should not have |

⇒ **A matching skip count proves nothing. Read the reason.**

⚠️ **CORRECTION (2026-08-14).** An earlier version of this note claimed the
two environments' totals "differ by two, because each runs tests the other
cannot". **That is false.** The totals are identical — the two environments
trade one skip for one run, so they cancel. The claim came from comparing CI
against a **stale** local figure (3281, measured on an older tree) and reading
the difference as environmental. Both numbers above are from the same commit.
⇒ **Before attributing a delta to environment, confirm both sides were
measured on the same tree.** A stale baseline invents differences that are not
there, and an explanation that fits a wrong number is worse than no
explanation.

⚠️ **CI is 3-4× faster than this box (4-5 min vs ~20).** That is contention
here, not a slow suite — see the I/O warning above. Do not treat the local
runtime as the suite's cost.

⚠️ **`cancel-in-progress` means a rapid series of pushes never gets a full
test run.** Measured on PR #19: three consecutive CI runs were cancelled by the
next push, so the ~20-minute job only completed once pushing stopped. The
setting is correct — a superseded commit should not hold a runner — but *wait
for the run that matters* before reading anything into a green board.

⚠️ **Editing source mid-run invalidates the run.** Python caches imported
modules, so a `src/` edit after collection is NOT picked up: the suite keeps
testing what was on disk at start and reports green for code you no longer
have. If you must edit, kill the run and relaunch — cheap early, and the only
honest option once it matters.

⚠️ **Runtime varies with what else the box is doing, a lot.** The same suite
measured 16m12s and 17m24s on different runs, and crawled at roughly a third of
that while two qemu VMs and a 300-round SQLite fuzz were competing for the
disk — `wchan` showed `jbd2_log_wait_commit`, i.e. blocked on the ext4 journal,
with `/proc/pressure/io` reporting ~11% full stall. **Do not read a slow run as
a hang, and do not start heavy I/O of your own alongside a gate.** Check
`grep full /proc/pressure/io` and the process state (`D` = blocked on I/O)
before diagnosing.

⚠️ **The local/clone split above no longer holds, and the 484-test gap is
history.** All 116 files under `tests/` are tracked now, and a `git worktree`
of `main` produced *exactly* the same 3244 as the working checkout — measured,
after predicting it would come out lower and being wrong. Do not expect a
worktree or clone to run fewer tests; if it does, something is genuinely
missing rather than withheld.

⛔ **Put `.venv/bin` on `PATH` before running the suite.** Without it
`tests/test_packaging.py` skips itself with "python not on PATH" and the skip
count reads **2** — which looks exactly like the lost-Argus-gate failure warned
about below, but is a different cause entirely. **Skip 1 is correct; always
check WHICH test skipped before concluding anything.**

⛔ **Long test runs get killed if they are a tracked background task.** Measured
2026-08-06: the same 16-minute run completed once, then was killed twice at 3
and 7 minutes with no test output, no OOM record, and 9 GB free. Detach it so
nothing tracked can reach it:

```bash
setsid nohup env PATH=".../.venv/bin:$PATH" LYNCEUS_ARGUS_CSV=... \
  bash -c 'python -m pytest -q > gate.log 2>&1; echo EXIT=$? > gate.done' \
  >/dev/null 2>&1 < /dev/null &
disown
```

then wait on `gate.done` with a *disposable* loop. The waiter may be killed —
it was, three times — but the detached run survives and its result is on disk.

### ⛔ Cite SHAs that are on `main`, not the branch SHA you measured at

Every PR here lands with `gh pr merge --rebase`, which **rewrites every commit
SHA**. So a doc written on a branch that cites its own commits is dangling the
moment it merges, and a reader who tries to check the measurement gets
`unknown revision`. This has already happened to this file and to
`docs/AUDIT_REGISTER.md`: nine citations across the two, of which six were
repointed once the mapping was provable.

Measure at the branch SHA, then **repoint the citation to the merged SHA before
or immediately after the merge** — the merged commit has the same subject, and
`git log origin/main --format='%h %s' | grep -F "<subject>"` finds it.

🪤 **Check the tree, not just the subject, before repointing.** A rebase onto a
main that has moved produces a commit with the same subject and a *different
tree*, and silently re-pointing a measurement at a different tree is worse than
leaving it dangling. Only substitute when
`git rev-parse <old>^{tree}` equals `git rev-parse <new>^{tree}`.

⚠️ Three citations below are deliberately left dangling for that reason:
`9b2636c`, `eca081a` and `ef1f566` are pre-merge branch SHAs whose on-main
counterparts (`989d41b`, `fd20111`, `3a10f56`) carry different trees. The
numbers recorded against them were measured on the branch, not on what landed.

### Current number to beat — repo root, 2026-08-02, at `44ccf02`

`feat/ui-integration`, run from `/home/kev/lynceus-warden` with `.venv/bin` on
`PATH`. **This is the number to compare against, not the `eca081a` one below**,
which records an `import_argus` failure that `962dab6` has since fixed.

| Gate | Result |
| --- | --- |
| `pytest -q` | **3083 passed, 1 skipped**, 47 deselected, 0 failed, 19m04s |
| `pytest -m diagnostic` | **47 passed**, 0 failed, 3m33s |
| `ruff check .` | clean |
| `python -m build --wheel` | `lynceus-0.9.5-py3-none-any.whl` |
| `ruff format --check .` | 93 files — red by design, unchanged across the branch |

The single skip is the good one: `test_setup_wizard.py:1955` skips *because* a
real BT adapter is present. Both figures were measured under a load average of
~15 on 12 cores, so treat the wall-clock times as an upper bound.

⚠️ **Both of the gates that had not been run when the branch was written came
back red**, and neither was reachable from a targeted test selection:

- `pytest -q` at `a2d35db` → 1 failed. A `/settings` fix had been applied to one
  of the two template branches that print the same command.
- `pytest -m diagnostic` at `e1ceadc` → 46 passed, 1 failed. The dashboard
  restructure blinded `test_diag_home_ack_flow`'s extractor.

That is the second time the diagnostic marker has hidden a red test in this
repo. Run **both** gates before believing a branch, every time.

### Measured from the repo root earlier the same day, at `eca081a`

Same host and interpreter, but run from `/home/kev/lynceus-warden` itself with
`.venv/bin` on `PATH`, rather than from a throwaway worktree:

| Gate | Result |
| --- | --- |
| `pytest -q` | **3060 passed, 1 FAILED, 1 skipped**, 47 deselected, 21m53s |
| `pytest -m diagnostic` | 47 passed, 0 failed, 4m54s |
| `ruff check .` | clean |
| `ruff format --check .` | 94 files (22 `src/`, 70 `tests/`, 1 `scripts/`, 1 `docs/`) |

+12 passes over the worktree baseline are the new BLE-G8 tests. The skip count
falls from 3 to 1 for two different reasons, and **only one of them is good**:

- `test_packaging.py` passes because `.venv/bin` was on `PATH`. Good.
- `test_import_argus.py` stopped skipping and started **failing**. Not good, and
  not a regression either — see the trap below.

⛔ **Running the gates in `.claude/worktrees/` silently disables the cross-repo
Argus test.** `test_cross_repo_live_argus_csv_imports_without_errors` locates the
live dataset relative to its own file:
`Path(__file__).parents[1].parent / "argus" / "exports" / "argus_export.csv"`.
From the repo root that resolves to `/home/kev/argus/exports/argus_export.csv`,
which has existed since 2026-07-28. From `.claude/worktrees/verify` it resolves
to `.claude/worktrees/argus/...`, which does not exist, so the test skips itself
with "live Argus CSV not found".

The baseline above therefore recorded it as a benign environment skip when it was
actually a **failing test hidden by the recommended verification procedure**. The
Commands section of this file tells you to run gates in a worktree; that
instruction is what removed the gate.

That is the **third** instance of one pattern in this repo, and the pattern is
worth naming: *how* you invoke the suite silently changes which gates exist.
`test_packaging.py` vanishes without `python` on `PATH`; the whole diagnostic
suite vanishes behind `-m 'not diagnostic'`; this one vanishes inside a
worktree. All three fail open — no error, no red, just a smaller suite. **Read
the skip reasons. A skip is a gate that did not run.**

The failure itself is pre-existing and is not a Lynceus regression:
`src/lynceus/cli/import_argus.py` and `tests/test_import_argus.py` are
byte-identical between `b5f9127` and `eca081a`. It is Argus-side drift, and it
needs a decision rather than a quick fix:

- 11 of 43116 rows are rejected with `confidence is required`.
- The export announces `schema_version='33'`; the accept-list is `25`–`31`.

So the export has moved two schema versions ahead of what Lynceus admits, and
`confidence` appears to have become optional or absent upstream. Whether the
fix is to widen the accept-list, relax the `confidence` requirement, or treat
these rows as legitimately bad data is a product call, not a test fix.

The formatter number is worth splitting when you read it. The `src/` figure
is the one that matters: it was 23 before a stray blank line in
`bridges/ble.py` pushed it to 24, which is how that drift was caught, and it
is back to 22 now. The `tests/` figure only became visible when the suite was
published, because ruff respects `.gitignore` and had been skipping the whole
directory.

The Windows "93" and the Linux "94" are the same source state, not drift.
93 is `22 src/ + 70 tests/ + 1 scripts/` — the `scripts/` file is the one the
"22 + 70" phrasing above silently omits. The 94th was a **Markdown** file:
ruff 0.16.1 formats Python fenced inside `.md`, which older ruff did not, so a
plan document under `docs/superpowers/` counted.

⚠️ **That directory was removed from the repo on 2026-08-21 and gitignored**, so
the Markdown file no longer contributes at all.

⛔ **Do not read 93/94 as a current number.** Measured 2026-08-21: `ruff format
--check .` reports **176 would be reformatted, 111 already formatted**. The
totals here drifted because the suite grew from roughly 3,200 tests to 4,560,
which is exactly the reason the note above says to compare the `src/` figure
across versions rather than the total. The split is the useful part; the sum is
not.

## The traps this repo actually has

**The suite is not all in the repo.** Eleven files stay gitignored because
they embed the capture adapter's MAC (`wlx<mac>` interface names, the
`00:c0:ca` OUI) or the rig account name. They are listed by name in
`.gitignore`. A clone therefore runs 118 files, not 129, and cannot reach the
3508 baseline above, which was measured on the full local suite. **State
which set you ran.** On a clone, `pytest -q` exits 5 with "no tests
collected" only if `tests/` is missing entirely; a clone has tests, so a 5
means something else broke.

**50 tests are deselected on every run.** `addopts` carries
`-m 'not diagnostic'`. That is deliberate: the diagnostic suite is
observation-only and asserts nothing about content. Run it explicitly with
`pytest -m diagnostic` before a push. A green default run says nothing about
those 50.

⛔ **That warning has already come true. v0.9.5 shipped with a failing
diagnostic test.** `tests/test_diag_home_ack_flow.py::test_diag_home_ack_flow`
asserted that every `hx-*` hit across the whole template directory came from
`index.html`. Because the default run deselects it, no release gate ever saw
it fail. Platform-independent (it failed on Windows too) and not caused by the
Linux fixes: `b5f9127..ef1f566` touches no template or webui file.
**Fixed now** by narrowing the assertion to the home surface it is actually a
diagnostic of.

Two corrections to how that was first written up, because both change the
lesson:

- **It was not `4d135ac`.** The `_alert_row.html` extraction was blamed, but
  the assertion globs *every* `*.html` in the templates directory, partials
  included. `_device_actions.html` gained `hx-post` at `7cb6667` (2026-05-30),
  six days before `d886a18`/`4d135ac` (2026-06-05). The clause it violated
  ("no other surface gained an htmx affordance") had been false for a week
  before the commit that got the blame.
- **It never passed in this repo.** The file entered git at `d829533`, the
  commit that published the suite. It arrived already red. So this is not a
  green test that drifted; it is an untracked local test that was published
  without anyone running the marker it carries.

The generalisable point is unchanged and is the reason this section exists:
**a marker that excludes tests from the default run excludes them from every
gate that matters.** Run `pytest -m diagnostic` before a push.

**28 skips are expected on Windows** and are POSIX-only `install.sh`,
file-mode, and symlink checks. On Linux that number should drop and the pass
count should rise. A Windows run is not evidence about the systemd or
installer paths. Confirmed: on Linux the clone run skips 3, not 27.

**A rise in skips is not automatically a regression.** Two of the three Linux
skips are caused by the host being *better* equipped, not worse.
`test_setup_wizard.py:1958` skips precisely *because* `/sys/class/bluetooth`
exists — with a real BT adapter plugged in it cannot exercise the missing-dir
branch. Read each skip reason before calling a rise a regression.

**No single run as one user can be fully green.** Some tests need root (the
`--system` scope paths); `test_install_sh.py:232` explicitly skips when the
runner *is* root, because it exercises the non-root pass-through. Running as
an ordinary user is the right default and is what the numbers above were
measured with.

⚠️ **How you invoke the venv changes the result.** Running
`./.venv/bin/python -m pytest` without activating leaves `python` off `PATH`,
and on a distro with no bare `python` (Ubuntu, Debian) `test_packaging.py:19`
skips itself with "python not on PATH" — silently dropping the wheel-build
gate with no failure. Activate the venv, or prepend `.venv/bin` to `PATH`.
That single test is the difference between the 3048/3 above and 3049/2.

**The formatter gate is red on purpose.** `make lint` runs only
`ruff check .` so it stays a gate that is expected to pass. Reformatting all
23 files is a dedicated pass nobody has done; doing it inside a feature
change buries the change in whitespace. Do not "fix" it opportunistically.

**The BLE scan path is `# pragma: no cover` and rig-only.** No amount of
green here says the bridge captures anything. That needs hardware.

**`bleak` is an optional extra.** Without `pip install 'lynceus[ble]'` the
bridge is inert by design and the tests still pass, so a green run is not
evidence the bridge works.

## Where to run

Not in the working checkout. At a committed SHA in a throwaway worktree:

```sh
git worktree add .claude/worktrees/verify --detach <sha>
cd .claude/worktrees/verify
git status --short          # must be empty before believing anything
ln -s ../../../.venv .venv  # deps, rather than reinstalling
```

Remove the `.venv` symlink **before** `git worktree remove --force`, or you
risk deleting through it into the real venv. On Windows `rm -f` refuses the
link because it resolves to a directory; use `rm -rf` on the link path or
delete the worktree with the link already gone.
