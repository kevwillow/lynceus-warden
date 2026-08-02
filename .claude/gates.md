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

The formatter number is worth splitting when you read it. The `src/` figure
is the one that matters: it was 23 before a stray blank line in
`bridges/ble.py` pushed it to 24, which is how that drift was caught, and it
is back to 22 now. The `tests/` figure only became visible when the suite was
published, because ruff respects `.gitignore` and had been skipping the whole
directory.

The Windows "93" and the Linux "94" are the same source state, not drift.
93 is `22 src/ + 70 tests/ + 1 scripts/` — the `scripts/` file is the one the
"22 + 70" phrasing above silently omits. The 94th is a **Markdown** file:
ruff 0.16.1 formats Python fenced inside `.md`, which older ruff did not, so
`docs/superpowers/plans/2026-07-28-ble-continuity-decoder.md` now counts.
Compare the `src/` figure across versions, not the total.

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
