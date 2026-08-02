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

A drop below 3508 is a regression. So is a **rise** in the 28 skips, even
though the run stays green.

The formatter number is worth splitting when you read it. The `src/` figure
is the one that matters: it was 23 before a stray blank line in
`bridges/ble.py` pushed it to 24, which is how that drift was caught, and it
is back to 22 now. The `tests/` figure only became visible when the suite was
published, because ruff respects `.gitignore` and had been skipping the whole
directory.

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

**28 skips are expected on Windows** and are POSIX-only `install.sh`,
file-mode, and symlink checks. On Linux that number should drop and the pass
count should rise. A Windows run is not evidence about the systemd or
installer paths.

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
