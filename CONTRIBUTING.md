# Contributing to Lynceus Warden

Thanks for looking. This is a personal-safety tool, so the bar for a change is
"does this hold up when someone is relying on it in the street", not "does it
pass".

## What this project wants

**Passive detection only.** Lynceus listens. It does not jam, spoof, deauth,
inject, or interfere with any device it hears, and that includes the
surveillance equipment it is built to spot. A patch that transmits is out of
scope no matter how well written.

**Honest claims.** Every user-facing sentence should be checkable against the
code, and several past defects were prose rather than logic: a page that said
"this view is empty" while showing retained history, a settings card promising a
device "will raise alerts on every future sighting" while no enabled rule
consulted the table. If you change behaviour, change the sentence that describes
it in the same commit.

**Silence must never be ambiguous.** The worst failure this tool can have is
appearing healthy while detecting nothing, because the operator reads silence as
safety. Anything that can stop the capture → match → alert → notify path should
say so loudly rather than fail quietly.

## Getting set up

Linux is the supported target. Python 3.11 is the floor.

```sh
git clone https://github.com/kevwillow/lynceus-warden
cd lynceus-warden
python3.11 -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
```

## Running the gates

```sh
pytest -q        # the suite -- roughly 18 minutes
ruff check .     # must be clean
python -m build --wheel
```

CI runs these on 3.11 and 3.12, and on arm64 as well as x86-64, for every pull
request.

It also runs five gates you cannot usefully run from a clean clone, because
each needs a tool or a privilege a contributor's checkout does not have. You
are not expected to run them locally. If one of them turns your PR red, this
is what it is telling you:

| CI gate | What it checks | Why not local |
| --- | --- | --- |
| `integrity / web-assets` | every tracked `.js` parses (`node --check`) | needs node |
| `integrity / systemd-units` | every unit passes `systemd-analyze verify` | needs systemd, and root to stub the `ExecStart` targets |
| `integrity / config-examples` | the shipped `config/*.yaml` pass `lynceus-validate` | needs the package installed, not just importable |
| `integrity / workflows` | the workflows themselves lint (`actionlint`) | needs the actionlint binary |
| `packaging` | the built **wheel** installs and its migrations apply | `pytest` runs against `src/`, so it cannot see a packaging bug |

⚠️ `integrity / systemd-units` is keyed on the verifier's **output**, not its
exit status. A malformed directive value makes systemd print a parse warning,
silently drop the directive, and exit **0**. The unit then runs unhardened
while an exit-code check calls it fine.

### Traps that make a green run mean less than it looks like

These have each cost real debugging time. `.claude/gates.md` has the full
history; these are the ones that will bite a contributor.

- **`ruff format --check` is red by design.** It is not part of `make lint` and
  CI does not gate on it. Do **not** reformat the repo to make it pass. That
  buries real changes under whitespace. Match the surrounding style instead.
- **Check *which* test skipped, never the skip count.** Two different causes
  produce a skip count of 2 and look identical: `python` missing from `PATH`
  (which makes `tests/test_packaging.py` skip itself), and the cross-repo Argus
  test not finding its CSV. `-ra` is on by default, so the reasons are printed.
  Read them.
- **The live-Argus test needs a sibling-repo export.** Set
  `LYNCEUS_ARGUS_CSV=/path/to/argus_export.csv` to run it locally. It skips in
  CI, which is expected.
- **Run the gates from the repo root, not a worktree.** A worktree relocates the
  path the cross-repo test resolves. It then silently *skips* rather than
  fails, so the suite looks better than the repo root's baseline.
- **Don't start heavy I/O alongside a run.** Measured: three concurrent
  subprocesses starved the suite into `D` state at 6.6% CPU and roughly tripled
  its wall clock. A slow run is not a hung one. Check
  `grep full /proc/pressure/io` before diagnosing.

## Writing tests

The suite is large (~3,250 tests) and the gaps that matter are not coverage
gaps, they are **failure-path** gaps. Two habits are worth more here than volume:

**Plant the defect.** A test you have not watched fail proves nothing. Break the
thing on purpose, confirm the test catches it, then restore. This is not
ceremony. A regression guard for a confirm-dialog bug was recently written,
passed 12/12, and was then found to be inert because the form carrying the
defect never rendered in its fixture. Guarding against a defect is not the same
as rendering the code that carries it.

**A double that can only succeed cannot test failure.** Every notifier test
double in this repo returned `True` unconditionally for a long time, which is
precisely why a defect that dropped alerts on a transient network error survived
a green suite.

Mark browser-dependent behaviour honestly. Some things (CSP enforcement, layout,
column persistence) genuinely cannot be asserted server-side. Say so in the
docstring rather than writing an assertion that passes for the wrong reason.

## Pull requests

- Branch from `main`, keep the change focused, and explain **why** in the commit
  message. This codebase's comments carry a lot of reasoning, and that is
  deliberate.
- Include the gate output in the PR description.
- If you found something you are not fixing, put it in `BACKLOG.md` rather than
  leaving it in a comment.

## Security

Please do **not** open a public issue for a vulnerability. See
[SECURITY.md](SECURITY.md) for how to report privately, and note the specific
data-at-rest concerns documented there. Probe-SSID history is a partial record
of where *bystanders* have been, not just the operator.

## Licence

Contributions are accepted under [AGPL-3.0-or-later](LICENSE). A separate
commercial licence exists ([COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md)); by
contributing you agree your work may be offered under both.
