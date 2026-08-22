"""The path a NEW USER takes: build the wheel, install it clean, run the wizard, serve the UI.

CI already proves the wheel installs and that every console script's `--help`
exits 0. Nothing proved that a person who runs `lynceus-setup` ends up with a
working system, and that is the only path a first-time user ever takes.

What this drives, in order, all against a wheel rather than the checkout:

    python -m build --wheel        the artifact a user actually installs
    pip install into a clean venv  no dev extras to mask a missing runtime dep
    lynceus-setup --user           the interactive wizard, answers on stdin
    lynceus-validate               the config the wizard just wrote
    lynceus-ui                     started for real, and a route fetched

The exit code IS the finding:

    0   the whole path works
    2   the wizard completed but the config it wrote does not validate
    3   the install did not produce a wizard to run
    4   the UI did not serve

⛔ 3 covers the wheel build, the install and the wizard itself. It has always
done so; the line here used to say "the wizard did not complete", which sent a
reader looking at the wizard for a failure that was two stages earlier.

REFUSES to run against a real home. Every step is done under a redirected HOME,
because an earlier version of the test suite wrote into the operator's actual
``~/.config/lynceus`` and the only reason nothing was destroyed was an overwrite
prompt added for an unrelated reason.

The wizard is interactive and has no --defaults flag, so the answers are fed on
stdin. That sequence is the brittle part and it is deliberately asserted rather
than assumed: if a prompt is added or reordered, this fails with the transcript
instead of hanging or writing a half-configured system.

Needs a machine with at least one capture interface, so CI cannot run it.

⭐ ``run_fresh_install()`` returns the EVIDENCE, not just the code, so a caller
can assert on what the run observed. An exit code alone cannot distinguish a
working install from a run that quietly did nothing, and this is now called from
``tests/test_release_gates.py`` where that distinction is the whole point.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

#: Answers, in prompt order, measured 2026-08-21 against the shipped wizard.
#: Declining the Bluetooth source keeps this deterministic: the prompt after it
#: enumerates real adapters, and the count differs per machine.
ANSWERS = [
    "",             # Kismet URL, accept the default
    "testkey123",   # API token, must be non-empty or the wizard loops
    "1",            # capture interface, picked by NUMBER not name
    "n",            # add a Bluetooth capture source
    "", "", "", "", "", "", "", "", "", "",
]


@dataclass
class FreshInstall:
    """What the run actually observed, stage by stage.

    ⚠️ Every path here points INSIDE a ``TemporaryDirectory`` that is already
    gone by the time this is returned. The paths are for the failure message.
    **Assert on the values, never by stat-ing the paths**, or the assertion
    passes for the wrong reason on a run that never created anything.
    """

    code: int = 3
    repo: Path | None = None
    sandbox_home: Path | None = None
    #: Filename of the wheel that was built, e.g. ``lynceus-1.0.0-py3-none-any.whl``.
    wheel: str | None = None
    #: ``lynceus*`` entry points the install put in the venv's bin, sorted.
    #: Empty means pip installed the dependencies and skipped the package.
    console_scripts: tuple[str, ...] = ()
    #: Names the wizard left in the config dir, sorted. Empty means it wrote nothing.
    config_files: tuple[str, ...] = ()
    #: Last line ``lynceus-validate`` printed, which carries its error count.
    validate_summary: str | None = None
    #: HTTP status from ``/healthz.json``. 0 means the UI never answered.
    healthz_status: int = 0
    healthz_body: str = ""
    #: Size of the database the UI created. -1 means the file was absent.
    db_bytes: int = -1
    #: Whatever failed, in the words of the thing that failed. Empty on success.
    failure: str = ""
    transcript: list[str] = field(default_factory=list)


def clean_env(**overrides) -> dict[str, str]:
    """The ambient environment with ``PYTHONPATH`` taken out.

    ⛔ **A venv that inherits PYTHONPATH is not a clean venv**, and this whole
    harness rests on that word. Measured 2026-08-22: with
    ``PYTHONPATH=<checkout>/src`` set, the ``src/lynceus.egg-info`` on that path
    makes pip resolve ``lynceus`` as ALREADY INSTALLED. It installs every
    dependency, skips the package, exits 0, and writes no console scripts. The
    run then dies on a missing ``lynceus-setup`` two stages later, which reads
    as "the wizard is broken".

    That is not an exotic setup. This repo is worked from git worktrees and the
    shared ``.venv`` pins the primary checkout's ``src`` absolutely, so
    ``PYTHONPATH=<worktree>/src`` is the standard way to test a worktree at all.
    The people most likely to run this gate are the people it would mislead.
    """
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env.update(overrides)
    return env


def run(cmd, **kw):
    kw.setdefault("env", clean_env())
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def run_fresh_install() -> FreshInstall:
    """Drive the whole new-user path once and report what happened.

    Prints as it goes, because under pytest the capture is shown on failure and
    a five stage failure is unreadable without knowing which stage it was.
    """
    ev = FreshInstall(repo=REPO)
    real_home = Path(os.path.expanduser("~")).resolve()

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        home = tmp / "home"
        (home / ".config").mkdir(parents=True)
        ev.sandbox_home = home

        # The guard comes BEFORE anything runs, not after. A harness that
        # checks it is safe only once it has already written is not a guard.
        assert real_home not in home.resolve().parents, "refusing to run against a real home"
        env = clean_env(
            HOME=str(home),
            XDG_CONFIG_HOME=str(home / ".config"),
            XDG_DATA_HOME=str(home / ".local" / "share"),
            XDG_STATE_HOME=str(home / ".local" / "state"),
        )

        print(f"tree under test: {REPO}")
        print(f"sandbox home:    {home}\n")

        print("[1/5] building the wheel")
        dist = tmp / "dist"
        r = run([sys.executable, "-m", "build", "--wheel", "--outdir", str(dist)], cwd=REPO)
        wheels = sorted(dist.glob("*.whl"))
        if r.returncode != 0 or not wheels:
            print(r.stdout[-2000:], r.stderr[-2000:])
            ev.failure = f"wheel build exited {r.returncode}, produced {len(wheels)} wheels"
            ev.code = 3
            return ev
        ev.wheel = wheels[0].name
        print(f"      {wheels[0].name}")

        print("[2/5] installing into a clean venv")
        venv = tmp / "venv"
        run([sys.executable, "-m", "venv", str(venv)])
        bins = venv / "bin"
        r = run([str(bins / "pip"), "install", "-q", str(wheels[0])])
        if r.returncode != 0:
            print(r.stdout[-2000:], r.stderr[-2000:])
            ev.failure = f"pip install of {wheels[0].name} exited {r.returncode}"
            ev.code = 3
            return ev

        # ⛔ Check the console scripts HERE, where the cause is, rather than
        # letting the next stage die on a missing executable. pip exits 0 when
        # it decides the package is already installed and only pulls the
        # dependencies, and the first visible symptom of that is a
        # FileNotFoundError on `lynceus-setup` that reads as a broken wizard.
        ev.console_scripts = tuple(
            sorted(p.name for p in bins.iterdir() if p.name.startswith("lynceus"))
        )
        if not ev.console_scripts:
            installed = sorted(p.name for p in bins.iterdir())
            print(f"      pip exited 0 but installed no lynceus scripts. bin/ holds: {installed}")
            ev.failure = (
                f"pip exited 0 and wrote no lynceus console scripts into {bins}. "
                f"It installed the dependencies and skipped the package, which is what "
                f"pip does when something already on sys.path advertises lynceus."
            )
            ev.code = 3
            return ev
        print(f"      {len(ev.console_scripts)} console scripts: {', '.join(ev.console_scripts)}")

        print("[3/5] driving lynceus-setup with answers on stdin")
        r = subprocess.run(
            [str(bins / "lynceus-setup"), "--user", "--skip-probes"],
            input="\n".join(ANSWERS) + "\n",
            capture_output=True, text=True, env=env, timeout=300,
        )
        cfg = home / ".config" / "lynceus" / "lynceus.yaml"
        ev.transcript = r.stdout.splitlines()[-25:]
        if r.returncode != 0 or not cfg.exists():
            print("      wizard did not complete. Transcript tail:")
            print("\n".join(("        " + ln) for ln in ev.transcript))
            print("      ⛔ If a prompt was ADDED or REORDERED, ANSWERS above is stale.")
            ev.failure = (
                f"wizard exited {r.returncode} and lynceus.yaml "
                f"{'exists' if cfg.exists() else 'was never written'}. "
                f"If a prompt was added or reordered, ANSWERS is stale."
            )
            ev.code = 3
            return ev
        ev.config_files = tuple(sorted(p.name for p in (home / ".config" / "lynceus").iterdir()))
        print(f"      wizard exit 0, wrote: {', '.join(ev.config_files)}")

        print("[4/5] validating the config the wizard wrote")
        r = run([str(bins / "lynceus-validate")], env=env)
        ev.validate_summary = (r.stdout.strip().splitlines() or ["ok"])[-1][:90]
        if r.returncode != 0:
            print((r.stdout + r.stderr)[-2000:])
            ev.failure = f"lynceus-validate exited {r.returncode}: {ev.validate_summary}"
            ev.code = 2
            return ev
        print(f"      {ev.validate_summary}")

        print("[5/5] serving the UI and fetching a route")
        # ⛔ lynceus-ui takes --config and nothing else. An earlier version of
        # this harness passed --port and the UI exited 2 with a usage message,
        # which read as "the UI is broken" when the harness was. The port comes
        # from the config the wizard wrote, so read it from there rather than
        # choosing one and hoping they agree.
        m = re.search(r"^ui_port:\s*(\d+)", cfg.read_text(), re.M)
        port = int(m.group(1)) if m else 8765
        ui = subprocess.Popen(
            [str(bins / "lynceus-ui"), "--config", str(cfg)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env,
        )
        try:
            for _ in range(40):
                time.sleep(0.5)
                try:
                    url = f"http://127.0.0.1:{port}/healthz.json"
                    resp = urllib.request.urlopen(url, timeout=3)
                    ev.healthz_status, ev.healthz_body = resp.status, resp.read().decode()[:120]
                    break
                except Exception:
                    if ui.poll() is not None:
                        break
            if ev.healthz_status != 200:
                out = ui.stdout.read() if ui.stdout else ""
                print(f"      UI did not serve. exit={ui.poll()}")
                print("\n".join(("        " + ln) for ln in out.splitlines()[-20:]))
                ev.failure = (
                    f"/healthz.json on port {port} answered {ev.healthz_status}, "
                    f"ui exit={ui.poll()}"
                )
                ev.code = 4
                return ev
            print(f"      /healthz.json -> {ev.healthz_status}  {ev.healthz_body}")
        finally:
            ui.terminate()
            try:
                ui.wait(timeout=10)
            except subprocess.TimeoutExpired:
                ui.kill()

        db = home / ".local" / "share" / "lynceus" / "lynceus.db"
        ev.db_bytes = db.stat().st_size if db.exists() else -1
        print(f"\n      database created: {db.exists()}"
              f"{'  (' + str(ev.db_bytes) + ' bytes)' if db.exists() else ''}")

        print("\n" + "=" * 66)
        print("✅ FRESH INSTALL WORKS: wheel -> clean venv -> wizard -> validate -> UI")
        print("   Nothing here touched the real home; every step ran in the sandbox.")
        ev.code = 0
        return ev


def main() -> int:
    return run_fresh_install().code


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130) from None
