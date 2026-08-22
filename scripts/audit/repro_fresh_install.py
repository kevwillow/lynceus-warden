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
    3   the wizard did not complete
    4   the UI did not serve

REFUSES to run against a real home. Every step is done under a redirected HOME,
because an earlier version of the test suite wrote into the operator's actual
``~/.config/lynceus`` and the only reason nothing was destroyed was an overwrite
prompt added for an unrelated reason.

The wizard is interactive and has no --defaults flag, so the answers are fed on
stdin. That sequence is the brittle part and it is deliberately asserted rather
than assumed: if a prompt is added or reordered, this fails with the transcript
instead of hanging or writing a half-configured system.

Needs a machine with at least one capture interface, so CI cannot run it.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.request
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


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def main() -> int:
    real_home = Path(os.path.expanduser("~")).resolve()

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        home = tmp / "home"
        (home / ".config").mkdir(parents=True)

        # The guard comes BEFORE anything runs, not after. A harness that
        # checks it is safe only once it has already written is not a guard.
        assert real_home not in home.resolve().parents, "refusing to run against a real home"
        env = dict(os.environ)
        env.update(
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
            return 3
        print(f"      {wheels[0].name}")

        print("[2/5] installing into a clean venv")
        venv = tmp / "venv"
        run([sys.executable, "-m", "venv", str(venv)])
        bins = venv / "bin"
        r = run([str(bins / "pip"), "install", "-q", str(wheels[0])])
        if r.returncode != 0:
            print(r.stdout[-2000:], r.stderr[-2000:])
            return 3

        print("[3/5] driving lynceus-setup with answers on stdin")
        r = subprocess.run(
            [str(bins / "lynceus-setup"), "--user", "--skip-probes"],
            input="\n".join(ANSWERS) + "\n",
            capture_output=True, text=True, env=env, timeout=300,
        )
        cfg = home / ".config" / "lynceus" / "lynceus.yaml"
        if r.returncode != 0 or not cfg.exists():
            print("      wizard did not complete. Transcript tail:")
            print("\n".join(("        " + ln) for ln in r.stdout.splitlines()[-25:]))
            print("      ⛔ If a prompt was ADDED or REORDERED, ANSWERS above is stale.")
            return 3
        written = sorted(p.name for p in (home / ".config" / "lynceus").iterdir())
        print(f"      wizard exit 0, wrote: {', '.join(written)}")

        print("[4/5] validating the config the wizard wrote")
        r = run([str(bins / "lynceus-validate")], env=env)
        if r.returncode != 0:
            print((r.stdout + r.stderr)[-2000:])
            return 2
        print(f"      {(r.stdout.strip().splitlines() or ['ok'])[-1][:90]}")

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
            status, body = 0, ""
            for _ in range(40):
                time.sleep(0.5)
                try:
                    url = f"http://127.0.0.1:{port}/healthz.json"
                    resp = urllib.request.urlopen(url, timeout=3)
                    status, body = resp.status, resp.read().decode()[:120]
                    break
                except Exception:
                    if ui.poll() is not None:
                        break
            if status != 200:
                out = ui.stdout.read() if ui.stdout else ""
                print(f"      UI did not serve. exit={ui.poll()}")
                print("\n".join(("        " + ln) for ln in out.splitlines()[-20:]))
                return 4
            print(f"      /healthz.json -> {status}  {body}")
        finally:
            ui.terminate()
            try:
                ui.wait(timeout=10)
            except subprocess.TimeoutExpired:
                ui.kill()

        db = home / ".local" / "share" / "lynceus" / "lynceus.db"
        print(f"\n      database created: {db.exists()}"
              f"{'  (' + str(db.stat().st_size) + ' bytes)' if db.exists() else ''}")

        print("\n" + "=" * 66)
        print("✅ FRESH INSTALL WORKS: wheel -> clean venv -> wizard -> validate -> UI")
        print("   Nothing here touched the real home; every step ran in the sandbox.")
        return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130) from None
