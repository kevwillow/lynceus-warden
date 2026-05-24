# Kali smoke checklist — Linux validation walkthrough

Operator-facing verification script for the Kali laptop smoke
session that follows a push of the pending branch. Pair with
[DEPLOYMENT.md](DEPLOYMENT.md) (canonical install path) and
[SMOKE.md](SMOKE.md) (steady-state first-run checks). This
checklist is narrower: it confirms the Linux side of the codebase
matches what was validated on Windows and that the install path
end-to-end works on a fresh Kali host.

Each step has an **action**, an **expected output**, and a
**flag condition**. If any step flags, **stop and capture
output** before proceeding — later steps assume earlier ones
passed.

The smoke session runs against the version on `main` at push
time: `lynceus 0.7.0`. Substitute the actual version if you
bumped before pushing.

> **Note on the suite count delta.** Windows-side baseline is
> **2812 passed / 18 platform-skipped / 22 diagnostic-deselected**.
> The 18 skipped tests are POSIX-only (install.sh bash-driven
> tests + `chmod` round-trip tests + POSIX file-mode tests in
> `test_setup_wizard.py`). On Linux they all run, so the
> expected Linux total is **2830 passed / 0 skipped** (still
> with 22 diagnostic tests deselected by default).

---

## 0. Pre-flight (host)

**Action:**

```bash
uname -srm                       # confirm Linux kernel + arch
python3 --version                # confirm 3.11+
command -v systemctl >/dev/null && echo "systemd OK"
command -v sqlite3 >/dev/null && echo "sqlite3 OK"
```

**Expected:** `Linux ...`, `Python 3.11.x` (or higher), `systemd
OK`, `sqlite3 OK`.

**Flag:** Python < 3.11 (`apt install python3` first); no
`systemctl` (this isn't a systemd host — checklist assumes
systemd from §6 onward); no `sqlite3` (`apt install sqlite3` for
the alert-row sanity check in §10).

---

## 1. Clone + commit-hash parity

**Action:**

```bash
git clone https://github.com/kevwillow/lynceus-warden
cd lynceus-warden
git log --oneline -1
```

**Expected:** the tip commit hash matches the HEAD you pushed
from the Windows side. Note the hash before pushing
(`git rev-parse --short HEAD` on Windows) and compare here.

**Flag:** any mismatch. Means the push didn't land what you
expected, or the Linux side picked up an older mirror.

---

## 2. Venv + editable install

**Action:**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[dev]"
```

**Expected:** clean install; `pip list | grep lynceus` shows
`lynceus 0.7.0` (editable). `.venv/bin/lynceus`,
`lynceus-ui`, `lynceus-import-argus`, `lynceus-validate`,
`lynceus-setup`, `lynceus-quickstart`,
`lynceus-bootstrap-kismet`, `lynceus-export-config`,
`lynceus-seed-watchlist` all present.

**Flag:** missing scripts → check `[project.scripts]` in
pyproject.toml ↔ `CONSOLE_SCRIPTS` in install.sh (the two are
kept in sync; a drift would surface here).

---

## 3. Full test suite

**Action:**

```bash
pytest tests/ --tb=short
```

**Expected:** `2830 passed in <N>s`.

Breakdown vs Windows:
- 2812 tests run on both platforms.
- 18 tests run only on POSIX (install.sh bash-driven tests +
  `chmod`/file-mode tests). They contribute the +18 delta.

**Flag:** any failure. Specifically:
- `test_packaging.py::test_wheel_install_finds_migrations` —
  known Windows-flaky, should pass cleanly on Linux. If it
  fails here, the failure is real and needs investigation.
- `test_install_sh.py::*` — any failure means install.sh has
  drifted from what the tests pin. Capture output and stop.
- `test_paths.py::test_*_perms` — chmod / mode round-trip
  tests. Failure means the install.sh perm-set logic is
  divergent from what's expected.

---

## 4. Diagnostic suite

**Action:**

```bash
pytest -m diagnostic
```

**Expected:** `22 passed, 2830 deselected`.

**Flag:** anything other than 22 passed. The diagnostic suite
is observation-only — failures here mean a surface assumption
has drifted between Windows and Linux runs.

---

## 5. Wheel build sanity (slow path)

**Action:**

```bash
pip install build
python -m build --wheel
ls -la dist/
```

**Expected:** `dist/lynceus-0.7.0-py3-none-any.whl` exists.

**Flag:** build failure → check the build log for missing
package-data files (most likely `migrations/*.sql` or
`webui/templates/*.html`). If the wheel builds but the
`test_wheel_install_finds_migrations` test in step 3 also
failed, the migration files probably aren't being packaged.

---

## 6. install.sh dry-run preview

**Action:** (no sudo needed for `--dry-run`)

```bash
./install.sh --dry-run --system
```

**Expected:** prints every command that *would* run, prefixed
with `DRY-RUN:`. Lists creation of:

- venv at `/opt/lynceus/.venv`
- console-script symlinks in `/usr/local/bin/` (9 scripts;
  see `CONSOLE_SCRIPTS` in install.sh)
- directories `/etc/lynceus`, `/var/lib/lynceus`,
  `/var/log/lynceus`
- systemd units installed to `/etc/systemd/system/`:
  `lynceus.service`, `lynceus-ui.service`,
  `lynceus-refresh.service`, `lynceus-refresh.timer`
- `systemctl daemon-reload`

No commands actually execute.

**Flag:** any error other than the platform check (which only
fires on non-Linux).

---

## 7. CLI smoke (no daemon)

**Action:** (still in the venv from §2)

```bash
lynceus-validate --version
lynceus-validate --help | head -5
lynceus-import-argus --help | head -5
lynceus-setup --help | head -5
lynceus-quickstart --help | head -5
lynceus-bootstrap-kismet --help | head -5
lynceus-export-config --help | head -5
lynceus-seed-watchlist --help | head -5
```

**Expected:**
- `--version` prints `lynceus-validate 0.7.0`.
- Every `--help` exits 0 with usage text.

**Flag:** non-zero exit or `ImportError` traceback. Most
common cause: missing optional dep (`PyYAML` or `pydantic`
mismatch) — re-check step 2.

---

## 8. System install per DEPLOYMENT.md

This is the actual install walk. Follow
[DEPLOYMENT.md](DEPLOYMENT.md) end-to-end. The cross-checks
below cover the points where Linux-side behavior is most
likely to drift from what Windows-side tests prove.

**Action:**

```bash
sudo ./install.sh --system
sudo lynceus-bootstrap-kismet           # if Kismet not already installed
sudo lynceus-setup --system             # generate /etc/lynceus/lynceus.yaml
sudo systemctl enable --now lynceus.service lynceus-ui.service
```

**Expected:** every step exits 0. `/etc/lynceus/lynceus.yaml`
exists owned `root:lynceus mode 0640`; `/var/lib/lynceus/`
exists owned `lynceus:lynceus`.

**Cross-checks against the systemd units:**

```bash
sudo systemctl status lynceus.service      # expect active (running)
sudo systemctl status lynceus-ui.service   # expect active (running)
sudo journalctl -u lynceus -n 80 --no-pager | grep -E '(health check passed|poll cycle|Traceback)'
```

**Expected:** both units `active (running)`. Journal shows
`Kismet health check passed` near startup, then periodic
`poll cycle` log lines. No tracebacks.

**Flag:** unit `failed` or `inactive` → `sudo journalctl -xeu
lynceus.service --no-pager | tail -60` and capture. Common
failures:
- Kismet not reachable (the v0.2 fail-fast probe aborts
  startup). Confirm `curl -s http://localhost:2501/` returns
  something.
- `/etc/lynceus` directory traversal denied (perms drift). The
  install.sh logic is `chown root:lynceus /etc/lynceus &&
  chmod 0750 /etc/lynceus` — if the perms are off, the daemon
  user can't read its own config.

---

## 9. Healthz endpoints

**Action:**

```bash
curl -i http://127.0.0.1:8765/healthz | head -5
curl -s http://127.0.0.1:8765/healthz.json | python3 -m json.tool
```

> Port is **8765** by default (`DEFAULT_UI_PORT` in
> [cli/quickstart.py](../src/lynceus/cli/quickstart.py)).
> If you overrode `ui_bind_port` in `/etc/lynceus/lynceus.yaml`,
> substitute that value.

**Expected:**
- `/healthz` returns `HTTP/1.1 200 OK` with `Content-Type:
  text/html`.
- `/healthz.json` returns a JSON object whose top-level keys
  match the set pinned by `tests/test_healthz_json.py`
  (config, db, kismet, etc.).

**Flag:** connection refused → `lynceus-ui.service` isn't
listening; check `sudo systemctl status lynceus-ui.service`.
HTTP 500 → check `sudo journalctl -u lynceus-ui -n 50
--no-pager` for a Python traceback.

---

## 10. End-to-end alert smoke

Follow [SMOKE.md](SMOKE.md) for the full first-run walk. The
abbreviated version, once Kismet is observing real signal:

**Action:**

```bash
# Trigger an alert by getting a known-watchlisted device into range,
# OR by adding your phone's MAC to /etc/lynceus/allowlist.yaml under
# a high-severity rule, OR by re-importing an Argus snapshot fresh:
sudo lynceus-import-argus --scope system --from-github
```

Then verify the alert pipeline:

```bash
sudo sqlite3 /var/lib/lynceus/lynceus.db "SELECT COUNT(*) FROM alerts"
sudo journalctl -u lynceus -n 20 --no-pager | grep -E '(alert|rule)'
```

**Expected:** alert count ≥ 1 after a real watchlisted observation
fires. ntfy delivery on the configured topic (check on your phone /
subscriber). Web UI `/alerts` lists the alert with the matched
rule.

**Flag:** zero alerts after sufficient observation time → check
that rules are enabled (`lynceus-validate --scope system`),
that observations are landing (`SELECT COUNT(*) FROM devices`
should be > 0), and that the watchlist is populated
(`SELECT COUNT(*) FROM watchlist` should be ~22k after Argus
import).

---

## 11. Cross-check the Windows ↔ Linux suite delta

**Action:**

```bash
pytest tests/ -v 2>&1 | tail -5
```

**Expected:**

```
==== 2830 passed in <N>s ====
```

**Flag:** if Linux total ≠ 2830:
- More than 2830 → new tests landed since this checklist
  was written; update the expected count.
- Less than 2830 → either a test is failing silently, or
  Linux is skipping tests that should run. Run with
  `pytest tests/ --co -q | wc -l` and confirm collection
  count (expect `2830/2853 tests collected (22 deselected)`),
  then `pytest tests/ -v` and check the SKIPPED list.

---

## Recovery posture

If **any** step flags:

1. **Stop.** Don't proceed past the flag.
2. Capture the failing command's full output (stdout + stderr +
   journalctl context for service-level flags).
3. File a fix prompt — small Linux-side fixups land as their own
   commits before re-running. Don't try to push-through.
4. Re-run the flagged step *only* after the fix lands.

If everything passes through step 11, the Linux side matches
Windows-side baseline + the expected POSIX-only test delta.
Tag operation (e.g. `v0.5.0`) can follow.
