# Deployment runbook — fresh host to working Lynceus

End-to-end install runbook for an operator with a fresh Kali / Debian
/ Ubuntu laptop who wants Lynceus capturing, alerting, and the web UI
serving locally.

Each step has an **action** (the command to run), an **expected
output** (so you can tell whether it worked), and a brief
**explanation** (why this step exists). If any step fails, **stop
and debug** before moving on — later steps assume earlier ones
landed cleanly. The cross-referenced docs (`CONFIGURATION.md`,
`RULES.md`, `NTFY_SETUP.md`, `SMOKE.md`) carry the deep-dive content;
this runbook is the install spine.

> **Platform.** This runbook targets **Linux** (Kali / Debian / Ubuntu).
> Lynceus's release packaging, systemd integration, and `install.sh`
> are Linux-only. macOS and Windows are **development-only**: see
> [docs/WINDOWS_DEV.md](WINDOWS_DEV.md) for the dev-only flow on
> non-Linux hosts.

> **Time budget.** Allow 30–45 minutes for a fresh-host install if
> Kismet is being installed from scratch. Subsequent re-runs (after
> the bootstrap step) are 5–10 minutes.

## Prerequisites

Before you start, confirm:

- A clean Kali / Debian-stable / Ubuntu-LTS host with `sudo` access.
- At least one WiFi adapter capable of monitor mode, OR a Bluetooth
  controller (`hci*`). Lynceus needs at least one capture surface;
  it polls Kismet and matches what Kismet hears. If you have a
  built-in WiFi-only laptop and no USB monitor-mode adapter, you
  can still run Lynceus on the BT controller alone, but coverage
  will be narrow.
- Network connectivity for the install steps that pull packages
  (`install.sh` is offline; `lynceus-bootstrap-kismet` and
  `lynceus-import-argus --from-github` are the network-using
  helpers).
- An ntfy broker decision: ntfy.sh (free, public), self-hosted
  ntfy, or skip notifications entirely. See
  [docs/NTFY_SETUP.md](NTFY_SETUP.md) for the trade-offs.

## 1. Clone the repository

**Action:**

```sh
git clone https://github.com/kevwillow/lynceus-warden
cd lynceus-warden
```

**Expected:** `lynceus-warden` directory exists; `git log -1` shows
the tip commit you intend to install. If you're installing a tagged
release, `git checkout v0.5.0` (substitute your target tag).

**Explanation:** Lynceus is installed from source. There is no
PyPI package and no `curl | bash` installer by design — read the
script before running it.

## 2. Install Lynceus

**Action (user install, recommended for laptop use):**

```sh
./install.sh --user
```

**Action (system install, for a dedicated host or Pi):**

```sh
sudo ./install.sh --system
```

**Expected:** the installer creates a Python venv (at
`~/.local/share/lynceus/.venv` for `--user`, `/opt/lynceus/.venv`
for `--system`), installs the wheel into it, and creates console-
script symlinks. The trailing lines should list every `lynceus-*`
command it installed. No errors. Confirm `lynceus --version` works
on `PATH`:

```sh
lynceus --version
# lynceus 0.5.0 (or your target version)
```

**Explanation:** `install.sh` is the offline install path —
it does not call the network. It uses a dedicated venv to comply
with PEP 668 on Debian-family distros where the system Python is
externally-managed. See `README.md` §Installation for the full
flag set (`--dry-run`, `--uninstall`, `--purge`).

**Troubleshoot:**
- `python3 -m venv` errors: `sudo apt install python3-venv` on
  Debian/Ubuntu/Kali. The installer surface lists the per-distro
  package name.
- `lynceus-*` commands not found on `PATH`: `~/.local/bin` (for
  `--user`) or `/usr/local/bin` (for `--system`) isn't on `PATH`.
  Add it to your shell profile — `install.sh --user` prints a
  one-liner hint when it detects this.

## 3. Bootstrap Kismet

**Action (Debian/Ubuntu/Kali):**

```sh
sudo lynceus-bootstrap-kismet
```

**Expected:** the helper adds the official Kismet apt repo, installs
the `kismet` package, detects monitor-mode-capable WiFi adapters
plus any `hci*` Bluetooth controllers, patches
`/etc/kismet/kismet_site.conf` (append-only — your edits survive),
and adds your user to the `kismet` group. The final line summarizes
what it did. Idempotent — safe to re-run if you add hardware later.

**Action (non-Debian distros):**

Install Kismet manually per [kismetwireless.net/packages](https://www.kismetwireless.net/packages/),
then skip ahead to step 4.

**Then, log out and back in** so the `kismet` group membership takes
effect.

**Verify:**

```sh
groups | tr ' ' '\n' | grep -x kismet
# kismet
sudo systemctl status kismet  # should be enabled (may not yet be running)
```

**Explanation:** Lynceus does not capture directly — it polls
Kismet over its REST API. Kismet handles the radio capture, channel
hopping, and source attribution. `lynceus-bootstrap-kismet` is the
ONE Lynceus CLI that touches the network during install (the
`install.sh` invariant of "offline" is preserved by keeping the
network-using helper as a separate, opt-in step).

## 4. Start Kismet and create the API key

**Action:**

```sh
sudo systemctl start kismet
sudo systemctl enable kismet  # auto-start on boot
xdg-open http://localhost:2501 || firefox http://localhost:2501
```

In the browser:

1. Set the admin password (Kismet prompts on first visit).
2. Navigate to **Settings → API Keys**.
3. Create a new key named `lynceus`, role `readonly`.
4. Copy the key value to your clipboard — you'll need it in step 5.

**Expected:** Kismet's web UI loads, the admin password is set, and
the new `lynceus` key appears in the API Keys list. Kismet's
service is `active (running)` (`sudo systemctl status kismet`).

**Explanation:** Lynceus needs Kismet running before its own
configuration wizard can probe for connectivity. The API key is
read-only — Lynceus never writes back to Kismet.

## 5. Configure Lynceus

**Action:**

```sh
lynceus-setup
```

The wizard:

1. Probes Kismet at `http://localhost:2501` and auto-locates the
   API key from `~/.kismet/session.db` (so you usually don't need
   the key you copied — the wizard finds it automatically).
2. Asks about probe SSID capture (privacy-sensitive — defaults to
   **off**; opt in only if you understand the implications).
3. Detects available Bluetooth (`hci*`) adapters and offers to add
   them as Kismet sources.
4. Prompts for ntfy broker URL + topic, OR press Enter to skip
   notifications. See [docs/NTFY_SETUP.md](NTFY_SETUP.md) for
   broker selection guidance.
5. Auto-imports the bundled threat-data watchlist (~22.5k Argus
   rows) — no manual import needed for the default coverage.

**Expected:** the wizard ends with a "Configuration complete" line
and writes `lynceus.yaml` to the canonical config dir
(`~/.config/lynceus/lynceus.yaml` for user install,
`/etc/lynceus/lynceus.yaml` for system install). The DB at the
canonical data path now exists and is populated with the bundled
watchlist.

**Explanation:** `lynceus-setup` is the primary configuration tool.
It probes for connectivity rather than asking you to copy-paste
endpoints, and the prompts are scoped to operator decisions
(capture surface, privacy posture, notification target). See
[docs/CONFIGURATION.md](CONFIGURATION.md) for the full schema
reference if you want to hand-edit `lynceus.yaml` later
(`lynceus-setup --reconfigure` rewrites; without that flag it
refuses to clobber).

## 6. Refresh the watchlist from upstream Argus (optional)

**Action:**

```sh
lynceus-import-argus --from-github
```

**Expected:** the importer fetches the latest Argus CSV from
GitHub Releases, caches it under
`<data-dir>/argus-cache/<ref>__argus_export.csv`, and reports the
number of rows imported / updated / skipped. Idempotent — re-running
is safe and only updates changed rows.

**Explanation:** The bundled watchlist that `lynceus-setup` imported
is a point-in-time snapshot. `--from-github` pulls the latest tagged
Argus release for the fresh corpus. Air-gapped operators pass
`--input <path-to-csv>` instead. This is the second of two CLIs
that touch the network during install.

## 7. Validate the configuration

**Action:**

```sh
lynceus-validate
# or for system install:
sudo -u lynceus lynceus-validate --scope system
```

**Expected:** stdout shows each config file with `OK` plus a one-line
summary; the trailing line reads `Summary: 0 errors, 0 warnings
across N files`. Exit code 0. If there are warnings, read them —
they may surface typos in optional files (severity overrides,
allowlist) that would silently disable a layer at daemon startup.

**Explanation:** `lynceus-validate` is the pre-flight check. It
re-uses the daemon's actual config loaders, so any error it
reports is what the daemon would hit at startup. Run this every
time you edit a YAML file. (`lynceus-validate` also hosts the
`rollback` subcommand for reversing DB migrations — see
[docs/CONFIGURATION.md §Database migration rollback](CONFIGURATION.md#database-migration-rollback)
for that operator-facing flow.)

## 8a. Enable the systemd units (system install only)

**Action:**

```sh
sudo systemctl enable --now lynceus.service lynceus-ui.service
sudo systemctl status lynceus lynceus-ui
```

**Expected:** both units are `active (running)`. `journalctl -u
lynceus -n 50 --no-pager` shows the startup health check passed,
then one poll-cycle log line per `poll_interval_seconds`. No Python
tracebacks.

**Explanation:** the installer copies the hardened systemd units
(`NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, restricted
namespaces, the `lynceus` system user) into
`/etc/systemd/system/` but doesn't auto-enable them. Enabling +
starting is the explicit operator decision.

**Optional — auto-refresh timer.** If you want the watchlist to
refresh on a schedule (default weekly), enable
`lynceus-refresh.timer`:

```sh
sudo systemctl enable --now lynceus-refresh.timer
sudo systemctl list-timers lynceus-refresh.timer
```

See `README.md` §Bundled threat data for the timer's behaviour
and the `systemctl edit` flow for customizing the cadence.

## 8b. Run in foreground (user install / dev / demo)

**Action:**

```sh
lynceus-quickstart
```

**Expected:** the launcher starts the poller daemon + the web UI
in the same process group, opens `http://localhost:8765` in your
browser, and streams log output to your terminal. Ctrl+C shuts
everything down cleanly.

**Explanation:** `lynceus-quickstart` is the convenience launcher
for development and demonstration. It is **not** suitable for
unattended operation — for that, install system-wide and use the
systemd units (step 8a above).

## 9. Smoke verification

Run through [docs/SMOKE.md](SMOKE.md) to confirm:

- Kismet is capturing (step 1 there).
- The Lynceus daemon is polling cleanly (step 2 there).
- The web UI is reachable and `/healthz` responds (step 3 there).
- Sightings are landing in the DB (step 4 there).
- The watchlist table is populated (step 5 there).
- An end-to-end alert fires when a watched MAC is observed (the
  remaining SMOKE steps).

SMOKE.md is the authoritative post-install verification surface and
covers every check + troubleshoot bullet — this runbook intentionally
does not duplicate its content.

## Common issues

The five operator-facing failure modes that surface most often during
fresh-host install. Each maps to a step above; if you hit one, the
fix is usually a one-line config change, not a re-install.

### 1. Kismet API key auto-detect fails

**Symptom:** `lynceus-setup` reports "could not locate Kismet API
key from session.db" and prompts you to paste the key manually.

**Cause:** the Kismet web admin password was set under a different
user account, OR Kismet hasn't yet written `~/.kismet/session.db`
because no admin login has happened.

**Fix:** open `http://localhost:2501`, log in via the web UI once
(this populates `session.db`), then re-run `lynceus-setup
--reconfigure`. Alternatively, paste the API key value from
step 4 into the wizard prompt.

### 2. `lynceus-*` commands not found on PATH after install

**Symptom:** `lynceus: command not found` immediately after a
successful `install.sh` run.

**Cause:** the install's bin directory isn't on `PATH`. For
`--user`, that's `~/.local/bin`; for `--system`, that's
`/usr/local/bin`. The `--user` case is the common one on minimal
Kali installs — the directory exists and contains the symlinks
but isn't on `PATH` for non-login shells.

**Fix:** `install.sh --user` prints a one-liner shell-profile
addition when it detects this. Apply it (or the equivalent for
your shell) and start a new terminal. For zsh:

```sh
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

### 3. Kismet sees the WiFi adapter but it's not in monitor mode

**Symptom:** the all-sources curl (from
[docs/SMOKE.md](SMOKE.md) step 1) reports the source name but its
`kismet.datasource.running` is `0`.

**Cause:** the kernel's NetworkManager is holding the interface in
managed mode, OR the adapter doesn't actually support monitor mode
(some onboard chipsets don't).

**Fix:** `sudo airmon-ng check kill` releases NetworkManager
control; if the adapter still won't switch, check
`iw list | grep -A 8 'Supported interface modes'` for `monitor`
support. If the adapter genuinely doesn't support monitor mode,
you need a different USB adapter — Alfa AWUS036ACS and similar
RTL8812AU-based devices are common Kali-compatible choices.

### 4. ntfy notifications never arrive

**Symptom:** the UI shows alerts; ntfy phone notifications don't.

**Cause:** the topic name is wrong (case-sensitive!), OR the phone
app isn't subscribed to the same topic, OR you're behind a captive
portal that blocks the ntfy WebSocket.

**Fix:** check `journalctl -u lynceus | grep -i ntfy` for the
URL the daemon is hitting. Copy that exact URL into your phone's
ntfy app subscription. The topic is the last path segment; spaces
and dashes matter. If the broker URL is `https://ntfy.sh/secret-foo`,
subscribe to `secret-foo` on the phone — NOT `Secret-Foo` or
`secret_foo`. See [docs/NTFY_SETUP.md](NTFY_SETUP.md) for the
end-to-end verification flow.

### 5. systemd unit fails to start with "permission denied"

**Symptom:** `lynceus.service` (system install) fails on
`systemctl start` with `Permission denied` on
`/var/lib/lynceus/lynceus.db` or `/etc/lynceus/lynceus.yaml`.

**Cause:** the install left a file with the wrong ownership.
`install.sh --system` sets `root:lynceus 0640` on the config and
`lynceus:lynceus 0750` on data dirs; a re-install on top of a
prior user-install can leave residual `0600 root:root` bits.

**Fix:**

```sh
sudo chown -R root:lynceus /etc/lynceus
sudo chmod -R 0640 /etc/lynceus
sudo chown -R lynceus:lynceus /var/lib/lynceus /var/log/lynceus
sudo systemctl restart lynceus lynceus-ui
```

If the residual is more tangled, `sudo ./install.sh --uninstall
--system` followed by a fresh `sudo ./install.sh --system` is the
clean restart. `--uninstall` preserves data; pass `--purge` only
if you want to wipe state too.

## Going further

After install, the operator-facing documentation surfaces are:

- [docs/CONFIGURATION.md](CONFIGURATION.md) — schema reference,
  worked examples, multi-adapter deployments, web UI POST routes,
  database migration rollback flow.
- [docs/RULES.md](RULES.md) — the rules engine, the five rule
  types, severity tiers, allowlist semantics.
- [docs/NTFY_SETUP.md](NTFY_SETUP.md) — ntfy broker selection,
  phone app setup, end-to-end verification, privacy notes.
- [docs/SMOKE.md](SMOKE.md) — first-run smoke checklist (also
  the post-restart verification surface).
- [README.md](../README.md) — project overview, install summary,
  CLI surface, architecture diagram.

For backlog / deferred items, see [BACKLOG.md](../BACKLOG.md). For
the project's release history and per-version operator-facing
notes, see [CHANGELOG.md](../CHANGELOG.md).
