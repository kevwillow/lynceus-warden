# talos

A personal RF security monitoring platform that runs on a Raspberry Pi, scanning WiFi and Bluetooth for known-bad devices, watchlist matches, and new non-randomized devices appearing in your environment. Alerts via ntfy.

v0.1.0 — feature-complete, ready for first deployment.

## What it does

- Polls a Kismet instance over its REST API for WiFi/BT/BLE device sightings
- Persists devices, sightings, and alerts to a local SQLite database
- Evaluates a YAML-defined ruleset against each new sighting
- Suppresses alerts for allowlisted devices (your gear, family, coworkers)
- Deduplicates repeat alerts within a configurable window
- Sends notifications to ntfy with severity-based priority and tags

## What it does not do (yet)

- MAC randomization defeat (limited by physics — covered in [docs/RULES.md](docs/RULES.md))
- Stalking heuristics (multi-location sighting analysis) — v0.2
- Stingray hunter integration — v0.2
- Web UI for ack/tuning rules — v0.2
- BLE service UUID extraction (AirTag-class detection) — v0.2

## Install paths

Two supported paths, depending on whether you're hacking on talos or running it.

### A) Editable (development, on your laptop)

```bash
git clone <your-fork-or-mirror> talos
cd talos
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest -v
```

### B) Wheel (production, on your Pi)

```bash
# On a build host (or the Pi itself):
git clone <your-fork-or-mirror> talos
cd talos
python -m build --wheel
# Copy the wheel to the Pi:
scp dist/talos-*.whl pi@raspberrypi.local:/tmp/
# On the Pi:
sudo pip install /tmp/talos-*.whl
```

The systemd unit and env file template live in `deploy/`. Install steps for the systemd path are in [deploy/README.md](deploy/README.md).

## First-run quickstart

1. Install Kismet on the Pi — see the [Kismet Linux install guide](https://www.kismetwireless.net/docs/readme/installing/linux/).
2. Generate a Kismet API key in the Kismet web UI, then set `kismet_api_key` in `talos.yaml`.
3. Copy `config/talos.example.yaml` to `/etc/talos/talos.yaml` and edit for your environment.
4. Seed the watchlist:
   ```bash
   talos-seed-watchlist --db /var/lib/talos/talos.db --threat-ouis
   ```
5. Enable the service:
   ```bash
   sudo systemctl enable --now talos
   ```

Then walk through [docs/SMOKE.md](docs/SMOKE.md) to verify everything wired up correctly.

## Configuration

The runtime is configured from a single YAML file (default `/etc/talos/talos.yaml`). Every field has a sensible default — only override what you need. Full field-by-field reference and worked examples are in [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

## Rules

Detection rules are defined in a separate YAML file pointed to by `rules_path`. The four rule types cover MAC, OUI, and SSID watchlists plus a "first sighting of a non-randomized device" trigger. Schema, semantics, and a tuning playbook are in [docs/RULES.md](docs/RULES.md).

## Project layout

```
src/talos/        application package
  __init__.py     version
  config.py       config loading and validation
  db.py           sqlite persistence and migrations
  kismet.py       Kismet REST client and observation parsing
  poller.py       poll loop and entrypoint
  rules.py        detection rules and evaluation
  allowlist.py    known-good device suppression
  notify.py       alert dispatch (ntfy, null, recording)
  cli/            command-line tools (talos-seed-watchlist)
  migrations/     sqlite schema migration files
  seeds/          built-in threat data (OUI list)
tests/            pytest suite, fixtures under tests/fixtures
deploy/           systemd unit, env template, Pi-install README
docs/             SMOKE checklist, CONFIGURATION reference, RULES reference
config/           example talos.yaml, rules.yaml, allowlist.yaml
```

## Threat model and limitations

- **Passive RF monitoring only.** No active probes, deauthentication frames, or decryption. Talos reads what Kismet sees and nothing more.
- **MAC randomization on modern phones limits some use cases.** Most current iOS and Android devices rotate WiFi MACs per-SSID and rotate BLE addresses on a timer, so persistent identification of randomizing handsets is not a goal of v0.1.
- **Storage grows with traffic.** The SQLite database accumulates devices, sightings, and alerts indefinitely. v0.1 has no automatic pruning — you will need to periodically vacuum or rotate the DB on long-lived deployments.
- **Detection is best-effort.** False negatives are possible. False positives **will** happen until you tune the allowlist for your environment — plan to spend the first week curating, not debugging.
- **Legal.** Passive listening is legal in most US jurisdictions, but rules vary — check yours before deploying. Never deauthenticate, decrypt, or actively interfere with traffic you don't own.

## Development

`Makefile` targets:

```bash
make install   # pip install -e ".[dev]"
make test      # pytest -v (full suite)
make lint      # ruff check . && ruff format --check .
```

The wheel-build test in `tests/test_packaging.py` is marked `slow`. To skip it during fast iteration:

```bash
pytest -v -m "not slow"
```

To run the full suite including the wheel build:

```bash
pytest -v
```

## License

TBD — add a LICENSE file before public release.

## Acknowledgments

Talos stands on top of [Kismet](https://www.kismetwireless.net/) for capture and [ntfy](https://ntfy.sh/) for notification delivery, and owes a debt to the wider open-source RF and wireless-security community whose tooling makes a project like this possible at all.
