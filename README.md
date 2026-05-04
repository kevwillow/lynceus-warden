# talos

Talos is a small personal-security tool that runs on a Raspberry Pi and watches the WiFi and Bluetooth airwaves around you. It listens for devices on a watchlist (e.g. known surveillance hardware), and for new devices that don't appear to be randomizing their address — the kind of thing worth a second look. When something matches, it sends a push notification to your phone via [ntfy](https://ntfy.sh/).

It does not transmit, attack, or interfere with any traffic. It is a passive listener: read-only on the radio, write-only to your phone.

Status: v0.2 cleanup. The daemon, ntfy delivery, and read-only web UI have shipped and are ready for first-Pi deployment. Things still on the roadmap are listed in [BACKLOG.md](BACKLOG.md).

## What it does

- Asks [Kismet](https://www.kismetwireless.net/) (which does the actual radio capture) what WiFi, Bluetooth, and BLE devices it has seen recently
- Saves those devices, sightings, and any alerts to a local SQLite database on the Pi
- Checks each sighting against a list of detection rules you define in YAML
- Skips alerts for devices on your allowlist (your phone, your laptop, your coworkers' headphones — anything you've already accounted for)
- Avoids repeating the same alert over and over by deduplicating within a configurable time window
- Pushes a notification to ntfy when something hits, with priority and emoji tags based on severity

## What it does not do (yet)

- See through MAC randomization. Modern phones rotate their MAC addresses on purpose, and there is no clean way around that in the general case — see [docs/RULES.md](docs/RULES.md) for what this means in practice.
- Correlate sightings across multiple locations to spot someone actively following you ("stalking heuristics") — postponed; needs real-world baseline data, see [BACKLOG.md](BACKLOG.md).
- Detect Stingrays / IMSI catchers directly — deferred until the active SIM and a working hunter (Rayhunter / Crocodile Hunter) are both in hand, see [BACKLOG.md](BACKLOG.md).
- Offer in-UI editing of rules and the allowlist. Read-only views landed in v0.2; editing is on the v0.3 backlog and needs validation/rollback first.
- Auto-prune the SQLite database. Sightings accumulate indefinitely; rotate or vacuum manually.

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

## Command-line tools

The wheel installs three console scripts:

### `talos`

Runs the poll loop. The systemd unit invokes this; you generally don't run it directly except to smoke-test a config.

```
talos --config PATH       # required: path to talos.yaml
talos --once              # run a single poll cycle and exit (useful for tests)
talos --version           # print version and exit
```

### `talos-ui`

Runs the read-only web UI server (uvicorn under the hood). Bound to `127.0.0.1:8765` by default; see `ui_bind_host` / `ui_bind_port` / `ui_allow_remote` in [docs/CONFIGURATION.md](docs/CONFIGURATION.md) to change that. Reads from the same SQLite database the daemon writes to — they coexist via WAL.

```
talos-ui --config PATH    # required: path to talos.yaml
talos-ui --version        # print version and exit
```

The available routes are documented in [docs/CONFIGURATION.md](docs/CONFIGURATION.md#web-ui-routes).

### `talos-seed-watchlist`

One-shot CLI to populate the `watchlist` table with seed data — bundled threat OUIs, BLE tracker UUIDs, or your own YAML. Re-runnable; identical entries are deduplicated.

```
talos-seed-watchlist --db PATH         # required: path to the talos sqlite db
                     --threat-ouis     # add bundled OUI watchlist (Pineapples, etc.)
                     --ble-uuids       # add bundled BLE tracker UUIDs (AirTag, etc.)
                     --yaml PATH       # path to a YAML file with watchlist entries
                     --log-level LEVEL # one of DEBUG, INFO, WARNING, ERROR (default INFO)
```

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

Detection rules are defined in a separate YAML file pointed to by `rules_path`. The five rule types cover MAC, OUI, and SSID watchlists, BLE service-UUID matching (AirTag-class trackers), plus a "first sighting of a non-randomized device" trigger. Schema, semantics, and a tuning playbook are in [docs/RULES.md](docs/RULES.md).

## Project layout

```
src/talos/        application package
  __init__.py     version
  config.py       config loading and validation
  db.py           sqlite persistence and migrations
  kismet.py       Kismet REST client and observation parsing
  poller.py       poll loop and `talos` entry point
  rules.py        detection rules and evaluation
  allowlist.py    known-good device suppression
  notify.py       alert dispatch (ntfy, null, recording)
  cli/            command-line tools (talos-seed-watchlist)
  webui/          read-only FastAPI web UI (`talos-ui`)
    app.py        app factory, routes, request handlers
    csrf.py       CSRF middleware for POST mutations
    server.py     uvicorn entry point
    templates/    Jinja2 templates
    static/       vendored Pico CSS, HTMX, plus talos.css/js
  migrations/     sqlite schema migration files
  seeds/          built-in threat data (OUI list, BLE tracker UUIDs)
tests/            pytest suite, fixtures under tests/fixtures
deploy/           systemd units (talos, talos-ui), env template, Pi-install README
docs/             SMOKE checklist, CONFIGURATION reference, RULES reference, WINDOWS_DEV guide
config/           example talos.yaml, talos.dev.example.yaml, rules.yaml, allowlist.yaml
```

## What you should know before relying on it

- **Listen-only.** Talos does not transmit anything on the air. It does not try to disconnect other devices, decrypt traffic, or send fake packets. It only reads what Kismet has already heard.
- **Modern phones are mostly invisible to it.** Current iPhones and Android devices change their WiFi and Bluetooth addresses on a regular basis specifically to avoid being tracked. That works against talos too: a randomizing phone walking past your Pi will look like a different device every few minutes. If your goal is "spot a specific person's phone," talos is the wrong tool. If your goal is "spot unfamiliar hardware that just turned up," it is a good fit.
- **The database grows over time.** Every sighting goes into SQLite, and talos has no automatic cleanup yet. On a long-running deployment you'll need to occasionally trim or rotate the file yourself. Disk usage is modest (sightings are small), but it is not zero.
- **It will be noisy at first.** False positives are not a bug — they are the system showing you what's around you. Expect to spend the first week or so building up your allowlist, not chasing crashes.
- **Check your local laws.** Quietly listening to broadcast WiFi and Bluetooth is legal in most US jurisdictions, but rules vary. Whatever you do, don't cross the line into active attacks (jamming, deauthing, decrypting traffic that isn't yours) — talos won't help you there, and it isn't trying to.

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
