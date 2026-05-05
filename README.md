# talos

A small personal-security tool that watches the WiFi and Bluetooth around
your home and tells you when something unfamiliar shows up.

## What it does

- Notices when a new WiFi or Bluetooth device starts hanging around your
  home that wasn't there before.
- Recognises specific hardware you've flagged in advance — known
  surveillance gear, tracker tags like AirTags, anything you've put on a
  watchlist.
- Lets you mark your own devices as "expected" so they don't trigger
  alerts.
- Pushes a notification to your phone when something matches.
- Keeps a local history of what's been seen, so you can look back and
  see when a device first appeared.

It does not transmit, attack, or interfere with anything. It only listens
to traffic that's already in the air.

## Status

v0.2 is feature-complete and waiting on its first real-hardware deployment.
The daemon, the alerting path, and the read-only web UI all work end-to-end
in development. For a more detailed snapshot — what's shipped, what's not,
what's been tested — see [docs/PROJECT_STATUS.md](docs/PROJECT_STATUS.md).
What's still on the roadmap lives in [BACKLOG.md](BACKLOG.md).

## How it works

talos runs as a small daemon on a Raspberry Pi. Every minute or so it asks
[Kismet](https://www.kismetwireless.net/) — which does the actual radio
capture — what devices it has seen recently, and writes those sightings to
a local SQLite database. Each sighting is checked against a list of
detection rules (watchlist matches, AirTag-class trackers, first sighting
of a non-randomized device) and against your allowlist of known-good
hardware. If a sighting matches a rule and isn't allowlisted, talos sends
a push notification to your phone via [ntfy](https://ntfy.sh/). A separate
read-only web UI lets you browse alerts, devices, and the rules that are
currently loaded. Everything runs locally on the Pi — no cloud, no
external services beyond ntfy delivery.

## What you need to run it

**Hardware**

- Raspberry Pi 4 or 5 (4 GB or more recommended).
- A WiFi adapter that supports monitor mode. The Pi's built-in radio works
  for short-range capture; an external USB adapter gives much better range.
- A Bluetooth adapter (the Pi's built-in one is fine; an external dongle
  gives more range).

**Software**

- Kismet, installed and configured to capture from your adapter(s).
  Install guide at [kismetwireless.net](https://www.kismetwireless.net/docs/readme/installing/linux/).
- Python 3.11 or newer.
- An ntfy server. The hosted [ntfy.sh](https://ntfy.sh/) is fine for personal
  use, or you can self-host.

**Accounts**

None required. Both Kismet and ntfy can run fully self-hosted; talos itself
does not phone home.

## Quick start

1. Install Kismet on the Pi and confirm it's running.
2. Build the talos wheel (`python -m build --wheel`) and install it on the
   Pi (`sudo pip install /tmp/talos-*.whl`).
3. Copy `config/talos.example.yaml` to `/etc/talos/talos.yaml` and fill in
   your Kismet API key, ntfy URL, and ntfy topic.
4. Seed the watchlist with the bundled threat data:
   `talos-seed-watchlist --db /var/lib/talos/talos.db --threat-ouis --ble-uuids`.
5. Start the service: `sudo systemctl enable --now talos`.

The full walkthrough — including systemd installation, env files, and
verification — lives in [deploy/README.md](deploy/README.md). For end-to-end
verification once you're running, follow [docs/SMOKE.md](docs/SMOKE.md).

## Watchlist data

The watchlist is the list of devices talos cares about. You seed it with
the `talos-seed-watchlist` CLI. Three sources are supported:

- **Built-in threat OUIs.** A bundled list of MAC prefixes for known
  surveillance hardware. Enabled with `--threat-ouis`.
- **Built-in BLE tracker UUIDs.** A bundled list of service UUIDs for
  AirTag-class tracker tags. Enabled with `--ble-uuids`.
- **Your own YAML.** Pass `--yaml PATH` to add custom entries. The schema
  is documented in [docs/CONFIGURATION.md](docs/CONFIGURATION.md). Any
  external watchlist can be brought in by converting it to that format.

The CLI is re-runnable. Identical entries are deduplicated, so you can
mix and match sources without worrying about duplicates.

## Privacy and limits

- **Passive only.** talos never transmits, never probes, never tries to
  associate with another network. It reads what Kismet has already heard.
- **MAC randomization is real.** Modern phones rotate their addresses on
  purpose to avoid being tracked. That works against talos too — a
  randomizing phone walking past your Pi will look like a different device
  every few minutes. talos is a good fit for spotting unfamiliar hardware
  that just turned up; it is the wrong tool for tracking a specific
  person's phone.
- **Storage grows over time.** Every sighting goes into SQLite. There is
  no automatic pruning yet, so on a long-running deployment you'll need
  to occasionally trim or rotate the database file yourself.
- **Expect noise at first.** False positives are how you learn what's
  around you. Plan to spend the first week building up your allowlist.
- **Check your local laws.** Passive WiFi/Bluetooth listening is legal in
  most US jurisdictions, but rules vary. It's the operator's job to
  verify what's allowed where they live. Don't cross into active attacks
  — talos won't help you there and isn't trying to.
- **No warranty.** This is a personal-use project, distributed in the
  hope it's useful, with no guarantees of any kind.

## Project layout

```
src/talos/        application package
  config.py         config loading and validation
  db.py             sqlite persistence and migrations
  kismet.py         Kismet REST client (real and fixture-based)
  poller.py         poll loop and `talos` entry point
  rules.py          detection rules and evaluation
  allowlist.py      known-good device suppression
  notify.py         alert dispatch (ntfy, null, recording)
  cli/              command-line tools (talos-seed-watchlist)
  webui/            read-only FastAPI web UI (`talos-ui`)
  migrations/       sqlite schema migrations
  seeds/            built-in threat data
tests/            pytest suite and fixtures
deploy/           systemd units, env template, install guide
docs/             configuration, rules, smoke, dev, status
config/           example YAML configs
```

## Documentation index

- [docs/CONFIGURATION.md](docs/CONFIGURATION.md) — every config field, with
  worked examples for home, office, travel, and multi-adapter setups.
- [docs/RULES.md](docs/RULES.md) — rule schema, semantics, and a tuning
  playbook for cutting down false positives.
- [docs/SMOKE.md](docs/SMOKE.md) — step-by-step verification once you've
  installed talos on the Pi.
- [docs/WINDOWS_DEV.md](docs/WINDOWS_DEV.md) — running and testing talos
  on a Windows or non-Linux dev machine.
- [docs/PROJECT_STATUS.md](docs/PROJECT_STATUS.md) — detailed status
  snapshot: what's shipped, what's deferred, what's tested.
- [deploy/README.md](deploy/README.md) — full systemd install walkthrough.
- [BACKLOG.md](BACKLOG.md) — deferred features and technical debt.

## Development

Day-to-day development happens on a Linux or Windows machine using a fake
Kismet client backed by a JSON fixture, so you don't need real radio
hardware to hack on talos. The full dev setup is in
[docs/WINDOWS_DEV.md](docs/WINDOWS_DEV.md). The project ships with 437
tests across 15 modules; run the fast suite with `pytest -v -m "not slow"`,
or `make test` for the whole thing including the wheel-build test.

## License

TBD before public release.

## Acknowledgments

talos is built on top of [Kismet](https://www.kismetwireless.net/) for the
radio capture and [ntfy](https://ntfy.sh/) for notification delivery, and
owes a debt to the wider open-source RF and wireless-security community
whose tooling makes a project like this possible at all.
