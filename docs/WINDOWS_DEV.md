# Talos local development on Windows

This guide describes running Talos against a fixture-driven fake Kismet on a Windows development machine. The actual capture path requires a Pi with a real WiFi monitor adapter and Kismet; that's covered in [deploy/README.md](../deploy/README.md) and [docs/SMOKE.md](SMOKE.md). This guide is for everything else: building, testing, running the daemon, exercising the web UI, and verifying behavior before deploying.

## Prerequisites

- Python 3.11 or newer on Windows.
- `git` and a recent browser (Edge / Chrome / Firefox).

You do **not** need: Linux, a Pi, a real Kismet, a monitor-mode adapter, or Bluetooth hardware. Everything below runs against bundled fixture files.

## Setup

```powershell
git clone <your-fork-or-mirror> talos
cd talos
python -m venv .venv
.\.venv\Scripts\activate
pip install -e ".[dev]"
pytest -v -m "not slow"
```

The fast suite should report ~410+ tests passing. The wheel-build test (`-m slow`) takes another 30–60 seconds and is gated behind `pytest -v` (no marker filter).

## Running the daemon against a fixture

Use [config/talos.dev.example.yaml](../config/talos.dev.example.yaml) as a template. Copy it to `talos.yaml` in the repo root:

```powershell
Copy-Item config/talos.dev.example.yaml talos.yaml
```

The fixture path in that file points at [tests/fixtures/dev_kismet.json](../tests/fixtures/dev_kismet.json), which ships with the repo. It contains seven devices (Wi-Fi APs, BLE devices including an AirTag, ordinary Bluetooth Classic gear) spread across a few minutes of synthetic time, designed to exercise every UI feature and at least three rule types if you point at `config/rules.yaml`.

Run:

```powershell
talos --config talos.yaml
```

Every poll cycle (default 5s in the dev config) the console should print devices processed from the fixture. Adjust `poll_interval_seconds` upward if the log gets too chatty.

## Running the web UI

In a second terminal, with the venv activated:

```powershell
talos-ui --config talos.yaml
```

Open `http://127.0.0.1:8765/` in your browser. You should see the index with health stats, the 30-day sparkline, recent alerts, and the navigation across the routes documented in [CONFIGURATION.md](CONFIGURATION.md#web-ui-routes).

## What works locally

- The daemon polls `FakeKismetClient` and writes to the local SQLite DB.
- Rules fire and alerts persist; `ntfy` notifications fail silently unless you configure a real ntfy server in `talos.yaml`.
- The web UI renders fully against the local DB.
- You can ack / unack alerts (single, bulk, ack-all-visible), view device history, and exercise the alerts/devices filters.
- Per-source location labelling works against the fixture — set `kismet_source_locations` in `talos.yaml` mapping `dev-builtin-wifi` / `dev-alfa-wifi` / `dev-builtin-bt` to override location IDs and verify the per-source attribution path.
- The static-asset regression tests (`tests/test_static_assets.py`) catch placeholder vendoring; a real browser load against `talos-ui` confirms Pico CSS is actually styling the pages.

## What doesn't work locally

- No real RF capture. The fixture is a fixed snapshot; new devices don't appear over time the way they would on a real Pi. To test "new device" behavior, edit the fixture and restart the daemon.
- The systemd unit files in `deploy/` are Linux-specific; ignore them on Windows. The `talos` and `talos-ui` console scripts are the dev path.
- Real Bluetooth detection on the Pi requires a real adapter; the fixture simulates BLE / Bluetooth Classic devices but no radios are involved.
- `kismet_health_check_on_startup` against a real `kismet_url` will fail outside the lab. Keep `kismet_fixture_path` set (which makes `FakeKismetClient.health_check()` always report reachable), or set `kismet_health_check_on_startup: false` if you point at a real URL.

## Iteration tips

- Edit fixtures to test new scenarios. [tests/fixtures/dev_kismet.json](../tests/fixtures/dev_kismet.json) and the `integration_kismet_*.json` files are good templates. The Kismet device shape is documented inline in [src/talos/kismet.py](../src/talos/kismet.py) (`parse_kismet_device`).
- Edit `rules.yaml` and `allowlist.yaml` on disk; restart the daemon to pick up changes. (Live reload is on the v0.3 backlog — see [BACKLOG.md](../BACKLOG.md).)
- Use the fast test loop while iterating:

  ```powershell
  pytest -v -m "not slow" --ff -x
  ```

  `--ff` re-runs failures first; `-x` stops on first failure. This usually puts you back in the feedback loop in under 5 seconds after a code change.
- Type checking and the test suite verify code correctness, not browser behavior. For UI work, keep a browser tab open against `http://127.0.0.1:8765/` and reload after each change. The ack flow in particular only exercises CSRF end-to-end through a real cookie jar.

## Maintenance: rebumping the dev fixture

The dev fixture (`tests/fixtures/dev_kismet.json`) ships with timestamps anchored to a specific real-world time. As wall-clock time advances, the recency-aware UI surfaces (devices-seen-in-last-24h, the 30-day sparkline, "Last polled" age, etc.) will start showing empty or stale state because the fixture's "newest" data falls out of view.

When this happens, run:

```powershell
python scripts/rebump_dev_fixture.py
```

This rewrites the fixture's timestamps to be relative to "now" (anchored one hour back, with devices spread across the last several hours). The fixture's MACs, vendors, SSIDs, and BLE service UUIDs are preserved verbatim — only timestamps change.

Use `--dry-run` first if you want to see what the script will do:

```powershell
python scripts/rebump_dev_fixture.py --dry-run
```

Why this is necessary: integration test fixtures freeze time within their tests, so they don't have this problem. The dev fixture is consumed by a live daemon, which compares fixture timestamps against the system clock. The durable fix is auto-shift-on-load in `FakeKismetClient` — see [BACKLOG.md](../BACKLOG.md). Until that lands, manual rebumping every few months is the expedient.

Commit the resulting fixture change separately from any other work, with a message like `chore: rebump dev fixture timestamps`. Future-you will appreciate the clean diff.

## When to stop iterating on Windows and move to the Pi

When the feature involves any of: real WiFi or BLE captures, monitor-mode behavior, multi-adapter testing, multi-Pi deployment, ntfy delivery to your phone, or systemd unit lifecycle. Everything else can be developed and tested on Windows with the fixture path.
