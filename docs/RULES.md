# Rules engine reference

Detection rules live in a separate YAML file pointed to by `rules_path` in `talos.yaml`. The schema is defined in [src/talos/rules.py](../src/talos/rules.py) and rejects unknown fields.

When a sighting comes in, the poller asks the allowlist whether the device is suppressed; if not, it evaluates the full ruleset against the observation and emits one alert per hit (subject to dedup).

## Schema

The top-level document is a `Ruleset`:

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `rules` | list of Rule | `[]` | The ordered list of rules to evaluate. Rule names must be unique within a ruleset. |

Each `Rule`:

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | string | (required) | Unique identifier. Used as the dedup key and recorded on every emitted alert. |
| `rule_type` | string | (required) | One of `watchlist_mac`, `watchlist_oui`, `watchlist_ssid`, `new_non_randomized_device`. |
| `severity` | string | (required) | One of `low`, `med`, `high`. |
| `enabled` | bool | `true` | When `false`, the rule is loaded but skipped during evaluation. Useful for keeping rules in the file without firing. |
| `patterns` | list of string | `[]` | Required and non-empty for all `watchlist_*` types. Must be empty for `new_non_randomized_device`. |
| `description` | string \| null | `null` | Free-form note. When set, it appears in the alert message body. |

Pattern format depends on rule type — see the per-type sections below. Patterns are normalized at load time (e.g. MACs are lowercased and converted to colon-separated form), so `AA-BB-CC-DD-EE-FF` and `aa:bb:cc:dd:ee:ff` are equivalent.

## The four rule types

### `watchlist_mac`

Fires when the observed device's MAC matches any pattern exactly.

```yaml
- name: known_bad_mac
  rule_type: watchlist_mac
  severity: high
  patterns:
    - DE:AD:BE:EF:00:01
    - aa:bb:cc:dd:ee:ff
  description: hostile MACs from internal threat intel
```

### `watchlist_oui`

Fires when the observed device's MAC begins with any 24-bit OUI prefix in `patterns`. Patterns must be three colon-separated hex octets.

```yaml
- name: hak5_pineapple_oui
  rule_type: watchlist_oui
  severity: high
  patterns: ["00:13:37"]
  description: Hak5 WiFi Pineapple OUI prefix
```

### `watchlist_ssid`

Fires when the device's `ssid` exactly matches any pattern. Only WiFi devices populate `ssid`; BLE and Bluetooth Classic sightings always miss.

```yaml
- name: rogue_ssids
  rule_type: watchlist_ssid
  severity: med
  patterns:
    - FreeAirportWiFi
    - attwifi-rogue
  description: SSIDs commonly used for evil-twin attacks
```

### `new_non_randomized_device`

Fires the **first** time a device is seen at this location, but only if its MAC is **not** locally administered (i.e. the second-least-significant bit of the first octet is 0). This catches IoT and older hardware that broadcasts a real OEM MAC. `patterns` must be empty.

```yaml
- name: new_device_alert
  rule_type: new_non_randomized_device
  severity: low
  description: first sighting of a non-randomized device at this location
```

## Severity tiers

Severity drives both the ntfy priority and the tag emoji:

| Severity | ntfy `Priority` header | ntfy `Tags` header | What it means | What you should do |
| --- | --- | --- | --- | --- |
| `low` | `2` | `information_source` | Low-priority FYI. Background noise is acceptable here. | Glance at the next time you check your phone. |
| `med` | `3` | `warning` | Default-priority alert worth attention. | Triage within minutes. |
| `high` | `5` | `rotating_light` | Maximum-priority alert. Phone breaks through Do Not Disturb on most ntfy clients. | Look immediately. |

The ntfy notification title is always `talos: {SEVERITY} alert` (uppercase severity), and the body is the rule's generated message. See [src/talos/notify.py](../src/talos/notify.py) for the exact mapping.

A rough calibration: reserve `high` for things you would actually drop a meeting for (Pineapple OUI, known bad MAC). Keep `low` for the broad "noticed something new" rule. Use `med` in between, sparingly.

## Allowlist semantics

The allowlist is checked **before** rule evaluation. If a device matches any allowlist entry, **all** alerts are suppressed for that sighting — including `new_non_randomized_device`.

This is a deliberate design choice: the allowlist is meant to mean "I know this device, do not bother me about it ever" with no per-rule carve-outs. If you find yourself wanting to allowlist a device for one rule but still alert on another, the right answer is usually to disable or scope down the noisy rule rather than to add a more granular allowlist.

`allowlist.yaml` shape (from [src/talos/allowlist.py](../src/talos/allowlist.py)):

```yaml
entries:
  - pattern: A4:83:E7:11:22:33
    pattern_type: mac          # mac | oui | ssid
    note: my laptop            # optional
```

Allowlist patterns are normalized identically to rule patterns.

## Dedup window

After a rule fires and an alert is written, the same `(rule_name, mac)` pair is suppressed for `alert_dedup_window_seconds` (default `3600`). This is the single most important knob for noise control on a long-running deployment — without it, a Pineapple sitting in your environment would generate one alert per poll, forever.

Dedup is keyed on `(rule_name, mac)`, not on rule type or severity, so:

- The same MAC matched by two different rules emits two alerts (one per rule), both subject to their own dedup window.
- Two different MACs matched by the same rule emit two alerts.
- Setting `alert_dedup_window_seconds: 0` disables dedup entirely — every hit becomes an alert. Useful in travel mode; painful at home.

Dedup state lives in the `alerts` table, so it survives restarts.

## MAC randomization caveat

Talos is **not** in the business of defeating MAC randomization. Modern iOS and Android randomize the WiFi MAC per-SSID (often per-association) and rotate BLE addresses on a timer measured in minutes. For those devices, neither `watchlist_mac` nor `new_non_randomized_device` will reliably catch a recurring presence — the MAC has changed by the next sighting.

What talos **is** useful for in v0.1:

- IoT devices (smart bulbs, plugs, cameras) that ship with stable OEM MACs.
- Fitness trackers, headphones, and other Bluetooth Classic gear.
- Specialty hardware with recognizable OUI prefixes (Pineapples, certain SDR rigs).
- Older or non-randomizing devices that don't bother hiding their real MAC.
- AirTag-class BLE trackers — **planned for v0.2** via service-UUID extraction; not present in v0.1.

If your threat model is "is a specific person's iPhone in this room," talos v0.1 is the wrong tool. If it's "did a piece of unfamiliar hardware just appear," it's a good fit.

## Tuning playbook (first week)

False positives in the first 24–48 hours are not a bug — they're the system showing you what it sees. Plan to spend the first week curating, not debugging.

A rough triage flow when an alert fires:

1. **Identify the device.** Look up the OUI vendor (the `oui_vendor` column in the `devices` table or any online OUI database). If it's your printer, your fridge, or a coworker's laptop: allowlist candidate.
2. **Decide: allowlist, disable, or tune?**
   - **Allowlist** when the device is yours or otherwise expected. Add an entry to `allowlist.yaml` keyed by MAC for one device or by OUI for a vendor block. This is the right answer for the bulk of first-week noise.
   - **Disable a rule** (`enabled: false`) when the rule itself doesn't fit your environment — for example, `new_non_randomized_device` set to `med` in a coffee shop is going to be useless. Drop its severity or turn it off.
   - **Raise the dedup window** when a single device legitimately matches but you don't need to be told every hour. Bump `alert_dedup_window_seconds` from `3600` to `86400` (one day) for a noisy persistent match.
3. **Restart talos** so the changes take effect (v0.1 has no live reload — see [CONFIGURATION.md](CONFIGURATION.md)).
4. **Keep notes.** A short comment on each allowlist entry (`note:`) is worth its weight three months later when you can't remember why a MAC is on the list.

By the end of week one, you should be down to a handful of alerts per day, almost all of which are interesting. If you're still drowning, the next move is usually to drop `new_non_randomized_device` to `low` (or off) and rely on the `watchlist_*` rules for signal.
