# Rules engine reference

Detection rules live in a separate YAML file pointed to by `rules_path` in `lynceus.yaml`. The schema is defined in [src/lynceus/rules.py](../src/lynceus/rules.py) and rejects unknown fields.

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
| `rule_type` | string | (required) | One of the eleven types listed below. |
| `severity` | string | (required) | One of `low`, `med`, `high`. |
| `enabled` | bool | `true` | When `false`, the rule is loaded but skipped during evaluation. Useful for keeping rules in the file without firing. |
| `shadow` | bool | `false` | When `true`, the rule is evaluated in full against live traffic and counted, but **cannot produce an alert or a notification**. See [Shadow mode](#shadow-mode-measure-a-rule-before-you-enable-it). Not a synonym for `enabled: false`, which skips the rule entirely and counts nothing. |
| `patterns` | list of string | `[]` | Depends on the rule type. See the three cases below; the old one-line rule here was wrong for ten of the eleven types. |
| `description` | string \| null | `null` | Free-form note. When set, it appears in the alert message body. |

Pattern format depends on rule type. See the per-type sections below. Patterns are normalized at load time (e.g. MACs are lowercased and converted to colon-separated form), so `AA-BB-CC-DD-EE-FF` and `aa:bb:cc:dd:ee:ff` are equivalent.

### When `patterns` must be empty, and when it must not

⛔ **Getting this wrong stops the daemon**, it does not disable one rule.
`load_ruleset` raises and the process exits non-zero, so you lose all detection
until the file is fixed. Run `lynceus-validate validate` after editing; it
catches the same error without taking the daemon down.

| case | types | `patterns` |
| --- | --- | --- |
| **must be EMPTY** | `new_non_randomized_device`, `watchlist_mac_range`, `watchful_recurrence` | `patterns: []` |
| **must be NON-EMPTY** | `ble_device_class` | at least one value |
| **either** (empty means DB delegation) | `watchlist_mac`, `watchlist_oui`, `watchlist_ssid`, `ble_uuid`, `watchlist_ble_manufacturer_id`, `watchlist_ble_local_name`, `watchlist_drone_id_prefix` | non-empty matches those literals in memory; `[]` delegates to the watchlist DB and takes severity from the matched row |

⚠️ **`watchlist_mac_range` is the trap.** It is the inverse of what you would
guess, it has no per-type section below, and this table is its only
documentation. `config/rules.yaml` says the same thing above the rule:
*"Patterns MUST be empty"*.

⚠️ This table replaces a single sentence that read *"Required and non-empty for
all `watchlist_*` and `ble_uuid` rules"*. That was correct for one of the eleven
types, and it instructed exactly the shape that hard-fails for
`watchlist_mac_range`.

## The rule types

⚠️ **There are eleven, and only five are documented in detail below.** This
heading read "The five rule types" until 2026-08-31, which was true when
written and stopped being true as types were added without the doc following.
The authoritative list is the `rule_type` literal in
[src/lynceus/rules.py](../src/lynceus/rules.py); a ruleset naming anything else
is rejected at load.

| type | documented below | notes |
| --- | --- | --- |
| `watchlist_mac` | ✅ | |
| `watchlist_oui` | ✅ | |
| `watchlist_ssid` | ✅ | |
| `ble_uuid` | ✅ | |
| `new_non_randomized_device` | ✅ | |
| `watchlist_mac_range` | ⛔ not yet | |
| `watchlist_ble_manufacturer_id` | ⛔ not yet | ships commented out; see [Shadow mode](#shadow-mode-measure-a-rule-before-you-enable-it) before enabling |
| `watchlist_drone_id_prefix` | ⛔ not yet | ships commented out; capture path unverified against a real drone |
| `watchlist_ble_local_name` | ⛔ not yet | ships commented out |
| `watchful_recurrence` | ⛔ not yet | |
| `ble_device_class` | ⛔ not yet | |

Writing the six missing sections is open work. They are named here rather than
omitted, because a list that silently stops at five reads as complete.

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

Fires when the device's `ssid` matches a watchlisted SSID. Only WiFi devices populate `ssid`; BLE and Bluetooth Classic sightings always miss.

Two modes, picked by whether `patterns` is empty:

**In-memory mode (non-empty `patterns`):** classic exact-string match against the listed patterns, case-sensitive per IEEE 802.11. Severity comes from the rule. This is the operator-curated path for known evil-twin SSIDs.

```yaml
- name: rogue_ssids
  rule_type: watchlist_ssid
  severity: med
  patterns:
    - FreeAirportWiFi
    - attwifi-rogue
  description: SSIDs commonly used for evil-twin attacks
```

**DB-delegation mode (empty `patterns`):** the rule consults the watchlist DB for every observation, dispatching two pattern_types under one rule:

- `pattern_type='ssid'`. **case-sensitive exact match**, consulted first.
- `pattern_type='ssid_pattern'`. **case-insensitive substring match**, consulted as a fallback when the exact match misses. The watchlist row's stored `pattern` is the substring needle; the observation's `ssid` is the haystack.

Severity comes from the matched DB row (not from `rule.severity`, which is ignored in this mode). The bundled `argus_ssid` rule in `config/rules.yaml` is the default-enabled delegation entry; the bundled `default_watchlist.csv` ships SSID rows imported from Argus (Flock cameras, Penguin trackers, and the FS Ext Battery family at the rc6 snapshot).

```yaml
- name: argus_ssid
  rule_type: watchlist_ssid
  severity: low  # ignored; actual severity comes from the matched row
  patterns: []
  description: "Argus + bundled SSID watchlist (exact + substring)"
```

Both modes coexist in the same ruleset. A typical deployment runs the delegation entry alongside any operator-curated in-memory entries for site-specific evil-twin SSIDs.

### `ble_uuid`

Fires when the device's advertised BLE GATT service UUIDs include any pattern. Patterns must be 128-bit UUIDs in the standard `8-4-4-4-12` hex form; they are normalized at load time (lowercased, dashes preserved). Only BLE devices populate `ble_service_uuids`. Wi-Fi and Bluetooth Classic sightings always miss.

This is the AirTag-class detector: Apple's tracker advertises a known service UUID even when in lost mode, and the same shape works for a growing list of consumer trackers. Bring your own list; the seed file in `src/lynceus/seeds/` is a starting point, not exhaustive.

```yaml
- name: airtag_detected
  rule_type: ble_uuid
  severity: high
  patterns:
    - 0000FD5A-0000-1000-8000-00805F9B34FB   # Apple AirTag service UUID
  description: AirTag-class BLE tracker observed
```

### `new_non_randomized_device`

Fires the **first** time a device shows up at this location, but only if it looks like the device is broadcasting a real, factory-assigned MAC address rather than a randomized one. (Technically: the second bit of the first byte of the MAC must be 0. Devices that are deliberately randomizing flip this bit on; real-vendor MACs leave it off.) The intent is to catch things like IoT gear, older laptops, and hardware that doesn't try to hide its identity, while ignoring the constant churn of randomized phones walking past. `patterns` must be empty for this rule type.

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

The ntfy notification title is always `lynceus: {SEVERITY} alert` (uppercase severity), and the body is the rule's generated message. See [src/lynceus/notify.py](../src/lynceus/notify.py) for the exact mapping.

A rough calibration: reserve `high` for things you would actually drop a meeting for (Pineapple OUI, known bad MAC). Keep `low` for the broad "noticed something new" rule. Use `med` in between, sparingly.

## Shadow mode: measure a rule before you enable it

Set `shadow: true` on a rule. It is then evaluated in full against live traffic
and its hits are counted, and it **alerts on nothing**.

```yaml
  - name: argus_ble_manufacturer_id
    rule_type: watchlist_ble_manufacturer_id
    severity: low
    patterns: []
    shadow: true          # evaluated, counted, alerts on NOTHING
```

Restart the daemon, leave it a day, then read the result on `/settings`, or:

```
journalctl -u lynceus.service | grep 'shadow rule'
```

**Why this exists.** Several rules ship commented out on an alert-storm
argument computed against the *bundled* watchlist. That argument says nothing
about your airspace, and until you can measure your own, enabling a rule is a
guess. Shadow mode turns the guess into a number from your own site.

⛔ **A shadow rule cannot alert, structurally rather than by convention.**
`evaluate()` returns only alertable hits; a shadow rule's hits go to a separate
sink and appear in no other return value. Forgetting the sink costs you counts.
It cannot cost you a storm.

⛔ **Read the denominator, not just the count.** Zero means two opposite things
and they demand opposite responses:

| result | meaning | what to do |
| --- | --- | --- |
| hits > 0 | the rule fires here | decide whether that volume is acceptable |
| 0 hits, field **was** seen | genuinely quiet on this site, this window | reasonable to enable |
| 0 hits, field **never** seen | the rule is inert; the capture path never populates the field | enabling it buys nothing and hides the gap |

The `/settings` card is three-valued (`fired` / `quiet` / `inert`) for exactly
this reason, and carries the window it counted over, because a total with no
window is not a rate.

⚠️ **The "inert" case is live, not theoretical.** For a Kismet-only install the
field paths for `ble_manufacturer_id` and `drone_id_prefix` are unverified
against a real capture, so those fields may read `None` on every observation.
With the BLE bridge on, the manufacturer-id half is proven end to end.

⚠️ **A quiet window is evidence about your site over that window**, not a
property of the rule. Airspace changes; so does the answer.

`enabled: false` is **not** a synonym. It skips the rule entirely, so it counts
nothing and teaches you nothing.

## Allowlist semantics

The allowlist is checked **before** rule evaluation, but what it suppresses depends on **which attribute matched**.

| entry `pattern_type` | kind | what it suppresses |
| --- | --- | --- |
| `mac`, `mac_range`, `oui` | **hard** (set by the radio) | everything for that sighting, including `new_non_randomized_device` |
| `ssid`, `ble_uuid`, `ble_manufacturer_id`, `ble_local_name`, `drone_id_prefix`, … | **soft** (chosen by the device) | ambient noise only. An explicit **watchlist hit still alerts**, and the daemon logs a WARNING saying so. |

⛔ **The soft case is a security boundary, not an inconsistency.** A soft value
is attacker-controlled: anything in range can broadcast a name or a service
UUID you have allowlisted. If a soft match could suppress watchlist hits, an
adversary could silence your own HIGH-severity MAC entry just by advertising
the right string. So `is_soft_attribute` (`allowlist.py:295`) splits them, and
`poller.py:798` refuses to suppress. Fixed in #82.

⚠️ **This section claimed "**all** alerts are suppressed ... no per-rule
carve-outs" until 2026-09-01.** That was true before #82 and was corrected in
`poller.py`'s own docstring at the time; this file was missed. It matters
because soft entries only reach the allowlist through a **hand-edited
`allowlist.yaml`**, which is exactly the file this section documents.
Suppressions created from the web UI always write `pattern_type: mac`, so they
are hard and unaffected.

For hard entries the original intent still holds: the allowlist means "I know
this device, do not bother me about it ever". If you want to allowlist a device
for one rule but still alert on another, the right answer is usually to disable
or scope down the noisy rule rather than to add a more granular allowlist.

`allowlist.yaml` shape (from [src/lynceus/allowlist.py](../src/lynceus/allowlist.py)):

```yaml
entries:
  - pattern: A4:83:E7:11:22:33
    pattern_type: mac          # mac | oui | ssid
    note: my laptop            # optional
```

Allowlist patterns are normalized identically to rule patterns.

## Dedup window

After a rule fires and an alert is written, the same `(rule_name, mac)` pair is suppressed for `alert_dedup_window_seconds` (default `3600`). This is the single most important knob for noise control on a long-running deployment, without it, a Pineapple sitting in your environment would generate one alert per poll, forever.

Dedup is keyed on `(rule_name, mac)`, not on rule type or severity, so:

- The same MAC matched by two different rules emits two alerts (one per rule), both subject to their own dedup window.
- Two different MACs matched by the same rule emit two alerts.
- Setting `alert_dedup_window_seconds: 0` disables dedup entirely. Every hit becomes an alert. Useful in travel mode; painful at home.

Dedup state lives in the `alerts` table, so it survives restarts.

## A note on MAC randomization

Lynceus does not try to defeat MAC randomization, and you should not expect it to. Modern iPhones and Android phones change their WiFi MAC for each network they connect to (sometimes for each individual connection), and they rotate their Bluetooth Low Energy address every few minutes regardless. So if the same phone walks past your Pi twice, it will most likely look like two completely different devices. Neither `watchlist_mac` nor `new_non_randomized_device` can stitch those sightings together.

What lynceus **is** useful for:

- IoT devices (smart bulbs, plugs, cameras) that ship with stable OEM MACs.
- Fitness trackers, headphones, and other Bluetooth Classic gear.
- Specialty hardware with recognizable OUI prefixes (Pineapples, certain SDR rigs).
- Older or non-randomizing devices that don't bother hiding their real MAC.
- AirTag-class BLE trackers, via the `ble_uuid` rule type plus a list of known tracker service UUIDs.

If your threat model is "is a specific person's iPhone in this room," lynceus is the wrong tool. If it's "did a piece of unfamiliar hardware just appear," it's a good fit.

## Tuning playbook (first week)

False positives in the first 24–48 hours are not a bug. They're the system showing you what it sees. Plan to spend the first week curating, not debugging.

A rough triage flow when an alert fires:

1. **Identify the device.** Look up the OUI vendor (the `oui_vendor` column in the `devices` table or any online OUI database). If it's your printer, your fridge, or a coworker's laptop: allowlist candidate.
2. **Decide: allowlist, disable, or tune?**
   - **Allowlist** when the device is yours or otherwise expected. Add an entry to `allowlist.yaml` keyed by MAC for one device or by OUI for a vendor block. This is the right answer for the bulk of first-week noise.
   - **Disable a rule** (`enabled: false`) when the rule itself doesn't fit your environment, for example, `new_non_randomized_device` set to `med` in a coffee shop is going to be useless. Drop its severity or turn it off.
   - **Raise the dedup window** when a single device legitimately matches but you don't need to be told every hour. Bump `alert_dedup_window_seconds` from `3600` to `86400` (one day) for a noisy persistent match.
3. **Make the change take effect.** ⭐ **An `allowlist.yaml` edit is live: no
   restart.** The poller stats both allowlist files before every tick and
   reloads on an mtime change, which is also why the web UI's snooze and
   allowlist buttons take effect immediately. Editing `rules.yaml` or
   `lynceus.yaml` **does** need `sudo systemctl restart lynceus`. See
   [CONFIGURATION.md](CONFIGURATION.md) for the per-file table.

   ⚠️ This step said "no live reload yet" until 2026-09-01. That was true for
   thirteen days in May 2026 and false ever since, and it was false about the
   one bullet above that this section calls the right answer for most
   first-week noise.
4. **Keep notes.** A short comment on each allowlist entry (`note:`) is worth its weight three months later when you can't remember why a MAC is on the list.

By the end of week one, you should be down to a handful of alerts per day, almost all of which are interesting. If you're still drowning, the next move is usually to drop `new_non_randomized_device` to `low` (or off) and rely on the `watchlist_*` rules for signal.
