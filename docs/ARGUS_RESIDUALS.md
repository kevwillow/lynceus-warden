# Argus Residual Types Audit

Generated: 2026-05-18T01:24:45Z
Argus snapshot: `C:/Claude/argus-db-main/exports/argus_export.csv`
Snapshot mtime: 2026-05-18T00:37:55Z
Argus schema_version: 21
Argus record_count (meta): 22533
Total CSV rows: 22533
Currently admitted: 22316 (99.0%)
Currently dropped (unknown_type): 217 (1.0%) across 28 distinct residual types

Refresh note (2026-05-18, rc6): `ssid_pattern` was admitted in this
cycle (migration 019 + the case-insensitive substring matcher in
``db.resolve_matched_ssid_pattern_for_eval``), moving 5 rows from
defer-pending-smoke to admit. Numbers below reflect the post-admit
counts.

Refresh note (2026-05-21, v0.6.1): `ble_local_name` was admitted in
this cycle (migration 020 + ``patterns._normalize_ble_local_name``
+ the watchlist_ble_local_name rule_type), moving 3 v1.4.0 rows
plus the 20 v1.4.1 rows due to land via the coordinated Argus
v1.4.2 release from drop-entirely to admit. The v1.4.0 verdict
(drop-entirely on yield grounds — 3 rows, below the
``NEGLIGIBLE_YIELD_THRESHOLD=5``) was correct at the prior yield;
v1.4.1's 6.7× jump (3 → 20) closes the residual with admit.
Numbers in the table below reflect the snapshot at audit time
(schema_version 21, 3 rows) since the audit was generated before
the v1.4.1 ingest; the verdict column has been updated to admit
to reflect the resolution. The Argus side IDENTIFIER_TYPE_TO_
PATTERN_TYPE promotion for ``ble_local_name`` ships in v1.4.2
alongside this Lynceus change.

## Per-type breakdown

| Type | Argus rows | Sample values | Surface verification | Recommendation |
|------|-----------|---------------|----------------------|----------------|
| `device_class_id` | 49 | `DJI device_type=1`, `DJI device_type=2`, `DJI device_type=3`, `DJI device_type=4`, `DJI device_type=5` | no-observation-surface | drop-entirely |
| `chipset_codename` | 39 | `APQ8009`, `APQ8016`, `APQ8017`, `APQ8036`, `APQ8037` | no-observation-surface | drop-entirely |
| `product_family_codename` | 20 | `AVICORE`, `CONDOR`, `DRONEDOCKINGSTATION`, `DRONERADAR`, `FALCON` | no-observation-surface | drop-entirely |
| `ble_protocol_byte_table` | 16 | `0x01`, `0x05`, `0x07`, `0x09`, `0x0A` | plausible-needs-smoke | defer-pending-smoke |
| `rf_channel` | 16 | `2414.5 MHz`, `2429.502441 MHz`, `2434.5 MHz`, `2444.5 MHz`, `2459.5 MHz` | no-observation-surface | drop-entirely |
| `asdstan_enum_value` | 14 | `asdstan_id_type_values.0=None`, `asdstan_id_type_values.1=Serial Number`, `asdstan_id_type_values.2=CAA-assigned registration ID`, `asdstan_height_type_enum.0=Above take-off`, `asdstan_height_type_enum.1=AGL` | no-observation-surface | drop-entirely |
| `alpr_model` | 11 | `builtin-generic-alpr`, `builtin-flock`, `builtin-motorola`, `builtin-genetec`, `builtin-leonardo` | no-observation-surface | drop-entirely |
| `asdstan_message_type` | 7 | `asdstan_msg_type_0`, `asdstan_msg_type_1`, `asdstan_msg_type_2`, `asdstan_msg_type_3`, `asdstan_msg_type_4` | no-observation-surface | drop-entirely |
| `ssid_pattern` | 5 | `flock`, `Flock`, `FLOCK`, `FS Ext Battery`, `Penguin` | verified-lynceus | admit (rc6: migration 019) |
| `ble_protocol_byte` | 4 | `0x07`, `0x12`, `0x19`, `0x0A` | plausible-needs-smoke | drop-entirely |
| `firmware_sha256_hash` | 4 | `8bcdd2fd8042ba91af2e94db044f301a293936980821a23564a85dfae41a7b12`, `08da4991581076e2d0b3be87c377c177d955d55c92be8ecee66e586181293a2f`, `dede8a4976eee00e464f6e7c301b291954e7941951fdcf23642613912a94bca7`, `0e03a8189b7451d1bb81d6fb10efbcefd399623edcb015af45008eedf8fd1298` | no-observation-surface | drop-entirely |
| `frequency_band` | 4 | `GSM900`, `DCS1800`, `GSM850`, `PCS1900` | no-observation-surface | drop-entirely |
| `rf_protocol_constant` | 4 | `ZC_root_seq=600,147`, `gold_seed=0x12345678 Nc=1600 len=1200`, `CRC_INIT=0x3692 CRC_POLY=0x11021`, `DroneID_packet_len=91 bytes (DRONEID_MAX_LEN), wire-read 177 bytes (raw+overhead)` | no-observation-surface | drop-entirely |
| `ble_characteristic` | 3 | `9b51c418-d3d6-4dab-95a6-a22f3ca01b6e`, `628913a6-8701-40ff-a3ce-8f453ff0818d`, `0000200b-0000-1000-1b7f-430ea194e6cf` | plausible-needs-smoke | drop-entirely |
| `ble_local_name` | 3 | `Penguin`, `Flock`, `FS Ext Battery` | verified-lynceus | admit (v0.6.1: migration 020, coordinated with Argus v1.4.2) |
| `gpt_partition_uuid` | 3 | `9bc13cdc-82e0-88d5-c693-103191f3d2a9`, `8902fc35-5b77-4647-e84b-8da793dff88c`, `6eb751a5-1ae1-1088-0027-860b563d12e5` | no-observation-surface | drop-entirely |
| `operator_profile` | 3 | `builtin-lowes`, `builtin-home-depot`, `builtin-simon-property-group` | no-observation-surface | drop-entirely |
| `x509_cert_sha256_prefix` | 3 | `e7d558a043b8e9eb`, `28c69882dead59ad`, `57158eaf1814d78f` | no-observation-surface | drop-entirely |
| `ble_adv_interval` | 2 | `2.0 s`, `0.033 s (33 ms)` | no-observation-surface | drop-entirely |
| `dji_protocol_struct_format` | 2 | `dji_v1:<H2s16siiHHhhhhhhiiBB20s`, `dji_v2:<H2s16siiHHhhhhQiiiiBB20s` | no-observation-surface | drop-entirely |
| `firmware_build_string` | 2 | `BOOT.BF.3.3-00163`, `modem-ci` | no-observation-surface | drop-entirely |
| `bandwidth_mhz` | 1 | `10 MHz (LTE-derived NCARRIERS=601, NFFT=1024, resample 15.36 MHz)` | no-observation-surface | drop-entirely |
| `ble_payload_offset` | 1 | `offset 7 .. 29 (23 bytes)` | no-observation-surface | drop-entirely |
| `firmware_branded_string` | 1 | `usb:force_eDL` | no-observation-surface | drop-entirely |
| `firmware_build_uuid` | 1 | `Q_SENTINEL_{F5653E1A-81E6-4F62-845C-D7D2E32DCFC4}_20170302_1126` | no-observation-surface | drop-entirely |
| `firmware_image_variant` | 1 | `JAADANAZA` | no-observation-surface | drop-entirely |
| `network_endpoint` | 1 | `http://crl.qdst.com/crls/qctdevattest.crl` | no-observation-surface | drop-entirely |
| `qualcomm_chip_format_id` | 1 | `8953A-JAADANAZA-40000000` | no-observation-surface | drop-entirely |
| `rf_burst_duration` | 1 | `630e-6 .. 665e-6 s (~640 µs)` | no-observation-surface | drop-entirely |

## Per-type surface detail

Detailed surface rationale for each residual type. The table above shows the classification label; the prose below shows why.

- **`device_class_id`** (no-observation-surface): DJI ``device_type`` decoder enum (``DJI device_type=1`` ... ``=70`` mapping to model names like Inspire 1 via the ``DRONEID_DRONE_TYPES`` table in the RUB-SysSec/DroneSecurity decoder). The byte IS in the DJI DroneID broadcast, but the Argus values are model-class enum codes from a decoder catalog rather than per-device identifiers — admitting them as watchlist patterns would alert on every drone of that model class in range, mirroring the unbounded-fanout posture the audit already records for ``rf_channel``. Per-device Remote-ID coverage is via ``drone_id_prefix`` (ANSI/CTA-2063-A serial number prefix, the UAS-ID field), already admitted and observed via ``_DRONE_ID_PATHS`` in ``src/lynceus/kismet.py``. Lynceus has no current probe for the device-type byte and adding one would require a new pattern_type + schema migration + observation surface for a match semantic the watchlist primitive does not fit. Verdict from the rc5 device_class_id archaeology pass (see CHANGELOG).
- **`chipset_codename`** (no-observation-surface): Silicon vendor part number (e.g. ``APQ8009``, ``BCM43xx``) — static manufacturer metadata, not present in Kismet runtime device emissions.
- **`product_family_codename`** (no-observation-surface): Vendor-internal product family designation (``AVICORE``, ``CONDOR``) — static spec metadata, never advertised.
- **`ble_protocol_byte_table`** (plausible-needs-smoke): First-byte protocol indicator inside the BLE manufacturer advertisement payload. Observable in principle via ``kismet.device.base.advdata`` but the byte-table view needs a live emission sample to pin the exact field.
- **`rf_channel`** (no-observation-surface): RF center frequency in MHz. Kismet emits ``kismet.device.base.frequency`` per device, but watchlist semantics — alert on every device on a given frequency — have unbounded fanout and no real detection value.
- **`asdstan_enum_value`** (no-observation-surface): ASD-STAN F3411 enum descriptor (e.g. ``asdstan_id_type_values.0=None``) — Remote-ID taxonomy spec value, not a runtime field.
- **`alpr_model`** (no-observation-surface): Argus-internal ALPR model identifier (``builtin-flock``, ``builtin-motorola``) — taxonomy metadata; no equivalent in Kismet emissions.
- **`asdstan_message_type`** (no-observation-surface): ASD-STAN F3411 message-type descriptor — Remote-ID spec taxonomy, not a runtime field.
- **`ssid_pattern`** (admitted rc6): Case-insensitive substring SSID match. Kismet already emits SSIDs and Lynceus already extracts them; the matcher landed in rc6 as ``db.resolve_matched_ssid_pattern_for_eval`` (case-insensitive substring via ``COLLATE NOCASE``), dispatched alongside the exact-match ``ssid`` type under the same ``watchlist_ssid`` rule_type. Migration 019 extended the ``pattern_type`` CHECK constraint to admit the new type. L-RULES-10 (case/whitespace folding for the existing ``ssid`` type) remains deferred — case-insensitivity is scoped to ``ssid_pattern`` only.
- **`ble_protocol_byte`** (plausible-needs-smoke): Single BLE protocol byte — same observation surface as ``ble_protocol_byte_table``, smaller value cardinality.
- **`firmware_sha256_hash`** (no-observation-surface): Firmware binary hash — static spec metadata from image inspection, never broadcast.
- **`frequency_band`** (no-observation-surface): Cellular band label (``GSM900``, ``DCS1800``) — Kismet does not emit a band-label field; closest is per-device frequency in MHz, which carries different semantics.
- **`rf_protocol_constant`** (no-observation-surface): PHY-layer protocol constants (Zadoff-Chu seeds, gold polynomials, CRC init/poly) — static spec values, not per-device emissions.
- **`ble_characteristic`** (plausible-needs-smoke): BLE GATT characteristic UUID. Kismet does not enumerate GATT services in its default device emission (only advertised service UUIDs); confirming requires a live capture against a connected device.
- **`ble_local_name`** (verified-lynceus, admitted v0.6.1): Kismet emits the BLE friendly name at ``kismet.device.base.name`` — already harvested in ``src/lynceus/kismet.py`` (``_BLE_NAME_FIELD``) when ``capture.ble_friendly_names`` is enabled. Lynceus v0.6.1 admits the pattern_type via migration 020 + ``patterns._normalize_ble_local_name`` + the ``watchlist_ble_local_name`` rule_type. The observation field was renamed ``obs.ble_name → obs.ble_local_name`` for symmetry with the pattern_type. Coordinated with Argus v1.4.2's ``IDENTIFIER_TYPE_TO_PATTERN_TYPE`` promotion; the consumer (Lynceus) admits first so the next Argus emission lands without dropping at the IDENTIFIER_TYPE_MAP gate. v1.4.0 yield was 3 rows (Flock Safety BLE device names: ``Penguin``, ``Flock``, ``FS Ext Battery``); v1.4.1 yield jumps 6.7× to 20 rows (adds ``FLOCK``, ``Flock-*`` shape variants).
- **`gpt_partition_uuid`** (no-observation-surface): GPT partition UUID from firmware image inspection — static metadata, never broadcast.
- **`operator_profile`** (no-observation-surface): Argus-internal operator profile (``builtin-lowes``, ``builtin-home-depot``) — taxonomy metadata.
- **`x509_cert_sha256_prefix`** (no-observation-surface): X.509 certificate hash prefix — TLS handshake artifact, not in Kismet's device emission surface.
- **`ble_adv_interval`** (no-observation-surface): BLE advertising interval in seconds — Kismet does not expose this as a per-device watchlist-shaped value.
- **`dji_protocol_struct_format`** (no-observation-surface): DJI binary struct-pack format string — spec descriptor for payload layout, not a runtime emission.
- **`firmware_build_string`** (no-observation-surface): Firmware build identifier (``BOOT.BF.3.3-00163``) from manufacturer specs — static metadata.
- **`bandwidth_mhz`** (no-observation-surface): Channel bandwidth in MHz — Kismet may expose channel width but watchlist semantics are not meaningful.
- **`ble_payload_offset`** (no-observation-surface): Byte offset descriptor inside a BLE adv payload — spec metadata, not a per-device runtime field.
- **`firmware_branded_string`** (no-observation-surface): Firmware-branded marker (e.g. ``usb:force_eDL``) — static spec string, never advertised.
- **`firmware_build_uuid`** (no-observation-surface): Firmware build UUID from manufacturer specs — static metadata, never broadcast.
- **`firmware_image_variant`** (no-observation-surface): Firmware image variant tag — static manufacturer metadata.
- **`network_endpoint`** (no-observation-surface): URL (CRL / OCSP endpoint) — TLS-layer artifact discovered in firmware inspection, not in Kismet emissions.
- **`qualcomm_chip_format_id`** (no-observation-surface): Qualcomm chip format identifier — static spec metadata.
- **`rf_burst_duration`** (no-observation-surface): RF burst duration in seconds — spec metadata, not a per-device emission.

## Summary

- **admit**: 2 type(s), 8 row(s)  *(rc6: ssid_pattern via migration 019; v0.6.1: ble_local_name via migration 020, coordinated with Argus v1.4.2)*
- **admit-via-normalization**: 0 type(s), 0 row(s)
- **defer-pending-smoke**: 1 type(s), 16 row(s)
- **drop-entirely**: 26 type(s), 198 row(s)
- **needs-classification**: 0 type(s), 0 row(s)

## Methodology

Row counts are derived by parsing the Argus CSV with the importer's ``parse_argus_csv`` helper, then grouping rows whose lowercased ``identifier_type`` is not a key in ``IDENTIFIER_TYPE_MAP`` (the same set the importer uses to decide admission). Sample values are the first five distinct ``identifier`` strings seen per group; small-cardinality residuals show all of them.

Surface verification is desk research, not live capture. Each residual type maps to a classification in ``RESIDUAL_SURFACE_TABLE`` in ``scripts/audit_residuals.py``:

- ``normalization-variant`` — the residual is the same underlying concept as an admitted ``pattern_type``, blocked only by case / hex-shape / dual-form rendering. Fix is in the importer's normalization layer, not a new Kismet surface.
- ``verified-lynceus`` — Lynceus's ``src/lynceus/kismet.py`` already extracts the underlying Kismet field for some purpose, so the observation path is confirmed by the existing code rather than speculative.
- ``verified-kismet-docs`` — the field appears in Kismet's documented device schema with a clear path; Lynceus has no current consumer but the surface is known.
- ``plausible-needs-smoke`` — likely observable based on the Kismet device data model, but not pinned to a specific documented field. A live capture against representative hardware is needed before committing to an admit path.
- ``no-observation-surface`` — the residual is static manufacturer metadata, taxonomy descriptors, or PHY-spec constants that Kismet does not emit at runtime.

Recommendation logic (see ``classify_recommendation``):

- ``admit-via-normalization`` if surface is ``normalization-variant``.
- ``drop-entirely`` if surface is ``no-observation-surface``, OR if yield is below ``NEGLIGIBLE_YIELD_THRESHOLD = 5`` (small-tail residuals don't justify a new code path).
- ``admit`` if surface is ``verified-lynceus`` and yield clears the threshold.
- ``defer-pending-smoke`` for the remainder (``verified-kismet-docs`` / ``plausible-needs-smoke`` with yield above the threshold).
- ``needs-classification`` if the residual type is not in ``RESIDUAL_SURFACE_TABLE`` at all — the audit refuses to fabricate a verdict for an unknown type and surfaces it for a table refresh.

## Re-running

    python scripts/audit_residuals.py [--csv PATH] [--output PATH]

Re-run after each Argus snapshot refresh; the report regenerates against the new CSV. If a new residual type lands in ``identifier_type`` that is not in ``RESIDUAL_SURFACE_TABLE``, the recommendation column shows ``needs-classification`` and the table needs an entry before the next F1/F2 sizing pass.
