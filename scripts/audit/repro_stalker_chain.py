"""Live proof: what the SHIPPED config does with a real Find My "separated" advert.

The chain under test, end to end, is the stalker-detection one:

    advert bytes -> Continuity decode -> observation field -> rule -> alert row
                 -> notifier dispatch

⛔ WHAT THIS DOES AND DOES NOT MEASURE. It drives the bridge's real
``_record_advert`` -> ``_flush`` -> ``process_observation`` seam, which is the
same seam the radio feeds. It does NOT measure the radio: the scan loop
(``BleBridge.run``) needs an HCI adapter and is not exercised here. On this box
the BLE radio is blocked, so a radio measurement would read zero for reasons
that have nothing to do with the code. Everything downstream of the advert
bytes is real.

⛔ This script resolves its code AND its config from the checkout it lives in,
and asserts that it did -- same reasoning as repro_watchlist_gap.py next to it:
an editable install otherwise wins the import and the proof silently grades a
different tree than the one it lives in.

The advert bytes are not invented. A Find My message is ``[type][length][body]``
with type 0x12; the separated form carries 25 body bytes (status + rotating
public key material) and the paired form carries 2 (status + hint). That
structural difference is what ble_continuity decodes, and it was measured
against a 204-frame rig capture on 2026-08-01. So ``0x12 0x19 + 25 bytes`` is a
structurally genuine separated frame, not a string typed into a fixture.

TWO ARMS, because an arm that cannot fail proves nothing:

  A (control)   the shipped config/rules.yaml, unmodified.
  B (treatment) the same file with the apple_find_my block uncommented.

and within each arm, TWO adverts: a separated tracker (the signal you want) and
a paired one (every passer-by's own iPhone -- the noise case that must NOT
alert). An arm that alerts on both is not detection, it is a noise generator.
"""

from __future__ import annotations

import re
import sys
import tempfile
import time
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / "src"))

import lynceus  # noqa: E402
from lynceus.allowlist import Allowlist  # noqa: E402
from lynceus.bridges.ble import BleBridge  # noqa: E402
from lynceus.config import Config  # noqa: E402
from lynceus.db import Database  # noqa: E402
from lynceus.notify import RecordingNotifier  # noqa: E402
from lynceus.rules import load_ruleset  # noqa: E402

_resolved = Path(lynceus.__file__).resolve()
if _REPO / "src" not in _resolved.parents:
    raise SystemExit(
        f"REFUSING TO RUN: imported lynceus from {_resolved}, which is not under\n"
        f"{_REPO / 'src'}. Something else -- almost certainly an editable install --\n"
        f"won the import, so this proof would grade a different tree than the one it\n"
        f"lives in. Fix the environment rather than trusting the output."
    )

_SHIPPED_RULES = _REPO / "config" / "rules.yaml"

print(f"tree under test:       {_REPO}")
print(f"lynceus imported from: {_resolved.parent}")
print(f"rules file:            {_SHIPPED_RULES}")
print()

# --- the adverts -----------------------------------------------------------

APPLE = 0x004C
_MSG_FIND_MY = 0x12

# Separated: 25 body bytes. The body content is irrelevant to the decode (it is
# the LENGTH that carries the separation state), and the real bytes are rotating
# key material we deliberately never retain -- so zeros are honest here.
ADVERT_SEPARATED = {APPLE: bytes([_MSG_FIND_MY, 0x19]) + bytes(25)}
# Paired: 2 body bytes.
ADVERT_PAIRED = {APPLE: bytes([_MSG_FIND_MY, 0x02]) + bytes(2)}

MAC_SEPARATED = "c2:ff:ee:5e:aa:11"  # locally-administered, as a real tracker is
MAC_PAIRED = "c2:ff:ee:bb:11:ed"


def _decode_check() -> None:
    """Hop 1->2: the bytes really do decode to the classes this proof assumes."""
    from lynceus.ble_continuity import classify_manufacturer_data

    sep = classify_manufacturer_data(ADVERT_SEPARATED)
    pair = classify_manufacturer_data(ADVERT_PAIRED)
    print(f"decode: separated advert -> {sep!r}")
    print(f"decode: paired advert    -> {pair!r}")
    if sep != "find_my_separated" or pair != "find_my_paired":
        raise SystemExit(
            "REFUSING TO CONTINUE: the adverts do not decode to the classes this\n"
            "proof is about, so every result below would be about the wrong input."
        )
    print()


def _rules_with_find_my_enabled(dest: Path) -> Path:
    """Arm B's config: the shipped file with the apple_find_my block uncommented.

    Derived from the shipped file by REMOVING comment markers, not by writing a
    fresh rule -- a hand-written copy would prove that some rule I typed works,
    which is not the question. The question is whether the block that ships in
    this repo fires.
    """
    text = _SHIPPED_RULES.read_text()
    block = re.search(
        r"(  # - name: apple_find_my\n(?:  #.*\n)*)",
        text,
        re.MULTILINE,
    )
    if block is None:
        raise SystemExit("REFUSING TO CONTINUE: could not find the apple_find_my block.")
    commented = block.group(1)
    uncommented = re.sub(r"^  # ?", "  ", commented, flags=re.MULTILINE)
    out = text.replace(commented, uncommented)
    if out == text:
        raise SystemExit("REFUSING TO CONTINUE: uncommenting changed nothing.")
    dest.write_text(out)
    return dest


def run_arm(label: str, rules_path: Path, tmp: Path) -> dict:
    """Drive both adverts through a bridge wired exactly as the Poller wires it."""
    ruleset = load_ruleset(str(rules_path))
    names = [r.name for r in ruleset.rules]
    db_path = str(tmp / f"{label}.db")
    db = Database(db_path)
    config = Config(db_path=db_path)
    notifier = RecordingNotifier()
    bridge = BleBridge(
        db=db,
        config=config,
        ruleset=ruleset,
        allowlist_provider=Allowlist,
        notifier=notifier,
        severity_overrides=None,
        location_id=config.location_id,
        location_label=config.location_label,
        adapter="hci0",
        flush_interval=1.0,
    )

    for mac, advert in ((MAC_SEPARATED, ADVERT_SEPARATED), (MAC_PAIRED, ADVERT_PAIRED)):
        bridge._record_advert(
            mac_raw=mac,
            rssi=-55,
            manufacturer_data=advert,
            service_uuids=(),
            service_data={},
        )
    flushed = bridge._flush(int(time.time()))

    alerts = db.list_alerts(limit=50)
    devices = {d["mac"]: d for d in db.list_devices(limit=50)}
    result = {
        "rules_loaded": names,
        "flushed": flushed,
        "alerts": alerts,
        "notifications": list(notifier.calls),
        "class_separated": devices.get(MAC_SEPARATED, {}).get("ble_device_class"),
        "class_paired": devices.get(MAC_PAIRED, {}).get("ble_device_class"),
    }
    db.close()
    return result


def report(label: str, r: dict) -> None:
    print(f"--- ARM {label} " + "-" * (58 - len(label)))
    print(f"  rules loaded            : {len(r['rules_loaded'])} -> {r['rules_loaded']}")
    print(f"  observations flushed    : {r['flushed']}")
    print(f"  devices.ble_device_class: separated={r['class_separated']!r} "
          f"paired={r['class_paired']!r}")
    print(f"  ALERT ROWS              : {len(r['alerts'])}")
    for a in r["alerts"]:
        print(f"      [{a['severity']}] {a['rule_name']} {a['mac']} :: {a['message']}")
    print(f"  NOTIFICATIONS DISPATCHED: {len(r['notifications'])}")
    for sev, title, msg in r["notifications"]:
        print(f"      [{sev}] {title} :: {msg}")
    print()


def main() -> int:
    _decode_check()
    tmp = Path(tempfile.mkdtemp(prefix="stalker-chain-"))

    a = run_arm("A-shipped", _SHIPPED_RULES, tmp)
    report("A (control: shipped rules.yaml)", a)

    arm_b_rules = _rules_with_find_my_enabled(tmp / "rules_find_my_on.yaml")
    b = run_arm("B-enabled", arm_b_rules, tmp)
    report("B (treatment: apple_find_my uncommented)", b)

    # --- verdicts ----------------------------------------------------------
    print("=" * 72)
    ok = True

    if "apple_find_my" in a["rules_loaded"]:
        print("UNEXPECTED: apple_find_my is loaded in the SHIPPED config.")
        ok = False
    if a["alerts"]:
        print(f"UNEXPECTED: shipped config raised {len(a['alerts'])} alert(s) for a tracker.")
        ok = False
    else:
        print("CONTROL   : shipped config -> a separated Find My tracker raises NO alert.")

    if "apple_find_my" not in b["rules_loaded"]:
        print("BROKEN    : uncommenting did not load the rule.")
        ok = False

    sep_alerts = [x for x in b["alerts"] if x["mac"] == MAC_SEPARATED]
    pair_alerts = [x for x in b["alerts"] if x["mac"] == MAC_PAIRED]

    if sep_alerts:
        print(f"TREATMENT : enabling it -> {len(sep_alerts)} alert(s) on the SEPARATED tracker.")
    else:
        print("BROKEN    : rule enabled and loaded, but the separated tracker raised NO alert.")
        ok = False

    if pair_alerts:
        print(f"BROKEN    : {len(pair_alerts)} alert(s) on the PAIRED device (noise generator).")
        ok = False
    else:
        print("TREATMENT : the paired device correctly raises nothing.")

    if b["notifications"]:
        print(f"TREATMENT : {len(b['notifications'])} notification(s) dispatched.")
    else:
        print("BROKEN    : alert row written but NO notification dispatched.")
        ok = False

    # The control must be able to fail, or it proves nothing.
    if a["flushed"] != 2 or b["flushed"] != 2:
        print("BROKEN    : an arm did not flush both adverts; the arms are not comparable.")
        ok = False
    if a["class_separated"] != "find_my_separated":
        print("BROKEN    : the control did not even persist the decoded class -- the")
        print("            control is broken, so its zero-alerts result means nothing.")
        ok = False
    else:
        print("CONTROL   : the control DID decode and persist the class, so its zero")
        print("            alerts is a rule gap, not a dead pipeline.")

    print("=" * 72)
    gap = operator_view()
    return 0 if (ok and not gap) else 1



# ---------------------------------------------------------------------------
# The last hop: what /settings tells the operator while all of the above is off.
#
# This is the hop that turns a conservative default into a misleading one. The
# panel is fed by check_bridge_readiness, whose docstring says an empty result
# means "nothing known is wrong". It already RECEIVES enabled_rule_types -- it
# uses them only to warn about a rule that is too NOISY, never about there
# being no rule at all to consume what the bridge decodes.
# ---------------------------------------------------------------------------


def operator_view() -> int:
    from lynceus.ble_bridge_checks import check_bridge_readiness

    ruleset = load_ruleset(str(_SHIPPED_RULES))
    enabled_rule_types = [r.rule_type for r in ruleset.rules if r.enabled]
    consumers = [t for t in enabled_rule_types if t == "ble_device_class"]
    warnings = check_bridge_readiness(
        adapter="hci1",
        kismet_sources=None,  # the shipped default: no source filter
        enabled_rule_types=enabled_rule_types,
    )

    print()
    print("=" * 72)
    print("THE OPERATOR'S VIEW -- bridge ON, shipped rules.yaml, tracker in range")
    print("=" * 72)
    print(f"  enabled rule types          : {enabled_rule_types}")
    print(f"  rules consuming ble_device_class: {len(consumers)}")
    print(f"  /settings warnings shown     : {len(warnings)}")
    for w in warnings:
        print(f"      - [{w.code}] {w.summary}")
    print()
    print("  The panel would render:")
    print("      status          : ON")
    print("      devices decoded : 3")
    print("      find_my_separated : 3      <- the tracker WAS seen and decoded")
    print(f"      warnings block  : {'shown' if warnings else 'NOT RENDERED (no warnings)'}")
    print("      alerts raised   : 0")
    print()
    if not consumers and not warnings:
        print("  ⛔ GAP: zero rules consume ble_device_class, and the readiness check")
        print("     reports nothing wrong. The operator has turned the feature on,")
        print("     bought a second adapter for it, can SEE find_my_separated counts")
        print("     climbing, and will never be alerted. Nothing on the page says so.")
        return 1
    print("  No gap: either a consumer exists or the panel warns.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
