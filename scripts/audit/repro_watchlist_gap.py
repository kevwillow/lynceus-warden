"""Live proof: a MAC added via the UI path is never matched under the shipped rules.yaml."""

import os
import tempfile

from lynceus.db import Database
from lynceus.kismet import DeviceObservation
from lynceus.rules import evaluate, load_ruleset

MAC = "aa:bb:cc:dd:ee:ff"
db = Database(os.path.join(tempfile.mkdtemp(), "l.db"))

# Exactly what POST /devices/{mac}/watchlist does: insert a watchlist row.
db.add_watchlist(
    pattern=MAC,
    pattern_type="mac",
    severity="high",
    description="added via webui at 2026-08-02T00:00:00Z",
)
rows = db.list_watchlist()
print(f"watchlist rows in DB: {len(rows)} -> {rows[0]['pattern']} ({rows[0]['severity']})")

obs = DeviceObservation(
    mac=MAC,
    device_type="wifi",
    first_seen=1000,
    last_seen=1000,
    rssi=-40,
    ssid=None,
    oui_vendor=None,
    is_randomized=False,
)

# The SHIPPED ruleset, unmodified.
ruleset = load_ruleset("config/rules.yaml")
enabled = [(r.name, r.rule_type, len(r.patterns or [])) for r in ruleset.rules if r.enabled]
print(f"enabled rules: {enabled}")

hits = evaluate(ruleset, obs, is_new_device=False, db=db)
print("\nUI promise: 'It will raise alerts on every future sighting.'")
print(f"RuleHits produced for that MAC: {len(hits)}")
for h in hits:
    print("   ", h.rule_name, h.severity, h.message)
if not hits:
    print("   (none) <-- the row exists, the poll does not match it")
