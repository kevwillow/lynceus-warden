"""Live proof: a MAC added via the UI path is never matched under the shipped rules.yaml.

⛔ This script resolves BOTH its code and its config from the checkout it lives
in, and asserts that it did.

🪤 It previously did neither. `from lynceus.db import Database` resolved through
whatever `lynceus` happened to be importable -- in a development environment
that is the editable install, which points at the PRIMARY checkout regardless of
which worktree or branch you invoke this from. `load_ruleset("config/rules.yaml")`
resolved relative to the CURRENT WORKING DIRECTORY. So a single run could grade
one tree's code against another tree's config and report a confident result
about neither.

That matters more here than in the other harnesses, because this file is
TRACKED: it ships to everyone who clones the repo, and its whole purpose is to
be believed as evidence. A proof that silently measures the wrong tree is worse
than no proof.

The assertion below is the load-bearing part. `sys.path` order is not a
guarantee when an editable install has already resolved the package, so the
path is inserted AND the resolved module file is checked.
"""

import os
import sys
import tempfile
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / "src"))

import lynceus  # noqa: E402
from lynceus.db import Database  # noqa: E402
from lynceus.kismet import DeviceObservation  # noqa: E402
from lynceus.rules import evaluate, load_ruleset  # noqa: E402

_resolved = Path(lynceus.__file__).resolve()
if _REPO / "src" not in _resolved.parents:
    raise SystemExit(
        f"REFUSING TO RUN: imported lynceus from {_resolved}, which is not under\n"
        f"{_REPO / 'src'}. Something else -- almost certainly an editable install --\n"
        f"won the import, so this proof would grade a different tree than the one it\n"
        f"lives in. Fix the environment rather than trusting the output."
    )
print(f"tree under test: {_REPO}")
print(f"lynceus imported from: {_resolved.parent}")

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
ruleset = load_ruleset(str(_REPO / "config" / "rules.yaml"))
enabled = [(r.name, r.rule_type, len(r.patterns or [])) for r in ruleset.rules if r.enabled]
print(f"enabled rules: {enabled}")

hits = evaluate(ruleset, obs, is_new_device=False, db=db)
print("\nUI promise: 'It will raise alerts on every future sighting.'")
print(f"RuleHits produced for that MAC: {len(hits)}")
for h in hits:
    print("   ", h.rule_name, h.severity, h.message)
if not hits:
    print("   (none) <-- the row exists, the poll does not match it")
