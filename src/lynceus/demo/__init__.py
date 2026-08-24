"""The bundled demo scenario.

⛔ This ships in the wheel. `tests/test_demo_mode.py` asserts that by building
one and listing it, because pytest reads the source tree and would pass either
way.
"""

from __future__ import annotations

from pathlib import Path

#: The curated Kismet fixture the demo replays.
DEMO_FIXTURE_PATH = Path(__file__).resolve().parent / "demo_kismet.json"
