.PHONY: install test lint format-check run

install:
	pip install -e ".[dev]"

# NOTE: tests/ is gitignored and is NOT part of a clone -- this target does
# nothing useful on a fresh checkout. See docs/TESTING.md for why the suite
# is maintained out-of-tree.
test:
	pytest -v

# Lint only. Kept separate from format-check so this stays a gate that is
# expected to pass: a permanently-red target is a target people stop reading.
lint:
	ruff check .

# Formatter drift. Currently FAILS on files that predate the pinned ruff
# version's output. Reformatting the repo wholesale would bury real changes
# under whitespace, so it is deliberately not part of `lint` and is left for
# a dedicated pass. Do not reformat repo-wide inside a focused change.
format-check:
	ruff format --check .

# Foreground daemon + UI + browser, Ctrl+C to stop. Dev/demo only -- for
# unattended operation use the systemd units (see docs/DEPLOYMENT.md).
run:
	lynceus-quickstart
