.PHONY: install test lint format-check run

install:
	pip install -e ".[dev]"

# The suite IS part of a clone. (This note previously said the opposite; that
# stopped being true once the tests were tracked, and it discouraged the one
# thing the README asks readers to do -- check its claims by running them.)
# Ten test files (plus one capture fixture) stay out, listed by name in
# .gitignore rather than hidden behind a glob, because they embed the capture
# adapter's own MAC or the rig account name.
#
# Takes roughly 18 minutes. See CONTRIBUTING.md for the traps that make a green
# run mean less than it looks like -- in particular, check WHICH test skipped
# rather than the skip count.
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
