.PHONY: install test release-gates lint format-check run

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

# The gates that need a real machine: a capture interface, and later a browser.
# `make test` deselects them, because a hosted runner has neither. Run this
# before tagging a release, on hardware, and read what it prints.
#
# It is the release evidence, so it is deliberately NOT part of `make test`:
# folding it in would make the everyday suite fail on any laptop without a
# capture interface, and a target that fails for everyone stops being read.
#
# ⛔ PYTEST_ADDOPTS is cleared, and the run must leave a SENTINEL behind.
# Measured 2026-08-22: `PYTEST_ADDOPTS=--collect-only make release-gates` exited
# 0 and printed "1/4626 tests collected", having executed nothing. A release
# gate that reports success without running is worse than no gate, and pytest's
# exit code cannot tell the two apart, because collecting nothing successfully
# is a success. So the target asserts a file the gate itself writes.
release-gates:
	@rm -f "$(CURDIR)/.release-gate-ran"
	env -u PYTEST_ADDOPTS LYNCEUS_GATE_SENTINEL="$(CURDIR)/.release-gate-ran" \
		pytest -m release_gate -v
	@test -s "$(CURDIR)/.release-gate-ran" || { \
		echo "⛔ pytest exited 0 but no gate body ran. Nothing is proven."; \
		exit 1; }
	@echo "✅ gates that actually executed:"; cat "$(CURDIR)/.release-gate-ran"
	@rm -f "$(CURDIR)/.release-gate-ran"

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
