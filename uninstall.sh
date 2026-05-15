#!/usr/bin/env bash
#
# uninstall.sh — thin convenience wrapper around `install.sh --uninstall`.
#
# Operators look for an uninstall.sh next to install.sh; we ship one
# so the discoverability gap doesn't push them into hand-rolled rm
# commands. All real work lives in install.sh — this script just
# auto-detects the install scope by looking for the venv marker
# directories and execs install.sh with the right flags.
#
# Like install.sh, this is intentionally self-contained and OFFLINE —
# no network access of any kind.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_SH="$SCRIPT_DIR/install.sh"

USER_VENV_MARKER="$HOME/.local/share/lynceus/.venv"
SYSTEM_VENV_MARKER="/opt/lynceus/.venv"

SCOPE=""
PASSTHRU=()

usage() {
    cat <<'EOF'
Usage: uninstall.sh [--user | --system] [--purge] [--dry-run] [--help]

Reverses a Lynceus install. With no scope flag, auto-detects by
looking for the venv marker directory:
  --user   marker: ~/.local/share/lynceus/.venv
  --system marker: /opt/lynceus/.venv

If both markers are present, refuses to guess and asks the operator
to pass --user or --system explicitly. If neither is present, prints
where it looked and points at `./install.sh --uninstall --user|--system`
for non-standard installs.

Options:
  --user        Force the per-user uninstall path.
  --system      Force the system-wide uninstall path (requires sudo).
  --purge       Also delete config / data / state directories. With
                --user that's the three XDG dirs; with --system that's
                /etc/lynceus and /var/lib/lynceus.
  --dry-run     Print every command that would have run, without
                running it.
  --help, -h    Show this help and exit.

This is a thin wrapper. All real work happens in install.sh; see
`./install.sh --help` for the full flag reference.
EOF
}

err() { printf '%s\n' "$*" >&2; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --user)
            if [[ -n "$SCOPE" && "$SCOPE" != "user" ]]; then
                err "Cannot combine --$SCOPE and --user."; exit 2
            fi
            SCOPE=user
            ;;
        --system)
            if [[ -n "$SCOPE" && "$SCOPE" != "system" ]]; then
                err "Cannot combine --$SCOPE and --system."; exit 2
            fi
            SCOPE=system
            ;;
        --purge|--dry-run)
            PASSTHRU+=("$1")
            ;;
        --help|-h) usage; exit 0 ;;
        *)
            err "Unknown option: $1"
            err ""
            usage >&2
            exit 2
            ;;
    esac
    shift
done

# --- scope auto-detection --------------------------------------------------

if [[ -z "$SCOPE" ]]; then
    user_present=0
    system_present=0
    [[ -d "$USER_VENV_MARKER" ]]   && user_present=1
    [[ -d "$SYSTEM_VENV_MARKER" ]] && system_present=1

    if [[ "$user_present" -eq 1 && "$system_present" -eq 1 ]]; then
        err "Both --user and --system installs detected:"
        err "  $USER_VENV_MARKER"
        err "  $SYSTEM_VENV_MARKER"
        err ""
        err "Re-run with --user or --system to pick one explicitly."
        exit 2
    fi

    if [[ "$user_present" -eq 0 && "$system_present" -eq 0 ]]; then
        err "No Lynceus install detected. Looked for:"
        err "  $USER_VENV_MARKER"
        err "  $SYSTEM_VENV_MARKER"
        err ""
        err "If Lynceus was installed to a non-standard location, run"
        err "install.sh directly: ./install.sh --uninstall --user|--system"
        exit 1
    fi

    if [[ "$user_present" -eq 1 ]]; then
        SCOPE=user
    else
        SCOPE=system
    fi
fi

# --- delegate --------------------------------------------------------------

# ${ARR[@]+"${ARR[@]}"} guards against the unbound-variable error that
# `set -u` raises when expanding an empty bash array.
exec "$INSTALL_SH" --uninstall "--$SCOPE" ${PASSTHRU[@]+"${PASSTHRU[@]}"}
