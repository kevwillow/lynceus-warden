#!/usr/bin/env bash
#
# install.sh — Linux installer for Lynceus.
#
# Modes:
#   ./install.sh [--user]              (default when not root)
#   sudo ./install.sh --system         (system-wide; needs systemd)
#   sudo ./install.sh --uninstall      (reverse a system install)
#
# This script is intentionally self-contained and does not fetch anything
# from the network. Operators must `git clone` the repo first. We do not
# ship a curl|bash one-liner — that contradicts the project's threat model.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SYSTEMD_SRC_DIR="$SCRIPT_DIR/systemd"
SYSTEMD_DEST_DIR="/etc/systemd/system"

MODE=""
DRY_RUN=0
PURGE=0

usage() {
    cat <<'EOF'
Usage: install.sh [--user | --system | --uninstall] [--dry-run] [--purge] [--help]

Modes:
  --user        Per-user install (default when not root). Calls
                "pip install --user -e ." (or "pip install -e ." inside a
                venv) and creates ~/.config/lynceus, ~/.local/share/lynceus,
                ~/.local/state/lynceus. No systemd integration.
  --system      System-wide install (default when run as root). Calls
                "pip install -e ." into the system Python, creates the
                "lynceus" system user, lays down /etc/lynceus,
                /var/lib/lynceus, /var/log/lynceus, copies the systemd
                units into /etc/systemd/system, and runs daemon-reload.
                Does NOT auto-enable the units.
  --uninstall   Reverse a --system install (units removed, daemon-reload).
                Config and data are preserved unless --purge is given.

Options:
  --dry-run     Print every command that would have run, without running it.
  --purge       With --uninstall, also delete /etc/lynceus and /var/lib/lynceus.
  --help, -h    Show this help and exit.

Lynceus is Linux-only for systemd integration. On macOS and Windows,
run "pip install -e ." from a clone — the Python tools (lynceus,
lynceus-ui, lynceus-setup, lynceus-quickstart) all work, but service
automation is unavailable.

After --user install:
  lynceus-setup           # configure
  lynceus-quickstart      # dev/demo

After --system install:
  sudo lynceus-setup --system
  sudo systemctl enable --now lynceus.service lynceus-ui.service
EOF
}

log() { printf '%s\n' "$*"; }
err() { printf '%s\n' "$*" >&2; }

run() {
    if [[ "$DRY_RUN" -eq 1 ]]; then
        printf 'DRY-RUN:'
        printf ' %q' "$@"
        printf '\n'
    else
        "$@"
    fi
}

# --- argument parsing ------------------------------------------------------

while [[ $# -gt 0 ]]; do
    case "$1" in
        --user)
            if [[ -n "$MODE" && "$MODE" != "user" ]]; then
                err "Cannot combine --$MODE and --user."; exit 2
            fi
            MODE=user
            ;;
        --system)
            if [[ -n "$MODE" && "$MODE" != "system" ]]; then
                err "Cannot combine --$MODE and --system."; exit 2
            fi
            MODE=system
            ;;
        --uninstall)
            if [[ -n "$MODE" && "$MODE" != "uninstall" ]]; then
                err "Cannot combine --$MODE and --uninstall."; exit 2
            fi
            MODE=uninstall
            ;;
        --purge)   PURGE=1 ;;
        --dry-run) DRY_RUN=1 ;;
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

# --- platform check (must happen before anything platform-specific) --------

UNAME_S="$(uname -s 2>/dev/null || echo unknown)"
if [[ "$UNAME_S" != "Linux" ]]; then
    err "install.sh supports Linux only. On macOS or Windows, use 'pip install -e .' from a clone."
    exit 1
fi

# --- default mode ----------------------------------------------------------

if [[ -z "$MODE" ]]; then
    if [[ "$(id -u)" -eq 0 ]]; then
        MODE=system
    else
        MODE=user
    fi
fi

# --- pre-flight ------------------------------------------------------------

require_python() {
    if ! command -v python3 >/dev/null 2>&1; then
        err "Python 3 not found on PATH. Install python3 (>=3.11) and re-run."
        exit 1
    fi
    if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'; then
        local v
        v="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
        err "Python >= 3.11 required (found $v)."
        exit 1
    fi
}

require_pip() {
    if ! python3 -m pip --version >/dev/null 2>&1; then
        err "pip is not available for python3. Install python3-pip and re-run."
        exit 1
    fi
}

require_systemctl() {
    if ! command -v systemctl >/dev/null 2>&1; then
        err "systemctl not found. --system / --uninstall require systemd."
        exit 1
    fi
}

preflight() {
    require_python
    require_pip
    if [[ "$MODE" == "system" || "$MODE" == "uninstall" ]]; then
        require_systemctl
    fi
}

# --- modes -----------------------------------------------------------------

install_user() {
    log "Installing Lynceus (--user) from $SCRIPT_DIR"

    local cfg_dir="$HOME/.config/lynceus"
    local data_dir="$HOME/.local/share/lynceus"
    local log_dir="$HOME/.local/state/lynceus"

    if [[ -d "$cfg_dir" || -d "$data_dir" ]]; then
        log "Already installed; updating."
    else
        log "Installing fresh."
    fi

    run mkdir -p "$cfg_dir" "$data_dir" "$log_dir"

    if [[ -n "${VIRTUAL_ENV:-}" ]]; then
        log "Detected VIRTUAL_ENV=$VIRTUAL_ENV; installing into the active venv."
        run python3 -m pip install --upgrade -e "$SCRIPT_DIR"
    else
        run python3 -m pip install --user --upgrade -e "$SCRIPT_DIR"
    fi

    log ""
    log "User install complete."
    log "Next: run 'lynceus-setup' to configure, then 'lynceus-quickstart'"
    log "for dev/demo, or enable a systemd --user unit for production."
}

install_system() {
    if [[ "$(id -u)" -ne 0 ]]; then
        err "Use sudo for --system."
        exit 1
    fi

    log "Installing Lynceus (--system) from $SCRIPT_DIR"

    if [[ -d /etc/lynceus || -d /var/lib/lynceus ]]; then
        log "Already installed; updating."
    else
        log "Installing fresh."
    fi

    run python3 -m pip install --upgrade -e "$SCRIPT_DIR"

    if ! id -u lynceus >/dev/null 2>&1; then
        log "Creating system user 'lynceus'."
        run useradd --system --no-create-home --shell /usr/sbin/nologin lynceus
    fi

    run mkdir -p /etc/lynceus /var/lib/lynceus /var/log/lynceus
    run chown -R lynceus:lynceus /var/lib/lynceus /var/log/lynceus

    run install -m 0644 "$SYSTEMD_SRC_DIR/lynceus.service"    "$SYSTEMD_DEST_DIR/lynceus.service"
    run install -m 0644 "$SYSTEMD_SRC_DIR/lynceus-ui.service" "$SYSTEMD_DEST_DIR/lynceus-ui.service"
    run systemctl daemon-reload

    log ""
    log "System install complete."
    log "Next:"
    log "  sudo lynceus-setup --system           # generate /etc/lynceus/lynceus.yaml"
    log "  sudo systemctl enable --now lynceus.service lynceus-ui.service"
}

uninstall_system() {
    if [[ "$(id -u)" -ne 0 ]]; then
        err "Use sudo for --uninstall."
        exit 1
    fi

    log "Uninstalling Lynceus systemd integration"

    for unit in lynceus.service lynceus-ui.service; do
        if systemctl is-enabled "$unit" >/dev/null 2>&1; then
            run systemctl disable "$unit" || true
        fi
        if systemctl is-active "$unit" >/dev/null 2>&1; then
            run systemctl stop "$unit" || true
        fi
        if [[ -f "$SYSTEMD_DEST_DIR/$unit" ]]; then
            run rm -f "$SYSTEMD_DEST_DIR/$unit"
        fi
    done
    run systemctl daemon-reload

    if [[ "$PURGE" -eq 1 ]]; then
        log "Purging /etc/lynceus and /var/lib/lynceus."
        run rm -rf /etc/lynceus /var/lib/lynceus
    else
        log "Leaving /etc/lynceus and /var/lib/lynceus in place. Pass --purge to remove them."
    fi

    log ""
    log "Uninstall complete. The 'lynceus' system user has been kept; run"
    log "'sudo userdel lynceus' if you want to remove it."
}

# --- entry point -----------------------------------------------------------

preflight

case "$MODE" in
    user)      install_user ;;
    system)    install_system ;;
    uninstall) uninstall_system ;;
    *)
        err "Internal error: unknown mode '$MODE'"
        exit 2
        ;;
esac
