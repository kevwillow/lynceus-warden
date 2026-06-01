#!/usr/bin/env bash
#
# install.sh — Linux installer for Lynceus.
#
# Modes:
#   ./install.sh [--user]                        (default when not root)
#   sudo ./install.sh --system                   (system-wide; needs systemd)
#   ./install.sh --uninstall [--user|--system]   (reverse an install)
#
# Lynceus installs into a dedicated Python venv to comply with PEP 668
# (the externally-managed-environment policy enforced by current
# Debian/Ubuntu/Kali system Pythons). The lynceus-* console scripts
# are exposed via symlinks from the venv's bin/ into a directory on
# PATH so operators do not need to activate the venv manually.
#
# This script is intentionally self-contained and does not fetch
# anything from the network. Operators must `git clone` the repo first.
# We do not ship a curl|bash one-liner — that contradicts the project's
# threat model.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SYSTEMD_SRC_DIR="$SCRIPT_DIR/systemd"
SYSTEMD_DEST_DIR="/etc/systemd/system"

USER_VENV="$HOME/.local/share/lynceus/.venv"
USER_BIN_DIR="$HOME/.local/bin"
USER_CONFIG_DIR="$HOME/.config/lynceus"
USER_DATA_DIR="$HOME/.local/share/lynceus"
USER_STATE_DIR="$HOME/.local/state/lynceus"
SYSTEM_PREFIX="/opt/lynceus"
SYSTEM_VENV="$SYSTEM_PREFIX/.venv"
SYSTEM_BIN_DIR="/usr/local/bin"

# Mirrors [project.scripts] in pyproject.toml. Any new entry point added
# there must be appended here so the symlink layer keeps it on PATH.
CONSOLE_SCRIPTS=(
    lynceus
    lynceus-ui
    lynceus-quickstart
    lynceus-setup
    lynceus-seed-watchlist
    lynceus-import-argus
    lynceus-validate
    lynceus-bootstrap-kismet
    lynceus-export-config
)

ACTION=install
SCOPE=""
SCOPE_EXPLICIT=0
DRY_RUN=0
PURGE=0

usage() {
    cat <<'EOF'
Usage: install.sh [--user | --system] [--uninstall] [--dry-run] [--purge] [--help]

Actions:
  (default)     Install Lynceus.
  --uninstall   Reverse an install. Combine with --user or --system to
                pick the scope; defaults to --user when not root,
                --system when root (same euid rule as install).

Scopes (apply to BOTH install and uninstall):
  --user        Per-user scope. Venv at ~/.local/share/lynceus/.venv,
                symlinks in ~/.local/bin/. XDG dirs:
                ~/.config/lynceus, ~/.local/share/lynceus,
                ~/.local/state/lynceus. No systemd integration; no
                root required.
  --system      System-wide scope. Venv at /opt/lynceus/.venv,
                symlinks in /usr/local/bin/. Creates the lynceus
                system user, lays down /etc/lynceus, /var/lib/lynceus,
                /var/log/lynceus, copies the systemd units into
                /etc/systemd/system, and runs daemon-reload. Does NOT
                auto-enable the units. Requires systemd.

Options:
  --dry-run     Print every command that would have run, without
                running it. --system in dry-run does NOT require root,
                so operators can preview the plan from a normal shell.
  --purge       Only valid with --uninstall. With --user, also deletes
                ~/.config/lynceus, ~/.local/share/lynceus, and
                ~/.local/state/lynceus (the latter two contain
                lynceus.db and logs). With --system, also deletes
                /etc/lynceus and /var/lib/lynceus.
  --help, -h    Show this help and exit.

Lynceus uses a dedicated Python venv to comply with PEP 668 (the
externally-managed-environment policy on Debian/Ubuntu/Kali). Operators
do not need to activate the venv manually; the symlinks make the
lynceus-* commands appear on PATH transparently. install.sh never
adds --break-system-packages — the venv is the whole point.

Lynceus is Linux-only for systemd integration. On macOS and Windows,
run "pip install -e ." from a clone — the Python tools (lynceus,
lynceus-ui, lynceus-setup, lynceus-quickstart) all work, but service
automation is unavailable.

After --user install:
  lynceus-setup                                # configure
  lynceus-quickstart                           # dev/demo
  lynceus-import-argus --from-github           # refresh watchlist (network)

After --system install:
  sudo lynceus-setup --system
  sudo systemctl enable --now lynceus.service lynceus-ui.service
  sudo lynceus-import-argus --scope system --from-github   # refresh watchlist
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
            if [[ -n "$SCOPE" && "$SCOPE" != "user" ]]; then
                err "Cannot combine --$SCOPE and --user."; exit 2
            fi
            SCOPE=user
            SCOPE_EXPLICIT=1
            ;;
        --system)
            if [[ -n "$SCOPE" && "$SCOPE" != "system" ]]; then
                err "Cannot combine --$SCOPE and --system."; exit 2
            fi
            SCOPE=system
            SCOPE_EXPLICIT=1
            ;;
        --uninstall)
            ACTION=uninstall
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

# --purge only makes sense with --uninstall.
if [[ "$PURGE" -eq 1 && "$ACTION" != "uninstall" ]]; then
    err "--purge is only valid together with --uninstall."
    exit 2
fi

# --- platform check (must happen before anything platform-specific) --------

UNAME_S="$(uname -s 2>/dev/null || echo unknown)"
if [[ "$UNAME_S" != "Linux" ]]; then
    err "install.sh supports Linux only. On macOS or Windows, use 'pip install -e .' from a clone."
    exit 1
fi

# --- default scope ---------------------------------------------------------

if [[ -z "$SCOPE" ]]; then
    if [[ "$(id -u)" -eq 0 ]]; then
        SCOPE=system
    else
        SCOPE=user
    fi
fi

# Refuse `sudo ./install.sh --user`. With EUID=0, $HOME resolves to
# /root (sudo doesn't reset HOME by default on most distros), so the
# install lands in /root/.local/share/lynceus/ — not the operator's
# home, and not where any subsequent non-sudo `lynceus-*` invocation
# would look. Silent re-routing is worse than refusal: the operator's
# last touch surface (install) must NOT silently switch scopes.
# Mirror the lynceus-setup refusal at src/lynceus/cli/setup.py:1412.
# Auto-resolved user (no explicit --user flag) under EUID=0 already
# took the --system branch above, so this only fires on explicit
# `sudo ./install.sh --user`. Bypassed during --dry-run so an operator
# can still preview the user-scope plan from a root shell.
if [[ "$ACTION" == "install" && "$SCOPE" == "user" && "$SCOPE_EXPLICIT" -eq 1 \
      && "$DRY_RUN" -eq 0 && "$(id -u)" -eq 0 ]]; then
    err "Refusing to install --user under sudo."
    err ""
    err "Running as root with --user scope would install to"
    err "  /root/.local/share/lynceus/"
    err "which is not your home directory and not where lynceus expects"
    err "to find data. Did you mean one of:"
    err ""
    err "  sudo ./install.sh             # system-wide (recommended)"
    err "  ./install.sh --user           # user scope, no sudo"
    exit 2
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

require_venv_module() {
    # Some Debian/Ubuntu/Kali images ship python3 without the venv
    # module; it lives in a separate apt package. Detect that here so
    # we fail fast with an actionable hint instead of crashing midway
    # through the install.
    if ! python3 -m venv --help >/dev/null 2>&1; then
        err "python3-venv is required. On Debian/Ubuntu/Kali: sudo apt install python3-venv. Aborting."
        exit 1
    fi
}

require_systemctl() {
    if ! command -v systemctl >/dev/null 2>&1; then
        err "systemctl not found. --system requires systemd."
        exit 1
    fi
}

preflight() {
    # python3 + python3-venv are install-only requirements. Uninstall
    # must work on a box where Python has already been removed —
    # operators tearing down a host should not be blocked by a missing
    # interpreter.
    if [[ "$ACTION" == "install" ]]; then
        require_python
        require_venv_module
    fi
    # systemctl is needed for both install-system (to copy + reload
    # units) and uninstall-system (to stop/disable + reload).
    if [[ "$SCOPE" == "system" ]]; then
        require_systemctl
    fi
}

# --- venv + symlink helpers -----------------------------------------------

create_or_update_venv() {
    local venv="$1"
    # editable=1 installs `pip install -e` (an __editable__*.pth pointing
    # back at $SCRIPT_DIR/src); editable=0 copies the package into the
    # venv. --user installs editable for dev convenience. --system MUST
    # NOT: $SCRIPT_DIR lives in the invoking operator's $HOME, which the
    # `lynceus` service user can't traverse, so a systemd daemon running
    # as User=lynceus crashes at import every start. A non-editable
    # install makes /opt/lynceus self-contained and independent of $HOME.
    local editable="${2:-0}"
    if [[ -d "$venv" && -x "$venv/bin/pip" ]]; then
        log "Reusing existing venv at $venv"
    else
        log "Creating venv at $venv"
        run python3 -m venv "$venv"
    fi
    run "$venv/bin/pip" install --upgrade pip
    # NEVER --break-system-packages here — installing into a venv is
    # exactly what PEP 668 expects, so the policy does not apply.
    if [[ "$editable" -eq 1 ]]; then
        run "$venv/bin/pip" install --upgrade -e "$SCRIPT_DIR"
    else
        run "$venv/bin/pip" install --upgrade "$SCRIPT_DIR"
    fi
}

create_symlinks() {
    local venv="$1"
    local bindir="$2"
    run mkdir -p "$bindir"
    local script
    for script in "${CONSOLE_SCRIPTS[@]}"; do
        # Idempotent: rm -f then ln -s rather than ln -sf, so a stale
        # regular file at the target gets replaced cleanly.
        run rm -f "$bindir/$script"
        run ln -s "$venv/bin/$script" "$bindir/$script"
    done
}

remove_symlinks() {
    local bindir="$1"
    log "Removing $bindir symlinks for: ${CONSOLE_SCRIPTS[*]}"
    local script
    for script in "${CONSOLE_SCRIPTS[@]}"; do
        if [[ -L "$bindir/$script" || -e "$bindir/$script" ]]; then
            run rm -f "$bindir/$script"
        fi
    done
}

note_path_if_missing() {
    local bindir="$1"
    case ":${PATH:-}:" in
        *":$bindir:"*) return 0 ;;
    esac
    log ""
    log "Note: $bindir is not on your PATH. Add it so the lynceus-* commands resolve, e.g.:"
    log ""
    log "    echo 'export PATH=\"$bindir:\$PATH\"' >> ~/.bashrc"
    log "    source ~/.bashrc"
}

# --- post-install "next steps" hint ----------------------------------------
#
# Prints a numbered getting-started block at the end of a successful
# install. Adapts to install scope so a --user install doesn't tell the
# operator to enable a system-wide systemd unit, and a --system install
# uses sudo + --scope system on the wizard. Detailed runbook lives in
# docs/DEPLOYMENT.md; we reference it rather than duplicating content.

print_next_steps() {
    local scope="$1"  # user | system
    local sudo_pfx setup_scope run_step

    if [[ "$scope" == "system" ]]; then
        sudo_pfx="sudo "
        setup_scope=" --system"
    else
        sudo_pfx=""
        setup_scope=""
    fi

    log ""
    log "Next steps:"
    log ""
    log "  1. Install Kismet (the data source Lynceus polls)."
    log "     bootstrap assumes Kismet is already present and only configures"
    log "     capture sources + group; pass --install to also apt-install it."
    log "     Pick the line that matches your host:"
    log "       Debian / Ubuntu / Kali / Raspberry Pi OS (Bookworm):"
    log "           sudo lynceus-bootstrap-kismet --install"
    log "         (apt repo + kismet package, then interface config + group)"
    log "       Other Linux distros (Parrot, Mint, Devuan, Fedora, Arch):"
    log "         install Kismet via your distro's package manager or"
    log "         https://www.kismetwireless.net/packages/, then:"
    log "           sudo lynceus-bootstrap-kismet"
    log "         (interface config + group only; no apt install)"
    log "       Already have Kismet:"
    log "           sudo lynceus-bootstrap-kismet"
    log ""
    log "  2. Log out and log back in so the kismet group takes effect"
    log "     (running shells don't pick up new groups)."
    log ""
    log "  3. Start Kismet and create a read-only API key for Lynceus:"
    log "         sudo systemctl start kismet"
    log "         open http://localhost:2501  # set admin password on first visit"
    log "         Settings -> API Keys -> Create  (name: lynceus, role: readonly)"
    log ""
    log "  4. Configure Lynceus:"
    log "         ${sudo_pfx}lynceus-setup${setup_scope}"
    log "     The wizard auto-locates the API key from ~/.kismet/session.db"
    log "     (no copy-paste in the common case), prompts for ntfy + probe-"
    log "     SSID capture, generates lynceus.yaml, and auto-imports the"
    log "     bundled threat-data watchlist."
    log "     Or, for a browser-based wizard with the same questions:"
    log "         ${sudo_pfx}lynceus-setup${setup_scope} --web"
    log "     (prints a loopback URL with a single-use token; open it in"
    log "     a browser to walk through the same 12-step flow)."
    log ""

    if [[ "$scope" == "system" ]]; then
        log "  5. Enable Lynceus (production):"
        log "         sudo systemctl enable --now lynceus.service lynceus-ui.service"
        log ""
        log "  6. (Optional) Enable weekly Argus watchlist refresh."
        log "     Default off so install.sh stays offline-by-default; this is"
        log "     the only Lynceus surface that opts the host into a recurring"
        log "     outbound network call:"
        log "         sudo systemctl enable --now lynceus-refresh.timer"
    else
        log "  5. Run Lynceus (dev / demo, foreground):"
        log "         lynceus-quickstart"
        log "     Launches the daemon + web UI and opens a browser tab;"
        log "     Ctrl+C shuts both down cleanly."
    fi

    log ""
    log "Full runbook + troubleshooting:  docs/DEPLOYMENT.md"
    log "Post-install verification:       docs/SMOKE.md"
}

# --- modes -----------------------------------------------------------------

install_user() {
    log "Installing Lynceus (--user) from $SCRIPT_DIR"

    if [[ -d "$USER_CONFIG_DIR" || -d "$USER_DATA_DIR" || -d "$USER_VENV" ]]; then
        log "Already installed; updating."
    else
        log "Installing fresh."
    fi

    run mkdir -p "$USER_CONFIG_DIR" "$USER_DATA_DIR" "$USER_STATE_DIR"

    create_or_update_venv "$USER_VENV" 1  # editable: dev convenience
    create_symlinks "$USER_VENV" "$USER_BIN_DIR"
    note_path_if_missing "$USER_BIN_DIR"

    log ""
    log "User install complete."
    print_next_steps user
}

install_system() {
    if [[ "$DRY_RUN" -eq 0 && "$(id -u)" -ne 0 ]]; then
        err "Use sudo for --system."
        exit 1
    fi

    log "Installing Lynceus (--system) from $SCRIPT_DIR"

    if [[ -d /etc/lynceus || -d /var/lib/lynceus || -d "$SYSTEM_VENV" ]]; then
        log "Already installed; updating."
    else
        log "Installing fresh."
    fi

    if ! id -u lynceus >/dev/null 2>&1; then
        log "Creating system user 'lynceus'."
        run useradd --system --no-create-home --shell /usr/sbin/nologin lynceus
    fi

    run mkdir -p "$SYSTEM_PREFIX"
    create_or_update_venv "$SYSTEM_VENV" 0  # non-editable: $HOME-independent
    # Ownership is set after pip install so the installed package tree in
    # the venv (site-packages + dist-info) ends up owned by the daemon
    # user too.
    run chown -R lynceus:lynceus "$SYSTEM_PREFIX"

    create_symlinks "$SYSTEM_VENV" "$SYSTEM_BIN_DIR"

    run mkdir -p /etc/lynceus /var/lib/lynceus /var/log/lynceus
    # /etc/lynceus is root-owned but lynceus-group readable so the
    # daemon (User=lynceus) can traverse the directory to reach
    # lynceus.yaml. Without this 0750 grant, file-level perms on
    # lynceus.yaml don't matter — directory-traversal denies the
    # daemon up front.
    run chown root:lynceus /etc/lynceus
    run chmod 0750 /etc/lynceus
    run chown -R lynceus:lynceus /var/lib/lynceus /var/log/lynceus

    run install -m 0644 "$SYSTEMD_SRC_DIR/lynceus.service"         "$SYSTEMD_DEST_DIR/lynceus.service"
    run install -m 0644 "$SYSTEMD_SRC_DIR/lynceus-ui.service"      "$SYSTEMD_DEST_DIR/lynceus-ui.service"
    # lynceus-refresh.{service,timer} ship installed-but-NOT-enabled,
    # the same posture install.sh applies to lynceus.service. Enabling
    # the timer is the only Lynceus surface that opts the host into a
    # recurring outbound network call (--from-github), so it stays an
    # explicit operator decision — install.sh's offline invariant
    # holds.
    run install -m 0644 "$SYSTEMD_SRC_DIR/lynceus-refresh.service" "$SYSTEMD_DEST_DIR/lynceus-refresh.service"
    run install -m 0644 "$SYSTEMD_SRC_DIR/lynceus-refresh.timer"   "$SYSTEMD_DEST_DIR/lynceus-refresh.timer"
    run systemctl daemon-reload

    log ""
    log "System install complete."
    print_next_steps system
}

uninstall_user() {
    log "Uninstalling Lynceus (--user)"

    # If nothing's there at all, tell the operator clearly and exit 0
    # rather than silently doing a bunch of no-op rms. Most likely the
    # operator picked the wrong scope.
    if [[ ! -d "$USER_VENV" && ! -d "$USER_CONFIG_DIR" && ! -d "$USER_DATA_DIR" \
          && ! -d "$USER_STATE_DIR" && ! -L "$USER_BIN_DIR/lynceus" ]]; then
        log "No --user install found. Checked:"
        log "  $USER_VENV"
        log "  $USER_CONFIG_DIR"
        log "  $USER_DATA_DIR"
        log "  $USER_STATE_DIR"
        log "  $USER_BIN_DIR/lynceus (symlink)"
        log ""
        log "If you installed system-wide, try: sudo $0 --uninstall --system"
        return 0
    fi

    remove_symlinks "$USER_BIN_DIR"

    # USER_VENV sits inside USER_DATA_DIR. We delete it explicitly here
    # so non-purge runs still drop the install artifact (the venv) while
    # preserving the operator's lynceus.db, which also lives under
    # USER_DATA_DIR.
    if [[ -d "$USER_VENV" ]]; then
        log "Removing venv at $USER_VENV"
        run rm -rf "$USER_VENV"
    fi

    if [[ "$PURGE" -eq 1 ]]; then
        log "Purging $USER_CONFIG_DIR, $USER_DATA_DIR, $USER_STATE_DIR."
        run rm -rf "$USER_CONFIG_DIR" "$USER_DATA_DIR" "$USER_STATE_DIR"
    else
        log "Preserving:"
        log "  $USER_CONFIG_DIR  (config)"
        log "  $USER_DATA_DIR    (contains lynceus.db)"
        log "  $USER_STATE_DIR   (logs / runtime state)"
        log "Pass --purge to remove them."
    fi

    log ""
    log "User uninstall complete."
}

uninstall_system() {
    if [[ "$DRY_RUN" -eq 0 && "$(id -u)" -ne 0 ]]; then
        err "Use sudo for --uninstall --system."
        exit 1
    fi

    log "Uninstalling Lynceus systemd integration"

    for unit in lynceus.service lynceus-ui.service lynceus-refresh.timer lynceus-refresh.service; do
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

    remove_symlinks "$SYSTEM_BIN_DIR"

    log "Removing venv at $SYSTEM_VENV (if present)."
    if [[ -d "$SYSTEM_VENV" ]]; then
        run rm -rf "$SYSTEM_VENV"
    fi

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

case "$ACTION:$SCOPE" in
    install:user)     install_user ;;
    install:system)   install_system ;;
    uninstall:user)   uninstall_user ;;
    uninstall:system) uninstall_system ;;
    *)
        err "Internal error: unknown ACTION:SCOPE '$ACTION:$SCOPE'"
        exit 2
        ;;
esac
