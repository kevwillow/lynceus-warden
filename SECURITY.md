# Security Policy

## Project status

Lynceus is currently personal-use software at version **0.3.0-rc1**. It is
not a hardened public product, has no dedicated security team, and offers
no formal disclosure SLA. Vulnerability reports are welcomed and taken
seriously, but response is best-effort.

## Threat model

**In scope.** Lynceus is designed to help an operator detect passive
surveillance devices in their own RF environment — drones, ALPRs,
gunshot-detection sensors, known hacking hardware, and similar gear. The
operator is the user; bystanders are not part of the threat model.

**Out of scope.** Lynceus is not designed to defend against:

- Network-level attacks against Lynceus itself (the daemon, the web UI,
  the API surface it exposes locally).
- Supply-chain compromises of upstream dependencies (FastAPI, uvicorn,
  Jinja2, requests, pydantic, sqlite3, etc.).
- Attackers with physical access to the host running Lynceus.
- Adversaries who can read or modify the SQLite database directly.

## Data at rest

The `lynceus.db` SQLite file is **unencrypted**. Lynceus uses the
stdlib `sqlite3` module (not SQLCipher); rely on full-disk encryption,
filesystem permissions, and physical security to protect the
database. The hardened systemd units lay the file down as
`0640 root:lynceus`; user-mode installs write `0600` on first
creation but operator-set modes are preserved on subsequent opens.

Two surfaces in `lynceus.db` are notably sensitive:

- **`evidence_snapshots`** (introduced in v0.4.0) stores the full
  Kismet device record at alert time. It can contain probe SSIDs and
  BLE friendly names when the matching `capture.*` toggles are
  enabled, and the OPERATOR's GPS fix when `evidence_store_gps` is
  enabled. Probe-SSID and GPS capture are off by default; the
  retention window is governed by `evidence_retention_days`
  (default 90).
- **WAL sidecars (`lynceus.db-wal`, `lynceus.db-shm`)** retain
  recently-written rows even after a `DELETE` has logically removed
  them — the prune does not synchronously rewrite the WAL. Standard
  rsync/borg backups sweep both files alongside `lynceus.db`.
  Operators who care about post-deletion residue should checkpoint
  the WAL before backing up:

  ```sh
  sqlite3 /var/lib/lynceus/lynceus.db "PRAGMA wal_checkpoint(TRUNCATE);"
  ```

  This is also worth running before handing the database to anyone
  outside the trust boundary, since rows the operator believes were
  pruned may otherwise be recoverable from the WAL.

## Reporting a vulnerability

**Preferred — private security advisory:**
<https://github.com/kevlattice/lynceus/security/advisories/new>
(GitHub: Settings → Security → Report a vulnerability)

**Low-severity issues — public issue tracker:**
<https://github.com/kevlattice/lynceus/issues>

Please include:

- Affected version (e.g. `0.3.0-rc1`).
- Reproduction steps.
- Expected vs. actual behavior.
- Your assessment of impact.

Response is best-effort. No SLA is promised.

## Scope

**In scope** (report here):

- Lynceus's own code under `src/lynceus/`.
- The installer (`install.sh`).
- Bundled systemd unit files under `systemd/`.
- Default configuration under `config/`.
- The bundled default watchlist at
  `src/lynceus/data/default_watchlist.csv`.

**Out of scope** (report to the relevant upstream):

- Kismet — report to Kismet upstream.
- ntfy — report to ntfy upstream.
- Python dependencies (FastAPI, uvicorn, Jinja2, requests, pydantic,
  etc.) — report to their maintainers.
- The operator's host OS, the Linux kernel, and hardware drivers.

## Disclosure timing

Fixes ship as part of normal point releases. Coordinated disclosure is
welcomed, but no specific embargo windows are committed in advance.
