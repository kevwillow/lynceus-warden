# Operator-configurable detection tuning, from the web UI

**Status:** design, not yet implemented.
**Written:** 2026-08-26, against `main` at `42e899e`.
**Proposes reversing:** the "read-only UI is a security boundary" non-negotiable
published at `README.md:157`. See §1 and §9.4 before treating that as settled.

Every measurement below is dated and sourced. Where a number came from the
backlog rather than from a fresh count, it says so and gives the date it was
taken, because a bare total is a claim with no expiry.

---

## 1. The problem

The `/settings` page is read-only. `app.py:6318` registers a `GET` and nothing
else, and `settings.html` contains zero `<form>` elements.

⛔ **That is a deliberate, published commitment, not an accident.** An earlier
draft of this document called it "where the product stopped". That was wrong.
`README.md:157` states it under a heading called **Non-negotiables**, described
there as "design commitments, not current limitations":

> **The read-only UI is a security boundary.** The web UI never mutates your
> configuration: `lynceus.yaml`, rules and capture settings change only
> out-of-band, via `lynceus-setup` or the YAML. [...] Read-only about
> configuration is a feature, not a missing one.

So this design proposes reversing a stated non-negotiable. That is allowed, it
is the owner's call, and it changes what the work includes: **the README must
reverse the commitment out loud, with the reason attached.** A published
non-negotiable that quietly disappears is worse than one that changes.

⭐ **The README already draws a better line than the one this design first
drew.** It distinguishes *operator decisions* the UI may record (acks, notes,
snoozes, watchful entries, the daemon-managed `allowlist_ui.yaml`) from
*configuration* it may not, and says what the UI cannot do is "change what
Lynceus captures or how it is deployed". Detection tuning changes what alerts,
so it falls on the configuration side. Two honest ways forward, and §9.4 records
this as open:

1. Move the boundary, and say in the README that tuning is now UI-editable and
   why the dry-run makes that safe.
2. Argue that suppression and severity are operator decisions rather than
   capture configuration, and keep the boundary where it is by narrowing what
   becomes editable to things that never change *what is captured*.

The current cost of leaving it exactly as-is:

1. **BLE-G1 is blocked on a judgement nobody can make.** The Bluetooth bridge is
   built and commented out in `config/rules.yaml` (lines 124–125, 148–149,
   154–155, 222–223). It stays off because enabling it *might* storm the
   operator.

   ⭐ **Re-measured 2026-08-26 against the shipped `default_watchlist.csv`
   (41,516 records, `schema_version=31`) and BLE-G1's figures are exactly
   right and still current:**

       identifier_type        rows   actionable
       ble_manufacturer_id    3969            2
       ble_company_id          715            2
       ────────────────────────────────────────
       the rule consumes      4684            4     0.085% signal

   "Actionable" means `device_category` is neither empty nor `unknown`.

   ⚠️ **State that universe whenever the number is quoted.** Counting *every*
   `ble_*` type instead gives 4,880 rows / 167 actionable / 3.42%, a different
   and also-correct answer that looks like a contradiction if the set is left off.
   The rule consumes only the two types above, because both collapse to the
   single watchlist `pattern_type` `ble_manufacturer_id` (`IDENTIFIER_TYPE_MAP`,
   `import_argus.py:72`).

   Nobody can say whether *this* operator's deployment would storm, because
   nobody has scored it against *their* data.

2. **The only way to tune detection is to hand-edit YAML over SSH** on a
   Raspberry Pi. For a device someone deploys and walks away from, that is not a
   defensible operator experience.

3. **Nothing tells an operator that the tuning file exists.** `severity_overrides.yaml`
   (`config.py:211`) is invisible from the product. There is no discovery path.

## 2. Scope, decided and deliberately narrow

**Editable from the UI: detection tuning only.** Rules, severities, suppression
filters, and the settings that decide what fires an alert.

**Not editable from the UI: identity, network and storage.** `ui_bind_host`,
authentication, database path, Kismet connection.

The line is drawn at a single question: *can a wrong value here make the box
unreachable?* A dry-run can prove a detection setting is sane by scoring it
against real stored observations. Nothing can prove you will still be able to
reach the machine after changing its bind address. The web UI serves no TLS, so
the connection carrying that change is already the weaker link.

⛔ **This is not "everything configurable, with a warning."** A warning is not a
safety boundary. That is the same reasoning that made #234 exit `2` rather than
print a banner and start anyway.

## 3. What already exists, and must not be rebuilt

Four of the hard parts are already built and proven in production. The design
leans on them rather than inventing parallels.

| Capability | Where | Notes |
|---|---|---|
| Pure rule evaluation | `rules.py:866` `evaluate() -> list[RuleHit]` | No notifier, no side effects. **This is what makes the dry-run possible.** |
| Live reload without restart | `poller.py:3120` `_maybe_reload_allowlist` | `stat()` pair per poll tick, reload only on mtime change. |
| Atomic config write | `allowlist.py:730` `_atomic_write_yaml` | tmpfile + `os.replace`; readers see old or new, never half. |
| Config export | `cli/export_config.py` | Redaction, `manifest.json`, SHA256 per file, self-describing archive. |

⭐ **`lynceus-export-config` already covers the export half** of import/export,
including which fields were redacted. There is **no import counterpart**. That
is the actual gap, and it must consume the manifest that export already writes.

The tuning model itself also exists: `RuntimeSeverityOverride` (`rules.py:360`)
already carries `device_category_severity`, `suppress_categories`,
`suppress_vendors`, `pattern_overrides` and `vendor_severity`, with key
normalisation in the model rather than the loader.

## 4. Architecture

### 4.1 The write path: a UI-owned sibling, never the operator's file

The UI writes its own file and the loader merges, exactly as the allowlist
already does (`allowlist.yaml` + `allowlist_ui.yaml`, per #218).

    severity_overrides.yaml       ← operator's, hand-edited, never written by the UI
    severity_overrides_ui.yaml    ← UI-owned, written atomically on save
                                    merged at load, operator file wins on conflict

⛔ **The UI must never rewrite a file a human hand-edits.** A round-trip through
a YAML serialiser destroys comment blocks, and in this repo the comments are
load-bearing, because they carry the measurements and the reasons. Separate files also
mean a hand-edit and a UI edit can never race each other into a lost update.

Operator-file-wins is the honest precedence: a value someone typed into a file
on the box should not be silently overridden by a click.

### 4.2 The reload path: extend the existing watch

`_maybe_reload_allowlist` becomes a general mtime watch covering the tuning
files too. Its existing failure semantics carry over unchanged and are the right
ones:

- **File vanished mid-run** → retain last-known-good, warn, update the mtime
  cache so the next tick re-checks.
- **Corrupt/unparseable** → retain last-known-good, warn. Swapping in an empty
  ruleset would drop every suppression at once and storm the operator.

⚠️ **Check the fail-safe direction per file, do not assume it generalises.** For
suppression, retaining the last good copy is fail-safe. For a *rules* file the
same reflex needs re-deriving rather than copying: the question is which
direction leaves the operator less protected, and it is not automatically the
same answer.

### 4.3 The dry-run, the piece that unblocks BLE-G1

Because `evaluate()` is pure, a candidate configuration can be scored without
firing anything:

1. Build the candidate `Ruleset` / `RuntimeSeverityOverride` from the unsaved
   form state, **never** from what is on disk.
2. Replay stored observations from the last N hours through `evaluate()`.
3. Report: how many alerts this would have produced, broken down by rule and
   severity, and how many the *current* config produced over the same window.

The operator sees the delta before committing. For BLE-G1 that turns "this might
storm" into a number from their own deployment.

⚠️ **The dry-run is an estimate, and must say so on screen.** It replays what was
stored, over a bounded window, on one machine. It is strong evidence and it is
not a guarantee about future traffic. A preview presented as a promise is worse
than no preview.

⚠️ **Report the window and the row count beside every number.** "4,684 alerts" is
not interpretable without "over the last 24h, from 12,300 stored observations".
Two correct answers computed over different windows look like a contradiction.

### 4.4 The "not configurable here" panel: derived, never transcribed

Every setting outside the editable scope gets a panel showing: the current value,
the file that holds it, the key name, and the exact commands to change it, each
with a copy-to-clipboard control.

⛔ **Derive all four from the running system. Do not type them as strings.**

- key name → the config model's own field name
- file path → the config path the daemon actually loaded (`_build_settings_context`
  already receives `loaded_config_path`)
- current value → read live, through the existing redaction in
  `_build_settings_context` (`app.py:1176`), so no secret reaches the template
- restart command → derived from the packaged unit name

A hardcoded instruction is four independent facts that can each rot. This repo
has already shipped a `Makefile` comment stating the test suite was not in a
clone *after* it had been tracked, and two "shipped limitations" that had quietly
become false (#223). A renamed field must break the page at import time, not
misinstruct someone at 2am.

**A guard enforces completeness**, in the shape of #234's exempt-set pinning and
#236's parity test: iterate the config model and assert every non-editable field
has a panel. Deriving the set is the point, because a hand-maintained list is a
list a new field silently falls off.

### 4.5 Three states, one page

`/settings` becomes a complete map of configuration:

- **Editable here.** Form, dry-run, save.
- **File-only.** Derived panel and exact commands.
- **Built but switched off.** Capability present, currently disabled, and what
  enabling it would cost. This is where the Bluetooth bridge finally becomes
  visible; today the product says nothing about it at all.

## 5. Import and reset

### 5.1 `lynceus-import-config`

Consumes what `lynceus-export-config` produces.

⛔ **An imported bundle reconfigures a security tool, so import is a trust
boundary, not a parser.** Validate before applying: verify each file's SHA256
against `manifest.json`, check the version for compatibility, reject paths that
escape the target directory, and validate the parsed config against the models
before anything touches disk.

The manifest records which fields were redacted, so import can say plainly which
secrets the operator must re-enter rather than silently installing blanks.

Default to a **preview**: show what would change, require an explicit flag to
apply.

### 5.2 `lynceus-reset-config`

The backstop, and the reason the risky settings can stay file-only.

- **It must work when the daemon will not start.** That is exactly when it is
  needed, so it must not import the daemon or require a healthy config.
- **It must print what it is about to discard and require confirmation.** It
  cannot become the thing that loses someone's tuning.
- **Granular, not just total:** resetting detection tuning is a different act
  from resetting the network settings, and the common case is the former.

⛔ **It must be executed in a test, not merely written.** A recovery path nobody
has run is an assumption. In this repo an untested delete-and-recreate has
already destroyed the thing it was meant to repair. The test must drive the real
path from a genuinely broken config, not a mocked one.

**README in the same change**, not a follow-up.

## 6. Failure modes worth naming up front

| Failure | Consequence | Mitigation |
|---|---|---|
| Half-written file read mid-save | Daemon loads a truncated ruleset | `_atomic_write_yaml` (`allowlist.py:730`), already solved, reuse it |
| Dry-run scores the saved config, not the form | Preview blesses something else | Build the candidate from unsaved form state; a test must plant a difference and prove the preview moves |
| Stolen session cookie | Attacker silently disables the alert that matters | Out of scope to fix here, but this change **raises what the web surface is worth attacking**. Worth a follow-up on audit-logging config changes |
| Corrupt UI file after a save | Suppressions dropped, storm | Retain-last-known-good, per §4.2 |
| Panel instructions go stale | Operator follows wrong steps | Derivation + completeness guard, per §4.4 |

## 7. Testing

- **Plant a defect for each guard.** A guard that has never been seen to fail is
  not known to work. Specifically: break the derivation and prove the
  completeness guard reddens; change a form value and prove the dry-run number
  moves.
- **Dry-run fidelity:** a candidate config whose preview says N must produce N
  when actually applied to the same stored window.
- **Reset from a genuinely broken config**, run for real (§5.2).
- **Import rejects a tampered bundle.** Flip one byte, assert the SHA256 check
  refuses it.
- **The operator file is never rewritten.** Assert byte-identical, comments
  included, after a UI save.

## 8. Deliberately not doing

- **Auto-rollback / commit-confirmed** for bind and auth. Genuinely safe, but it
  is a scheduler, a pending-config state machine, and a recovery path that must
  itself be tested. The reset CLI covers the rare lockout at a fraction of the
  cost. Revisit if bind/auth editing is ever actually wanted.
- **Editing `rules.yaml` directly.** The shipped file keeps its comments and its
  measurements whatever else is decided; where rule *enablement* is stored is
  still open (§9.2).
- **TLS.** Unchanged and still absent. Off-loopback remains SSH-tunnel-or-private-network.

## 9. Open questions

1. **Dry-run window.** Fixed 24h, or operator-chosen? Longer is better evidence
   and more expensive to replay.
2. **Does rule enablement belong in the sibling YAML or the database?** The
   allowlist precedent split: file for operator entries, DB for UI state (#218).
   Worth re-deriving rather than assuming.
3. **Audit log for config changes.** Probably yes once the UI can change
   detection behaviour, but it is a separate piece of work.
4. **Does the boundary move, or does tuning get reclassified?** See §1. Either
   the README says the read-only-configuration commitment is lifted and why, or
   this design narrows to things that never change what is captured, and the
   commitment survives intact. This has to be answered before phase 4, and it
   decides what the README change says.

## 10. Implementation order

This is more than one plan's worth of work. It decomposes into four phases that
each land independently and leave the product working:

1. **`lynceus-reset-config` + README.** The backstop everything else leans on,
   and the only phase with no prerequisites. Built first precisely because later
   phases are safer once it exists.
2. **The `(pattern_type, device_category)` suppression filter.** One new field on
   `RuntimeSeverityOverride` (`rules.py:360`), following the existing
   `suppress_categories` pattern, plus the loader and reload wiring. **This alone
   unblocks BLE-G1** even with no UI work at all.
3. **Dry-run scoring**, exposed first as a CLI subcommand so it can be tested
   without any web surface, then surfaced in the UI.
4. **The editable settings page and the derived "not configurable here" panel.**
   Last, because it depends on 2 and 3, and because it is the phase that widens
   the security surface.

`lynceus-import-config` (§5.1) can land any time after 1; it is independent of
the UI work.

## Appendix: side findings from writing this

Two documentation inaccuracies surfaced while checking the numbers above. Neither
blocks this design; both are worth a cheap fix.

- **`Makefile:28` calls `default_watchlist.csv` "45,663-row".** That is a *line*
  count, not a record count. `description` and `source_excerpt` contain embedded
  newlines, so `wc -l` over-counts by roughly 10%. The file holds **41,516 CSV
  records** across 45,703 non-comment lines. The figure is used to explain why
  `make release-gates` takes nine minutes, so it is read by people sizing a wait.
- **The file's own `# meta:` header declares `record_count=41518`**, against
  41,516 actually parsed. A two-row gap of unknown origin, worth a look only if
  the manifest count is ever relied on for integrity rather than description.
