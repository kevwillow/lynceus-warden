# Install-flow webui — Phase 1 scout findings

Read-only investigation. No production code changed.

This document inventories `lynceus-setup` and `lynceus-ui`, identifies
the seams for extracting a shared config-application core, and proposes
a file-level Phase 1 touch breakdown for the install-flow webui arc.

**Verification convention used throughout.** Each structural claim is
tagged ✅ (verified by reading the cited file:line) or ⚠ (could not
locate / not in tree). When a fact is inferred from one citation but the
inference itself isn't reproduced here, the marker reflects what was
actually read, not the inference.

Repo state at scout time: on tag `v0.6.3`, clean working tree except
the untracked `.claude/launch.json` workspace file. ✅
[`git status` output](#)

---

## Section 1 — `lynceus-setup` inventory

### Entry point

- ✅ Entry resolved via [pyproject.toml:64](pyproject.toml:64) →
  `lynceus-setup = "lynceus.cli.setup:main"`.
- ✅ `main()` at [src/lynceus/cli/setup.py:1964](src/lynceus/cli/setup.py:1964):
  reconfigures stdout to UTF-8 (line 1967, prevents Windows cp1252
  crashes on the `═` box-drawing chars), parses args
  ([`_build_parser`:1922](src/lynceus/cli/setup.py:1922)), applies the
  sudo-without-`--system` refusal at
  [setup.py:1980](src/lynceus/cli/setup.py:1980), then delegates to
  `run_wizard`.
- ✅ `run_wizard()` at
  [src/lynceus/cli/setup.py:1400](src/lynceus/cli/setup.py:1400) is the
  flow body. Returns an int exit code; `main()` forwards via
  `sys.exit(main())`.

### Flow, named phases (verified line ranges)

All citations are `src/lynceus/cli/setup.py`. Names below match the
inline `# (a)` … `# (k)` comments where present.

| Phase | Lines | Summary |
|---|---|---|
| Scope + path resolution | 1409–1410 | `determine_scope(args)` → `resolve_config_path(scope, args.output)`. ✅ |
| Preflight: existing config | 1412–1415 | `preflight_existing` refuses without `--reconfigure`. Returns 2. ✅ |
| Preflight: scope/privilege | 1417–1420 | `preflight_scope` checks euid for `--system` on POSIX, `is_writable_system_path` on Windows. ✅ |
| (a) Kismet URL prompt | 1428–1457 | `_print_section` + context block; `prompt_url` with `_URLPromptAborted` exit on 4 invalid attempts. ✅ |
| (b) Kismet API key | 1458–1509 | `_kismet_api_key_candidate_paths(scope)` → `_read_kismet_api_key` walks `~/.kismet/session.db` JSON, prefers name=`lynceus` → role=readonly → role=admin → first; fall-through prompts hidden `prompt_secret`. ✅ |
| (c) Kismet probe + sources query | 1511–1546 | `probe_kismet` (REST `/system/status.json`) + `probe_kismet_sources` (driver-classified into wifi/bt). Probe-fail → `Continue anyway?` prompt. ✅ |
| (d) WiFi source selection | 1548–1577 | When Kismet reachable: numbered choice from `wifi_sources`. Otherwise fallback to `enumerate_wireless_interfaces` (`/sys/class/net/*/wireless`). Exits 1 if reachable Kismet has zero wifi sources. ✅ |
| (d2) BT source selection | 1578–1621 | Mirror of (d) for `linuxbluetooth`-driver sources or `/sys/class/bluetooth/hci*`. ✅ |
| (e) `probe_ssids` toggle | 1623–1629 | `prompt_yes_no` default False (privacy default). ✅ |
| (f) `ble_friendly_names` toggle | 1630–1635 | `prompt_yes_no` default True. ✅ |
| (g) ntfy URL (skip path) | 1637–1679 | Empty input = skip ntfy; non-empty triggers (h)/(i). ✅ |
| (h) ntfy topic | 1680–1704 | `_prompt_ntfy_topic` with `_NTFY_TOPIC_RE` (`[A-Za-z0-9_-]{6,64}`) + deny-list; `SetupError` after `NTFY_TOPIC_MAX_ATTEMPTS=4`. ✅ |
| (i) ntfy probe | 1705–1714 | POST a one-line test to `{url}/{topic}`. Continue-anyway gate on fail. ✅ |
| (j) RSSI threshold | 1716–1727 | `prompt_default` with `-70` default. Invalid → fall back to default with print. ✅ |
| (k) Severity overrides path | 1729–1744 | `SEVERITY_OVERRIDES_EXPLANATION` printed, then `prompt_default` with `_looks_like_path` re-prompt loop (no hard cap). ✅ |
| Config write + perms | 1746–1775 | `render_config_yaml(answers)` (hand-rolled YAML string with section comments, NOT `yaml.safe_dump`) → `write_config` (atomic, mode 0o600) → `_apply_system_perms_to_file` (root:lynceus 0640) under `--system` → `scaffold_severity_overrides` → re-apply perms. Then `paths.default_data_dir`/`default_log_dir` `mkdir(parents=True, exist_ok=True)` + `_apply_system_perms_to_dir` (lynceus:lynceus 0750). ✅ |
| Summary block | 1777–1795 | Prints `Config written to:` + selected answers; redacts `ntfy_topic` via `redact_ntfy_topic` (line 1789). ✅ |
| Bundled watchlist import | 1797–1815 | `import_bundled_watchlist(db_path, override_file)` subprocesses `lynceus-import-argus` with `BUNDLED_IMPORT_TIMEOUT_SECONDS=120` bound (line 174 + 1056). Silent skip when CSV resource absent. ✅ |
| Post-import DB chown | 1817–1834 | Under `--system`, walks `db_path.parent.glob(name + "*")` to chown `.db`, `-wal`, `-shm` to lynceus:lynceus 0640. ✅ |
| Enable-alerting flow | 1836–1856 | `run_enable_alerting_flow` (line 1263): gate prompt → per-pattern-type prompts (only for types with `count_watchlist_by_pattern_type > 0`) → `render_rules_yaml(enabled_rule_types)` → `_atomic_write`. ✅ |
| Wire rules_path | 1858–1871 | Re-reads target, only appends if `rules_path:` not already present. ✅ |
| Touched-files summary | 1873–1878 | `--system` only — prints `Applied lynceus group ownership: …` list. ✅ |
| Completion-marker block | 1880–1916 | Pre-marker hint block (lines 1881–1903), then explicit `─` × 60 marker (lines 1911–1914) + `sys.stdout.flush()`. This is the v0.6.3 Touch 2 fix; the marker IS the "wizard exited cleanly" signal. ✅ |

### Every prompt at a glance

| # | Prompt text fragment | Default | Validation | On bad input |
|---|---|---|---|---|
| a | "Kismet API URL" | `http://127.0.0.1:2501` | scheme+host via `_is_valid_url` | re-prompt × 4, then `_URLPromptAborted` → exit 1 |
| b1 | "Use this key?" (only if located) | Y | yes/no | re-prompt |
| b2 | "Kismet API token (input hidden)" | — | non-empty | re-prompt forever |
| c-fail | "Continue anyway?" (Kismet probe failed) | N | yes/no | "Aborted." exit 1 if N |
| d | "Select Kismet Wi-Fi datasource:" / "Select capture interface:" | — | 1..N | re-prompt |
| d2 | "Add a Bluetooth capture source?" + numbered choice | Y | yes/no, 1..N | re-prompt |
| e | "Capture probe SSIDs…" | N | yes/no | re-prompt |
| f | "Capture BLE advertised names?" | Y | yes/no | re-prompt |
| g | "ntfy broker URL (Enter to skip…)" | none | scheme+host or empty | re-prompt × 4, then `_URLPromptAborted` → exit 1 |
| h | "ntfy topic name (Enter to accept…)" | generated `lynceus-<8hex>` | `_NTFY_TOPIC_RE` + deny-list | re-prompt × 4, then `SetupError` → exit 1 |
| i-fail | "Continue anyway?" (ntfy probe failed) | N | yes/no | "Aborted." exit 1 |
| j | "RSSI threshold (dBm)…" | `-70` | `int(...)` | fall back to default (silent) |
| k | "Severity overrides file path" | `<config_dir>/severity_overrides.yaml` | `_looks_like_path` | re-prompt indefinitely |
| alerting gate | "Enable Argus-backed alerting?" | N | yes/no | re-prompt |
| alerting per-type | `"Enable {rule_type} ({count:,} {label})?"` (only when count>0) | N | yes/no | re-prompt |
| alerting overwrite | "Overwrite?" (only when rules.yaml exists) | N | yes/no | re-prompt |

All prompt helpers ([setup.py:447–587](src/lynceus/cli/setup.py:447))
take an `input_fn=` keyword; the wizard is fully driven by injected
`input`/`getpass` callables — that's the test seam for the 200-test
regression suite. ✅

### Every file write

| Path | Content shape | Mode (user) | Mode (system) | Helper |
|---|---|---|---|---|
| `<config_dir>/lynceus.yaml` | hand-rolled YAML string, `render_config_yaml` | 0600 | 0640 root:lynceus | `write_config` → `_atomic_write` ([:980](src/lynceus/cli/setup.py:980)) |
| `<config_dir>/severity_overrides.yaml` | static `SEVERITY_OVERRIDES_TEMPLATE` | 0600 | 0640 root:lynceus | `scaffold_severity_overrides` ([:985](src/lynceus/cli/setup.py:985)) |
| `<config_dir>/rules.yaml` | `render_rules_yaml(enabled_rule_types)` | 0600 | 0640 root:lynceus | `_atomic_write` ([:1341](src/lynceus/cli/setup.py:1341)) |
| `<config_dir>/lynceus.yaml` (rules_path append) | text append, not atomic | preserves existing | preserves existing | `append_rules_path_to_config` ([:1246](src/lynceus/cli/setup.py:1246)) |
| `<data_dir>/lynceus.db*` | created by `lynceus-import-argus` subprocess | sqlite default | 0640 lynceus:lynceus | post-hoc chown loop ([:1828](src/lynceus/cli/setup.py:1828)) |

Directories created via `mkdir(parents=True, exist_ok=True)`:
config dir (implicit via `write_config` line 981), `paths.default_data_dir`
+ `paths.default_log_dir` (explicit at lines 1768–1769). Under
`--system`, dirs chmod 0750 lynceus:lynceus. ✅

### Subprocess invocations

Only one in setup.py. ✅

- `lynceus-import-argus` via
  [`import_bundled_watchlist`:1003](src/lynceus/cli/setup.py:1003).
  Command: `lynceus-import-argus --input <bundled_csv> --db <db_path> [--override-file <sev>]`.
  Blocking with `subprocess.Popen(stdout=PIPE, stderr=PIPE, text=True)` →
  `proc.communicate(timeout=BUNDLED_IMPORT_TIMEOUT_SECONDS=120)`. Kill +
  5s second-communicate on `TimeoutExpired`. Failure modes returned as
  `(False, "import failed: …")`; only the import summary line is parsed
  out for the success message. ✅

- `lynceus-bootstrap-kismet` is **not** invoked by setup.py at all;
  it only appears as a hint string at
  [setup.py:1440](src/lynceus/cli/setup.py:1440). ✅
  Bootstrap is currently an entirely separate operator action, run
  before `lynceus-setup`. ([src/lynceus/cli/bootstrap_kismet.py:1116](src/lynceus/cli/bootstrap_kismet.py:1116)
  is its `run()`; itself a ~1300-line script with its own root gate,
  apt operations, interface config, group membership.)

### Branching conditions

- `scope` ("user" vs "system") at every perm-applying site
  ([setup.py:1750](src/lynceus/cli/setup.py:1750),
  [:1770](src/lynceus/cli/setup.py:1770),
  [:1825](src/lynceus/cli/setup.py:1825),
  [:1850](src/lynceus/cli/setup.py:1850),
  [:1873](src/lynceus/cli/setup.py:1873)). ✅
- `args.reconfigure` (preflight at line 1412). ✅
- `args.output` (explicit path override at line 1410). ✅
- `args.skip_probes` (lines 1517, 1706). ✅
- `_is_windows()` indirection ([:343](src/lynceus/cli/setup.py:343))
  used inside `_atomic_write`, `_apply_system_perms_*`,
  `user_config_dir`, `system_config_dir`, `_kismet_api_key_candidate_paths`,
  `is_writable_system_path`. ✅
- `sources_list is None` (Kismet probe-failed OR list-sources-failed)
  branches every datasource-selection step into OS-fallback enumeration. ✅
- `bundled_ok` gates the post-import DB chown loop
  ([:1825](src/lynceus/cli/setup.py:1825)) — if the bundled import
  failed, no chown happens. ✅
- Fresh-install vs reconfigure: not a separate code path beyond the
  `preflight_existing` gate; `--reconfigure` just permits overwrite of
  lynceus.yaml. rules.yaml has its own independent overwrite confirm
  ([:1322](src/lynceus/cli/setup.py:1322)). ✅

### Inter-step state

✅ **Loose `dict` named `answers`**, declared at
[setup.py:1425](src/lynceus/cli/setup.py:1425). Keys progressively
populated: `kismet_url`, `kismet_api_key`, `kismet_sources`,
`probe_ssids`, `ble_friendly_names`, `ntfy_url`, `ntfy_topic`,
`min_rssi`. `sev_path` and a few other locals live outside the dict.

There is **no** `WizardState` dataclass and **no** Pydantic model
gating the in-flight answers — validation happens at the per-prompt
helper or not at all. The final `render_config_yaml(answers)` is a
straight dict-key formatter and does no validation; the canonical
`Config` model at [src/lynceus/config.py:55](src/lynceus/config.py:55)
only runs against the written-back YAML when the daemon loads it (or
when an operator runs `lynceus-validate`). ✅

### Completion-marker block (v0.6.3 fix)

✅ At [setup.py:1904–1915](src/lynceus/cli/setup.py:1904). Inline
comment (lines 1904–1910) explains the marker exists because operators
perceived `--system` as hanging silently after completion. The marker
is three printed lines:

```
─ × 60
Setup complete — exiting. Config at <target>.
─ × 60
```

followed by `sys.stdout.flush()`. The marker is the structural
"clean exit" signal `tests/test_setup_wizard.py` pins via
`test_setup_writes_completion_marker_under_system` and related. ✅
(Specific test names verified by grep; 200 tests total in
`tests/test_setup_wizard.py`.)

---

## Section 2 — `lynceus-ui` inventory

### Layout

- ✅ Module: `src/lynceus/webui/` (4 files):
  [`app.py`](src/lynceus/webui/app.py) (3325 lines),
  [`server.py`](src/lynceus/webui/server.py) (77 lines),
  [`csrf.py`](src/lynceus/webui/csrf.py) (212 lines),
  [`pagination.py`](src/lynceus/webui/pagination.py) (122 lines).
- ✅ Entry: `lynceus-ui = "lynceus.webui.server:main"`
  ([pyproject.toml:62](pyproject.toml:62)). `server.main()` constructs
  the FastAPI app via `create_app(config, db)` and hands it to
  `uvicorn.run` ([server.py:53–63](src/lynceus/webui/server.py:53)).
- ✅ Templates: `src/lynceus/webui/templates/*.html` (19 files
  including `_topnav.html`, `_sparkline.html`, `_watchful_actions.html`
  partials and `base.html` shell). Resolved via
  `importlib.resources.files` ([app.py:73](src/lynceus/webui/app.py:73)).
- ✅ Static: `src/lynceus/webui/static/` ships `htmx.min.js`,
  `lynceus.css`, `lynceus.js`, `pico.min.css`. Pico.css is the visual
  framework; htmx is loaded but I did **not** verify how broadly it's
  used (didn't read templates).

### Framework

- ✅ **FastAPI** (pyproject lists `fastapi>=0.115,<1.0`,
  `uvicorn[standard]`, `python-multipart`, `jinja2`). Imports at
  [app.py:17–20](src/lynceus/webui/app.py:17):
  `FastAPI, Form, HTTPException, Query, Request` +
  `HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse`.

### Routing structure

- ✅ Single-file app factory pattern. `create_app(config, db) -> FastAPI`
  at [app.py:1101](src/lynceus/webui/app.py:1101). All routes are
  registered as `@app.<method>(...)` closures inside `create_app`, so
  they capture `config` and `db` from the enclosing scope rather than
  going through DI. No `APIRouter`s; no `Blueprint`-style modularization.
- ✅ Inventoried routes (from grep at `^@app\.`):

  - `GET /healthz` / `GET /healthz.json`
  - `GET /` (index)
  - `GET /alerts`, `GET /alerts.csv`, `GET /alerts/{alert_id}`
  - `POST /alerts/bulk-ack`, `/ack-all-visible`,
    `/{id}/ack`, `/unack`, `/allowlist`, `/snooze`,
    `/allowlist/remove`, `/note`, `/watch`
  - `POST /watchful/{entry_id}/{dismiss,promote,reset,investigate,confirm-safe}`,
    `GET /watchful`, `GET /watchful/{id}`
  - `GET /devices`, `GET /devices/{mac:path}`
  - `GET /rules`, `POST /rules/{rule_type}/snooze`, `unsnooze`
  - `GET /watchlist`, `/watchlist.csv`, `/watchlist/{id}`
  - `GET /settings` (read-only — see below)
  - `GET /allowlist`, `POST /allowlist/add`, `/bulk_remove`

- The closure-style means new routes naturally live alongside the
  existing block inside `create_app`. Splitting routes into routers
  would itself be a refactor — flag for Section 6.

### Auth model

- ✅ **No user authentication.** No login layer, no API tokens, no
  session cookie beyond the CSRF cookie.
- ✅ Confinement comes from binding loopback by default:
  `ui_bind_host: "127.0.0.1"` ([config.py:82](src/lynceus/config.py:82))
  + a model-validator at [config.py:228–237](src/lynceus/config.py:228)
  that refuses non-loopback bind unless `ui_allow_remote: true` is set
  explicitly.
- ✅ CSRF is the only token surface:
  [`webui/csrf.py`](src/lynceus/webui/csrf.py) — double-submit cookie
  pattern, `lynceus_csrf` cookie + `X-CSRF-Token` header or `_csrf`
  form field, body-replay middleware. Enforced on all
  POST/PUT/PATCH/DELETE; safe methods set the cookie if missing.
  Cookie `Secure` flag flips on iff `config.ui_allow_remote` (line
  [app.py:1129](src/lynceus/webui/app.py:1129)).

### Templating

- ✅ Jinja2 via `fastapi.templating.Jinja2Templates`, attached at
  [app.py:1116](src/lynceus/webui/app.py:1116).
- ✅ Existing custom filters/globals registered there:
  `unix_to_iso`, `unix_to_utc_human`, `device_label`, `relative_time`,
  `csrf_token`. The `relative_time` filter is the user's standing
  pattern referenced in the prompt. ✅
- ✅ Pagination via `pagination.PaginationParams` / `parse_pagination` /
  `build_pagination` — used for `/alerts` and `/allowlist`. This IS
  the `PaginationParams`-style helper referenced in the prompt. ✅

### Streaming / real-time

- ✅ **No SSE, no websockets, no polling helper exists today.**
  `StreamingResponse` is imported and used twice
  ([app.py:1572](src/lynceus/webui/app.py:1572) and
  [:2970](src/lynceus/webui/app.py:2970)) — both are
  `media_type="text/csv; charset=utf-8"` for the alerts/watchlist CSV
  exports. ✅
- htmx is present in static — I did not verify its use in templates.
  Whether htmx polling is already in use somewhere in the UI is
  **unverified**. ⚠ (Worth confirming during Phase 2 design; if htmx
  polling is already idiomatic, that's a lighter pattern than SSE.)

### Form handling

- ✅ FastAPI `Form()` dependencies (pyproject's `python-multipart`
  enables it). See [app.py:3172](src/lynceus/webui/app.py:3172)
  (`allowlist_add`) as the most form-heavy handler.
- ✅ Validation pattern: handlers do per-field type checks, build a
  Pydantic `AllowlistEntry`, and catch `ValidationError` →
  `_first_validation_error(exc)` ([app.py:433](src/lynceus/webui/app.py:433)).
  On error the handler re-renders the page with `add_form` (echo) +
  `add_error` populated so the operator's input survives the round-trip.
  No WTForms.
- ✅ Redirect after POST via `RedirectResponse(..., status_code=303)`
  with `?success=<token>&count=<n>` flash tokens
  ([app.py:3247](src/lynceus/webui/app.py:3247)).

### Test patterns

- ✅ `fastapi.testclient.TestClient` is the route-test pattern
  (`tests/test_webui.py:11`).
- ✅ Tests construct apps via `create_app(config, Database(tmp_path / ...))`
  and assert on response content + headers. CSRF tests live in
  [`tests/test_csrf.py`](tests/test_csrf.py).
- ✅ Setup wizard tests
  ([`tests/test_setup_wizard.py`](tests/test_setup_wizard.py): **200
  tests**) drive `run_wizard` through injected `input_fn`/`getpass_fn`
  callables. Total non-diagnostic test count for the suite was not
  re-measured here.

### Reusable helpers worth knowing about for Phase 2/3

- ✅ `_resolve_templates_dir` / `_resolve_static_dir` — handle both the
  installed-wheel and source-checkout cases via `importlib.resources`
  with file-system fallback.
- ✅ `CSRFMiddleware` + `get_csrf_token` Jinja global — ready to wire
  into any new POST surface.
- ✅ `parse_pagination` / `build_pagination` — ready to reuse for any
  list page.
- ✅ `relative_time` Jinja filter — ready to use on a progress view.
- ✅ `redact_ntfy_topic` / `redact_topic_in_url` (`src/lynceus/redact.py`)
  + the `_redact_kismet_api_key` head/tail preview in setup.py —
  ready to reuse on any review-before-write page.
- ✅ Settings page (`GET /settings` at
  [app.py:3030](src/lynceus/webui/app.py:3030)) is **read-only today**;
  `_build_settings_context` ([app.py:757](src/lynceus/webui/app.py:757))
  computes a redacted-display payload only. Phase 3's
  "persistent admin pages" effectively means lifting these surfaces
  from read-only to read-write.

### Systemd integration relevant to web flows

- ✅ `systemd/lynceus-ui.service` runs `lynceus-ui` as
  `User=lynceus Group=lynceus`, reading
  `/etc/lynceus/lynceus.yaml`. ([systemd/lynceus-ui.service:9–11])
- ⚠ Implication for Phase 3 (persistent admin write): under
  `--system`, the daemon user has **read-only** access to
  `/etc/lynceus/*` (mode 0640 root:lynceus, see
  [setup.py:1751](src/lynceus/cli/setup.py:1751)). Persistent
  config-write from `lynceus-ui` either needs group-write (`0660`),
  a polkit/sudo helper, or the run-once daemon being a different
  process from `lynceus-ui`. Out of Phase 1 scope but worth flagging.

---

## Section 3 — Phase 1 seams analysis

### Classification of phases

Using the phases from Section 1:

| Phase | Class | Notes |
|---|---|---|
| Scope + path resolution | Pure | `determine_scope`, `resolve_config_path` are arg→Path. Lift as-is. |
| Preflight (existing + scope) | Pure | Take Path + scope, return optional error string. Lift as-is. |
| (a) Kismet URL | Interactive-only (prompt) + Pure (validate) | `_is_valid_url` is the validator; the prompt loop is CLI-only. |
| (b) Kismet key | Mixed | The auto-locate (`_kismet_api_key_candidate_paths`, `_read_kismet_api_key`) is pure data extraction. The "Use this key?" prompt + secret entry is interactive-only. |
| (c) Kismet probe + (d/d2) sources | Pure (probes) + Interactive-only (selection) | `probe_kismet`, `probe_kismet_sources` are pure (network + parsed dict). Numbered choice prompts are interactive-only. The `Continue anyway?` on probe-fail is a policy decision the web flow may handle differently. |
| (e)/(f) toggles | Interactive-only | Two booleans. |
| (g) ntfy URL (skip path) | Interactive-only + Pure (validate) | Same shape as (a). |
| (h) ntfy topic | Interactive-only + Pure (validate) | `_looks_like_ntfy_topic` is pure; the generate-suggested + re-prompt loop is interactive. |
| (i) ntfy probe | Pure | `probe_ntfy` is pure. |
| (j) RSSI | Interactive-only + Pure (`int(...)` parse) | |
| (k) Severity overrides path | Interactive-only + Pure (`_looks_like_path`) | |
| Config write | Pure | `render_config_yaml`, `write_config`, `_atomic_write`, `_apply_system_perms_*`. |
| Severity overrides scaffold | Pure | `scaffold_severity_overrides`. |
| Data/log dir create + perms | Pure | `paths.default_data_dir/log_dir.mkdir` + `_apply_system_perms_to_dir`. |
| Bundled import | Pure (with subprocess) | `import_bundled_watchlist` already returns `(ok, msg)` — already in a lift-as-is shape. |
| Post-import DB chown | Pure | `glob` + `_apply_system_perms_to_dir(mode=0o640)`. |
| Enable-alerting gate + per-type | Mixed | `count_watchlist_by_pattern_type` (pure), `render_rules_yaml` (pure), `_atomic_write` (pure) are already separable. The "ask the operator which rule_types to enable" prompts are the only interactive part. Whether to wire `rules_path` is pure logic given the operator's answers. |
| Wire rules_path | Pure | `append_rules_path_to_config` + the "rules_path: already present?" check. |
| Touched-files summary | Pure | A list-build + print. The print is interactive-only; the list-build is pure. |
| Completion-marker block | Interactive-only | The marker IS a CLI-output artefact. Web flows have their own "we're done" UX. |

**Headline finding.** The "ask" code and the "write" code are
**structurally already separable** — `run_wizard` is mostly a sequence
of `prompt_X(...)` calls that fill a `dict`, followed by pure
"`render_*` → `_atomic_write`" calls + perms helpers. The hard part
of the extraction is **not** untangling interleaved interaction +
side-effects; it's:

1. Promoting the loose `answers: dict` to a typed input model.
2. Threading a structured `ApplyReport` through the side-effect
   functions so a non-CLI frontend can render step-by-step status
   without parsing stdout.
3. Deciding what subset of the post-write flow (bundled import,
   enable-alerting prompts) the core owns vs. what stays in a
   higher-level orchestrator.

### Proposed core API shape

✅ A `LynceusConfig` Pydantic model **already exists** at
[src/lynceus/config.py:55](src/lynceus/config.py:55) as `Config`. It
has every field that ends up in lynceus.yaml plus a `capture`
sub-model. Most validator rules the wizard duplicates today
(scheme+host on URLs, RSSI floor, port range) are already on `Config`.

Recommendation: **`Config` IS the validated input model.** Don't
invent a parallel "wizard answers" model. The wizard frontend builds a
`Config` (with the constructor doing validation), and the core
consumes it.

Two pieces of the wizard's "answers" don't currently live on `Config`:

- `severity_overrides_path` — already exists on `Config` ✅
  ([config.py:77](src/lynceus/config.py:77)) but the wizard does NOT
  persist it. (Comment at lines 68–76 explicitly notes this.) Phase 1
  should decide whether to start persisting it (parity-breaking) or
  preserve the current behavior (parity-keeping). Recommend: **preserve
  parity, persist nothing the wizard doesn't persist today** — call it
  out in the changelog as a known gap to revisit.
- `rules_path` — exists on `Config` ([config.py:66](src/lynceus/config.py:66)).
  The wizard appends it to the YAML file post-write rather than
  including it in the initial render. The core can either pass
  `rules_path` directly in the input `Config` and have a single
  `render_config_yaml` covering it, or preserve the "append after
  enable-alerting flow" sequence. Recommend: **drive the whole render
  from a single populated `Config`**; the append-after-the-fact
  sequence exists only because the wizard didn't know whether
  alerting would be enabled until late. The core should accept a
  fully-populated `Config` and write once.

Bootstrap-only side-channel fields that don't belong in `Config`:

- `kismet_api_key` is already there — but it's a secret. ✅
- `kismet_sources`, `kismet_source_locations`, `capture.probe_ssids`,
  `capture.ble_friendly_names` — already there. ✅
- The wizard's transient `sev_path` is a side input for
  `scaffold_severity_overrides`; recommend treating it as a separate
  arg to the core ("where to scaffold the overrides file") rather
  than persisting it.

**Proposed core signature** (placeholder names — kev to pick):

```python
def apply_config(
    config: Config,
    *,
    scope: Literal["user", "system"],
    target_path: Path,                # where to write lynceus.yaml
    severity_overrides_path: Path,    # where to scaffold the overrides file
    enabled_rule_types: set[str] | None,  # None = no rules.yaml
    run_bundled_import: bool,          # default True; web wizard may toggle
    progress: ProgressSink | None = None,
) -> ApplyReport
```

`ProgressSink` is a thin callback interface (one method, takes a step
record). The CLI frontend instantiates a "print-each-line" sink; the
web wizard instantiates a "push to SSE queue" sink. This keeps the
core synchronous and yieldable without ratholing on
async/await.

### Proposed `ApplyReport` shape

```python
@dataclass(frozen=True)
class ApplyStep:
    name: str                       # "write_config", "scaffold_overrides",
                                    # "chown_data_dir", "import_bundled",
                                    # "write_rules", "wire_rules_path", …
    status: Literal["ok", "skipped", "warned", "failed"]
    message: str                    # operator-readable one-liner
    detail: str | None = None       # multi-line, for failures + warnings

@dataclass(frozen=True)
class ApplyReport:
    steps: tuple[ApplyStep, ...]
    target_path: Path
    overall_status: Literal["ok", "partial", "failed"]
```

The CLI frontend renders `steps` line-by-line (≈ what the wizard
prints today, minus the prompts). The web frontend streams each step
to the client as it lands. The shape is intentionally JSON-serializable
so it can double as the SSE payload schema.

### Where the core module lives

Three sensible candidates, all in the existing layout:

1. `src/lynceus/setup/core.py` (new package). Pro: clean
   namespacing for Phase 2/3 to grow into. Con: introduces a third
   `setup`-related namespace (we have `cli.setup` and the systemd
   `setup.service`-ish wording).
2. `src/lynceus/apply.py` (single module). Pro: short and concrete —
   `from lynceus.apply import apply_config` reads well. Con: less room
   to grow when Phase 2 adds a `lynceus.setup.web` module.
3. `src/lynceus/cli/setup.py` split: keep the file, extract the pure
   functions into `src/lynceus/setup_core.py` and import them back. Pro:
   minimal disruption to existing test imports. Con: leaves
   `cli/setup.py` as a thick frontend with mixed responsibilities.

**Recommended:** **(1)** — a new `src/lynceus/setup/` package with
`core.py`, `models.py` (for `ApplyStep`/`ApplyReport`), and `prompts.py`
(the CLI-frontend prompt helpers split off from `cli/setup.py`).
`cli/setup.py` becomes a 100-line frontend that builds a `Config`
from prompts, calls `apply_config`, and renders the `ApplyReport`.
Phase 2 grows into `src/lynceus/setup/web.py`. The naming is verbose
but doesn't collide with the existing `setup_*` pattern in any
distracting way; kev to confirm in Section 4.

### `lynceus-bootstrap-kismet` integration

✅ Today: `lynceus-bootstrap-kismet` is **not called from setup.py at
all**, only mentioned in the operator-facing hint at
[setup.py:1440](src/lynceus/cli/setup.py:1440). It's a separate root-
required ~1300-line script that operators run BEFORE `lynceus-setup`.

Recommendation for Phase 1: **don't touch bootstrap-kismet's surface.**
It's run-once, root-only, and orchestrating it from a non-root web
wizard (Phase 2) is its own design problem. Phase 1's `apply_config`
should NOT try to call bootstrap-kismet. The current "install Kismet,
THEN run lynceus-setup" sequence is preserved.

For Phase 2's awareness: if the web wizard wants to drive
bootstrap-kismet, it'll need either a polkit prompt, a setup-mode
"the operator confirms each step" interactive flow, or it'll surface
"open a terminal and run `sudo lynceus-bootstrap-kismet` first" as a
preflight gate. Recommend the third option — bootstrap is genuinely
sudo work, and a web wizard pretending it isn't would create more
friction than it removes.

---

## Section 4 — Open architectural questions for kev

Each question is framed as a choice with a recommended default. Phase
1's touch breakdown doesn't need any of these answered — they're for
the Phase 2/3 design that follows.

### Q1. Kismet password + API key bootstrap (Phase 2)

**Today:** the wizard expects the operator to have already (a) launched
Kismet, (b) set the admin password via Kismet's first-run UI prompt,
(c) created an API key via Kismet's web UI → Settings → Login
Configuration. Lynceus then auto-locates the key from
`~/.kismet/session.db` ✅ ([setup.py:641–742](src/lynceus/cli/setup.py:641))
or falls back to manual paste.

**Options for Phase 2:**

- **A. Manual paste (parity).** Web wizard shows the same Kismet-UI
  walkthrough, accepts the pasted key, validates via probe.
- **B. API orchestration.** Lynceus drives Kismet's REST API to set the
  initial password and mint a key.

**Verifying option B's feasibility:** I did NOT find Kismet docs in
the tree to check whether Kismet exposes a password-set endpoint, and
`KismetClient` ([src/lynceus/kismet.py](src/lynceus/kismet.py)) was
NOT read during this scout. ⚠ Whether a password-set / key-create
API surface exists is **unverified**.

**Recommended default:** **A**. Manual paste matches v0.6.3 behavior,
keeps Lynceus's blast radius limited (no privileged automation of
Kismet), and the auto-locate already handles 90% of the friction. A
later "Lynceus drives Kismet provisioning" feature can layer on top.

### Q2. Service start in `--system` mode (Phase 2)

**Today:** `run_wizard` writes the config and exits. The operator
runs `sudo systemctl enable --now lynceus.service lynceus-ui.service`
themselves (printed as the closing hint at
[setup.py:1900](src/lynceus/cli/setup.py:1900)).

**Options for Phase 2:**

- **A. Wizard prompts "Start the service now?", calls `systemctl` as
  root.** Requires the wizard to BE root (already true for `--system`).
- **B. Print-and-exit-with-instructions (parity).** Operator copies the
  shell command. Today's behavior.
- **C. Generate a NOPASSWD sudo rule** at install time so a non-root
  web wizard can start the service.

**Recommended default for Phase 1:** **B** (parity). The web wizard is
Phase 2; the question of whether the run-once web flow has root
isn't a Phase 1 problem. Phase 1's `apply_config` should NOT touch
systemd.

### Q3. Run-once auth pattern for the web wizard (Phase 2)

**Today's UI auth model** (Section 2): bind loopback by default, no
user auth, CSRF only. ✅

**Options for Phase 2:**

- **A. Setup token in URL query param.** `lynceus-setup --web` prints
  a URL like `http://127.0.0.1:9000/?token=<random>`; the server
  validates the token on every request, expires it on completion.
- **B. Localhost-only, no token.** Matches the existing
  `lynceus-ui` posture. Trusts that any browser on the box is the
  operator's.
- **C. No auth, no localhost binding** — equivalent to current dev
  defaults. Bad fit for the Pi-via-SSH-tunnel use case.

**Recommended default:** **A** + bind loopback. The token solves the
"same-machine browser tab can hit `127.0.0.1` without consent"
problem AND survives the SSH-tunnel scenario (operator forwards the
port, opens `http://localhost:9000/?token=...` from the laptop).
Reuse `secrets.token_urlsafe(32)` like the CSRF cookie does — same
crypto, no new dependency.

### Q4. Progress streaming: SSE vs htmx polling

**Today:** no streaming pattern in the UI. ✅ `StreamingResponse` is
present but only for CSV exports. htmx is loaded in static but I did
NOT verify whether existing pages use it. ⚠

**Options for Phase 2:**

- **A. Server-Sent Events** (`text/event-stream`). FastAPI supports
  this via `StreamingResponse` with an async generator. Browser-side
  is one-line `new EventSource(...)`. No new dependency.
- **B. htmx polling.** htmx is already loaded; `hx-trigger="every 1s"`
  on a status div polls a `/status` JSON endpoint. Simpler model,
  more requests, slightly less "live".
- **C. WebSockets.** FastAPI supports them but it's a heavier
  abstraction for one-way progress notifications.

**Recommended default:** **A (SSE)**. It's the lighter pattern for
one-way server-push, doesn't add a dependency, and the `ApplyReport`
shape proposed in Section 3 lends itself directly to a step-per-event
stream. If kev's exploration of templates surfaces htmx-polling
already in use somewhere, **B** is a fine alternative — but I didn't
verify that during this scout. ⚠

### Q5. Persistent mode scope (Phase 3)

The prompt asserts: "Phase 3 is Lynceus-config-only — Kismet bootstrap
stays in Phase 2 run-once."

**Verification against the seams from Section 3:** Most config-only
surfaces map cleanly:

- ntfy URL/topic — pure config field. ✅
- Capture toggles (probe_ssids, ble_friendly_names) — pure config field. ✅
- Severity overrides editing — file write to `<config_dir>/severity_overrides.yaml`. ✅
- Rules engine toggles (enable/disable per rule_type) — file write to
  rules.yaml. ✅
- min_rssi, kismet_url, kismet_api_key edit — pure config fields. ✅

**One friction point worth flagging:** under `--system` the daemon
user has **read-only** access to `/etc/lynceus/*` (mode 0640 root:lynceus).
Persistent admin write needs either group-write on the config files
or a privileged helper. (Detailed in Section 2's systemd subsection.)
**Recommended default:** group-write (0660 root:lynceus). Documented
trade-off: a compromised daemon can rewrite its own config; mitigated
by the daemon already being able to read every secret in the config,
so write doesn't expand its existing capabilities materially.

Persistent mode scope **maps cleanly** to Phase 1's seams. No re-scope
needed.

---

## Section 5 — Phase 1 touch breakdown

File-level granularity. Each touch is one feat→test→docs trio per the
project's atomic-commit rule.

### Touch 1: Introduce `ApplyReport` + `ProgressSink`

- **Files touched (new):**
  - `src/lynceus/setup/__init__.py`
  - `src/lynceus/setup/models.py`
- **What changes:** Define `ApplyStep`, `ApplyReport`, `ProgressSink`
  (Protocol with one `record(step: ApplyStep) -> None` method).
  No callers yet — this is the type vocabulary the next touches
  consume.
- **Test surface:** Tiny — frozen-dataclass equality, overall-status
  derivation from a list of steps (~5 tests).
- **Risks/unknowns:** Naming. `setup` collides with the existing
  `cli/setup.py` mental model. Confirm in Q1-of-Section-4 review.
  Alternative: `src/lynceus/apply.py` flat module if kev prefers.

### Touch 2: Extract `apply_config` + pure side-effect helpers

- **Files touched:**
  - **New:** `src/lynceus/setup/core.py`
  - **Modified:** `src/lynceus/cli/setup.py` (re-import the moved
    helpers; `run_wizard` body shrinks by ≈300 lines)
- **What changes:** Move `_atomic_write`, `_apply_system_perms_to_file`,
  `_apply_system_perms_to_dir`, `render_config_yaml`, `write_config`,
  `scaffold_severity_overrides`, `import_bundled_watchlist`,
  `count_watchlist_by_pattern_type`, `render_rules_yaml`,
  `append_rules_path_to_config` into `setup/core.py`. Define
  `apply_config(config, scope, target_path, severity_overrides_path,
  enabled_rule_types, run_bundled_import, progress)` that runs the
  whole side-effect chain and returns an `ApplyReport`. `cli/setup.py`
  imports them back so existing tests' import paths keep working
  (or we update them — call out below).
- **Test surface:** All of `tests/test_setup_wizard.py`'s 200 tests
  must keep passing. New tests for `apply_config` itself: feed a
  fully-populated `Config` + scope, assert the report (ok/skipped/
  failed status per step) and the on-disk artefacts. Rough count:
  10-20 new tests covering the report-shape contract.
- **Risks/unknowns:**
  - **Test imports.** Many of the 200 existing tests likely import
    `from lynceus.cli.setup import _atomic_write` (etc.) — moving the
    helpers will require re-pointing those imports. The F6 should
    decide between (a) re-import-back from `cli/setup.py` to keep
    existing tests working, (b) update tests to import from
    `setup.core`. Recommend (a) for Phase 1 to keep the diff
    reviewable.
  - **The system-mode chown sequence is order-sensitive.** The
    current wizard chowns `data_dir` and `log_dir` AFTER `mkdir` but
    BEFORE the bundled import (so sqlite writes as lynceus, not root),
    then post-import chowns the `.db*` files. `apply_config` must
    preserve this exact order — pin it with a regression test that
    asserts step ordering against `ApplyReport.steps`.

### Touch 3: Wire CLI frontend to `apply_config`

- **Files touched:**
  - **Modified:** `src/lynceus/cli/setup.py` only.
- **What changes:** `run_wizard` no longer writes files directly. It
  builds a `Config` from prompts, calls
  `apply_config(config, scope, target, sev_path, enabled_rule_types,
  run_bundled_import=True, progress=CLIProgressSink(stdout))`, and
  renders the report. The completion-marker block stays in
  `cli/setup.py` — the marker is a CLI-output artefact, not part of
  the core.
- **Test surface:** Existing 200 tests should still pass byte-for-byte
  on stdout (or with minimal whitelisted diffs). A new test pins that
  the CLI frontend prints one line per `ApplyStep` and surfaces the
  completion marker after the report renders. ≈5 new tests.
- **Risks/unknowns:**
  - **stdout-string regression.** The wizard's printed line shapes
    are pinned by many tests (greps for specific summary strings).
    The CLI sink must reproduce them. Recommend: keep the exact
    line text in `cli/setup.py`, derive only the timing from
    `ApplyReport.steps`. The sink translates one step → one line.
  - **Severity-overrides path.** Today's behavior is "scaffold the
    file but do NOT persist `severity_overrides_path` into
    lynceus.yaml" ([config.py:68–76](src/lynceus/config.py:68)).
    Phase 1 preserves this; the `Config` passed to `apply_config`
    must NOT set `severity_overrides_path` even though the wizard
    knows the value.

### Touch 4: Extract prompt helpers into a separable module

- **Files touched:**
  - **New:** `src/lynceus/setup/prompts.py`
  - **Modified:** `src/lynceus/cli/setup.py` (re-import)
- **What changes:** Move `prompt_default`, `prompt_secret`,
  `prompt_url`, `prompt_yes_no`, `prompt_numbered_choice`,
  `_print_section`, `_print_context`, `_URLPromptAborted`,
  `_is_valid_url`, `_looks_like_ntfy_topic`, `_looks_like_path` into
  `setup/prompts.py`. These are the building blocks the CLI frontend
  uses today and that Phase 2's web frontend will NOT use (it'll have
  its own form-validation layer). Putting them in their own module
  draws a bright line between "CLI input" and "config application".
- **Test surface:** Existing prompt-helper tests should be re-pointed
  (or, with a re-import shim, kept). No new tests required.
- **Risks/unknowns:** This touch is optional for Phase 1's *behavior*
  goal — it's a hygiene step. Recommend including it to make Phase 2
  smaller. If F6 time gets tight, defer to Phase 2 and let Phase 2
  do the split.

### Touch 5: CHANGELOG + README documentation

- **Files touched:**
  - **Modified:** `CHANGELOG.md`, `README.md` (no version bump yet —
    Phase 1 is internal refactor only).
- **What changes:** Add an internal-refactor entry to CHANGELOG (no
  user-facing behavior change). README's `lynceus-setup` section
  stays — refactor is invisible.
- **Test surface:** None.
- **Risks/unknowns:** None. Standard atomic-commit docs trio.

### Touches summary

Five touches → expected 4 feat commits + 1 docs commit + per-touch
regression tests in between. Roughly matches the "3-6 touches"
expectation in the brief. The seam analysis surfaced cleaner
separation than worst-case, which is why Touch 4 (prompt extraction)
is small enough to consider optional.

---

## Section 6 — Cross-cutting notes

### Already-extracted shapes worth crediting

- ✅ `Config` Pydantic model at
  [src/lynceus/config.py:55](src/lynceus/config.py:55) covers every
  field the wizard writes. Phase 1 does NOT need to invent a parallel
  model.
- ✅ `paths.default_*` helpers at
  [src/lynceus/paths.py](src/lynceus/paths.py) — already the single
  source of truth for config/data/log directory resolution. The
  wizard's `user_config_dir` / `system_config_dir` at
  [setup.py:349–377](src/lynceus/cli/setup.py:349) duplicate a
  subset of `paths.default_config_dir` but with subtly different
  Windows fallbacks. Phase 1 should pick one (recommend
  `paths.default_config_dir`) and remove the duplicate — but only if
  the test suite confirms equivalence on every platform branch.
- ✅ `import_bundled_watchlist` already returns `(ok, msg)` ✅
  ([setup.py:1003](src/lynceus/cli/setup.py:1003)) — almost
  `ApplyStep` shape already. Easy lift.
- ✅ `render_rules_yaml(enabled_rule_types: set[str])` ✅
  ([setup.py:1196](src/lynceus/cli/setup.py:1196)) is already a pure
  function. Lift as-is.

### Fragile areas for the Phase 1 F6 to be careful about

- ⚠ **`run_wizard`'s system-mode permissions sequence**
  ([setup.py:1746–1878](src/lynceus/cli/setup.py:1746)) is dense
  with order-sensitive steps: write config → chmod → scaffold
  overrides → chmod → mkdir data/log → chown → bundled import → chown
  db files → rules.yaml → chmod → append rules_path → final summary.
  The inline comments call out which step closes which rc1 bug (S1,
  S2, Bug 6). The refactor MUST preserve this order; pin it with a
  regression test that asserts step ordering against
  `ApplyReport.steps`. Don't reorder for "code clarity" — the
  ordering IS the fix.
- ⚠ **Atomic write race.** `_atomic_write` ✅
  ([setup.py:72](src/lynceus/cli/setup.py:72)) uses
  `os.open(..., O_WRONLY|O_CREAT|O_TRUNC, mode)` to set mode at fd
  creation, closing the S2 race window. The refactor must preserve
  this; a fall-back to `path.write_text` + `path.chmod` would
  silently re-introduce the race. Already a pinned regression — keep
  it pinned.
- ⚠ **The `append_rules_path_to_config` skip-when-already-present
  check** ([setup.py:1869](src/lynceus/cli/setup.py:1869)) is a
  silent idempotency guard. If the refactor changes when
  `apply_config` writes the initial config (now including
  `rules_path` if known), this skip check becomes vestigial. Decide
  during F6: drop it, or keep as belt-and-suspenders.
- ⚠ **The `run_enable_alerting_flow` writes rules.yaml via
  `_atomic_write` but uses a DIFFERENT default mode** — review
  [setup.py:1341](src/lynceus/cli/setup.py:1341) vs
  [setup.py:72](src/lynceus/cli/setup.py:72): `_atomic_write` defaults
  to `mode=0o600` and rules.yaml doesn't override. Under `--system`
  the explicit `_apply_system_perms_to_file(rules_target)` then resets
  to 0640 root:lynceus. The refactor must preserve both halves.
- ⚠ **Sudo-without-system refusal** at
  [setup.py:1980](src/lynceus/cli/setup.py:1980) is a `main()`-level
  gate, not a `run_wizard`-level gate. The CLI frontend keeps this;
  `apply_config` itself should NOT carry the sudo policy
  (Phase 2's web wizard will have a different posture).

### Regression baseline

- ✅ **`tests/test_setup_wizard.py` has 200 tests** (verified via
  `grep -c '^def test_' tests/test_setup_wizard.py`). Phase 1 must
  preserve every one of them. Tests that get split across new modules
  (`setup/core.py`, `setup/prompts.py`) should land in proportional
  new files (e.g., `tests/test_setup_core.py`,
  `tests/test_setup_prompts.py`) so the grouping in the test tree
  mirrors the package layout.

### What I did NOT inspect (admit to it)

- ⚠ `src/lynceus/kismet.py` — Q1 of Section 4 turns on whether
  `KismetClient` can drive a password-set / key-create API; I did
  not verify either direction by reading this file. Phase 2 will need
  to revisit.
- ⚠ Templates in `src/lynceus/webui/templates/` — I confirmed file
  names exist but read none of them. Whether htmx polling is already
  idiomatic in the existing UI templates is unverified; Q4 of
  Section 4 hinges on this.
- ⚠ `src/lynceus/cli/bootstrap_kismet.py` beyond
  [the `run()` opening](src/lynceus/cli/bootstrap_kismet.py:1116). The
  recommendation in Section 3 ("don't touch bootstrap-kismet's
  surface in Phase 1") doesn't require deeper inspection, but if
  Phase 2 wants to integrate bootstrap into the web wizard it will.

---

## Scout result

Phase 1 of the install-flow webui arc is a tractable 3-5 touch
refactor. The "ask" and "write" code in `lynceus-setup` are
structurally already separable; the work is mostly extracting +
threading a structured `ApplyReport` through the existing side-effect
helpers and adopting `Config` as the validated input model. The
existing UI's framework (FastAPI), CSRF middleware, pagination helper,
and Jinja filter conventions are all reusable for Phase 2/3. No
in-progress half-extraction was found in the tree — the v0.6.3 surface
is the starting state.

Five open questions for kev (Section 4) shape Phase 2/3 but do NOT
block Phase 1. Each carries a recommended default.

This document is the scout output for kev's review. No Phase 1 F6
should begin until the recommendations above are confirmed or revised.
