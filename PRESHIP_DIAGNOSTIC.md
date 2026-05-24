# Pre-push v0.7.0 diagnostic findings

Second adversarial pass before pushing v0.7.0. Anchored at HEAD
(80 commits ahead of `origin/main`; includes Phase 1, Phase 2a,
Phase 2b, batch 1 + batch 2 fixes, and the smoke-driven UX polish
pass). New ground vs. [PHASE_2_DIAGNOSTIC.md](PHASE_2_DIAGNOSTIC.md):

* the batch 1 + batch 2 fix code itself (net-new, never read
  adversarially)
* Phase 1 `apply_config` core (passed tests but never read
  adversarially)
* the CLI wizard `run_wizard` flow (passed tests but never read
  adversarially)
* cross-platform behavior, error-message quality, real-data edges

Out of scope (covered by [PHASE_2_DIAGNOSTIC.md](PHASE_2_DIAGNOSTIC.md)):
concurrency / SSE lifecycle / teardown / re-apply / invalid-state /
resource-cleanup on the unchanged-by-fixes surface.

Verification convention: ✅ verified in code; ⚠ inferred but not
directly executed.

## Executive summary

| Severity | Count |
| --- | --- |
| critical | 0 |
| serious | 2 |
| minor | 8 |
| note | 23 |

(Plus 2 cross-reference entries that point at findings from
[PHASE_2_DIAGNOSTIC.md](PHASE_2_DIAGNOSTIC.md) — 6.1 → P2.7.5,
4.4 → P2.5.2.)

**Pre-push read:** the diagnostic-driven fix batches landed cleanly
— no critical regressions introduced by the batch 1 or batch 2 code
itself. Two serious findings remain reachable by an operator under
real conditions:

* **Finding 1.1** — `apply_post` resets `apply_stream_consumed` on
  re-run but does NOT reset `apply_stream_active`; the prior run's
  generator can strand the flag in narrow edge cases, locking out
  every future SSE connection on the session with 409.
* **Finding 1.2** — the hand-edit overwrite warning added by the
  batch 1 fix (Finding P2.9.2) lives only on the apply-complete
  Re-run section. The FIRST-apply path (review page) gets no
  warning, even though `--reconfigure` on a hand-edited
  `lynceus.yaml` will silently clobber operator changes there too.

The remaining 8 minor findings are mostly secondary papercuts:
plain-text 409 surfaces, an event-loop blocker in the synchronous
probe handlers, the Done button missing the same disable-on-click
that batch 2 added to Apply / Re-run, and a UX dead-end on the
Kismet-sources step when probe-and-no-sources is hit. The notes
record verifications and intentional design choices.

Also recorded as a workspace state observation, not a finding:
`scripts/smoke_wizard.py` is untracked in the working tree
alongside the expected `.claude/launch.json`. It's a local smoke
helper, not part of the v0.7.0 ship; surface to the user before
the bundle ship-it so they can decide whether to track it, leave
it, or stash it.

---

## Section 1: Batch 1 fix code audit

### Finding 1.1: `apply_post` resets `apply_stream_consumed` on re-run but not `apply_stream_active`; stranded flag locks out every future SSE consumer

**Severity:** serious
**Location:** [src/lynceus/setup/web/review.py:601-608](src/lynceus/setup/web/review.py:601), [src/lynceus/setup/web/review.py:735](src/lynceus/setup/web/review.py:735), [src/lynceus/setup/web/review.py:768-774](src/lynceus/setup/web/review.py:768)
**Description:** The Finding P2.1.4 fix introduced `apply_stream_active`,
set synchronously in the handler BEFORE the `StreamingResponse` is
returned (L735), cleared in the generator's `finally` (L774). The
fix's correctness story relies on the generator's `finally` always
firing. It does — IF the generator body runs at all.

If Starlette never iterates the generator (e.g., the client
disconnects between the handler's return at L789 and Starlette's
first `await send(...)` at the start of `StreamingResponse.__call__`),
the async generator is garbage-collected unstarted. Python's
asyncgen finalizer discards an unstarted generator without running
the body — so the `try` is never entered and the `finally` never
fires. `apply_stream_active` stays stuck `True` for the life of the
wizard process.

`apply_post` (L601-608) resets `apply_stream_consumed = False` but
NOT `apply_stream_active`. So a re-apply that lands after the
stranding sees `apply_stream_active == True` and 409s every SSE
connection on the new run. The operator clicks Re-run, sees the
state-machine advance to "running", but `/apply-progress` opens an
`EventSource` that immediately fires `onerror` (409 closes the
EventSource per the WHATWG spec) — they're left on "Connecting…"
with the error message "Lost the progress stream", with no path
back besides Cancel + start over.

The window for the unstarted-generator scenario is narrow (sub-
millisecond on loopback). But it's reachable: the operator hits
Stop in the browser during the SSE handshake, or a misbehaving
extension opens-and-closes the request, and the wizard is wedged
until restart.
**Repro:** ⚠ hard to repro deterministically; easiest to simulate
by directly setting `session.apply_stream_active = True` then
triggering re-apply and observing 409 on `/apply-stream`.
**Fix shape:** reset `apply_stream_active = False` in `apply_post`
alongside the existing `apply_stream_consumed = False` reset at
L607. Single-line fix. Also worth considering: set the flag inside
the generator's first try-block line (with a TOCTOU-acceptable
narrow window) rather than synchronously in the handler, so the
flag's lifecycle matches the generator's body.

**Fix:** Landed in commit `be82312`.

### Finding 1.2: Hand-edit overwrite warning only on Re-run page, not on first Apply

**Severity:** serious
**Location:** [src/lynceus/setup/web/templates/apply_complete.html:78-84](src/lynceus/setup/web/templates/apply_complete.html:78), [src/lynceus/setup/web/templates/review.html:84-100](src/lynceus/setup/web/templates/review.html:84)
**Description:** Finding P2.9.2's batch 1 fix (commit `ef73949`) added
a "hand-edits will be overwritten" warning to the Re-run section of
`apply_complete.html`. The same risk applies to the FIRST apply
when the operator is running with `--reconfigure` over a previously-
applied (and possibly hand-edited) `lynceus.yaml` — but the review
page's Apply article (L84-100 of `review.html`) has no equivalent
warning. The copy on review.html names every file the apply touches
("writes lynceus.yaml, scaffolds severity_overrides.yaml…") and
calls the chain "idempotent", which is true for the wizard's own
writes but misleading if operator edits sit on top.

The realistic operator path: complete a wizard run cleanly, hand-
edit `lynceus.yaml` to set `ui_allow_remote: true` (a field the
wizard doesn't expose), later re-run `lynceus-setup --reconfigure
--web` to tweak one Kismet source, walk through to the review page,
click Apply — and the `ui_allow_remote: true` line is silently
gone. The Re-run-after-failure warning never fires here because
the first apply succeeded.
**Repro:** apply once cleanly; add an unrelated YAML line to
`lynceus.yaml`; re-run wizard with `--reconfigure`; observe review
page has no warning; Apply clobbers the addition.
**Fix shape:** add a parallel `<p class="wizard-error">` warning to
the Apply article in `review.html`, gated on `reconfigure==True`
(`request.app.state.reconfigure` is on `app.state` per
[app.py:128](src/lynceus/setup/web/app.py:128)). Or unconditional
— a first-time user who pre-edited the file by hand hits the same
risk. Match the wording of the Re-run warning for consistency.

**Fix:** Landed in commit `af95d61`.

### Finding 1.3: `/done` 409 mid-apply returns plain text, not a rendered HTML page

**Severity:** minor
**Location:** [src/lynceus/setup/web/review.py:497-502](src/lynceus/setup/web/review.py:497)
**Description:** The Finding P2.3.1 fix correctly refuses Done with
HTTP 409 when an apply is in flight. The response is constructed as
`Response("apply still in progress; wait for the completion page or
for the post-apply grace timer to expire", status_code=409)` —
default content-type `text/plain`. The operator clicks Done in
their browser; the browser navigates to the 409 response and
renders it as a plain unstyled page with the bare text. The
realistic operator hits this only via the cited two-tabs race
(stale completion page in another tab); the page-aware operator
won't see it. But for the operator who DOES see it, they get an
unstyled error with no obvious path forward.
**Repro:** start an apply in tab A; open a stale `/apply-complete`
in tab B; click Done in tab B → unstyled "apply still in progress
..." text.
**Fix shape:** render a `done_busy.html` template (or reuse
`apply_progress.html` with a top banner) so the operator sees a
styled page with a link to `/apply-progress` and a "wait for
completion" hint. Same shape as the other state-aware redirects
already in `apply_progress_get` / `apply_complete_get`.

**Fix:** Landed in commit `e662ea0`.

### Finding 1.4: Done button has no disable-on-click; double-click strands the prior shutdown_task without a strong ref

**Severity:** minor
**Location:** [src/lynceus/setup/web/templates/apply_complete.html:91-94](src/lynceus/setup/web/templates/apply_complete.html:91), [src/lynceus/setup/web/review.py:517-519](src/lynceus/setup/web/review.py:517)
**Description:** Finding P2.4.3's batch 2 fix (commit `7f93e6f`)
added `onsubmit="this.querySelector('button[type=submit]').disabled
= true;"` to the Apply form (review.html) and the Re-run form
(apply_complete.html). The DONE form on the same apply_complete.html
page (L91-94) was NOT updated — it submits unprotected.

On double-click, two `/done` POSTs land microseconds apart. Both
pass the `apply_state == "running"` 409 guard (state is terminal
on the completion page). Both proceed to L517-519 which assigns
`session.shutdown_task = asyncio.create_task(...)`. The second
assignment OVERWRITES the first task ref. The first task is no
longer held by the session — it's held only by the asyncio loop's
weak reference, which is the exact GC-vulnerability scenario
Finding P2.3.4 was meant to close.

In practice both shutdown_tasks fire (the loop's weak ref is
strong enough to survive 500ms in most cases), and
`server.should_exit = True` is idempotent per Finding P2.3.3, so
the operator sees the server exit. But the fix design relied on
session.shutdown_task being a stable strong ref; the
double-click breaks that invariant.
**Repro:** in dev tools, set a breakpoint after the first Done
POST's response; manually fire a second POST; observe both
shutdown_tasks created, first one orphaned to weak-ref-only.
**Fix shape:** add the same `onsubmit` disable handler to the
Done form. One template attribute, matches the existing pattern
on the Apply and Re-run forms.

**Fix:** Landed in commit `0afcdfb`.

### Finding 1.5: Grace timer race I worried about — does NOT exist; recording for the record

**Severity:** note
**Location:** [src/lynceus/setup/web/review.py:404-416](src/lynceus/setup/web/review.py:404)
**Description:** I probed whether the Finding P2.4.1 reorder
(arm grace timer before state flip) introduces a new race where
the SSE generator could see a sentinel + terminal-state in a
window that lets the JS navigate to `/apply-complete` → redirect
to `/apply-progress` → new SSE → hang on empty queue.

Traced through the event loop: `_run_apply_task`'s finally body
runs A (`queue.put_nowait(None)`) → B (`_schedule_apply_grace_
shutdown` which is sync) → C (`session.apply_state = new_state`)
with NO `await` between. The whole block is event-loop-atomic.
The SSE generator's `await queue.get()` doesn't resume until the
next loop turn, by which point state has been flipped to
terminal. No race window exists. ✅

### Finding 1.6: `/cancel` after a clean apply destroys the operator's view of the just-completed apply report

**Severity:** minor (pre-existing, not Phase 2 regression)
**Location:** [src/lynceus/setup/web/app.py:197-217](src/lynceus/setup/web/app.py:197)
**Description:** The Finding P2.1.6 fix correctly gates `/cancel`
on `apply_state == "running"` (redirect to `/apply-progress`).
But the gate does NOT also cover the `completed` / `failed`
states. If the operator successfully applies, lands on
`/apply-complete`, then clicks the Cancel link in the page footer
of some OTHER page they navigate to (the Cancel link is in
`_base.html` and renders on every page that doesn't override the
footer block), `session_store.clear()` runs, the session is
destroyed, and the operator's view of `apply_report` (the per-
step transcript with success/failure markers) is gone. The next
`/apply-complete` GET hits a fresh idle session and redirects to
`/review`. The config was applied to disk; only the in-memory
report is lost.

Pre-existing behavior, not Phase 2 regression. Cancel is a "start
over" gesture, but its only consequence in the terminal state is
the operator losing their report view. Mild UX glitch.
**Fix shape:** consider also gating `/cancel` on terminal states
to render a "wizard already complete — review your transcript at
/apply-complete or close the tab" page rather than clearing. Or
hide the Cancel link from the footer on every page once
`apply_state != "idle"`. Defer per the locked decision to keep
the batch 1 fix minimum-viable.

### Finding 1.7: 410 / 404 / 409 SSE responses are JSON; the JS doesn't display the error body

**Severity:** note
**Location:** [src/lynceus/setup/web/review.py:700-728](src/lynceus/setup/web/review.py:700), [src/lynceus/setup/web/templates/apply_progress.html:62-68](src/lynceus/setup/web/templates/apply_progress.html:62)
**Description:** The Finding P2.5.1 / P2.2.3 / P2.1.4 fixes return
JSON error bodies on the non-stream cases ({"error": "..."}). The
browser's EventSource doesn't expose the body of a non-2xx
response to the JS — only `onerror` fires, and the existing JS
shows a generic "Lost the progress stream" message regardless of
which of the three (404 / 410 / 409) actually fired. So the JSON
body the server crafts is invisible to the operator; they can
distinguish only via dev tools network tab.

Not a bug — the JSON body is useful for cURL / scripts hitting
the endpoint directly, and the generic onerror message is fine
for the browser flow. Recording so a future reader doesn't think
the JSON body is operator-facing.

---

## Section 2: Batch 2 fix code audit

### Finding 2.1: SSE generator `event: error` is silently dropped by the JS

**Severity:** minor
**Location:** [src/lynceus/setup/web/review.py:753-766](src/lynceus/setup/web/review.py:753), [src/lynceus/setup/web/templates/apply_progress.html:36-68](src/lynceus/setup/web/templates/apply_progress.html:36)
**Description:** Finding P2.2.5's batch 2 fix (commit `74a0be3`)
wraps `json.dumps + yield` in a try/except so a future caller
enqueuing an unserializable item produces `event: error` +
`event: end` on the wire instead of dying mid-stream. The
client-side half of this design is missing: the JS has
`es.onmessage` (default message events), `es.addEventListener
("end", ...)`, and `es.onerror` (transport-level), but NO
`es.addEventListener("error", ...)` for the named-event SSE
`event: error`.

Per the SSE spec, named events without a registered listener are
silently dropped. The closing `event: end` still fires correctly
and the JS navigates to `/apply-complete`, where the operator
sees the partial transcript (no record of the serialization
failure). The actual error (json.dumps exception) is logged
server-side via `logger.exception` but doesn't reach the
operator.

The trigger is "future caller bypasses `_json_safe`" — today no
caller does. So the path is unreachable from production code; the
fix is defense-in-depth. Recording the wire/UI mismatch in case
the path becomes reachable.
**Fix shape:** add `es.addEventListener("error", function(evt) {
...show errorMsg with evt.data... });` to the JS. Or treat the
defensive wire-side fix as enough and document that operators
must consult `journalctl` (or stderr) on a wizard
serialization failure.

### Finding 2.2: `failsafe state-flip` finally body — if synthesize raises, sentinel and grace-arm never land

**Severity:** note
**Location:** [src/lynceus/setup/web/review.py:386-416](src/lynceus/setup/web/review.py:386)
**Description:** Finding P2.7.2's batch 2 fix (commit `13514cd`)
adds a finally block that synthesizes a `failed` ApplyStep when
the task was cancelled mid-`to_thread`. The synthesize uses
`ApplyStep(...)` construction and `ApplyReport(steps=(...))` —
both frozen dataclasses with no validation logic, so construction
cannot fail in practice. ✅

But if any line in the finally before `queue.put_nowait(None)`
(L404) were to raise — e.g., `session.apply_report = ApplyReport
(...)` if `session` got a property descriptor that raised, or if
`tuple(sink.records)` raised on a mutated records list — the
sentinel would never post and SSE consumers would block forever.
The realistic failure mode is zero today (session is a plain
dataclass, sink.records is a list owned by the worker thread
that has terminated by the time we read it). Recording for the
record.

### Finding 2.3: `apply_lock` binds to loop on first acquire — correct for production, footgun for cross-loop reuse

**Severity:** note
**Location:** [src/lynceus/setup/web/session.py:81](src/lynceus/setup/web/session.py:81)
**Description:** Finding P2.1.1's batch 2 fix (commit `f288728`)
adds `apply_lock: asyncio.Lock = field(default_factory=asyncio.
Lock)` to `WizardSession`. The dataclass `default_factory` calls
`asyncio.Lock()` at WizardSession construction time. In Python
3.10+, asyncio.Lock construction does NOT bind to a loop; binding
happens on first `acquire()`. For production (one wizard run, one
uvicorn loop) this is correct ✅.

For tests using `pytest-asyncio` (which constructs a fresh loop
per test): the SessionStore lazily creates sessions, so the lock
binds to the per-test loop on first acquire within that test —
safe. The footgun is if a future test or helper reuses a session
constructed under one loop with handlers running on another loop
(e.g., parameterized async tests sharing a fixture). Today no
test does this; recording so a future test author doesn't
struggle with "RuntimeError: this Lock is bound to a different
loop". Not a finding against current code.

### Finding 2.4: Apply / Re-run disable-on-click — failure-mode trapdoor on 403 or validation 303

**Severity:** note
**Location:** [src/lynceus/setup/web/templates/review.html:101-108](src/lynceus/setup/web/templates/review.html:101), [src/lynceus/setup/web/templates/apply_complete.html:85-89](src/lynceus/setup/web/templates/apply_complete.html:85)
**Description:** Finding P2.4.3's batch 2 fix disables the submit
button onsubmit. If the form submission fails (CSRF 403, or the
303 redirect to `/review` on ValidationError), the browser
navigates to the response page. For the CSRF 403 case the
operator sees the 403 page and clicks back — the cached form has
button disabled, but a refresh (cmd-R / F5) reloads it enabled.
For the 303-to-review case the response IS a new page so the
button is fresh.

So the failure-mode trapdoor exists only on the CSRF 403 path,
and only if the operator uses back-button-without-refresh.
Acceptable UX papercut, documented at design time. Recording.

---

## Section 3: Phase 1 `apply_config` core adversarial read

### Finding 3.1: OSError-raising steps surface as a generic `apply_config` failed step, not as the specific step that raised

**Severity:** note
**Location:** [src/lynceus/setup/core.py:805-1008](src/lynceus/setup/core.py:805), [src/lynceus/setup/web/review.py:352-373](src/lynceus/setup/web/review.py:352)
**Description:** `apply_config` has no per-step try/except — each
step's helper (`_atomic_write`, `_apply_system_perms_to_file`,
`scaffold_severity_overrides`, etc.) can raise `OSError` (disk
full, permission denied, path-too-long), and the exception
propagates out of `apply_config` without emitting a per-step
`status="failed"` ApplyStep. The wizard's caller catches
`Exception` at [review.py:352](src/lynceus/setup/web/review.py:352)
and synthesizes a SINGLE `ApplyStep(name="apply_config", ...)`
with the traceback.

For per-step failures the core DOES handle (e.g.,
`import_bundled_watchlist` returning `(False, msg)` with explicit
failure path), the wizard sees a named failed step with the
specific error.

So operator-visibility is uneven: a `PermissionError` on
`_atomic_write` surfaces as "apply_config: PermissionError [Errno
13]" with a traceback — actionable but generic; a failed
bundled-import surfaces as a named ❌ `import_bundled_watchlist
— import failed: ...` step which is much clearer.

The transcript IS useful — it shows every step that succeeded
before the failure point, so the operator knows the failure was
after the last successful step. Recording rather than calling
for a fix; the inhomogeneity is a known consequence of the
"raise vs return" design split.

### Finding 3.2: `_apply_system_perms_to_file` failure on missing `lynceus` group leaves an 0600 root:root config behind

**Severity:** note
**Location:** [src/lynceus/setup/core.py:165-179](src/lynceus/setup/core.py:165), [src/lynceus/setup/core.py:805-822](src/lynceus/setup/core.py:805)
**Description:** Apply order under `--system`: `write_config` →
`_atomic_write` (creates the file 0600 root:root via os.open
mode) → `_apply_system_perms_to_file` (chowns to root:lynceus
0640). If the chown raises `SetupError("Group 'lynceus' does not
exist")`, the file already exists on disk with the
atomic-write default mode. apply_config propagates the
SetupError to the caller without an emit.

If the operator fixes the missing group and re-runs, `write_
config` overwrites and chown succeeds. If they start the daemon
between attempts, it fails to read the 0600 root:root config —
but the wizard's error message explicitly says "Run `sudo
./install.sh --system` first", which the operator does, which
creates the group, then they re-run. So the recovery path is
clean. Recording the file-residue behavior so an operator running
strace doesn't think the wizard corrupted state.

### Finding 3.3: `lynceus-import-argus` stdout summary parser is fragile to capitalization changes

**Severity:** note
**Location:** [src/lynceus/setup/core.py:539-543](src/lynceus/setup/core.py:539)
**Description:** The parser at L539 does
`next((line for line in stdout.splitlines() if line.lstrip().
startswith("imported")), "imported successfully")` — case-
sensitive `startswith("imported")`. If a future
`lynceus-import-argus` change emits "Imported 1,234 records" with
a capital I, the filter misses and the wizard reports "imported
successfully" as a generic summary instead of the actual row
count. Behavior is correct (the import succeeded), just less
informative. Recording.

### Finding 3.4: `enabled_rule_types` containing a typo silently drops with no warning

**Severity:** note
**Location:** [src/lynceus/setup/core.py:652-699](src/lynceus/setup/core.py:652), [src/lynceus/setup/core.py:973-1006](src/lynceus/setup/core.py:973)
**Description:** `render_rules_yaml` iterates
`DELEGATION_RULES` and activates an entry only if its
`rule_type` is in `enabled_rule_types`. A `rule_type` in the
caller's set that doesn't exist in `DELEGATION_RULES` is
silently dropped: every DELEGATION_RULES entry renders
commented, no error fires, the operator's apply succeeds with
zero active rules and no clue why.

The web wizard's step 12 form only submits canonical names from
`DELEGATION_RULES`, so the path is unreachable from the wizard's
UI today. But the API is `set[str]` — a future caller (a test,
a script, a custom CLI invocation) passing typos has no
validation surface. Recording rather than calling for a fix; the
contract today is "caller's responsibility to pass canonical
names".

### Finding 3.5: Lazy-import proxies (`_frontend_*`) — propagate ImportError if `cli.setup` fails to load

**Severity:** note
**Location:** [src/lynceus/setup/core.py:60-111](src/lynceus/setup/core.py:60)
**Description:** The three `_frontend_*` proxies each do
`from lynceus.cli import setup as _frontend` lazily. By call time,
`cli.setup` is fully loaded in any production scenario (the user
invoked `lynceus-setup` which entered `cli.setup.main`). The
proxies hit `sys.modules` ✅.

The fragile case: a future test that imports `lynceus.setup.core`
in isolation and runs `apply_config` directly without going
through `cli.setup`. The first proxy call would trigger the lazy
import. If `cli.setup` raises at module load time (a broken
import in any of its transitive dependencies — `requests`,
`pydantic`, `yaml`), the proxy call raises ImportError. The
wizard would crash with `ModuleNotFoundError` or whatever the
underlying cause is. Same fragility for the partially-loaded
case (circular import mid-tear-down — extreme edge). Recording.

### Finding 3.6: `probe_kismet` / `probe_ntfy` / `probe_kismet_sources` run synchronously inside async handlers — block the event loop

**Severity:** minor
**Location:** [src/lynceus/setup/web/steps_kismet.py:226-229](src/lynceus/setup/web/steps_kismet.py:226), [src/lynceus/setup/web/steps_capture.py:208](src/lynceus/setup/web/steps_capture.py:208)
**Description:** `probe_kismet` uses `requests.get` (synchronous);
the wizard's `kismet_probe_get` handler awaits the result
directly — but `probe_kismet` doesn't yield, so the entire event
loop blocks for up to `PROBE_TIMEOUT_SECONDS` (5s) on every
probe. If the operator opens another tab during a slow probe,
that tab's request queues until the probe returns.

For a single-operator loopback wizard this is tolerable but
not great. Worst case: operator opens `/apply-progress` in a
second tab while step 3's Kismet probe is hanging — the
second tab's GET sits in the queue until the probe times out,
masking the live-stream UX the wizard otherwise gives. Same
shape for `probe_ntfy` (5s) and `probe_kismet_sources` (5s).
**Fix shape:** wrap each probe in `await asyncio.to_thread(...)`
so the event loop stays responsive during the network call. Same
pattern the apply-pipeline already uses for `apply_config`.

**Fix:** Landed in commit `8fe7812`.

### Finding 3.7: `count_watchlist_by_pattern_type` `.exists()` check could raise on a path with embedded null bytes

**Severity:** note
**Location:** [src/lynceus/setup/core.py:633](src/lynceus/setup/core.py:633)
**Description:** `Path(db_path).exists()` raises `ValueError`
on embedded null bytes ("embedded null byte" on Linux,
"OSError: [WinError 123]" on Windows). The function's `except
sqlite3.Error` doesn't catch ValueError, so the call site sees
an uncaught exception. Reachable only if the caller passes a
db_path with `\x00` embedded — not realistic for the wizard's
controlled inputs (`paths.default_db_path(scope)` never
contains nulls). Recording for the API-contract record.

---

## Section 4: CLI wizard flow adversarial read

### Finding 4.1: EOFError (Ctrl-D) and KeyboardInterrupt (Ctrl-C) during prompts surface as uncaught tracebacks

**Severity:** minor
**Location:** [src/lynceus/setup/prompts.py:36-58](src/lynceus/setup/prompts.py:36), [src/lynceus/cli/setup.py:678-1188](src/lynceus/cli/setup.py:678)
**Description:** `input()` and `getpass.getpass()` raise
`EOFError` on stdin close and `KeyboardInterrupt` on Ctrl-C.
Neither is caught anywhere in `prompt_default`, `prompt_secret`,
or `run_wizard`. The operator hitting Ctrl-C mid-wizard sees
Python's default unhandled-exception traceback to stderr instead
of "Wizard cancelled, no changes written" or similar friendly
message. Same for Ctrl-D (closes stdin, raises EOFError).

Pre-existing behavior, not a Phase 2 regression. Workflow
operators have learned to expect the traceback. Calling out so a
future "make Ctrl-C cleaner" pass knows where to add the try/
except. The web wizard isn't affected — its analog is "close
the browser tab" which is clean.
**Fix shape:** wrap the body of `run_wizard` in `try / except
(EOFError, KeyboardInterrupt): print("\\nWizard cancelled — no
changes written.", file=sys.stderr); return 130`. ~3 LOC.

**Fix:** Landed in commit `64a5652`.

### Finding 4.2: `--reconfigure` discards existing config silently; operator re-enters every field

**Severity:** note (intentional, but worth recording)
**Location:** [src/lynceus/cli/setup.py:209-215](src/lynceus/cli/setup.py:209)
**Description:** `preflight_existing` checks file existence and
short-circuits with an error unless `--reconfigure` is set. With
`--reconfigure`, the existing file is ignored — the wizard
prompts every field from scratch, then OVERWRITES the existing
file via `_atomic_write`. The operator changing one field
re-enters Kismet URL, key, sources, ntfy URL, topic, RSSI, etc.

Worse, the wizard doesn't pre-populate from the existing config:
defaults shown at each prompt are the wizard's defaults, not
the operator's existing values. If the operator hits Enter at
each prompt to "keep" their value, they reset to default.

Intentional v0.6.x design. Recording so a future "make
--reconfigure preserve answers" UX pass has the context.

### Finding 4.3: `sys.stdout.reconfigure()` in `main()` may fail under unusual stdout wrappers (some test runners, captured stdout)

**Severity:** note
**Location:** [src/lynceus/cli/setup.py:1265](src/lynceus/cli/setup.py:1265)
**Description:** `sys.stdout.reconfigure(encoding="utf-8",
errors="replace")` requires `sys.stdout` to be a `TextIOWrapper`
or similar object with `.reconfigure()`. If the operator
redirects to a StringIO-like wrapper (some custom test
harnesses, IDE consoles, certain Python embedding contexts), the
attribute access raises `AttributeError`.

Pytest's `capsys` and `capfd` use objects WITH `.reconfigure()`
(they wrap the real stdout file), so the test suite is unaffected.
Recording in case a future operator embeds the wizard's
`main()` in a non-standard runtime. The reconfigure call is the
only fix for the v0.6.3 Windows cp1252 crash, so removing it is
not an option. A defensive `try / except AttributeError: pass`
around the call would close the edge case at zero cost.

### Finding 4.4: `POST /done` with `apply_state == "idle"` shuts down the server having applied nothing

**Severity:** see Finding P2.5.2
**Location:** [src/lynceus/setup/web/review.py:497](src/lynceus/setup/web/review.py:497)
**Description:** Cross-reference to PHASE_2_DIAGNOSTIC.md Finding
5.2 — the batch 1 fix added the `running` gate but did NOT add
the `idle` gate. Recording to confirm the prior finding is still
live after batch 1.

### Finding 4.5: Path inputs accepted at prompt time can fail with cryptic OSError at apply time

**Severity:** minor
**Location:** [src/lynceus/setup/prompts.py:206-220](src/lynceus/setup/prompts.py:206), [src/lynceus/cli/setup.py:1010-1022](src/lynceus/cli/setup.py:1010), [src/lynceus/setup/web/steps_severity_rules.py:91-106](src/lynceus/setup/web/steps_severity_rules.py:91)
**Description:** `_looks_like_path` accepts any string with a
path separator or `.yaml` / `.yml` extension. No "can we
actually write here?" check at prompt time. If the operator
types `/dev/null/foo.yaml` (CLI) or pastes a similar invalid
path in step 11 (web), the wizard accepts it; the failure
surfaces at apply time as `OSError: [Errno 20] Not a directory:
'/dev/null/foo.yaml'` propagating out of `scaffold_severity_
overrides` → `_atomic_write`. The operator-visible surface in
the web wizard is the traceback in `apply_complete.html`'s
collapsible detail; in the CLI it's a stack trace to stderr.

Pre-existing in v0.6.x, not a Phase 2 regression. Defer; the
realistic operator hits a sensible default and the prompts'
heuristic catches the common typo cases.

---

## Section 5: Cross-platform Windows / Linux

### Finding 5.1: `_atomic_write` is NOT atomic on Windows (falls back to `write_text`)

**Severity:** note (pre-existing, Windows is not a production target)
**Location:** [src/lynceus/setup/core.py:149-154](src/lynceus/setup/core.py:149)
**Description:** On Windows, `_atomic_write` falls back to
`path.write_text(content, encoding="utf-8")` which is NOT
atomic — a concurrent reader can observe a partial file.
Pre-existing design choice: the S2 race that drove `_atomic_
write` was POSIX-specific (umask-derived mode bits between
`write_text` and `chmod`). Windows doesn't have that race
because Windows file ACLs don't depend on creation-time umask.
But the loss of atomicity on Windows means a wizard interrupted
mid-write leaves a truncated file. Recording.

### Finding 5.2: `subprocess.Popen(..., text=True)` uses platform-default encoding for stdout/stderr decoding

**Severity:** note (low-impact for current parser)
**Location:** [src/lynceus/setup/core.py:501-506](src/lynceus/setup/core.py:501)
**Description:** `text=True` to subprocess.Popen uses
`locale.getpreferredencoding(False)` to decode. On Linux this is
usually utf-8 ✅; on Windows it's typically cp1252. If
`lynceus-import-argus` emits non-ASCII to stdout (e.g., box-
drawing chars or unicode in record summaries), Windows could
mojibake the decoded output. The wizard's parser only looks for
the `"imported"` prefix and the last stderr line, so mojibake
doesn't affect correctness. Recording for the encoding-
correctness record.
**Fix shape:** pass `encoding="utf-8", errors="replace"` to
Popen to make decoding deterministic across platforms.

### Finding 5.3: `stderr` is NOT reconfigured to UTF-8 — logging unicode could crash on Windows cp1252 console

**Severity:** minor
**Location:** [src/lynceus/cli/setup.py:1265](src/lynceus/cli/setup.py:1265), [src/lynceus/setup/web/review.py:353](src/lynceus/setup/web/review.py:353)
**Description:** The v0.6.3 fix reconfigures `sys.stdout` to
utf-8 but does NOT do the same for `sys.stderr`. Wizard
`logger.exception` and `logger.warning` calls (which include the
apply failure traceback) emit to stderr. On a Windows console
with cp1252, a logger record containing non-ASCII (e.g., a
file path with unicode, a Pydantic error message with smart-
quotes) raises `UnicodeEncodeError` and the log message is
silently dropped — or worse, the logging handler crashes and
kills the wizard process.

The exception surfaces only when the operator hits the unhappy
path (apply_config raises, logger fires). Most apply runs don't
log to stderr at all (log level INFO doesn't emit per-step).
Recording as minor — same shape as the v0.6.3 stdout fix would
close it.
**Fix shape:** add `sys.stderr.reconfigure(encoding="utf-8",
errors="replace")` next to the existing stdout call in `main()`.

**Fix:** Landed in commit `9e46d85`.

### Finding 5.4: `is_writable_system_path` on Windows is permissive (`os.access(W_OK)` returns True for read-only files)

**Severity:** note (pre-existing, Windows not a production target)
**Location:** [src/lynceus/cli/setup.py:187-200](src/lynceus/cli/setup.py:187)
**Description:** Per Python docs, on Windows `os.access(W_OK)`
checks only the read-only attribute, not real ACLs. So a
non-admin user gets True for paths they cannot actually write
to. `preflight_scope` for `--system` on Windows trusts this
check and the wizard proceeds to a hard write failure at apply
time. Pre-existing v0.6.x behavior. `--system` is Linux-only
in practice. Recording.

---

## Section 6: Error-message quality and logging

### Finding 6.1: Wizard logs go to uvicorn's stderr only — no journald integration for backgrounded wizards

**Severity:** see Finding P2.7.5
**Location:** [src/lynceus/setup/web/server.py:81-83](src/lynceus/setup/web/server.py:81)
**Description:** Cross-reference to PHASE_2_DIAGNOSTIC.md Finding
7.5. The batch 1 and batch 2 fix passes did NOT address this; the
wizard process still emits via uvicorn's default logger to
stderr only. An operator running the wizard under `nohup`,
`systemd-run`, or a detached tmux pane gets no log capture in
journald. Recording to confirm the prior finding is still live
after both batches.

### Finding 6.2: Pydantic ValidationError surfaces are terse — operator sees the framework's default `msg` text

**Severity:** note
**Location:** [src/lynceus/setup/web/review.py:186-196](src/lynceus/setup/web/review.py:186)
**Description:** `_format_validation_errors` renders one row
per Pydantic error with `<code>{field}</code>: {msg}`. The
`msg` text is whatever Pydantic produces by default — e.g.,
"Value error, kismet_url must include scheme...". For
multi-field model validators (e.g., `_validate_ntfy_pair`'s
"ntfy_topic required when ntfy_url is set"), `loc` is empty
(model-level) so FIELD_STEP_INDEX returns None and no "edit
step X" link appears. The operator sees the error message but
no jump-back link.

Realistic? Yes — an operator who enters an ntfy URL then later
clears just the topic via the back button would hit
`_validate_ntfy_pair` with no step-link affordance. They'd
have to navigate via the in-page edit links rather than the
error row. Recording.

### Finding 6.3: Subprocess failure surfaces only the LAST line of stderr — multi-line tracebacks lose context

**Severity:** note
**Location:** [src/lynceus/setup/core.py:534-537](src/lynceus/setup/core.py:534)
**Description:** On non-zero `lynceus-import-argus` exit, the
parser does `detail = (stderr or stdout or f"exit code {rc}").
strip().splitlines(); reason = detail[-1] if detail else f"exit
code {rc}"` — last line only. If the underlying error is a
Python traceback (which can happen if the importer hits an
unexpected condition), the operator sees only the bottom line
(the exception class + message), not the file/line. The full
context is in the subprocess's stderr which is captured but
discarded after the last-line extract.

Operator-recoverable: re-run the import via `lynceus-import-
argus --input ...` outside the wizard and see the full
traceback. Recording.

### Finding 6.4: Setup token middleware returns opaque 403 on UnicodeDecodeError in query string

**Severity:** note
**Location:** [src/lynceus/setup/web/auth.py:56-59](src/lynceus/setup/web/auth.py:56)
**Description:** If a client sends a query string that isn't
valid latin-1 (which UTF-8 multi-byte sequences are not, in
some byte combinations), `parse_qs(qs.decode("latin-1"))` raises
`UnicodeDecodeError`, the except returns None token, and the
request gets a generic 403 "setup token required". The actual
cause (malformed query encoding) is invisible. Realistic
trigger zero — browsers URL-encode multi-byte cleanly.
Recording.

### Finding 6.5: Apply failure transcript per-step asymmetry

**Severity:** see Finding 3.1
**Location:** Same as Finding 3.1
**Description:** Cross-reference within this document — Finding
3.1 covered this. Recording so the S6-shaped reader doesn't
expect a separate entry.

---

## Section 7: Real-data edge cases

### Finding 7.1: Web wizard step 4 dead-ends silently when Kismet probe reachable but no Wi-Fi sources

**Severity:** minor
**Location:** [src/lynceus/setup/web/steps_kismet.py:304-337](src/lynceus/setup/web/steps_kismet.py:304), [src/lynceus/setup/web/templates/kismet_sources.html:19-26](src/lynceus/setup/web/templates/kismet_sources.html:19)
**Description:** The template at L19-26 of kismet_sources.html
renders an error block when `probed and not wifi_choices`
("Kismet has no Wi-Fi datasource configured"), but does NOT
render a wifi_interface fallback input. The "Next →" button is
still there at L79. The operator clicks Next; the POST handler
gets empty wifi_source AND empty wifi_interface, re-renders the
template with error "Pick a Wi-Fi source (or enter an interface
name)" — but the template still doesn't show any input, so the
operator can't actually fix the failure from this page. Their
only options are the Previous link (back to step 3) or the
Cancel link in the footer.

The CLI flow under the same condition (line 829-836 of
cli/setup.py) explicitly aborts with `print(...) ; return 1`. The
web flow leaves the operator on a dead-end page with no
explicit "click Cancel to exit and fix your Kismet config"
instruction.
**Repro:** start Kismet with no `source=` line; run wizard with
`--web`; complete steps 1-3; observe step 4 dead-end.
**Fix shape:** add a "Cancel wizard" button (similar to the
probe-failure page at step 3) and a clearer next-action message
("fix your Kismet sources config, restart Kismet, re-run this
wizard") on the no-wifi-sources branch.

**Fix:** Landed in commit `ffa142f`.

### Finding 7.2: Web wizard step 4 free-form text input lets operator complete with no real hardware

**Severity:** minor
**Location:** [src/lynceus/setup/web/steps_kismet.py:281-301](src/lynceus/setup/web/steps_kismet.py:281), [src/lynceus/setup/web/templates/kismet_sources.html:52-57](src/lynceus/setup/web/templates/kismet_sources.html:52)
**Description:** The "probe failed / skipped" branch falls back
to `enumerate_wireless_interfaces()`. If that returns None or
empty (no /sys/class/net entries — likely on a non-Linux dev
box or a container without networking), the template renders a
free-form text input for the interface name. The operator can
type any string ("wlan0", "foo", a typo) and the wizard accepts
it. The resulting config will silently drop every observation at
poll time (no matching Kismet source).

The CLI under the same condition prompts for a free-form name
too (line 848-853 of cli/setup.py), so this matches CLI behavior
— but the CLI usually runs on the Linux box where the daemon
will also run, so the operator's typed name is at least
syntactically plausible. The web wizard might be used from a
desktop browser pointed at a remote box; the fallback text
input gives no validation. The template DOES warn about silent-
drop ("If the value you pick doesn't match the name= on the
Kismet side, the poller will silently drop every observation —
no alerts, no error, just nothing in the database. Double-check
the name now."), which mitigates.
**Fix shape:** none required for correctness. Consider adding a
"verify the source name from `kismet -t source_list` on the
target box" instruction.

### Finding 7.3: No length validation on user inputs — a 10MB pasted API key is accepted and written to lynceus.yaml

**Severity:** note
**Location:** [src/lynceus/setup/web/steps_kismet.py:158-191](src/lynceus/setup/web/steps_kismet.py:158), [src/lynceus/setup/prompts.py:51-57](src/lynceus/setup/prompts.py:51)
**Description:** Neither the prompts nor the web wizard's form
handlers enforce any length limits on free-form inputs. A
fat-fingered paste of a 10MB document into the API key field
gets accepted, stored on the session, written verbatim to
lynceus.yaml at apply time, and silently fails at the daemon's
next Kismet request (HTTP header too large). FastAPI's default
form-parser limits the request body size (Starlette default is
~1MB per field I think, configurable), so realistically a 10MB
paste might be rejected at the HTTP layer first. For values
just under that limit (e.g., 800KB), the wizard accepts. Mostly
self-inflicted by an operator pasting the wrong clipboard.
Recording.

### Finding 7.4: `_yaml_str` escapes backslash and double-quote but NOT control characters

**Severity:** note
**Location:** [src/lynceus/setup/core.py:381-386](src/lynceus/setup/core.py:381)
**Description:** `_yaml_str` produces `"escaped"`. If the input
contains a literal newline (`\n`), tab, or other control char,
the output is `"foo\nbar"` with a real newline INSIDE the YAML
double-quoted string — which breaks the YAML parser (line
continuation rules in flow scalars differ). The wizard's inputs
go through prompt validators that strip whitespace but don't
reject embedded control chars (a regex like
`_NTFY_TOPIC_RE` only allows `[A-Za-z0-9_-]` so it's safe; paths
go through `_looks_like_path` which doesn't restrict). The
realistic trigger is "operator pastes a multi-line string into a
single-line field" — unusual enough that recording is the right
posture.
**Fix shape:** if a future input class allows multi-line, escape
control chars in `_yaml_str` (`\\n` → `\\\\n`).

### Finding 7.5: Existing `lynceus.yaml` with unknown / forward-compat fields is silently clobbered

**Severity:** note (design choice, paired with Finding 1.2)
**Location:** [src/lynceus/setup/core.py:396-444](src/lynceus/setup/core.py:396)
**Description:** The wizard's `render_config_yaml` produces a
fixed shape from the operator's answers. Apply overwrites the
target file via `_atomic_write`. Any operator hand-edit
(unrelated to the wizard's prompts — `ui_allow_remote`,
`evidence_capture_enabled`, `min_rssi` if tuned manually, etc.)
is gone. Pre-existing behavior; the wizard owns the file, by
design. Finding 1.2 above is the operator-warning gap; Finding
P2.9.2 is the prior diagnostic's coverage on the Re-run path.
Recording so the design rationale is on the record.

### Finding 7.6: ntfy probe returns success on any 2xx — doesn't distinguish 200 OK from a silent-discard 200 from a misconfigured broker

**Severity:** note
**Location:** [src/lynceus/cli/setup.py:497-517](src/lynceus/cli/setup.py:497)
**Description:** `probe_ntfy` returns ok=True for any
`200 <= status_code < 300`. A self-hosted ntfy with auth
required but no auth header sent typically returns 401, which
the probe surfaces. But a broker behind a misconfigured proxy
that returns 204 No Content (silently dropping the publish) is
indistinguishable from a successful publish. The probe success
message ("ntfy publish OK, check your subscriber for the test
message") tells the operator to verify on their subscriber —
which is the right belt-and-suspenders. Recording.

---

## Recommended pre-push fix order

The two serious findings should land before push. The minor
findings are operator-acceptable for v0.7.0; defer per time
budget.

### Should-fix before push (serious)

1. **Finding 1.1** — `apply_post` reset `apply_stream_active =
   False` alongside the existing `apply_stream_consumed = False`
   reset. One LOC + 1 test that exercises the stranded-flag-then-
   re-apply path. Closes a real (if narrow) wedge.

2. **Finding 1.2** — add the hand-edit overwrite warning to the
   review page's Apply article (parallel to the Re-run section's
   warning added in batch 1's `ef73949`). Gated on
   `reconfigure==True` is the cleaner choice, or unconditional
   for first-time users with pre-edited files. ~5 lines of
   template + 1 test pinning the copy renders.

### Defer if time-constrained (minor)

3. **Finding 1.4** — Done button disable-on-click. One attribute
   on the Done form in apply_complete.html.

4. **Finding 1.3** — render the `/done` 409 page as styled HTML
   instead of bare text.

5. **Finding 3.6** — wrap `probe_kismet` / `probe_ntfy` /
   `probe_kismet_sources` in `await asyncio.to_thread(...)` so
   the event loop stays responsive during probes. ~3 LOC each.

6. **Finding 5.3** — reconfigure `sys.stderr` to utf-8 alongside
   the existing stdout reconfigure. Closes a latent Windows
   crash path on apply-failure logging.

7. **Finding 4.1** — catch `EOFError` / `KeyboardInterrupt` at
   the `run_wizard` boundary and exit cleanly. ~3 LOC.

8. **Finding 7.1** — surface "Cancel wizard" + clearer next-
   action on the step 4 no-wifi-sources dead-end.

### Notes (no fix required)

Remaining `note`-severity findings document verified-correct
behavior, intentional design choices, or extreme edges not
realistically reachable from the wizard's UI. Recorded so a
future reader doesn't re-investigate the same code paths.
