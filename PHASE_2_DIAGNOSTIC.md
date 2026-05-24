# Phase 2 web wizard pre-smoke diagnostic findings

Adversarial read of the integrated Phase 1 + Phase 2a + Phase 2b
surface (`src/lynceus/setup/core.py`, `src/lynceus/setup/web/*`,
`src/lynceus/setup/web/templates/*`). No code changes; every claim
anchored to `file:line`.

Verification convention: ✅ verified in code; ⚠ inferred / probable
but not directly executed.

## Executive summary

| Severity | Count |
| --- | --- |
| critical | 2 |
| serious | 6 |
| minor | 14 |
| note | 20 |

(Plus 3 cross-reference entries that point at findings recorded under
another section — `6.3 → 1.6`, `8.6 → 2.3`, `9.3 → 7.5`.)

**Pre-smoke read:** two critical issues (`POST /done` mid-apply kills
the apply; Cancel-during-apply → orphan apply + ability to spawn a
second concurrent apply on top) are reachable by an operator who
clicks the right button at the wrong moment. The review page also
still ships the Phase 2a "this is a noop" copy on the Apply button
article — that's user-facing misinformation and should not go to
smoke as-is. The remaining serious findings are mostly SSE
edge-cases (multi-tab, reconnect, completed-state stream hang) and
re-apply concurrency races. The full pre-smoke fix order is at the
bottom of this document.

The 200-test suite is healthy at HEAD — these findings are paths the
tests do not currently exercise.

---

## Section 1: Concurrency & threading

### Finding 1.1: `apply_post` apply_state check-then-set is not atomic, only window-narrow

**Severity:** minor
**Location:** [src/lynceus/setup/web/review.py:465-501](src/lynceus/setup/web/review.py:465)
**Description:** `apply_post` reads `session.apply_state == "running"`
at L465, then sets state to `"running"` at L485, with only synchronous
work between (`_resolve_apply_args`, `asyncio.get_running_loop()`,
`asyncio.Queue()`). Today no `await` sits between the check and the
set, so under a single-process uvicorn the two operations are
event-loop-atomic and the 409 guard at L466 is effective ✅. The
risk is **fragility**: any future `await` inserted between L465 and
L485 (e.g., logging an audit row, calling a probe, looking up disk
state) silently opens a TOCTOU window that lets two concurrent POSTs
both proceed and spawn two `_run_apply_task` background coroutines.
There is no `asyncio.Lock` anchoring the invariant.
**Fix shape:** wrap the check + state-set + queue-allocate + task-
create in an `asyncio.Lock` held on the session, so the invariant is
enforced regardless of future awaits.

### Finding 1.2: Worker-thread to event-loop bridge is consistent; partial-report rebuild reads worker-thread state

**Severity:** note
**Location:** [src/lynceus/setup/web/sse_sink.py:83](src/lynceus/setup/web/sse_sink.py:83), [src/lynceus/setup/web/review.py:352](src/lynceus/setup/web/review.py:352)
**Description:** The only cross-thread put onto `session.apply_queue`
is `_loop.call_soon_threadsafe(...)` in `SSEProgressSink.record` (the
documented asyncio.Queue pattern from a non-loop thread) ✅. All
other puts (`queue.put` at L351/L357) run in the event-loop
coroutine after `await asyncio.to_thread(...)` has returned, so they
are on-loop ✅. The synthetic-failed-step branch (L352) reads
`sink.records` from the event loop after `to_thread` raised — at
that point the worker thread has definitely terminated (the future
the loop awaited resolved with the exception), so the read is safe ✅.
This section logged as a note to record the verification, not a bug.

### Finding 1.3: `asyncio.Queue` is unbounded

**Severity:** note
**Location:** [src/lynceus/setup/web/review.py:483](src/lynceus/setup/web/review.py:483)
**Description:** `apply_queue = asyncio.Queue()` has no `maxsize`.
For `apply_config` the producer emits at most ~7 records + sentinel,
so the queue never grows large. Worth flagging only if the step list
expands materially in future phases. ✅

### Finding 1.4: Multiple SSE clients on the same session steal each other's events

**Severity:** serious
**Location:** [src/lynceus/setup/web/review.py:576-594](src/lynceus/setup/web/review.py:576)
**Description:** `apply_stream_get` resolves the session by the
single shared setup token (one operator, but multiple browser
tabs/windows allowed by the design). Every connection's
`event_stream()` `await queue.get()`s from the SAME
`session.apply_queue`. `asyncio.Queue.get()` removes the item, so
each step record goes to exactly one of the connected consumers. If
the operator opens `/apply-progress` in two tabs (e.g., refreshes
without closing, or background-tab pre-render), one tab gets ~half
the records and the sentinel and navigates to `/apply-complete`; the
other tab is left awaiting on an empty queue indefinitely with the
"Connecting…" UI still showing under broken state.
**Repro:** open two tabs to the wizard, complete the form, click
Apply in one tab; race a second open of `/apply-progress?token=...`
in the other tab before the apply finishes.
**Fix shape:** either (a) make the SSE generator fan-out a single
producer to N consumer-queues using a broadcast list, or (b) reject
concurrent SSE connections (409 if `session.apply_queue` is already
being drained by an active generator — track an in-flight counter
on the session).

### Finding 1.5: Sentinel-push at end of `_run_apply_task` is cancellation-vulnerable

**Severity:** minor
**Location:** [src/lynceus/setup/web/review.py:356-357](src/lynceus/setup/web/review.py:356)
**Description:** The `finally` posts the sentinel via
`await queue.put(None)`. On unbounded queues this returns
synchronously, but it is an `await` — if `_run_apply_task` itself
is cancelled (Ctrl-C / shutdown) at exactly that point the put may
be skipped, leaving any waiting SSE consumer blocked forever. The
window is tiny but real.
**Fix shape:** replace with `queue.put_nowait(None)` (the queue is
unbounded so it can't QueueFull) — eliminates the await point.

### Finding 1.6: Cancel-during-apply orphans the apply and lets the operator spawn a second concurrent apply

**Severity:** critical
**Location:** [src/lynceus/setup/web/app.py:185-201](src/lynceus/setup/web/app.py:185), [src/lynceus/setup/web/review.py:96-98](src/lynceus/setup/web/review.py:96)
**Description:** The Cancel link is rendered on every page that
inherits the default `_base.html` footer (review, every form step).
`/cancel` calls `session_store.clear()` which removes ALL sessions.
The running `_run_apply_task` still holds a Python reference to the
OLD `WizardSession` (it was passed in as `session=` at L494) and
continues writing files, chowning, and shelling out to
`lynceus-import-argus` — but the operator's NEXT request gets a
freshly-created session via `get_or_create` (review.py:97-98) whose
`apply_state` is `"idle"`. From that fresh session the operator can
fill the form again and POST `/apply`; the 409 guard does not fire
because the NEW session's state is idle. Result: **two
`apply_config` invocations running concurrently against the same
target_path, severity_overrides_path, and sqlite DB**. The bundled-
import subprocess can deadlock against itself on sqlite write locks;
`_atomic_write` calls can race and leave whichever writer-loses' bits
on disk; chowns are racing root:lynceus changes.
**Repro:** open `/apply-progress`, in another tab navigate to
`/cancel?token=<t>`, then back to `/` and re-walk the wizard to
`/apply` while the original apply is still mid-pipeline.
**Fix shape:** (a) refuse `/cancel` when `apply_state == "running"`
(403 or redirect to `/apply-progress`); AND (b) key the session on
something stable across requests so a `clear()` doesn't strand a
running task; AND/OR (c) keep a process-wide "an apply is in flight"
guard separate from session state so a freshly-minted session can't
race past it.

---

## Section 2: SSE lifecycle

### Finding 2.1: SSE generator does not detect client disconnect

**Severity:** minor
**Location:** [src/lynceus/setup/web/review.py:586-594](src/lynceus/setup/web/review.py:586)
**Description:** `event_stream()` awaits `queue.get()` with no
`request.is_disconnected()` check. If the operator closes the tab
mid-apply, the generator remains blocked on `queue.get()` until the
worker thread enqueues the NEXT step (or the sentinel at the end of
apply); only then does `yield` raise via StreamingResponse's failed
send and unwind the generator with `GeneratorExit`. The worker
thread keeps running regardless ✅ (apply completes). The leak is
the generator coroutine sitting idle until the next enqueue — at
most ~1s on a normal apply, irrelevant. Note that the worker is NOT
notified to stop; that is the intended behavior (apply is not
cancellable by the operator) but worth recording.
**Fix shape:** none required for correctness. If desired, race
`queue.get()` against `request.is_disconnected()` to close the
generator immediately on disconnect.

### Finding 2.2: Sentinel-on-exception path is robust for the documented `apply_config` raises but fragile for pre-try failures

**Severity:** minor
**Location:** [src/lynceus/setup/web/review.py:326-357](src/lynceus/setup/web/review.py:326)
**Description:** The `try` begins at L327 — the `SSEProgressSink(...)`
construction at L326 sits ABOVE the try. If `SSEProgressSink.__init__`
were to raise (it does not today — it's two attribute assignments
plus a list init), the `finally` at L355 would never fire, the
sentinel would never be posted, and any in-flight SSE consumer would
block forever on `queue.get()`. Also, the `synthetic` step
construction at L343-348 calls `f"{type(exc).__name__}: {exc}"`; if
the underlying exception's `__str__` itself raised (degenerate), the
except branch would propagate and the finally would still run — so
the sentinel is still posted, but `session.apply_report` stays
`None` and `apply_state` stays `"running"`.
**Fix shape:** move sink construction INSIDE the try; ensure
synthetic construction tolerates broken `__str__` (use `repr(exc)`
or `try/except` around the f-string).

### Finding 2.3: EventSource reconnect during apply loses already-streamed events; reconnect after completion hangs forever

**Severity:** serious
**Location:** [src/lynceus/setup/web/review.py:586-594](src/lynceus/setup/web/review.py:586), [src/lynceus/setup/web/templates/apply_progress.html:32](src/lynceus/setup/web/templates/apply_progress.html:32)
**Description:** Browser `EventSource` auto-reconnects on connection
loss with `Last-Event-ID`. The generator at L592-594 emits events
without any `id:` line, so the client's `Last-Event-ID` is always
empty. On reconnect the new generator subscribes to the SAME
`session.apply_queue`. Two failure modes:
1. **Mid-apply reconnect:** events the dead connection consumed
   (which dequeued them via `queue.get()`) are gone — the new
   generator only sees the remaining undelivered events. The
   transcript on the page is missing the early steps; the
   "End → navigate to /apply-complete" works, but the operator's
   live view is corrupt.
2. **Post-completion reconnect:** the sentinel was already consumed
   by the prior generator (which closed the connection on
   `event: end`). The new generator's `await queue.get()` blocks
   forever because nothing else is being put. The page sits on
   "Connecting…" indefinitely. The state-machine redirect in
   `apply_progress_get` would re-route to `/apply-complete` ✅, but
   it only fires on a full page navigation — an in-place EventSource
   reconnect does not consult that redirect.
   The JS in [apply_progress.html:62-68](src/lynceus/setup/web/templates/apply_progress.html:62)
   surfaces a "Lost the progress stream" error on `onerror`, which
   helps the second case. But there's no client-side timeout on
   "still connecting after N seconds, give up and link to
   `/apply-complete`."
**Fix shape:** either (a) emit `id:` lines and have the generator
honor `Last-Event-ID` by replaying from a session-side ring buffer
of recent events, or (b) detect "stream already drained" at the
endpoint (e.g., `session.apply_state in {completed, failed}` AND
queue is empty AND a previous generator already closed) and 410/204
the reconnect so the client `onerror` path fires and the user can
click through to `/apply-complete`.

### Finding 2.4: SSE response headers set correctly

**Severity:** note
**Location:** [src/lynceus/setup/web/review.py:599-608](src/lynceus/setup/web/review.py:599)
**Description:** `Cache-Control: no-cache`, `Connection: keep-alive`,
`X-Accel-Buffering: no` all present ✅. No finding; recording the
verification.

### Finding 2.5: `json.dumps` in the SSE generator can raise on unforeseen `detail` values; defended at the sink

**Severity:** minor
**Location:** [src/lynceus/setup/web/review.py:594](src/lynceus/setup/web/review.py:594), [src/lynceus/setup/web/sse_sink.py:45-58](src/lynceus/setup/web/sse_sink.py:45)
**Description:** `_json_safe` recursively flattens `Path`, dicts,
lists, dataclasses, and falls back to `str()` for anything else ✅.
So `json.dumps(item)` at L594 should never raise on serializable
output. The defense lives at the sink, not the generator — if a
future caller bypasses `serialize_step` and enqueues a raw object,
`json.dumps` would raise mid-stream and the generator would unwind,
killing the SSE connection without posting the closing
`event: end`. The worker thread's sentinel post via `finally`
guards the queue-drain side but does not save the consumer that
already failed.
**Fix shape:** wrap the `yield` in a try/except that logs and emits
an `event: error` instead of letting the generator die mid-stream.

---

## Section 3: Teardown & lifecycle

### Finding 3.1: `POST /done` during an in-flight apply kills the apply mid-pipeline

**Severity:** critical
**Location:** [src/lynceus/setup/web/review.py:411-447](src/lynceus/setup/web/review.py:411)
**Description:** `done_post` does not gate on `apply_state`. It
cancels the (not-yet-armed) grace timer and schedules
`server.should_exit = True` after `DONE_SHUTDOWN_DELAY_SECONDS`
(0.5s) regardless of whether `apply_config` is running. Uvicorn
begins shutdown; the asyncio loop closes; the worker thread
(`asyncio.to_thread`'s default executor) is non-daemon by default
and Python's atexit MAY wait for it OR may proceed to interpreter
shutdown depending on the executor's idle-thread state — behavior
is brittle. The bundled-import subprocess (`lynceus-import-argus`)
that may be running is a separate process; uvicorn shutdown does
not kill it, so it continues with no parent waiting on it ⚠.
Result: the apply may be left at any of: chown'd dirs but no DB,
DB chowned but rules.yaml not written, partial subprocess output
abandoned. `_atomic_write` itself mitigates partial-file risk on
POSIX (single fd open with mode at create) ✅, but the pipeline as
a whole is NOT atomic.
The Done button is normally only visible on `/apply-complete`
(which redirects when state is `running`), so a careful operator
won't hit this — but `POST /done` is reachable by any client with
the token (curl, dev tools, malicious in-tab JS via the operator's
other tabs if CSRF is somehow leaked, etc.). At minimum, an
operator with two tabs (one on `/apply-progress`, one on a stale
`/apply-complete` from a prior failed run) can race the buttons.
**Repro:** start an apply; in a second tab open the rendered
`apply_complete.html` for a prior run and click Done while the new
apply is still in-flight.
**Fix shape:** in `done_post`, if `session.apply_state == "running"`,
return 409 with a body explaining "apply still in progress — wait
for the completion page". Optionally, also surface a more
informative "wait" page that polls `/apply-complete` once the state
transitions.

### Finding 3.2: Grace timer is only armed AFTER apply completes; runtime-during-apply concern is moot

**Severity:** note
**Location:** [src/lynceus/setup/web/review.py:355-362](src/lynceus/setup/web/review.py:355)
**Description:** The Asked question "grace timer fires during a
slow apply" doesn't apply: `_schedule_apply_grace_shutdown` is
called inside `_run_apply_task`'s `finally` block, AFTER
`apply_config` has returned (or raised). So during the apply itself
no grace timer exists ✅. Recording for completeness.

### Finding 3.3: Multiple shutdown signals are idempotent at the uvicorn level

**Severity:** note
**Location:** [src/lynceus/setup/web/review.py:403-408](src/lynceus/setup/web/review.py:403)
**Description:** `_shutdown_after_delay` sets `server.should_exit
= True` — assignment is idempotent. Multiple `/done` clicks each
schedule an independent task; all of them set the flag.
`_grace_shutdown` does the same. No race; no double-shutdown bug.

### Finding 3.4: `_shutdown_after_delay` is fire-and-forget; Python 3.12+ may garbage-collect the task before it fires

**Severity:** minor
**Location:** [src/lynceus/setup/web/review.py:440](src/lynceus/setup/web/review.py:440)
**Description:** `asyncio.create_task(_shutdown_after_delay(...))`
is not stored on the session or anywhere else. Python's asyncio
keeps only a weak reference to tasks in the loop, so if the loop's
internal task set is reaped between create and run, the task can be
GC'd and silently dropped — Python 3.12+ raises a "Task was
destroyed but it is pending!" warning to stderr. Symptom would be
"operator clicked Done, page rendered, server never exits." Easy
to miss in dev because dev loops run quickly enough that the task
fires before GC.
**Fix shape:** hold a module-level set of background tasks (e.g.,
`_BACKGROUND_TASKS: set[asyncio.Task] = set()`, `task = ...;
_BACKGROUND_TASKS.add(task); task.add_done_callback(_BACKGROUND_TASKS.discard)`)
— the standard asyncio workaround.

### Finding 3.5: `_shutdown_after_delay` 500ms hardcoded; may be too short on slow render paths

**Severity:** minor
**Location:** [src/lynceus/setup/web/review.py:74](src/lynceus/setup/web/review.py:74)
**Description:** `DONE_SHUTDOWN_DELAY_SECONDS = 0.5` is hardcoded
at the module level (overridable by monkeypatch in tests ✅). On
loopback to a local browser 500ms is comfortable for the response
to flush. On a remote operator via SSH port-forward or a high-RTT
tunnel, 500ms could be insufficient and the operator may see a
connection-reset error instead of the "shutting down" page. Not
critical (the server is shutting down anyway, the apply is done)
but flagged.
**Fix shape:** none required; consider 1500ms if smoke shows the
race or if the wizard supports remote-bind use cases in the future.

### Finding 3.6: Re-apply correctly cancels the prior grace timer (when arming has completed)

**Severity:** note
**Location:** [src/lynceus/setup/web/review.py:488-490](src/lynceus/setup/web/review.py:488)
**Description:** The re-apply branch cancels `session.apply_grace_task`
and clears it. This handles the common case ✅. See Finding 4.1
below for the race window where the cancel runs BEFORE the prior
task's finally has armed the grace timer.

---

## Section 4: Re-apply flow

### Finding 4.1: Race between prior apply's `finally`-block grace-timer arm and new `/apply` POST's cancel

**Severity:** serious
**Location:** [src/lynceus/setup/web/review.py:338-362](src/lynceus/setup/web/review.py:338), [src/lynceus/setup/web/review.py:488-490](src/lynceus/setup/web/review.py:488)
**Description:** `_run_apply_task` sets `session.apply_state =
"completed"|"failed"` at L338-339 BEFORE the `finally` block runs,
and the grace-timer arm happens INSIDE the finally at L362. The
operator sees state == terminal → renders `/apply-complete` → clicks
Re-run → `apply_post` runs. The cancel-prior-grace block at L488-490
checks `session.apply_grace_task is not None and not done()`. If
the prior task is still mid-`finally` (between the queue-put
sentinel at L357 and the grace-task assignment at L383-385), the
cancel-check sees `None` and does nothing. Microseconds later the
prior task's `finally` assigns a fresh grace task to the SAME
`session.apply_grace_task`. That grace task is now armed against
the NEW apply run and will fire `server.should_exit = True` after
APPLY_GRACE_SECONDS (10 min). If the new apply takes a long time
or the operator walks through the completion page slowly, this
shuts the server down mid-new-run or right after a successful new
run without a Done click ever firing.
**Repro:** ⚠ time-dependent; not easily reproducible without
instrumentation. Easiest to reason about: insert a sleep in
`_schedule_apply_grace_shutdown` to widen the window, then rapidly
trigger Re-run after the completion page loads.
**Fix shape:** swap the order in `_run_apply_task`: arm the grace
timer BEFORE setting `apply_state = "completed"|"failed"`, or
acquire a session-level lock around the "arm grace + flip state"
pair so the new `/apply` POST can't interleave.

### Finding 4.2: Re-apply correctly replaces the queue; stale-queue contamination test passes

**Severity:** note
**Location:** [src/lynceus/setup/web/review.py:483-484](src/lynceus/setup/web/review.py:483), [tests/test_setup_web_apply.py:404-421](tests/test_setup_web_apply.py:404)
**Description:** `apply_post` allocates a fresh `asyncio.Queue()`
each call ✅. The prior SSE generator (if any) holds a local
reference to the old queue and drains it independently. No
contamination. Recording for completeness.

### Finding 4.3: Concurrent Re-run POSTs share the same TOCTOU concern as initial Apply

**Severity:** minor
**Location:** [src/lynceus/setup/web/review.py:465-501](src/lynceus/setup/web/review.py:465)
**Description:** Same as Finding 1.1. Today no `await` between
check & set so two simultaneous Re-run POSTs cannot interleave on a
single-process uvicorn. Same fragility caveat. Browsers double-click
to a POST form by submitting twice; the standard mitigation
"disable submit button on click" is NOT present on the Re-run
button at [apply_complete.html:78-81](src/lynceus/setup/web/templates/apply_complete.html:78).
**Fix shape:** add `onsubmit="this.querySelector('button').disabled=true"`
to the Re-run form (and the initial Apply form) as defense in depth
behind the server-side 409 guard.

---

## Section 5: Invalid-state paths

### Finding 5.1: `/apply-stream` when state is `completed` or `failed` hangs forever

**Severity:** serious
**Location:** [src/lynceus/setup/web/review.py:576-594](src/lynceus/setup/web/review.py:576)
**Description:** `apply_stream_get` only 409s when
`session.apply_queue is None` — i.e., when no apply has EVER run on
the session. After an apply completes, `session.apply_queue`
still references the (now-drained) queue object. A new connection
to `/apply-stream` passes the L578 check, enters `event_stream()`,
and blocks indefinitely on `await queue.get()` because nothing
else is being enqueued. The connection sits there leaking memory
and a coroutine until the operator closes the tab or the server
exits. Same root cause as Finding 2.3 case (2).
**Repro:** run an apply to completion in one tab; in another tab
`curl -N "http://127.0.0.1:8766/apply-stream?token=<t>"` — observe
the connection hang with no data.
**Fix shape:** also 409 when `session.apply_state in {completed,
failed}` AND the queue has been drained (track "consumed" with a
flag). Cleaner: route the SSE endpoint via `apply_state` — only
serve when state == running; otherwise 409/410.

### Finding 5.2: `POST /done` when state is `idle` shuts down the server with no apply ever performed

**Severity:** minor
**Location:** [src/lynceus/setup/web/review.py:411-447](src/lynceus/setup/web/review.py:411)
**Description:** Operator opens wizard, never fills any form, POSTs
`/done` directly. The handler doesn't gate on state. Server shuts
down. The "Setup complete" copy on `done.html` is misleading — the
config was NOT applied. Marginal user-facing harm because the
done.html does not explicitly claim apply success; it says the
HTTP server is closing. Still potentially confusing.
**Fix shape:** in `done_post`, if `apply_state == "idle"`, render
a different "wizard closed without applying" template — or simply
include a conditional sentence on `done.html`.

### Finding 5.3: Sessions are keyed by the single setup token; multi-session is not a feature

**Severity:** note
**Location:** [src/lynceus/setup/web/review.py:96-98](src/lynceus/setup/web/review.py:96), [src/lynceus/setup/web/session.py:65-71](src/lynceus/setup/web/session.py:65)
**Description:** `_session` calls
`get_or_create(state.setup_token)` using the SERVER's token
(not the request's). Since there's only one valid token per wizard
run, all valid requests share one session ✅. Multi-session is by
design absent. Recording for completeness — the SSE multi-tab
behavior in Finding 1.4 is downstream of this design choice.

### Finding 5.4: Token enforcement on every endpoint is verified

**Severity:** note
**Location:** [src/lynceus/setup/web/auth.py](src/lynceus/setup/web/auth.py), [tests/test_setup_web_apply.py:491-502](tests/test_setup_web_apply.py:491)
**Description:** SetupTokenMiddleware enforces token on every non-
exempt route ✅. No-token = 403. Wrong-token = 403 via constant-
time compare. Token in either `?token=` or `X-Setup-Token` header.
Recording for completeness.

---

## Section 6: Resource cleanup

### Finding 6.1: Worker-thread cleanup on server shutdown is brittle around `asyncio.to_thread`

**Severity:** minor
**Location:** [src/lynceus/setup/web/review.py:328-337](src/lynceus/setup/web/review.py:328)
**Description:** `asyncio.to_thread` schedules the call on the
loop's default `ThreadPoolExecutor`. Python's default executor
threads are NOT daemon (per `concurrent.futures.thread` impl); on
interpreter shutdown, `threading._shutdown` waits for non-daemon
threads to finish. When `server.should_exit = True` fires, uvicorn
shuts the loop down, but the executor thread continues running
`apply_config` until it returns. If `apply_config` is mid-
subprocess (`lynceus-import-argus` running), `subprocess.communicate`
blocks until the child exits — so the wizard PROCESS may stay alive
beyond the operator's "Done" click for up to BUNDLED_IMPORT_TIMEOUT_SECONDS
(120s in [core.py:231](src/lynceus/setup/core.py:231)). Operator-
visible symptom: "I clicked Done and the terminal still shows the
wizard process running for 2 minutes." ⚠ Inferred from executor
internals; not directly observed.
**Fix shape:** none required for correctness — the apply ultimately
completes. Document as expected. Or, for cleanliness, spin up the
apply on a dedicated executor with daemon threads, accepting that
shutdown-during-apply will abandon the subprocess.

### Finding 6.2: Asyncio tasks for apply worker and grace timer are stored; no dangling-task GC risk

**Severity:** note
**Location:** [src/lynceus/setup/web/review.py:491-501](src/lynceus/setup/web/review.py:491), [src/lynceus/setup/web/review.py:383-385](src/lynceus/setup/web/review.py:383)
**Description:** Both `session.apply_task` and
`session.apply_grace_task` hold strong refs to their tasks ✅.
Python 3.12+'s "Task was destroyed but it is pending!" cannot fire
here for these two. The exception is the fire-and-forget
`_shutdown_after_delay` task — see Finding 3.4.

### Finding 6.3: `cancel` handler clears the entire session store mid-apply

**Severity:** see Finding 1.6
**Location:** [src/lynceus/setup/web/app.py:185-201](src/lynceus/setup/web/app.py:185)
**Description:** Cross-reference to Finding 1.6 — same root cause.

---

## Section 7: Error handling

### Finding 7.1: `apply_state = "running"` flip happens BEFORE the task is created; task-create failure leaves a stuck session

**Severity:** minor
**Location:** [src/lynceus/setup/web/review.py:485-501](src/lynceus/setup/web/review.py:485)
**Description:** Order is: set `apply_state = "running"` (L485),
clear `apply_report` (L486), cancel prior grace task (L488-490),
THEN `asyncio.create_task(_run_apply_task(...))` (L491). If the
task creation itself raises (extremely rare — `create_task` only
raises on closed loop), the session is left at `apply_state ==
"running"` permanently with no task to set it back. The 409 guard
on the next `/apply` POST would then refuse the re-run.
**Fix shape:** flip the order — create the task first; only after
successful creation, set state to running.

### Finding 7.2: `except Exception` doesn't catch `CancelledError` (Python 3.8+); CancelledError mid-`to_thread` leaves state stuck at "running"

**Severity:** minor
**Location:** [src/lynceus/setup/web/review.py:340-354](src/lynceus/setup/web/review.py:340)
**Description:** In Python 3.8+, `asyncio.CancelledError` is a
`BaseException`, not `Exception`. So `except Exception` at L340
does not catch it. If `_run_apply_task` is cancelled mid-
`to_thread` (uvicorn shutdown, future feature, etc.), the except
branch never runs, `session.apply_state` stays `"running"`, the
`finally` posts the sentinel and arms the grace timer. The grace
timer will eventually shut down the server. But if the operator
reconnects in the meantime, `/apply-complete` redirects them to
`/apply-progress` (state == running), which renders the SSE page
and connects to an empty queue → hangs forever.
**Fix shape:** ensure cancellation flips state to a terminal value
in the finally (e.g., `if session.apply_state == "running": session
.apply_state = "failed"`).

### Finding 7.3: No XSS in synthesized failed-step rendering

**Severity:** note
**Location:** [src/lynceus/setup/web/templates/apply_complete.html:19-29](src/lynceus/setup/web/templates/apply_complete.html:19)
**Description:** `{{ failed_step.message }}` and
`{{ failed_step.detail.traceback }}` are rendered with Jinja2's
default autoescape ✅ (FastAPI's `Jinja2Templates` uses
`select_autoescape` defaulting on for .html). The SSE generator's
output is JSON-decoded by the JS and inserted via
`textContent` / `createTextNode` ✅. No XSS surface.

### Finding 7.4: ValidationError on `_resolve_apply_args` redirects to `/review`; the review page re-renders the errors

**Severity:** note
**Location:** [src/lynceus/setup/web/review.py:468-477](src/lynceus/setup/web/review.py:468), [src/lynceus/setup/web/review.py:243-260](src/lynceus/setup/web/review.py:243)
**Description:** Round-trip is idempotent: `apply_post`'s 303 to
`/review` causes `review_get` to rebuild the Config, catch
ValidationError, and render the per-field error rows ✅.

### Finding 7.5: Wizard logs go to uvicorn's stderr; no journald integration

**Severity:** minor
**Location:** [src/lynceus/setup/web/server.py:81-83](src/lynceus/setup/web/server.py:81)
**Description:** `uvicorn.Config(..., log_level="info",
access_log=True)`. Wizard apply errors via `logger.exception(...)`
at [review.py:341](src/lynceus/setup/web/review.py:341) go to
stderr. The wizard runs in the foreground from
`lynceus-setup --web`, so the operator sees the trace in their
shell — that's the intended ops path. However, if an operator
invokes the wizard via `nohup` / `systemd-run` / a tmux pane they
later detach, those tracebacks are not in journald (the daemon's
logging config doesn't run for the wizard process). Document or
add a minimal journald handler for `--system` invocations.
**Fix shape:** none required. If desired, route logger output
through the daemon's logging configuration when `scope == "system"`.

### Finding 7.6: Bare `except (FileNotFoundError, OSError)` in `import_bundled_watchlist` is acceptable

**Severity:** note
**Location:** [src/lynceus/setup/core.py:480-487](src/lynceus/setup/core.py:480)
**Description:** Catches the documented "bundled CSV absent" and
"as_file resource extraction failed" cases. Not a swallow-and-
ignore — the function returns `(False, BUNDLED_ABSENT_MESSAGE)`
which apply_config translates into a `skipped` ApplyStep. ✅

---

## Section 8: Browser behavior assumptions

### Finding 8.1: `review.html` Apply button article still ships Phase 2a "noop" copy

**Severity:** serious
**Location:** [src/lynceus/setup/web/templates/review.html:84-95](src/lynceus/setup/web/templates/review.html:84)
**Description:** The Apply block reads:
> **Phase 2a note:** the Apply button below confirms what WOULD be
> applied; it does not write the config to disk yet. The full apply
> pipeline (write yaml, scaffold overrides, import bundled
> watchlist, write rules.yaml, chown system files) lands in
> Phase 2b. Until then, [the JSON preview] is the contract Phase 2b's
> apply route will consume.

Phase 2b is now landed at HEAD ✅ but this copy still tells the
operator nothing will be written. An operator who reads carefully
will click Apply expecting a dry run, then be surprised when their
existing `/etc/lynceus/lynceus.yaml` is overwritten with the
wizard's output. This is user-facing misinformation; should not
ship to smoke.
**Fix shape:** replace the article body with current-state copy:
clicking Apply writes the config + side effects per the apply
pipeline; operator can re-run if it fails.

### Finding 8.2: Token in URL retained in browser history; acceptable for one-shot wizard

**Severity:** note
**Location:** [src/lynceus/setup/web/app.py:138-146](src/lynceus/setup/web/app.py:138)
**Description:** Every wizard URL carries `?token=<token>`; browser
history retains it. After server exit (Done / grace timer / Ctrl-C),
the token is invalid — replaying a history URL just gets 403 on
the rebuilt server (different token). Loopback-only by default
limits leak surface. Acceptable design choice; documented.

### Finding 8.3: `Referer` header leak of token is minimal

**Severity:** note
**Location:** [src/lynceus/setup/web/templates/done.html](src/lynceus/setup/web/templates/done.html), [src/lynceus/setup/web/templates/_base.html](src/lynceus/setup/web/templates/_base.html)
**Description:** Templates surface no external `<a href>` to non-
loopback hosts during the wizard's life ✅. The Pico CSS is served
from the same origin. No Referer leak path. Recording for
completeness.

### Finding 8.4: EventSource cookie/credentials behavior does not depend on cookies

**Severity:** note
**Location:** [src/lynceus/setup/web/templates/apply_progress.html:32](src/lynceus/setup/web/templates/apply_progress.html:32)
**Description:** `new EventSource(streamUrl)` — default
withCredentials=false. The setup token is in the URL, not a
cookie, so the SSE endpoint works without cookie credentials ✅.
CSRF cookie is unused by the SSE endpoint (SSE is a GET; CSRF
middleware only enforces on POST/PUT/PATCH/DELETE). ✅

### Finding 8.5: CSRF on `/done` is enforced and tested

**Severity:** note
**Location:** [src/lynceus/webui/csrf.py:143-211](src/lynceus/webui/csrf.py:143), [tests/test_setup_web_teardown.py:229-240](tests/test_setup_web_teardown.py:229)
**Description:** `/done` POST requires a valid CSRF cookie + form
token pair ✅. Test pins the 403 behavior. Recording.

### Finding 8.6: Browser-close-during-apply recoverable via `/apply-complete`; reconnect to `/apply-progress` hits Finding 2.3 case (2)

**Severity:** see Finding 2.3
**Location:** [src/lynceus/setup/web/review.py:505-527](src/lynceus/setup/web/review.py:505)
**Description:** If the operator closes the tab during apply, the
worker thread continues and state transitions to completed/failed ✅.
On reconnect, `/apply-progress` redirects to `/apply-complete` for
terminal states ✅. The hang scenario only fires if the operator
re-opens `/apply-progress` AFTER apply finished but BEFORE the
state-aware redirect at L517-518 has been served — which it
always will be on a fresh GET ✅. So the realistic browser-close
case is fine; only the EventSource-reconnect case in Finding 2.3
is broken.

---

## Section 9: Cross-cutting

### Finding 9.1: Phase 1 lazy-import proxies ARE hit on every wizard apply (not just test-monkeypatch)

**Severity:** note (regression risk)
**Location:** [src/lynceus/setup/core.py:60-111](src/lynceus/setup/core.py:60), [src/lynceus/setup/core.py:149](src/lynceus/setup/core.py:149), [src/lynceus/setup/core.py:806](src/lynceus/setup/core.py:806), [src/lynceus/setup/core.py:890](src/lynceus/setup/core.py:890)
**Description:** `_frontend_is_windows`, `_frontend_render_config_yaml`,
`_frontend_import_bundled_watchlist` are called by `_atomic_write`
(every file write), `apply_config`'s render call (once per apply),
and `apply_config`'s import call (once per apply). The wizard's
apply path executes ALL of these, not just the CLI's. The lazy
`from lynceus.cli import setup as _frontend` import is a sys.modules
hit after first call ✅, but it does mean a regression where the
CLI frontend module is renamed / restructured breaks the wizard
too — these aren't isolated test-only seams.
**Fix shape:** none. Recording the architectural reality: the
proxies are load-bearing for both frontends, not test-only.

### Finding 9.2: `apply_config` overwrites operator edits to `lynceus.yaml` and `rules.yaml` on re-apply

**Severity:** serious
**Location:** [src/lynceus/setup/core.py:442-444](src/lynceus/setup/core.py:442), [src/lynceus/setup/core.py:973-976](src/lynceus/setup/core.py:973)
**Description:** Re-apply uses `_atomic_write` which unconditionally
overwrites the target. If an operator successfully applies, then
hand-edits `/etc/lynceus/lynceus.yaml` (e.g., to add a non-wizard
setting like `ui_allow_remote: true`), then re-runs the wizard
(perhaps to change one Kismet source), the hand-edits are silently
clobbered. Same for `rules.yaml`. No diff preview, no "you have
hand-edits in this file — overwrite?" prompt. The completion page
encourages re-run: "the apply chain is largely idempotent…
re-running after fixing an environmental issue is usually safe"
([apply_complete.html:68-77](src/lynceus/setup/web/templates/apply_complete.html:68))
— which is true for the wizard's own writes but not for operator
edits between runs.
**Fix shape:** none for this diagnostic — this is pre-existing
behavior, not Phase 2 regression. Flag for documentation and
consider a "config has unexpected content" warning step before
overwrite in a future phase.

### Finding 9.3: Wizard runs without the daemon's logging config

**Severity:** see Finding 7.5
**Location:** [src/lynceus/setup/web/server.py:81-83](src/lynceus/setup/web/server.py:81)
**Description:** Cross-reference to Finding 7.5. Wizard log
output is uvicorn's default stderr; daemon's `logging_config.py`
is not loaded for the wizard process.

### Finding 9.4: Uvicorn `access_log=True` logs every step POST and the SSE connection open

**Severity:** minor
**Location:** [src/lynceus/setup/web/server.py:81-82](src/lynceus/setup/web/server.py:81)
**Description:** With `access_log=True`, uvicorn logs every HTTP
request to stderr. Wizard run = ~15 form POSTs + ~10 page GETs +
1 long-lived SSE connection. Tolerable noise in the operator's
shell. Recording.
**Fix shape:** none required. Could downgrade to `access_log=False`
for production wizard launches if the noise becomes a complaint.

### Finding 9.5: `APPLY_GRACE_SECONDS` is module-level constant; overridable by tests ✅

**Severity:** note
**Location:** [src/lynceus/setup/web/review.py:73](src/lynceus/setup/web/review.py:73)
**Description:** `APPLY_GRACE_SECONDS: float = 600.0` is module-
level and monkeypatched in tests at
[tests/test_setup_web_teardown.py:184](tests/test_setup_web_teardown.py:184)
✅. Same shape for `DONE_SHUTDOWN_DELAY_SECONDS`. No finding;
recording the testability verification.

### Finding 9.6: `apply_config` idempotency holds for the wizard's own writes (with operator-edit caveat)

**Severity:** note
**Location:** [src/lynceus/setup/core.py:743-1008](src/lynceus/setup/core.py:743)
**Description:** Per-step idempotency review:
- `write_config`: atomic overwrite ✅ (clobbers operator edits — see 9.2)
- `scaffold_severity_overrides`: only writes if absent ✅
- `create_data_dir` / `create_log_dir`: `mkdir(exist_ok=True)` ✅
- `import_bundled_watchlist`: per-record dedup ✅ (subprocess
  re-runs cost ~10s but produce identical DB state)
- `chown_db_files`: chown to same owner/mode is a no-op ✅
- `write_rules`: atomic overwrite ✅ (clobbers operator edits — see 9.2)

---

## Recommended pre-smoke fix order

Items listed in suggested fix sequence. The two critical findings
must land before smoke; the serious findings should land before
smoke unless explicitly deferred.

### Must-fix before smoke (critical)

1. **Finding 8.1** — Replace Phase 2a "noop" copy on review page.
   Lowest-risk change with highest user impact. (1 template edit.)
2. **Finding 3.1** — Gate `/done` on `apply_state` (409 when
   running). Closes the worst footgun. (~5 LOC + 1 test.)
3. **Finding 1.6** — Refuse `/cancel` when `apply_state == "running"`.
   Closes the orphan-apply + spawn-second-apply path. (~5 LOC + 1
   test.) Pair with a session-key change OR a process-wide "apply
   in flight" flag if the team wants belt-and-braces.

### Should-fix before smoke (serious)

4. **Finding 5.1** — `/apply-stream` 410/204 when state is terminal
   and queue is drained. Stops the silent-hang on stream reconnect
   after completion. (~5 LOC + 1 test.)
5. **Finding 2.3** — Either emit SSE `id:` lines + replay, OR
   detect post-drain reconnect and refuse it (overlaps with 5.1
   fix). Closes the "live progress page sits on Connecting…
   forever" UX bug. (~20 LOC + 2 tests.)
6. **Finding 1.4** — Reject concurrent SSE consumers on the same
   session OR fan-out. Pick the simpler option (reject with 409).
   (~10 LOC + 1 test.)
7. **Finding 4.1** — Reorder `_run_apply_task` finally so the grace
   timer arms BEFORE state transitions to terminal. Closes the
   race. (~3 LOC swap + 1 test that pins the order.)
8. **Finding 9.2** — Document the "re-apply clobbers hand-edits"
   behavior in the wizard's completion page Re-run blurb. Defer
   the diff/confirm UX to a future phase. (~2 lines of template
   copy.)

### Defer if time-constrained (minor)

9. **Finding 3.4** — Hold `_shutdown_after_delay` task ref. (~3 LOC.)
10. **Finding 7.1** — Reorder `apply_post` to create task before
    flipping state. (~3 LOC swap.)
11. **Finding 7.2** — Failsafe state-flip in `_run_apply_task`
    finally for cancellation path. (~3 LOC.)
12. **Finding 4.3** — Disable-on-click on Re-run and Apply forms.
    (~1 attribute per template.)
13. **Finding 1.1** — Add `asyncio.Lock` around the apply_state
    check-then-set. (~5 LOC.)

### Notes (no fix required)

Remaining `note`-severity findings document verified-correct or
verified-acceptable behavior. They are recorded so a future reader
doesn't re-investigate the same code paths.
