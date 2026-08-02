# Audit register

Findings from the gap audit: **what a surface claims** vs **what the code does**. The bug class is
the control plane working while the payload never lands — the handler returns 200, the row is
written, the UI turns green, and the thing that was supposed to change never changes.

**Taken at**: `3704737`, 2026-08-02. Wave 1 of a planned sweep; 4 of ~16 surfaces covered.

Every entry below was confirmed at its file:line by re-reading the code, not accepted from the
auditor that reported it. **Three of the four reported CORE-BROKEN findings did not survive that
check** — see *Refuted* below, and read it before re-reporting any of them.

---

## Confirmed

| # | Finding | Anchor | Bucket |
|---|---|---|---|
| 1 | `find("r1")` matches random token content, not the rule row, so the assertion window misses `fires`. Flaky, ~1 run in 100. Caused the single failure in a 17-minute suite run. | `tests/test_webui.py:1194` | 🔴 test defect |
| 2 | README claims "at runtime the only outbound connections are to the ntfy broker you configured and to GitHub". This omits Kismet, which every poll tick contacts and which accepts any `http(s)` host. | `README.md:136-138`, `src/lynceus/config.py:29-34`, `src/lynceus/kismet.py:655-660` | 🟡 doc inaccuracy |
| 3 | The UI writes `allowlist_ui.yaml`, a YAML file that changes alerting behaviour, while the README says "every config change happens out-of-band via `lynceus-setup` or the YAML". Defensible — it is a daemon-managed operational store, not `lynceus.yaml` — but the wording invites the opposite reading. | `src/lynceus/webui/app.py:2321`, `README.md:133-135` | 🟡 wording |

### Cross-cutting: the test suite is the accomplice

Three independent auditors each flagged the same pattern without being told to look for it. Every
one of these is a test that claims an end-to-end guarantee and mocks the boundary that would prove it:

| Claim | What the test actually does | Anchor |
|---|---|---|
| allowlist suppression works end to end | manually reloads the allowlist instead of exercising `Poller._maybe_reload_allowlist`; supplies no real notifier | `tests/test_webui.py:4556`, `:4566` |
| BLE bridge scans passively | replaces the scan boundary with `fake_scan` | `tests/test_poller_ble_bridge.py:54-57` |
| probe-SSID opt-out holds | substitutes `_ListClient` for the Kismet transport | `tests/test_tier1_capture.py:468-497` |

The production call paths were separately read and are correct. The point is narrower and still
matters: **these three guarantees currently rest on reading the code, not on the tests that cite
them.** One live end-to-end run would be worth more than all three.

---

## Refuted — do not re-report without new evidence

| Reported as | Why it does not hold |
|---|---|
| **CORE-BROKEN**: device silence secretly stops watchful tracking, contradicting "tracking continues regardless" | Three different mechanisms were conflated. The watch form's `snooze_duration` creates a *watchful entry* (`app.py:3246`, `create_watchful_from_alert`), not an allowlist entry, so its tooltip is accurate about its own control. Allowlist precedence is deliberate and documented three times: `poller.py:288-300` in-line, `WATCHFUL_SNOOZE_DESIGN.md:148`, and `:489-493` ("an allowlisted MAC under watchful snooze sees no `sighting_count`"). The cited `:569` describes the *per-alert* snooze, a fourth mechanism, which genuinely is orthogonal. |
| **CORE-BROKEN**: the read-only UI promise is false because 23 mutative POST routes exist | The promise is scoped: "surfaces state and never mutates **configuration**" (`README.md:133-135`). Acks, snoozes, notes and watchful entries are operational state, not configuration. The one residual point is recorded as finding 3 above, at its real severity. |

⭐ **The lesson to carry into wave 2.** Both refutations came from a delegate reading a promise more
broadly than it was written, then finding code that failed the broadened version. Quote the promise
verbatim before judging whether code violates it. A delegate's report is a lead, not a finding.

---

## ✅ Verified working end to end — do not re-audit before `3704737` changes

| Surface | Evidence |
|---|---|
| Passive only | Kismet integration exposes REST GETs only (`kismet.py:655-660`, `:680-686`, `:735-740`); no association or injection API exists. BLE constructs Bleak with `scanning_mode="passive"` (`bridges/ble.py:349-358`) and is really started by the daemon (`poller.py:1316-1319`). |
| Probe SSIDs off by default | Default `False` (`config.py:51`), propagated into the real poll (`poller.py:513-519`), gates extraction (`kismet.py:568-570`) and storage (`poller.py:229-237`). Evidence snapshots redact nested probe fields (`evidence.py:100-128`). |
| No telemetry (phone-home) | No analytics implementation or dependency; UI assets local (`templates/base.html:114-116`); ntfy POSTs only when configured (`notify.py:165`). See finding 2 for the wording gap. |
| Allowlist / device snooze | UI writes `allowlist_ui.yaml` (`app.py:2352`); poller reloads before each tick (`poller.py:1335`); match returns before both `add_alert` and `notifier.send` (`poller.py:286`, `:411`). |
| Rule snooze / unsnooze | POST commits or deletes the row (`app.py:3521`, `:3540`); every rule hit reads it before row creation and notification (`poller.py:386`). |

---

## Not yet audited

`/settings` and the ntfy notifier were swept but their reports are not yet verified. Untouched:
watchlist provenance, rules-engine matching, devices and probes surfaces, health and poll-tick
observability, dark-mode persistence, config reload semantics, multi-adapter deployment, systemd
unit hardening, migration rollback.

## Method note

Do not run gates from a throwaway worktree. A worktree relocates `Path(__file__).parents[1].parent`
and **silently disables** the cross-repo Argus test — it skips rather than fails, so the suite looks
better than the repo root's baseline. Measured this session: worktree reported 0 Argus failures
where the repo root reports 1. See `.claude/gates.md`.
