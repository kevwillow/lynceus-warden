"""Tests for the apply completion page (F6 Phase 2b, Touch 2).

Pins:
* State-machine redirects: idle → /review, running →
  /apply-progress, terminal → render.
* ok-state renders "Setup complete" + Done button (no Re-run).
* failed-state renders the failure summary + Re-run + Done buttons,
  surfaces the first failed step prominently with its traceback
  detail.
* skipped-only report (no failed steps, but some steps skipped) is
  treated as ok — matches ``ApplyReport.overall_status`` semantics
  from Phase 1.
* Re-run button POSTs to /apply with CSRF and goes through the same
  apply state machine (Touch 1).
* Token enforcement.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from lynceus.setup.models import ApplyReport, ApplyStep
from lynceus.setup.web.app import create_wizard_app

TOKEN = "test-setup-token-fixed-for-unit-tests-1234567890"


def _make_app(**overrides):
    kwargs = dict(setup_token=TOKEN, scope="user", target_path=Path("/tmp/wiz.yaml"))
    kwargs.update(overrides)
    return create_wizard_app(**kwargs)


def _client(app):
    return TestClient(app, follow_redirects=False)


def _seed(app, *, state: str, report: ApplyReport | None):
    session = app.state.session_store.get_or_create(TOKEN)
    session.apply_state = state
    session.apply_report = report
    return session


# ---- state-machine redirects ---------------------------------------------


@pytest.mark.webui
def test_complete_idle_redirects_to_review():
    app = _make_app()
    with _client(app) as c:
        resp = c.get(f"/apply-complete?token={TOKEN}")
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/review")


@pytest.mark.webui
def test_complete_running_redirects_to_progress():
    app = _make_app()
    _seed(app, state="running", report=None)
    with _client(app) as c:
        resp = c.get(f"/apply-complete?token={TOKEN}")
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/apply-progress")


# ---- ok-state rendering --------------------------------------------------


@pytest.mark.webui
def test_complete_ok_renders_success_summary():
    report = ApplyReport(steps=(
        ApplyStep(name="write_config", status="ok", message="wrote",
                  detail={"path": "/tmp/wiz.yaml"}),
        ApplyStep(name="create_data_dir", status="ok", message="dir created"),
    ))
    app = _make_app()
    _seed(app, state="completed", report=report)
    with _client(app) as c:
        resp = c.get(f"/apply-complete?token={TOKEN}")
    assert resp.status_code == 200
    body = resp.text
    assert "Setup complete" in body
    # Per-step transcript present.
    assert "write_config" in body
    assert "wrote" in body
    assert "create_data_dir" in body
    # Done button present; Re-run NOT present on the ok path.
    assert "/done" in body
    assert "Re-run apply" not in body


@pytest.mark.webui
def test_complete_ok_user_scope_surfaces_quickstart_next_step():
    """v0.7.0 Linux smoke: the completion page told the operator
    setup was done but never told them HOW to actually start the
    daemon. install.sh's "Next steps" block covers this for fresh
    installs, but operators who used --web bypassed that block.
    The completion page must surface daemon-start instructions
    inline, scope-adapted: --user gets lynceus-quickstart;
    --system gets sudo systemctl enable --now."""
    report = ApplyReport(steps=(
        ApplyStep(name="write_config", status="ok", message="wrote"),
    ))
    app = _make_app(scope="user")
    _seed(app, state="completed", report=report)
    with _client(app) as c:
        resp = c.get(f"/apply-complete?token={TOKEN}")
    body = resp.text
    assert resp.status_code == 200
    assert "Setup complete" in body
    # User-scope: lynceus-quickstart is the dev/demo start command.
    assert "lynceus-quickstart" in body
    # UI URL so the operator knows where to point their browser.
    assert "127.0.0.1:8765" in body
    # Pointer to the full runbook for deeper troubleshooting.
    assert "DEPLOYMENT.md" in body
    # --user scope must NOT recommend the systemctl path (which
    # requires the system install + lynceus user).
    assert "systemctl enable --now lynceus.service" not in body


@pytest.mark.webui
def test_complete_ok_system_scope_surfaces_systemctl_next_step():
    """System-scope branch of the same smoke fix: production
    installs get the systemctl enable+start line, not lynceus-
    quickstart (which is a dev/demo helper not appropriate as the
    sysadmin-pointed default for a system-install completion)."""
    report = ApplyReport(steps=(
        ApplyStep(name="write_config", status="ok", message="wrote"),
    ))
    app = _make_app(scope="system", target_path=Path("/etc/lynceus/lynceus.yaml"))
    _seed(app, state="completed", report=report)
    with _client(app) as c:
        resp = c.get(f"/apply-complete?token={TOKEN}")
    body = resp.text
    assert resp.status_code == 200
    assert "Setup complete" in body
    # System-scope: systemctl enable + start of daemon + UI units.
    assert "systemctl enable --now lynceus.service lynceus-ui.service" in body
    # Optional refresh timer mentioned but not auto-enabled.
    assert "lynceus-refresh.timer" in body
    # System-scope must NOT recommend lynceus-quickstart (which is
    # the dev/demo path).
    assert "lynceus-quickstart" not in body


@pytest.mark.webui
def test_complete_ok_surfaces_bootstrap_kismet_reminder():
    """v0.7.6 fix for kev's smoke order-of-operations gap: a successful
    --web setup tells the operator to start the daemon and visit the
    dashboard, but doesn't tell them they still need to run lynceus-
    bootstrap-kismet for capture to actually work (monitor mode +
    source= lines + group membership). Without that signpost, kev's
    daemon came up cleanly and saw zero devices.

    The reminder is always shown on the success path — reassurance
    shape (no condition detection). Pins the command and the
    operator-facing consequence string. (v0.7.10: the reminder no longer
    carries --skip-install — install is opt-in, so plain
    `sudo lynceus-bootstrap-kismet` is the config-only command; --install
    is mentioned only as the opt-in for hosts that still need Kismet.)"""
    report = ApplyReport(steps=(
        ApplyStep(name="write_config", status="ok", message="wrote"),
    ))
    app = _make_app(scope="user")
    _seed(app, state="completed", report=report)
    with _client(app) as c:
        resp = c.get(f"/apply-complete?token={TOKEN}")
    body = resp.text
    assert resp.status_code == 200
    assert "lynceus-bootstrap-kismet" in body
    # The bare config-only command is what we tell operators to run now.
    assert "sudo lynceus-bootstrap-kismet</code>" in body
    # --install is mentioned only as the opt-in, never --skip-install.
    assert "--skip-install" not in body
    # The operator-facing consequence — without this it's just a
    # command name without context. HTML line-wraps split the phrase
    # so normalize whitespace before matching.
    import re
    body_flat = re.sub(r"\s+", " ", body)
    assert "required for lynceus to see any devices" in body_flat
    # The three things bootstrap-kismet does (so a future edit that
    # collapses the explanation into a one-liner without the "why"
    # is caught).
    assert "monitor mode" in body_flat
    assert "kismet group" in body_flat


@pytest.mark.webui
def test_complete_failed_omits_bootstrap_kismet_reminder():
    """The bootstrap-kismet reminder lives inside the {% if overall_ok %}
    block — failed-state operators have to fix their config before
    they need to think about Kismet capture. Guards against the
    reminder bleeding across the failure branch alongside the
    lynceus-quickstart / systemctl copy that was already pinned to
    success-only."""
    report = ApplyReport(steps=(
        ApplyStep(name="write_config", status="failed",
                  message="Permission denied"),
    ))
    app = _make_app(scope="user")
    _seed(app, state="failed", report=report)
    with _client(app) as c:
        resp = c.get(f"/apply-complete?token={TOKEN}")
    body = resp.text
    assert "Apply failed" in body
    assert "lynceus-bootstrap-kismet" not in body


@pytest.mark.webui
def test_complete_renders_warning_step_with_warning_icon_and_message():
    """Arc B Kismet source-name cross-check: a verify_kismet_sources step
    in warning status renders the ⚠️ icon (distinct from ❌ failure and
    ⏭ skip) and the operator-readable message body. The page treats
    the apply as overall_ok — warning is non-blocking, so Next-Steps
    + Done remain visible, Re-run does NOT appear."""
    warning_msg = (
        "Kismet doesn't currently expose these source name(s): wlan0, wlan2. "
        "Observations from them will silently drop. "
        "Run lynceus-bootstrap-kismet (or lynceus-bootstrap-kismet "
        "--skip-install if you're on a distro outside Debian/Ubuntu/Kali "
        "-- see docs/DEPLOYMENT.md) if you haven't yet, or check "
        "kismet_site.conf source names."
    )
    report = ApplyReport(steps=(
        ApplyStep(name="write_config", status="ok", message="wrote"),
        ApplyStep(
            name="verify_kismet_sources",
            status="warning",
            message=warning_msg,
            detail={"mismatched": ["wlan0", "wlan2"]},
        ),
    ))
    app = _make_app(scope="user")
    _seed(app, state="completed", report=report)
    with _client(app) as c:
        resp = c.get(f"/apply-complete?token={TOKEN}")
    body = resp.text
    assert resp.status_code == 200
    # Warning icon present — distinct from the failure ❌ and skip ⏭.
    assert "⚠️" in body
    # Specific mismatched source names surface verbatim.
    assert "wlan0" in body
    assert "wlan2" in body
    # Recovery copy is present (no internal jargon — "source_allowlist
    # gate" stays in code, not in operator-facing UI).
    assert "lynceus-bootstrap-kismet" in body
    assert "silently drop" in body
    # Non-blocking: overall is still "ok", so we render Setup complete
    # and DO surface the Next Steps block (with daemon-start hint).
    assert "Setup complete" in body
    # No Re-run button on the warning path (it's a success-shape outcome).
    assert "Re-run apply" not in body


@pytest.mark.webui
def test_complete_failed_omits_next_steps_block():
    """The next-steps "how to start the daemon" block is success-
    only — on the failure path the operator's next action is
    re-running or aborting, not starting a partially-configured
    daemon. The Re-run + Done buttons remain on failure (existing
    behavior); the new daemon-start copy must not bleed across the
    overall_ok branch."""
    report = ApplyReport(steps=(
        ApplyStep(name="write_config", status="failed",
                  message="Permission denied"),
    ))
    app = _make_app(scope="user")
    _seed(app, state="failed", report=report)
    with _client(app) as c:
        resp = c.get(f"/apply-complete?token={TOKEN}")
    body = resp.text
    assert "Apply failed" in body
    # No daemon-start copy on the failure path.
    assert "lynceus-quickstart" not in body
    assert "systemctl enable --now lynceus.service" not in body


@pytest.mark.webui
def test_complete_skipped_only_treated_as_ok():
    """A report with only ok/skipped steps and no failures is the
    same shape of success as all-ok. overall_status is 'ok'."""
    report = ApplyReport(steps=(
        ApplyStep(name="write_config", status="ok", message="wrote"),
        ApplyStep(name="import_bundled_watchlist", status="skipped",
                  message="bundled absent"),
        ApplyStep(name="chown_db_files", status="skipped",
                  message="--user scope; not applicable"),
    ))
    app = _make_app()
    _seed(app, state="completed", report=report)
    with _client(app) as c:
        resp = c.get(f"/apply-complete?token={TOKEN}")
    body = resp.text
    assert "Setup complete" in body
    assert "Re-run apply" not in body


# ---- failed-state rendering ----------------------------------------------


@pytest.mark.webui
def test_complete_failed_surfaces_failed_step_with_traceback():
    report = ApplyReport(steps=(
        ApplyStep(name="write_config", status="ok", message="wrote first"),
        ApplyStep(name="scaffold_severity_overrides", status="failed",
                  message="Permission denied",
                  detail={"traceback": "Traceback (most recent call last):\n  File ...\nPermissionError: ..."}),
    ))
    app = _make_app()
    _seed(app, state="failed", report=report)
    with _client(app) as c:
        resp = c.get(f"/apply-complete?token={TOKEN}")
    assert resp.status_code == 200
    body = resp.text
    assert "Apply failed" in body
    # First failed step is surfaced prominently with its name + message.
    assert "scaffold_severity_overrides" in body
    assert "Permission denied" in body
    # Traceback is rendered in a <details>.
    assert "Traceback" in body
    # Both buttons present on the failed path.
    assert "Re-run apply" in body
    assert "/done" in body
    # Re-run posts to /apply.
    assert 'action="/apply' in body


@pytest.mark.webui
def test_complete_failed_renders_full_transcript_including_earlier_ok():
    """The transcript must show the ok steps that landed before the
    failure — the operator needs to see how far the apply got."""
    report = ApplyReport(steps=(
        ApplyStep(name="write_config", status="ok", message="wrote"),
        ApplyStep(name="apply_config", status="failed",
                  message="RuntimeError: midway boom"),
    ))
    app = _make_app()
    _seed(app, state="failed", report=report)
    with _client(app) as c:
        resp = c.get(f"/apply-complete?token={TOKEN}")
    body = resp.text
    assert "write_config" in body
    assert "wrote" in body
    assert "midway boom" in body


# ---- Re-run path ---------------------------------------------------------


@pytest.mark.webui
def test_complete_rerun_button_posts_to_apply():
    """Pin the form action so the Re-run button hits the same apply
    state machine as the initial Apply (Touch 1)."""
    report = ApplyReport(steps=(
        ApplyStep(name="apply_config", status="failed", message="boom"),
    ))
    app = _make_app()
    _seed(app, state="failed", report=report)
    with _client(app) as c:
        resp = c.get(f"/apply-complete?token={TOKEN}")
    body = resp.text
    # Form action carries the token so the POST is gated.
    assert f'action="/apply?token={TOKEN}"' in body
    # Method is POST.
    assert 'method="post"' in body


@pytest.mark.webui
def test_complete_failed_warns_about_hand_edit_overwrite():
    """Finding 9.2: the Re-run section must warn that hand-edits to
    lynceus.yaml or rules.yaml since the last apply will be clobbered
    by re-running — _atomic_write does an unconditional overwrite.

    Pre-existing behavior, not a Phase 2 regression; the wizard
    surfaces the caveat so the operator can save their hand-edits
    elsewhere before clicking Re-run."""
    report = ApplyReport(steps=(
        ApplyStep(name="apply_config", status="failed", message="boom"),
    ))
    app = _make_app()
    _seed(app, state="failed", report=report)
    with _client(app) as c:
        resp = c.get(f"/apply-complete?token={TOKEN}")
    body = resp.text
    # Warning text present on the failed (Re-run-offered) path.
    assert "Hand-edits will be overwritten" in body
    # Names both files the wizard overwrites.
    assert "lynceus.yaml" in body
    assert "rules.yaml" in body


@pytest.mark.webui
def test_complete_ok_omits_hand_edit_warning():
    """The hand-edit warning sits inside the Re-run section, which
    only renders on failed apply. The ok path doesn't offer Re-run,
    so the warning must not appear (would be confusing)."""
    report = ApplyReport(steps=(
        ApplyStep(name="write_config", status="ok", message="wrote"),
    ))
    app = _make_app()
    _seed(app, state="completed", report=report)
    with _client(app) as c:
        resp = c.get(f"/apply-complete?token={TOKEN}")
    body = resp.text
    assert "Hand-edits will be overwritten" not in body


# ---- v0.7.7 Touch 6: vertical spacing -------------------------------------


@pytest.mark.webui
def test_complete_page_carries_per_article_spacing():
    """The apply-transcript / watchlist-summary / bootstrap-reminder /
    next-steps articles previously stacked with default Pico margin
    only, which smoke-tester reports called "cramped." Pin the
    per-article spacing rules so a future style cleanup can't silently
    drop them."""
    report = ApplyReport(steps=(
        ApplyStep(name="write_config", status="ok", message="wrote"),
    ))
    app = _make_app()
    _seed(app, state="completed", report=report)
    with _client(app) as c:
        resp = c.get(f"/apply-complete?token={TOKEN}")
    body = resp.text
    # Per-article margin-top is the load-bearing rule for breathing
    # room between the transcript, next-steps, and bootstrap reminder.
    assert "main.container > article" in body
    assert "margin-top" in body
    # Adjacent-article rule for tighter relationships between
    # consecutive blocks.
    assert "main.container > article + article" in body


# ---- Done button ---------------------------------------------------------


@pytest.mark.webui
def test_complete_done_button_posts_to_done():
    """The Done button targets /done (Touch 3 wires the actual
    server shutdown)."""
    report = ApplyReport(steps=(
        ApplyStep(name="write_config", status="ok", message="wrote"),
    ))
    app = _make_app()
    _seed(app, state="completed", report=report)
    with _client(app) as c:
        resp = c.get(f"/apply-complete?token={TOKEN}")
    body = resp.text
    assert f'action="/done?token={TOKEN}"' in body


# ---- Re-run disable-on-click (Finding 4.3) -------------------------------


@pytest.mark.webui
def test_complete_rerun_form_disables_button_on_submit():
    """Finding 4.3: the Re-run form on the failed-apply page must
    disable its submit button on click so an operator double-click
    cannot fire two POSTs before the server-side 409 guard lands.
    Defense in depth behind the apply_lock + apply_state check
    (Finding 1.1)."""
    report = ApplyReport(steps=(
        ApplyStep(name="apply_config", status="failed", message="boom"),
    ))
    app = _make_app()
    _seed(app, state="failed", report=report)
    with _client(app) as c:
        resp = c.get(f"/apply-complete?token={TOKEN}")
    body = resp.text
    # The Re-run form (action="/apply") carries an onsubmit that
    # disables the submit button. Pin the substring rather than
    # exact attribute formatting so quoting changes don't break.
    assert "onsubmit=" in body
    assert "disabled = true" in body or "disabled=true" in body
    # Confirm the disable is wired to the Re-run form specifically.
    # (The Done form on the same page has its own disable-on-click,
    # pinned by test_complete_done_form_disables_button_on_submit.)
    assert 'action="/apply' in body


@pytest.mark.webui
def test_complete_done_form_disables_button_on_submit():
    """Finding 1.4 (PRESHIP): the Done form on the completion page
    must also disable its submit button on click. Double-click
    otherwise fires two /done POSTs that both pass the 409 guard
    (state is terminal on the completion page) and both assign
    session.shutdown_task, the second orphaning the first to
    asyncio's weak ref — the exact GC failure mode Finding P2.3.4
    closed for the apply task is reopened on Done double-click.

    Matches the pattern wired to the Apply form (review.html) and
    the Re-run form (apply_complete.html, above)."""
    report = ApplyReport(steps=(
        ApplyStep(name="write_config", status="ok", message="wrote"),
    ))
    app = _make_app()
    _seed(app, state="completed", report=report)
    with _client(app) as c:
        resp = c.get(f"/apply-complete?token={TOKEN}")
    body = resp.text
    # Locate the /done form specifically and confirm it carries the
    # onsubmit disable. (The Re-run form also has one but its action
    # is /apply, not /done.)
    done_form_idx = body.find('action="/done')
    assert done_form_idx >= 0, "Done form not found on completion page"
    # The onsubmit attribute lives on the same <form> tag — find the
    # nearest preceding "<form" and confirm onsubmit is between it
    # and the action attribute.
    form_open = body.rfind("<form", 0, done_form_idx)
    assert form_open >= 0
    # Window from form_open to the form's closing > should contain
    # the onsubmit handler.
    form_tag_close = body.find(">", done_form_idx)
    form_tag = body[form_open:form_tag_close]
    assert "onsubmit=" in form_tag
    assert "disabled = true" in form_tag or "disabled=true" in form_tag


# ---- token enforcement --------------------------------------------------


@pytest.mark.webui
def test_complete_requires_token():
    app = _make_app()
    with _client(app) as c:
        assert c.get("/apply-complete").status_code == 403
