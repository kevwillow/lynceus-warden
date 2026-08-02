"""Regression tests for apply_config's ``argus_choice`` dispatch (v0.7.6 Tier 4).

The wizard's argus step (steps_argus.py) captures the operator's
load-mode choice and passes it through review.py's apply route to
``apply_config``. These tests pin the four modes' dispatch outcomes
plus the Skip-preserves-existing-watchlist invariant the spec calls
out explicitly.

We exercise ``apply_config`` directly with a Config + an explicit
``ArgusChoice`` so the contract is tied to the dispatch helper, not
the wizard frontend's form handler.
"""

from __future__ import annotations

import pytest

from lynceus.cli import setup as wiz
from lynceus.config import CaptureConfig, Config
from lynceus.setup import core as setup_core
from lynceus.setup.core import apply_config
from lynceus.setup.models import ArgusChoice

# ---- fixtures --------------------------------------------------------------


def _config() -> Config:
    return Config(
        kismet_url="http://127.0.0.1:2501",
        kismet_api_key="testtoken",
        kismet_sources=["wlan0"],
        capture=CaptureConfig(probe_ssids=False, ble_friendly_names=True),
        ntfy_url="https://ntfy.sh",
        ntfy_topic="lynceus-abc123",
        min_rssi=-70,
    )


@pytest.fixture
def _isolated_paths(monkeypatch, tmp_path):
    from lynceus import paths as paths_mod

    data_dir = tmp_path / "data"
    log_dir = tmp_path / "log"
    db_path = data_dir / "lynceus.db"
    monkeypatch.setattr(paths_mod, "default_data_dir", lambda scope: data_dir)
    monkeypatch.setattr(paths_mod, "default_log_dir", lambda scope: log_dir)
    monkeypatch.setattr(paths_mod, "default_db_path", lambda scope: db_path)
    return {"data_dir": data_dir, "log_dir": log_dir, "db_path": db_path}


@pytest.fixture(autouse=True)
def _stub_verify_kismet(monkeypatch):
    """Default the kismet cross-check to "unreachable" so apply_config
    completes without touching a real Kismet."""

    class _Unreachable:
        def list_sources(self, *, only_running=True):
            raise RuntimeError("Kismet unreachable (test stub)")

    monkeypatch.setattr(
        setup_core, "_make_verify_kismet_client", lambda config: _Unreachable()
    )


def _step(report, name):
    return next(s for s in report.steps if s.name == name)


def _apply_args(tmp_path):
    return {
        "scope": "user",
        "target_path": tmp_path / "lynceus.yaml",
        "severity_overrides_path": tmp_path / "severity_overrides.yaml",
        "allowlist_path": tmp_path / "allowlist.yaml",
        "enabled_rule_types": None,
    }


# ---- (a) Skip ---------------------------------------------------------------


def test_argus_choice_skip_does_not_call_importer(_isolated_paths, tmp_path, monkeypatch):
    """Skip mode must not invoke any importer; the step renders as
    skipped with the operator-choice message."""
    # Sentinel: fail loudly if any code path tries to import bundled.
    monkeypatch.setattr(
        wiz,
        "import_bundled_watchlist",
        lambda *a, **kw: pytest.fail("Skip mode must not call import_bundled_watchlist"),
    )
    # Sentinel: fail if anyone shells out to lynceus-import-argus.
    monkeypatch.setattr(
        setup_core.subprocess,
        "Popen",
        lambda *a, **kw: pytest.fail("Skip mode must not subprocess into lynceus-import-argus"),
    )
    report = apply_config(
        _config(),
        **_apply_args(tmp_path),
        argus_choice=ArgusChoice(mode="skip"),
    )
    step = _step(report, "import_bundled_watchlist")
    assert step.status == "skipped"
    assert "operator choice" in step.message.lower()
    assert step.detail and step.detail.get("argus_choice") == "skip"


# ---- Skip-preserves-existing-watchlist regression --------------------------


def test_argus_choice_skip_preserves_existing_watchlist_rows(
    _isolated_paths, tmp_path, monkeypatch
):
    """Re-running the wizard with Skip against an existing populated
    DB must leave the existing watchlist rows in place. Skip means
    "don't run the importer," not "clear the watchlist." This was
    called out explicitly in the v0.7.6 Tier 4 spec."""
    from lynceus.db import Database

    db_path = _isolated_paths["db_path"]
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db = Database(str(db_path))
    try:
        with db._conn:
            db._conn.execute(
                "INSERT INTO watchlist(pattern, pattern_type, severity, description) "
                "VALUES (?, ?, ?, ?)",
                ("aa:bb:cc:dd:ee:ff", "mac", "high", "test row"),
            )
            db._conn.execute(
                "INSERT INTO watchlist(pattern, pattern_type, severity, description) "
                "VALUES (?, ?, ?, ?)",
                ("Flock", "ssid", "med", "test ssid row"),
            )
    finally:
        db.close()

    apply_config(
        _config(),
        **_apply_args(tmp_path),
        argus_choice=ArgusChoice(mode="skip"),
    )

    db = Database(str(db_path))
    try:
        rows = db._conn.execute(
            "SELECT pattern, pattern_type, severity FROM watchlist ORDER BY pattern"
        ).fetchall()
    finally:
        db.close()
    patterns = [(r["pattern"], r["pattern_type"]) for r in rows]
    assert ("Flock", "ssid") in patterns
    assert ("aa:bb:cc:dd:ee:ff", "mac") in patterns


# ---- (b) Bundled ----------------------------------------------------------


def test_argus_choice_bundled_invokes_bundled_importer(
    _isolated_paths, tmp_path, monkeypatch
):
    """Bundled mode must call the existing import_bundled_watchlist
    code path against the wheel-shipped CSV."""
    seen_calls: list[dict] = []

    def fake_bundled(db_path, override_file):
        seen_calls.append({"db_path": db_path, "override_file": override_file})
        return True, "imported 12345 records"

    monkeypatch.setattr(wiz, "import_bundled_watchlist", fake_bundled)
    report = apply_config(
        _config(),
        **_apply_args(tmp_path),
        argus_choice=ArgusChoice(mode="bundled"),
    )
    assert len(seen_calls) == 1
    step = _step(report, "import_bundled_watchlist")
    assert step.status == "ok"
    assert step.detail and step.detail.get("argus_choice") == "bundled"


# ---- (c, d) GitHub --------------------------------------------------------


class _FakePopen:
    """Minimal subprocess.Popen stand-in for the github / file paths.

    Captures the argv tail so tests can pin the operator's choice
    (e.g. --from-github --repo OWNER/NAME --ref TAG) reached the
    importer subprocess.
    """

    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = ""):
        self._returncode = returncode
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = returncode
        self.invoked_argv: list[str] | None = None

    def __call__(self, argv, **kwargs):
        # Popen is the constructor; record argv then return self as
        # the proc handle.
        self.invoked_argv = list(argv)
        return self

    def communicate(self, timeout=None):
        return self._stdout, self._stderr


def test_argus_choice_github_success_emits_ok(
    _isolated_paths, tmp_path, monkeypatch
):
    """GitHub mode with a successful subprocess emits an ok step
    naming the resolved ref (or 'latest' when ref is None)."""
    fake = _FakePopen(returncode=0, stdout="imported 41428 records\n", stderr="")
    monkeypatch.setattr(setup_core.subprocess, "Popen", fake)
    report = apply_config(
        _config(),
        **_apply_args(tmp_path),
        argus_choice=ArgusChoice(
            mode="github",
            github_repo="kevwillow/argus-db",
            github_ref="v1.4.1",
        ),
    )
    step = _step(report, "import_bundled_watchlist")
    assert step.status == "ok"
    assert "v1.4.1" in step.message
    assert "kevwillow/argus-db" in step.message
    assert fake.invoked_argv is not None
    assert "--from-github" in fake.invoked_argv
    assert "--repo" in fake.invoked_argv
    assert "kevwillow/argus-db" in fake.invoked_argv
    assert "--ref" in fake.invoked_argv
    assert "v1.4.1" in fake.invoked_argv


def test_argus_choice_github_failure_emits_warning(
    _isolated_paths, tmp_path, monkeypatch
):
    """GitHub mode with a non-zero exit emits warning (not failed),
    so the apply still completes and the operator can retry."""
    fake = _FakePopen(
        returncode=1, stdout="", stderr="HTTPSConnectionPool: name resolution failed\n"
    )
    monkeypatch.setattr(setup_core.subprocess, "Popen", fake)
    report = apply_config(
        _config(),
        **_apply_args(tmp_path),
        argus_choice=ArgusChoice(mode="github", github_repo="kevwillow/argus-db"),
    )
    step = _step(report, "import_bundled_watchlist")
    assert step.status == "warning", (
        f"GitHub failure must degrade to warning, got {step.status}: {step.message}"
    )
    assert "github" in step.message.lower() or "fetch" in step.message.lower()
    # The apply must still complete overall (warning is non-blocking).
    assert report.overall_status == "ok"


# ---- (e, f) File ----------------------------------------------------------


def test_argus_choice_file_valid_csv_emits_ok(_isolated_paths, tmp_path, monkeypatch):
    """File mode with a readable Argus CSV at an absolute path emits
    ok after the importer subprocess returns success."""
    csv_path = tmp_path / "operator.csv"
    csv_path.write_text(
        "# meta: schema_version=30, exported_at=2026-05-25T00:00:00Z, "
        "record_count=2, confidence_threshold=0\n"
        "argus_record_id,id,identifier,identifier_type,device_category,"
        "manufacturer,model,confidence,source_type,source_url,source_excerpt,"
        "geographic_scope,description,first_seen,last_verified,notes\n",
        encoding="utf-8",
    )
    fake = _FakePopen(returncode=0, stdout="imported 0 records\n")
    monkeypatch.setattr(setup_core.subprocess, "Popen", fake)
    report = apply_config(
        _config(),
        **_apply_args(tmp_path),
        argus_choice=ArgusChoice(mode="file", file_path=str(csv_path)),
    )
    step = _step(report, "import_bundled_watchlist")
    assert step.status == "ok"
    assert fake.invoked_argv is not None
    assert "--input" in fake.invoked_argv
    assert str(csv_path) in fake.invoked_argv


def test_argus_choice_file_missing_path_emits_failed_with_path_named(
    _isolated_paths, tmp_path, monkeypatch
):
    """File mode with a missing path emits failed (not warning) and
    names the offending path so the operator can copy-paste from the
    apply transcript."""
    missing = tmp_path / "does_not_exist.csv"
    # Sentinel: importer subprocess must not run on validation failure.
    monkeypatch.setattr(
        setup_core.subprocess,
        "Popen",
        lambda *a, **kw: pytest.fail(
            "File-validation failure must not reach the importer subprocess"
        ),
    )
    report = apply_config(
        _config(),
        **_apply_args(tmp_path),
        argus_choice=ArgusChoice(mode="file", file_path=str(missing)),
    )
    step = _step(report, "import_bundled_watchlist")
    assert step.status == "failed"
    assert str(missing) in step.message
