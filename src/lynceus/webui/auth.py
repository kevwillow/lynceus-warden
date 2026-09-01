"""Single-operator password authentication for the lynceus web UI.

Three pieces, deliberately separable so each can be tested without a server:

* ``hash_password`` / ``verify_password`` — scrypt, stdlib only, self-describing
  encoding so the cost parameters can change without a migration.
* ``SessionStore`` — server-side sessions keyed by a random token. In memory,
  so a restart logs the operator out and revocation is a dict deletion rather
  than a signature scheme with a revocation list bolted on.
* ``AuthMiddleware`` — ASGI, enforcing the session on every request that is not
  explicitly exempt.

⛔ **Middleware, not ``Depends()``.** There are 42 routes. A per-route dependency
is a list a new route can silently fall off, which is precisely the failure this
repo has already shipped twice (``DOWNLOAD_SUFFIXES`` in the browser gate; the
hardcoded POST-route list that four merges outran, see
``tests/test_webui_post_routes_are_classified.py``). A middleware is fail-closed
by construction: a route added tomorrow is behind it without anyone remembering,
and the thing that has to be maintained is the much shorter EXEMPT list — where
forgetting an entry produces a visible 401 rather than a silent hole.

⚠️ **What this does not do.** It authenticates ONE operator against ONE password.
There are no accounts, no roles, and no audit of who did what, because the
system has exactly one user by design. If that stops being true, this module is
the wrong shape and should be replaced rather than extended.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from collections.abc import Iterable
from dataclasses import dataclass, field

# --- Password hashing ---------------------------------------------------------

#: scrypt cost parameters. N=2**14 with r=8 is ~16 MB of working memory per
#: verification, which is the point: it is what makes an offline attack on a
#: stolen hash expensive.
#:
#: ⚠️ The Pi is the deployment target and these were NOT measured there. On the
#: 12-core desktop a verification is ~15 ms (see tests/test_webui_auth.py::
#: test_a_verification_is_not_absurdly_slow, which asserts a ceiling rather than
#: a value). If a Pi turns out to be slow enough to matter, lower SCRYPT_N and
#: leave the encoding alone — that is what the parameters-in-the-string format
#: is for, and existing hashes keep verifying at the cost they were written at.
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
SCRYPT_SALT_BYTES = 16

#: Cap on what we will feed to scrypt. Without it, a POST body of a few hundred
#: megabytes becomes a few hundred megabytes of hashing on an UNAUTHENTICATED
#: route — a denial of service delivered through the login form.
MAX_PASSWORD_BYTES = 1024

#: The floor a new password must clear. Not a policy about character classes
#: (which push operators towards `Passw0rd!`), just length, which is the part
#: that actually buys anything.
MIN_PASSWORD_LENGTH = 12


class PasswordError(ValueError):
    """A password was rejected before it was ever hashed."""


def hash_password(password: str) -> str:
    """Return a self-describing scrypt hash: ``scrypt$N$r$p$salt$key``.

    The parameters travel with the hash so ``verify_password`` never has to
    assume the constants above were the ones in force when it was written.
    """
    _check_password_bounds(password)
    salt = secrets.token_bytes(SCRYPT_SALT_BYTES)
    key = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_DKLEN,
    )
    return "$".join(
        [
            "scrypt",
            str(SCRYPT_N),
            str(SCRYPT_R),
            str(SCRYPT_P),
            base64.b64encode(salt).decode("ascii"),
            base64.b64encode(key).decode("ascii"),
        ]
    )


def _check_password_bounds(password: str) -> None:
    if not isinstance(password, str):
        raise PasswordError("password must be a string")
    encoded = password.encode("utf-8")
    if len(encoded) > MAX_PASSWORD_BYTES:
        raise PasswordError(
            f"password is longer than {MAX_PASSWORD_BYTES} bytes; that is a "
            "denial-of-service vector, not a strong password"
        )
    if len(password) < MIN_PASSWORD_LENGTH:
        raise PasswordError(
            f"password must be at least {MIN_PASSWORD_LENGTH} characters "
            f"(got {len(password)})"
        )


def verify_password(password: str, encoded: str) -> bool:
    """Constant-time verify against a ``hash_password`` string.

    ⛔ Returns False for a malformed or unparseable ``encoded`` rather than
    raising. The caller is a login handler on an unauthenticated route; a
    traceback there is a 500 that distinguishes "credentials file is corrupt"
    from "wrong password" for anyone who can reach the port.
    """
    if not isinstance(password, str) or not isinstance(encoded, str):
        return False
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        return False
    parts = encoded.split("$")
    if len(parts) != 6 or parts[0] != "scrypt":
        return False
    try:
        n, r, p = int(parts[1]), int(parts[2]), int(parts[3])
        salt = base64.b64decode(parts[4], validate=True)
        expected = base64.b64decode(parts[5], validate=True)
    except (ValueError, TypeError):
        return False
    # A hostile credentials file could otherwise name N=2**30 and turn one
    # login attempt into an out-of-memory kill.
    if not (0 < n <= 2**20) or not (0 < r <= 32) or not (0 < p <= 16):
        return False
    if n & (n - 1):  # scrypt requires a power of two; hashlib raises otherwise
        return False
    try:
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=n,
            r=r,
            p=p,
            dklen=len(expected) or SCRYPT_DKLEN,
        )
    except (ValueError, MemoryError):
        return False
    return hmac.compare_digest(actual, expected)


#: A real hash of a value nobody knows, verified against when no credential is
#: configured or the submitted form has no password. Without it, "no password is
#: set on this install" answers in microseconds while a wrong password takes
#: ~15 ms, and the difference is readable from off the machine.
_DUMMY_HASH = hash_password(secrets.token_urlsafe(32))


def verify_against_configured(password: str, encoded: str | None) -> bool:
    """Verify, burning the same work when there is nothing to verify against."""
    if encoded is None:
        verify_password(password or "x" * MIN_PASSWORD_LENGTH, _DUMMY_HASH)
        return False
    return verify_password(password, encoded)


# --- Sessions -----------------------------------------------------------------

SESSION_COOKIE_NAME = "lynceus_session"

#: Idle timeout. Deliberately equal to ``csrf.CSRF_COOKIE_MAX_AGE``: a session
#: that outlives its CSRF cookie gives the operator a page that looks logged in
#: and answers 403 "CSRF token mismatch" to every button, which reads as a bug
#: rather than as an expiry.
#:
#: ⚠️ The relationship is the point, not the number, and it is asserted rather
#: than transcribed — see
#: ``test_the_session_idle_window_does_not_outlive_the_csrf_cookie``. Writing
#: ``60 * 60 * 8`` in two files and a comment claiming they match is how the
#: comment goes on saying "deliberately equal" after somebody changes one.
SESSION_IDLE_SECONDS = 60 * 60 * 8

#: Absolute ceiling, refreshed by nothing. A session that is used every seven
#: hours forever is still a session that was authenticated once.
SESSION_ABSOLUTE_SECONDS = 60 * 60 * 24 * 7

SESSION_TOKEN_BYTES = 32


@dataclass
class _Session:
    created_at: float
    last_seen_at: float


class SessionStore:
    """In-memory session table.

    ⚠️ **In memory, and that is a decision with a visible consequence:**
    restarting ``lynceus-ui`` logs the operator out. The alternative — a signed
    stateless cookie — makes logout and revocation into problems that need
    their own machinery, and makes a leaked signing key a permanent forgery
    rather than something a restart ends. For a single-operator tool that is
    restarted by systemd rarely, being logged out on restart is the cheaper
    side of that trade. It is documented in docs/CONFIGURATION.md so it is not
    discovered as a bug.

    ⭐ It also buys the property a stateless cookie would have had to build:
    **changing the password revokes every existing session.** Not by any code
    here — the credentials file is read once at startup, so a password change
    requires a restart, and a restart empties this table. There is deliberately
    no ``revoke_all``; the restart is the mechanism, and a second one would be a
    second thing to keep correct.

    ⚠️ Not thread-safe against a threaded server by design of the caller:
    uvicorn runs this app on one event loop. The dict operations here are each
    atomic under the GIL, so the worst a race produces is a session validated
    one tick after it was revoked, never a corrupted table.
    """

    def __init__(
        self,
        *,
        idle_seconds: int = SESSION_IDLE_SECONDS,
        absolute_seconds: int = SESSION_ABSOLUTE_SECONDS,
        now: object = None,
    ) -> None:
        self._sessions: dict[str, _Session] = {}
        self.idle_seconds = idle_seconds
        self.absolute_seconds = absolute_seconds
        self._now = now or time.time

    def create(self) -> str:
        now = self._now()
        token = secrets.token_urlsafe(SESSION_TOKEN_BYTES)
        self._sessions[token] = _Session(created_at=now, last_seen_at=now)
        return token

    def validate(self, token: str | None) -> bool:
        """True when ``token`` names a live session, refreshing its idle clock."""
        if not token:
            return False
        session = self._sessions.get(token)
        if session is None:
            return False
        now = self._now()
        if now - session.created_at >= self.absolute_seconds:
            del self._sessions[token]
            return False
        if now - session.last_seen_at >= self.idle_seconds:
            del self._sessions[token]
            return False
        session.last_seen_at = now
        return True

    def revoke(self, token: str | None) -> None:
        if token:
            self._sessions.pop(token, None)

    def purge_expired(self) -> int:
        """Drop expired rows and report how many.

        Called from the login path: without it the table only ever grows, and
        the only thing that empties it is a restart.

        ⚠️ **This bounds growth over TIME, not the number of live sessions.**
        An earlier version of this docstring claimed it "bounds an unbounded
        dict", which overstates it: nothing here removes a session that is
        still inside both its idle and absolute windows, so a caller who knows
        the password can hold open as many concurrent sessions as they like
        until the absolute lifetime retires them. That is a marginal residual —
        it requires the password, and anyone holding it can already do
        everything the dashboard offers — but the claim was wrong as written,
        and a guarantee nobody checks is how the next reader builds on sand.
        """
        now = self._now()
        dead = [
            token
            for token, s in self._sessions.items()
            if now - s.created_at >= self.absolute_seconds
            or now - s.last_seen_at >= self.idle_seconds
        ]
        for token in dead:
            del self._sessions[token]
        return len(dead)

    def __len__(self) -> int:
        return len(self._sessions)


def build_session_cookie(token: str, *, secure: bool, max_age: int) -> str:
    """Build the ``Set-Cookie`` value for a session.

    ⛔ ``secure`` describes the TRANSPORT and must be derived from the request
    scheme, never from a config flag about the bind address. This repo has
    already shipped that exact confusion once: ``Secure`` was attached to the
    CSRF cookie whenever ``ui_allow_remote`` was set, nothing here serves TLS,
    and so a browser stored the cookie and then withheld it from every
    subsequent request — turning on remote access broke every form on the site.
    See ``csrf.CSRFMiddleware._build_cookie_value``.
    """
    parts = [
        f"{SESSION_COOKIE_NAME}={token}",
        f"Max-Age={max_age}",
        "Path=/",
        "HttpOnly",
        "SameSite=Strict",
    ]
    if secure:
        parts.append("Secure")
    return "; ".join(parts)


def clear_session_cookie(*, secure: bool) -> str:
    parts = [
        f"{SESSION_COOKIE_NAME}=",
        "Max-Age=0",
        "Path=/",
        "HttpOnly",
        "SameSite=Strict",
    ]
    if secure:
        parts.append("Secure")
    return "; ".join(parts)


# --- Login rate limiting ------------------------------------------------------

#: Failures tolerated inside one window before the client is locked out.
LOGIN_MAX_FAILURES = 5
#: The window failures are counted in, and the length of the lockout.
LOGIN_WINDOW_SECONDS = 300
LOGIN_LOCKOUT_SECONDS = 300

#: Ceiling on tracked clients. An attacker forging a client address per request
#: would otherwise grow this dict without bound. On overflow we do NOT stop
#: limiting — see ``_evict``.
MAX_TRACKED_CLIENTS = 4096

#: Global ceiling on how much scrypt work unauthenticated callers can spend,
#: as a token bucket shared by every client.
#:
#: ⛔ **This is deliberately NOT a second lockout, and the difference is the
#: whole design.** The per-client limiter above is keyed on the peer address
#: precisely so that one attacker cannot lock the operator out. A global
#: FAILURE COUNTER would hand that lever straight back: five wrong guesses from
#: anywhere and the operator is refused for ``LOGIN_LOCKOUT_SECONDS``. A token
#: bucket has no lockout period at all — it refills continuously, so the moment
#: an attacker stops, the operator is served again within seconds.
#:
#: ⚠️ **What it is for.** Measured 2026-09-01: an attacker rotating source
#: address (trivial on an IPv6 /64) took **30,000 login attempts without ever
#: being refused**, because each address gets its own bucket and ``_evict``
#: only protects ACTIVE lockouts — the attacker's own never-locked buckets are
#: recycled forever. Every one of those attempts ran a full scrypt:
#: ~16 MB and ~29 ms on a 12-core x86, and this is deployed on a Pi. The body
#: size was already capped (``MAX_PASSWORD_BYTES``) for exactly this reason;
#: the request COUNT was not.
#:
#: Sizing: an operator types a handful of passwords in a burst and never
#: notices 30 tokens. A sustained attacker is throttled to one verification a
#: second, which is a trickle rather than a saturated core.
GLOBAL_VERIFY_BURST = 30
GLOBAL_VERIFY_REFILL_PER_SECOND = 1.0


@dataclass
class _Bucket:
    failures: int = 0
    window_started_at: float = 0.0
    locked_until: float = 0.0
    last_touched_at: float = field(default=0.0)


class LoginRateLimiter:
    """Per-client failure counter with a fixed-window lockout.

    ⚠️ **Keyed on the client address reported by the ASGI server**, which is
    the peer socket. Behind a reverse proxy every request is the proxy, and the
    whole world shares one bucket — one attacker then locks the operator out.
    That is not a supported deployment (the documented remote paths are an SSH
    tunnel or a private network, both of which preserve the peer), and honesty
    about it here is worth more than trusting an ``X-Forwarded-For`` header any
    unauthenticated caller can write.

    ⛔ **Fails closed.** A request whose client cannot be identified is bucketed
    under a sentinel key and limited with everyone else in that state, rather
    than waved through as unlimited.
    """

    UNKNOWN_CLIENT = "<unknown>"

    def __init__(
        self,
        *,
        max_failures: int = LOGIN_MAX_FAILURES,
        window_seconds: int = LOGIN_WINDOW_SECONDS,
        lockout_seconds: int = LOGIN_LOCKOUT_SECONDS,
        global_burst: int = GLOBAL_VERIFY_BURST,
        global_refill_per_second: float = GLOBAL_VERIFY_REFILL_PER_SECOND,
        now: object = None,
    ) -> None:
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self._now = now or time.time
        self._buckets: dict[str, _Bucket] = {}
        # Global scrypt-work budget, shared by every client. Starts full so a
        # freshly started server does not refuse the operator's first login.
        self.global_burst = global_burst
        self.global_refill_per_second = global_refill_per_second
        self._global_tokens = float(global_burst)
        self._global_refilled_at = self._now()

    def _bucket(self, client: str) -> _Bucket:
        bucket = self._buckets.get(client)
        if bucket is not None:
            return bucket
        if len(self._buckets) >= MAX_TRACKED_CLIENTS and not self._evict():
            # ⛔ Full, and every entry is an ACTIVE LOCKOUT that must not be
            # discarded. Rather than growing without bound or waving the new
            # client through unlimited, share the sentinel bucket: a caller in
            # this state is still counted, just counted together with everyone
            # else who arrived while the table was saturated. Fails closed.
            return self._buckets.setdefault(self.UNKNOWN_CLIENT, _Bucket())
        bucket = _Bucket()
        self._buckets[client] = bucket
        return bucket

    def _evict(self) -> bool:
        """Make room. False when there was nothing safe to drop.

        ⛔ **An active lockout is never evicted**, and that is the whole
        security property of this function. Measured while writing
        ``test_a_flood_cannot_evict_an_active_lockout``: plain
        least-recently-used eviction let an attacker who had been locked out
        clear their own lockout by making requests from enough other addresses
        to push their (now cold, because they had stopped failing) bucket out
        of the table. The lockout is the state worth protecting; a partial
        failure count mid-window is not, and this deliberately does not pretend
        to protect one.

        Among evictable entries the coldest go first.
        """
        now = self._now()
        evictable = [
            (token, bucket)
            for token, bucket in self._buckets.items()
            if bucket.locked_until <= now and token != self.UNKNOWN_CLIENT
        ]
        if not evictable:
            return False
        evictable.sort(key=lambda kv: kv[1].last_touched_at)
        for token, _ in evictable[: max(1, len(evictable) // 4)]:
            del self._buckets[token]
        return True

    def _lookup(self, client: str | None) -> _Bucket | None:
        """The bucket a client is being counted in, without creating one.

        ⛔ Must mirror ``_bucket``'s fallback exactly. When the table is
        saturated a new client is counted in the shared sentinel bucket, and a
        reader that looked only for the client's own key would report "not
        locked" for a caller that ``record_failure`` had just locked — the
        limiter would count but never refuse. Found by
        ``test_a_client_arriving_at_a_saturated_table_is_still_limited``.
        """
        key = client or self.UNKNOWN_CLIENT
        bucket = self._buckets.get(key)
        if bucket is not None:
            return bucket
        if len(self._buckets) >= MAX_TRACKED_CLIENTS:
            return self._buckets.get(self.UNKNOWN_CLIENT)
        return None

    def is_locked(self, client: str | None) -> bool:
        bucket = self._lookup(client)
        if bucket is None:
            return False
        return self._now() < bucket.locked_until

    def try_spend_verification(self) -> bool:
        """Take one token from the global scrypt budget. False when empty.

        ⛔ **Call this BEFORE running scrypt, and skip the hash when it returns
        False.** Spending the CPU and then refusing would defeat the entire
        point: the cost being bounded here IS the hash.

        ⚠️ **Not a lockout.** There is no penalty window. Tokens refill at
        ``global_refill_per_second`` continuously, so an operator refused
        during an attack is served again seconds after it stops, rather than
        waiting out a ``LOGIN_LOCKOUT_SECONDS`` timer an attacker set for them.
        That distinction is why this is safe to make global while the failure
        counter above must stay per-client.

        ⚠️ **Counts ATTEMPTS, not failures.** A correct password costs the
        server the same scrypt as a wrong one, so budgeting only failures would
        leave the work unbounded. The operator's own successful logins are far
        too few to matter against a 30-token burst.
        """
        now = self._now()
        elapsed = max(0.0, now - self._global_refilled_at)
        self._global_refilled_at = now
        self._global_tokens = min(
            float(self.global_burst),
            self._global_tokens + elapsed * self.global_refill_per_second,
        )
        if self._global_tokens < 1.0:
            return False
        self._global_tokens -= 1.0
        return True

    def global_seconds_remaining(self) -> int:
        """Whole seconds until one more verification is affordable."""
        if self._global_tokens >= 1.0 or self.global_refill_per_second <= 0:
            return 0
        return max(1, int((1.0 - self._global_tokens) / self.global_refill_per_second + 0.999))

    def seconds_remaining(self, client: str | None) -> int:
        bucket = self._lookup(client)
        if bucket is None:
            return 0
        return max(0, int(bucket.locked_until - self._now()))

    def record_failure(self, client: str | None) -> bool:
        """Count a failure. True when this one triggered the lockout."""
        key = client or self.UNKNOWN_CLIENT
        now = self._now()
        bucket = self._bucket(key)
        bucket.last_touched_at = now
        if now - bucket.window_started_at >= self.window_seconds:
            bucket.window_started_at = now
            bucket.failures = 0
        bucket.failures += 1
        if bucket.failures >= self.max_failures:
            bucket.locked_until = now + self.lockout_seconds
            bucket.failures = 0
            bucket.window_started_at = now
            return True
        return False

    def record_success(self, client: str | None) -> None:
        self._buckets.pop(client or self.UNKNOWN_CLIENT, None)


def client_key(scope) -> str:
    """The rate-limit bucket for an ASGI scope, never None."""
    client = scope.get("client")
    if not client:
        return LoginRateLimiter.UNKNOWN_CLIENT
    host = client[0] if isinstance(client, (tuple, list)) else client
    return str(host) if host else LoginRateLimiter.UNKNOWN_CLIENT


# --- Redirect targets ---------------------------------------------------------


def safe_next_path(candidate: str | None, default: str = "/") -> str:
    """Reduce an untrusted ``?next=`` to a same-site path, or the default.

    ⛔ Rejects anything that is not a single-slash-rooted path. ``//evil.test``
    and ``/\\evil.test`` are both read as a network-relative URL by browsers,
    so a login form that echoed them back would be an open redirect on the one
    page an operator is guaranteed to be typing a password into.

    ⚠️ The control-character check rejects the whole C0 range rather than the
    three characters that have actually bitten us, because a guard that matches
    a spelling misses the next rendering of the same idea. The WHATWG URL parser
    **strips** ASCII tab, LF and CR from a URL before parsing it, so
    ``/\\t/evil.test`` is read by a browser as ``//evil.test`` — network-relative,
    the exact shape the two checks below exist to refuse. Listing ``\\r\\n\\x00``
    caught two of those three and let tab through.
    """
    if not candidate or not isinstance(candidate, str):
        return default
    if len(candidate) > 2048:
        return default
    if any(ch <= "\x1f" or ch == "\x7f" for ch in candidate):
        return default
    if not candidate.startswith("/"):
        return default
    if candidate.startswith("//") or candidate.startswith("/\\"):
        return default
    return candidate


# --- The middleware -----------------------------------------------------------

#: Paths reachable without a session, and the reason each one is on this list.
#:
#: ⛔ **Each entry is a claim, and each was measured rather than assumed.**
#:
#: * ``/login`` — the credential surface itself. Circular otherwise.
#: * ``/static`` — the site's own CSS and JS. Contains no operator data; the
#:   login page is unstyled without it.
#: * ``/healthz``, ``/healthz.json`` — the documented monitoring contract
#:   (docs/CONFIGURATION.md, docs/SMOKE.md, docs/KALI_SMOKE_CHECKLIST.md) and
#:   the readiness probe ``lynceus-quickstart`` polls. **Measured 2026-08-25**
#:   with a watchlist row, a device row and an alert all seeded: neither surface
#:   names a MAC, a vendor or a description. They disclose aggregate counts,
#:   staleness, the schema version and the size of the ruleset. That the
#:   measurement stays true is pinned by
#:   ``tests/test_webui_auth.py::test_the_exempt_health_surfaces_name_no_device``,
#:   which greps the bytes rather than trusting this comment.
#:
#: ⚠️ Matched exact-equal or child-of, so ``/static`` covers ``/static/x.css``
#: and not ``/staticthing``. Same rule as ``setup/web/auth.py``.
EXEMPT_PATHS: tuple[str, ...] = ("/login", "/static", "/healthz", "/healthz.json")


def _has_dot_segment(path: str) -> bool:
    """True when any segment is ``.`` or ``..``.

    Split on ``/`` and compare whole segments, rather than substring-searching
    for ``/../``: a substring test misses a trailing ``/..`` and reports a hit
    for an ordinary filename like ``/static/..hidden.css``.
    """
    return any(part in ("..", ".") for part in path.split("/"))


def _is_exempt(path: str, exempt: Iterable[str]) -> bool:
    """True when ``path`` is one of the exempt surfaces.

    ⛔ **A path containing a dot segment is never exempt**, whatever it starts
    with. ``/healthz/../devices`` starts with ``/healthz/``, and a prefix match
    alone would wave it past the session check.

    ⚠️ Measured 2026-08-25 with hand-built ASGI scopes (a test client is no use
    here — httpx normalises ``..`` away before sending, so the first probe of
    this reported "no bypass" while testing nothing): today those paths reach
    the router and 404, so there was no live bypass. But that safety was a
    property of **Starlette's** matcher declining to match them, not of this
    code. Depending on a dependency's normalisation for an access-control
    outcome is how a bypass arrives in a routine upgrade with no diff of ours
    to review. Pinned by
    ``test_an_exempt_prefix_cannot_be_used_to_reach_a_protected_route``.
    """
    if _has_dot_segment(path):
        return False
    for entry in exempt:
        if path == entry or path.startswith(entry + "/"):
            return True
    return False


def session_token_from_scope(scope) -> str | None:
    """The session token in this request, or None.

    ⛔ **The ONE reader.** The login handler calls this too rather than using
    ``Request.cookies``, and the reason is measured. The two parsers disagreed
    on three inputs:

    ========================================  ================  ==============
    Cookie header                             Request.cookies   this function
    ========================================  ================  ==============
    ``lynceus_session="abc"``                 ``abc``           ``"abc"``
    ``lynceus_session=abc; lynceus_session=xyz``  ``xyz`` (last)  ``abc`` (first)
    ========================================  ================  ==============

    Neither disagreement admits an attacker — both orderings refuse rather than
    allow — but they make the middleware and the login page reach DIFFERENT
    answers about whether you are signed in, and the visible symptom is an
    infinite redirect loop between ``/login`` and ``/``. An access-control
    decision made two ways is one refactor from being made wrongly.

    ⛔ **Duplicates fail closed.** Two ``lynceus_session`` cookies with
    different values is not a request to resolve by picking one; it is an
    ambiguous credential, and cookie shadowing is how an attacker who can write
    a cookie on a sibling origin gets to choose which parser wins. Refusing is
    the only answer that does not depend on parser order. Two cookies with the
    SAME value are accepted — that is a duplicate, not an ambiguity.
    """
    found: list[str] = []
    for name, value in scope.get("headers") or []:
        if name.decode("latin-1").lower() != "cookie":
            continue
        for part in value.decode("latin-1").split(";"):
            if "=" not in part:
                continue
            k, v = part.split("=", 1)
            if k.strip() != SESSION_COOKIE_NAME:
                continue
            v = v.strip()
            # Strip one layer of quoting, for parity with Starlette's parser.
            # A urlsafe-base64 token never needs quoting, so this is about the
            # two readers agreeing rather than about a value we emit.
            if len(v) >= 2 and v.startswith('"') and v.endswith('"'):
                v = v[1:-1]
            found.append(v)
    if not found:
        return None
    if len(set(found)) > 1:
        return None
    return found[0] or None


class AuthMiddleware:
    """Require a valid session on every request that is not exempt.

    ⚠️ **Two different refusals, on purpose.** A browser navigating to a page
    gets ``303`` to ``/login?next=…`` so the operator lands somewhere useful. A
    programmatic caller — anything not asking for HTML, and every non-GET —
    gets ``401`` with a plain body, because silently 303-ing a ``curl`` POST to
    a login page returns ``200 OK`` and an HTML form, which a script reads as
    success. That mistake is already recorded in this repo: a login redirect is
    a 303, and the one test whose job was to notice authentication landing
    would have passed once it did.
    """

    def __init__(
        self, app, *, sessions: SessionStore, exempt_paths: Iterable[str] = EXEMPT_PATHS
    ) -> None:
        self.app = app
        self.sessions = sessions
        self.exempt_paths = tuple(exempt_paths)

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        if _is_exempt(path, self.exempt_paths):
            await self.app(scope, receive, send)
            return
        if self.sessions.validate(session_token_from_scope(scope)):
            await self.app(scope, receive, send)
            return
        await self._refuse(scope, send)

    async def _refuse(self, scope, send) -> None:
        method = scope.get("method", "GET").upper()
        accept = ""
        for name, value in scope.get("headers") or []:
            if name.decode("latin-1").lower() == "accept":
                accept = value.decode("latin-1").lower()
                break
        wants_html = "text/html" in accept
        if method in ("GET", "HEAD") and wants_html:
            target = scope.get("path", "/")
            query = (scope.get("query_string") or b"").decode("latin-1")
            if query:
                target = f"{target}?{query}"
            await _send_redirect(send, "/login?next=" + _quote(safe_next_path(target)))
            return
        await _send_401(send)


def _quote(value: str) -> str:
    from urllib.parse import quote

    return quote(value, safe="")


async def _send_redirect(send, location: str) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": 303,
            "headers": [
                (b"location", location.encode("latin-1")),
                (b"content-length", b"0"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": b"", "more_body": False})


async def _send_401(send) -> None:
    body = b"authentication required\n"
    await send(
        {
            "type": "http.response.start",
            "status": 401,
            "headers": [
                (b"content-type", b"text/plain; charset=utf-8"),
                (b"content-length", str(len(body)).encode("latin-1")),
                # No WWW-Authenticate: this is not HTTP Basic, and sending one
                # makes a browser pop its own credential dialog that can never
                # succeed against a form login.
                (b"cache-control", b"no-store"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body, "more_body": False})
