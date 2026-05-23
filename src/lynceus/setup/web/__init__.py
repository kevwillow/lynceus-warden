"""Web-based ``lynceus-setup`` wizard (run-once on demand).

A separate FastAPI app from the persistent ``lynceus.webui`` dashboard.
The operator invokes ``lynceus-setup --web``; this package spins up a
token-gated, loopback-bound server hosting a multi-page form that
mirrors the CLI flow. Input is validated through the same
``Config`` constructor the CLI uses, so the two frontends can never
diverge on what counts as a valid configuration.

Phase 2a ships the scaffold + form pages + a noop apply placeholder.
The actual ``apply_config`` invocation, SSE progress streaming, and
post-apply completion page land in Phase 2b.
"""
