"""Capture bridges that feed observations into the shared alert pipeline.

Each bridge owns its own ``Database`` connection (WAL second-writer pattern)
and reuses ``poller.process_observation`` rather than re-implementing the
persist + rule-eval path. Bridges never call into the Poller or mutate
Poller-owned state.
"""
