# Talos

Personal RF security monitoring platform for Raspberry Pi.

## Status

Skeleton only — no functionality implemented yet.

## Requirements

- Python 3.11+
- Linux (Raspberry Pi target); developed on any POSIX-compatible host

## Quickstart

```sh
make install   # pip install -e ".[dev]"
make test      # pytest -v
make lint      # ruff check . && ruff format --check .
make run       # placeholder
```

## Layout

```
src/talos/        application package
  __init__.py     version
  db.py           sqlite persistence
  kismet.py       Kismet REST client
  poller.py       poll loop
  rules.py        detection rules
  notify.py       alert dispatch
  allowlist.py    known-good device suppression
  main.py         entrypoint
tests/            pytest suite
config/           rules.yaml, allowlist.yaml
migrations/       sqlite schema migrations
```

## Stack

Runtime: `requests`, `pydantic` v2, `PyYAML`, stdlib `sqlite3`.
Dev: `pytest`, `pytest-mock`, `freezegun`, `ruff`.
