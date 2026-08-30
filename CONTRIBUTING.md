# Contributing to Fleet Audit

## Development setup

```bash
git clone https://github.com/ericjaytech/fleet-audit.git
cd fleet-audit
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
```

## Quality gates

Run these before submitting a pull request:

```bash
python -m ruff format --check .
python -m ruff check .
python -m pytest
shellcheck --external-sources --source-path=src/fleet_audit/collectors \
  src/fleet_audit/collectors/*.sh
shfmt --diff --indent 4 src/fleet_audit/collectors/*.sh
bats tests/bats
python -m build
```

## Adding a new collector

1. Create a shell script in `src/fleet_audit/collectors/`. It must:
   - Accept a workspace directory as its first argument.
   - Write output files into that directory.
   - Exit 0 on success, 10 when the capability is unavailable, or any other non-zero code on error.
   - Never write to stdout or stderr (both are redirected to `/dev/null` by the runner).

2. Create a parser module in `src/fleet_audit/collection/`. It must:
   - Inherit its error class from `fleet_audit.collection._parsing.ParsingError`.
   - Use the shared helpers in `_parsing.py` for file reading and text validation.
   - Return a domain dictionary matching the snapshot schema.

3. Register the collector in `src/fleet_audit/collection/_orchestrator.py`:
   - Add the collector name and script filename to `_COLLECTOR_RESOURCES`.
   - Add a `_parse_<name>_capture` function and register it in `_PARSER_REGISTRY`.
   - Add the domain default to `_unavailable_domain`.

4. Add the domain to the JSON Schema in `src/fleet_audit/schemas/snapshot-v1.schema.json`.

5. Add Python tests in `tests/python/` and BATS tests in `tests/bats/`.

## Adding a new policy check type

1. Define a frozen dataclass in `src/fleet_audit/policy.py`.
2. Add it to the `PolicyCheck` union type.
3. Add a `_parse_check` branch for the new type.
4. Write an `_evaluate_<name>` function.
5. Add its evaluator to the explicit dispatch in `evaluate_policy`.
6. Add tests in `tests/python/test_policy.py`.

## Coding conventions

- Python 3.11+ with `from __future__ import annotations`.
- Ruff linting with rules `B`, `C4`, `E`, `F`, `I`, `SIM`, `T20`, `UP`.
- Line length: 100 characters.
- Shell scripts: `shellcheck` clean, `shfmt` with 4-space indentation.
- All public functions must have docstrings describing parameters, return values and raised exceptions.
- Use frozen dataclasses for value objects.
