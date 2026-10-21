# Contributing

## Before you send a pull request

1. `cd exploitgym && pytest -q` — 142 tests, and they must stay green.
2. `ruff check .` from the repository root (config in `ruff.toml`).
3. Keep the scope gate intact. A change that lets an agent reach a host outside
   `scope.yaml` will not be merged, whatever else it improves.

## Adding a vulnerability type

`docs/adding-new-vuln.md` walks the whole path: context taxonomy → payload generator →
oracle → data pipeline → trainer → agent registration in
`exploitgym/src/exploitgym/config.py`. The oracle is the load-bearing part — see lesson 5 in
the README for why a lenient oracle is worse than no model.

## House style

- Standard library first. The framework's only runtime dependencies are `pydantic` and
  `pyyaml`; keep it that way.
- Tests must not depend on your machine's state. If a test needs model directories or an
  existing history, build it in `tmp_path` — a test that only passes on the author's disk is a
  bug.
- Small, focused commits with a message that says what changed and why.
