# Contributing

For a bug report, include the command you ran, what you expected, and what happened. Please remove tokens and other private data from logs before posting them.

For a code change, open a pull request and link the related issue. Keep changes focused and add a test when behavior changes. Before submitting, run:

```sh
poetry run ruff format --check .
poetry run ruff check .
poetry run mypy main.py merkle_proof.py util.py
poetry run bandit -r . -c pyproject.toml
poetry run pytest
```
