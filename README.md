# Rekor monitor

This is my CS-GY 9223 Assignment 1 project. It checks an artifact's signature and Rekor inclusion proof, fetches a log checkpoint, and compares an older checkpoint with a newer one.

## Setup

Use Python 3.11 or newer and Poetry:

```sh
poetry install
```

The verification commands need an internet connection to reach Rekor.

## Run it

Fetch a checkpoint:

```sh
poetry run python main.py -c
```

This saves `checkpoint.json` and a second file named with the tree ID and size, so an older checkpoint is kept when you fetch a new one.

Check the included artifact:

```sh
poetry run python main.py --inclusion 3098661564 --artifact artifact.md
```

Compare an older checkpoint with Rekor's current checkpoint:

```sh
poetry run python main.py --consistency --tree-id <TREE_ID> --tree-size <TREE_SIZE> --root-hash <ROOT_HASH>
```

Use the values from the older saved checkpoint for that last command.

## Development

Run the tests with `poetry run pytest`. The project also uses Ruff, mypy, and Bandit; the commands are in CONTRIBUTING.md.

## Verification limits

The signature check uses the public key in the certificate returned with the log entry. This project does not validate the certificate's trust chain or a signed Rekor checkpoint.
