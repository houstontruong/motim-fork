# Contributing to MOTIM

Thanks for your interest in contributing!

## Development Setup

```bash
git clone https://github.com/vaibhavk97/motim.git
cd motim
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,curl,linkfinder]"
```

## Running Tests

```bash
pytest
```

## Code Style

This project uses [ruff](https://docs.astral.sh/ruff/) for linting and formatting:

```bash
ruff check .
ruff format .
```

Type checking with mypy:

```bash
mypy motim/
```

## Submitting Changes

1. Fork the repository
2. Create a feature branch (`git checkout -b my-feature`)
3. Make your changes and add tests
4. Run `pytest` and `ruff check .` to verify
5. Commit and push to your fork
6. Open a pull request

## Reporting Issues

Please open a GitHub issue with:
- What you expected to happen
- What actually happened
- Steps to reproduce
- Your OS and Python version
