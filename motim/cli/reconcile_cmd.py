"""CLI commands for offline account-read reconciliation."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from motim.reconcile import Outcome, reconcile
from motim.reconcile.models import SCHEMA_VERSION_OUTPUT

# Exit code mapping as defined in SPEC.md
OUTCOME_EXIT_CODES = {
    Outcome.OK.value: 0,
    Outcome.PARTIAL.value: 2,
    Outcome.UNSUPPORTED_SCHEMA.value: 3,
    Outcome.INVALID_INPUT.value: 4,
}


@click.command(name="reconcile")
@click.option(
    "--input",
    "-i",
    "input_file",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to input JSON Lines file containing sanitized exchange objects",
)
@click.option(
    "--provider",
    "-p",
    required=True,
    type=click.Choice(["bybit", "lighter"], case_sensitive=False),
    help="Exchange provider (bybit or lighter)",
)
@click.option(
    "--as-of",
    required=True,
    help="Deterministic as-of timestamp (RFC3339 UTC with Z, e.g. 2026-08-23T14:05:00Z)",
)
@click.option(
    "--max-age-seconds",
    default=0,
    type=int,
    help="Maximum age in seconds for facts to be fresh (default: 0)",
)
@click.option(
    "--strict/--no-strict",
    default=True,
    help="Enforce strict sanitized exchange schema validation (default: strict)",
)
def reconcile_cmd(
    input_file: Path,
    provider: str,
    as_of: str,
    max_age_seconds: int,
    strict: bool,
) -> None:
    """Reconcile sanitized exchange JSON Lines into traceable account facts.

    Offline-only, deterministic translator. Emits exactly one JSON result to stdout.
    """
    result = reconcile(
        input_file,
        provider=provider,
        as_of=as_of,
        max_age_seconds=max_age_seconds,
        strict=strict,
    )
    result_json = json.dumps(result.to_dict(), indent=2, ensure_ascii=False)
    click.echo(result_json)

    exit_code = OUTCOME_EXIT_CODES.get(result.outcome, 0)
    sys.exit(exit_code)


@click.command(name="facts")
@click.option(
    "--result",
    "-r",
    "result_file",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to previously produced motim.account_read.v1 result JSON file",
)
@click.option(
    "--type",
    "-t",
    "fact_type",
    default=None,
    help="Filter facts by fact_type (e.g. position, fill, funding, balance, equity, pnl)",
)
def facts_cmd(result_file: Path, fact_type: str | None) -> None:
    """Filter and view facts from a previously generated reconciliation result."""
    try:
        data = json.loads(result_file.read_text(encoding="utf-8"))
    except Exception as e:
        click.echo(f"Error: Failed to read result file: {e}", err=True)
        sys.exit(1)

    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION_OUTPUT:
        click.echo(
            f"Error: Expected {SCHEMA_VERSION_OUTPUT} result file",
            err=True,
        )
        sys.exit(1)

    facts = data.get("facts", [])
    if not isinstance(facts, list):
        facts = []

    if fact_type:
        target_type = fact_type.strip().lower()
        facts = [f for f in facts if isinstance(f, dict) and str(f.get("fact_type", "")).lower() == target_type]

    click.echo(json.dumps(facts, indent=2, ensure_ascii=False))
    sys.exit(0)


@click.command(name="issues")
@click.option(
    "--result",
    "-r",
    "result_file",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to previously produced motim.account_read.v1 result JSON file",
)
@click.option(
    "--code",
    "-c",
    "issue_code",
    default=None,
    help="Filter issues by issue code (e.g. stale_fact, duplicate_event, unsupported_schema, malformed_record, invalid_input)",
)
def issues_cmd(result_file: Path, issue_code: str | None) -> None:
    """Filter and view issues from a previously generated reconciliation result."""
    try:
        data = json.loads(result_file.read_text(encoding="utf-8"))
    except Exception as e:
        click.echo(f"Error: Failed to read result file: {e}", err=True)
        sys.exit(1)

    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION_OUTPUT:
        click.echo(
            f"Error: Expected {SCHEMA_VERSION_OUTPUT} result file",
            err=True,
        )
        sys.exit(1)

    issues = data.get("issues", [])
    if not isinstance(issues, list):
        issues = []

    if issue_code:
        target_code = issue_code.strip().lower()
        issues = [i for i in issues if isinstance(i, dict) and str(i.get("code", "")).lower() == target_code]

    click.echo(json.dumps(issues, indent=2, ensure_ascii=False))
    sys.exit(0)
