"""Service management commands for MOTIM CLI."""

from pathlib import Path

import click

from ..config import get_config
from ..exchange_db import ExchangeDB
from ..redact import get_redactor


@click.group(invoke_without_command=True)
@click.pass_context
def services(ctx):
    """Manage captured API services.

    Without a subcommand, lists all captured services.

    Examples:
        motim services              # List all services
        motim services show notion  # Show service details
        motim services delete notion
        motim services clear        # Delete all
    """
    if ctx.invoked_subcommand is None:
        # Default behavior: list services
        ctx.invoke(list_services)


@services.command("list")
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON")
def list_services(as_json: bool = False):
    """List all captured services."""
    import json as _json

    config = get_config()

    db_path = Path(config.capture.exchange_db_path).expanduser()
    if not db_path.exists():
        if as_json:
            click.echo(_json.dumps([]))
        else:
            click.echo("No exchange DB found yet.")
            click.echo("\nTo capture traffic:")
            click.echo("  1. motim start")
            click.echo("  2. Configure browser proxy: localhost:8080")
            click.echo("  3. Browse APIs you want to capture")
        return

    with ExchangeDB(db_path, max_body_bytes=int(config.capture.max_body_bytes)) as db:
        summaries = db.service_summaries()

    if as_json:
        click.echo(_json.dumps(summaries, ensure_ascii=False, default=str))
        return

    if not summaries:
        click.echo("No services indexed yet.")
        click.echo("If you have an existing DB, run: motim rebuild-index")
        return

    click.echo(f"Captured services ({len(summaries)}):\n")
    for s in summaries:
        service_key = str(s["service_key"])
        endpoints = int(s["endpoints"])
        exchanges = int(s["exchanges"])
        has_auth = "✓" if bool(s["has_auth"]) else "✗"
        last_seen = str(s["last_ts"])[:10] if s.get("last_ts") else "unknown"
        click.echo(
            f"  {service_key:30} "
            f"{endpoints:3} endpoints  "
            f"{exchanges:5} exchanges  "
            f"auth: {has_auth}  "
            f"last: {last_seen}"
        )


@services.command()
@click.argument("name")
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON")
def show(name: str, as_json: bool):
    """Show details for a service.

    NAME can be a partial match (e.g., 'notion' matches 'api_notion_com')
    """
    import json as _json

    config = get_config()
    with ExchangeDB(
        Path(config.capture.exchange_db_path).expanduser(),
        max_body_bytes=config.capture.max_body_bytes,
    ) as db:
        skey = db.resolve_service_key(name)
        if not skey:
            if as_json:
                click.echo(_json.dumps({"error": f"Service '{name}' not found."}))
            else:
                click.echo(f"Service '{name}' not found.")
            raise click.Abort()

        origin = db.latest_origin(skey) or ""
        snap = db.latest_auth_snapshot(skey)
        endpoints = db.endpoint_summaries(service=skey, limit=20_000)

        if as_json:
            payload = {
                "service_key": skey,
                "base_url": origin,
                "auth": snap,
                "endpoints": endpoints,
            }
            click.echo(_json.dumps(payload, ensure_ascii=False, default=str))
            return

        click.echo(f"Service: {skey}")
        click.echo(f"Base URL: {origin or '(unknown)'}")

        if snap:
            headers = snap.get("headers") or {}
            click.echo(f"\nAuth snapshot: {snap.get('id')} (last: {str(snap.get('ts'))[:19]})")
            click.echo(f"Auth headers: {len(headers)}")
            for k, v in list(headers.items())[:20]:
                vv = str(v)
                if len(vv) > 60:
                    vv = vv[:57] + "..."
                click.echo(f"  {k}: {vv}")
        else:
            click.echo("\nAuth snapshot: none")

        click.echo(f"\nEndpoints ({len(endpoints)}):")
        for e in endpoints[:50]:
            click.echo(
                f"  {e['method']} {e['path_template']}  "
                f"n={e['count']} ex={e.get('example_exchange_id')}"
            )
        if len(endpoints) > 50:
            click.echo(f"  ... and {len(endpoints) - 50} more")


@services.command()
@click.argument("name")
@click.option("--endpoint", "-e", help="Filter by endpoint pattern")
@click.option("--limit", "-n", default=5, help="Number of samples to show")
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON")
def samples(name: str, endpoint: str | None, limit: int, as_json: bool):
    """Show recent exchanges for a service (DB-backed)."""
    import json as _json

    config = get_config()
    with ExchangeDB(
        Path(config.capture.exchange_db_path).expanduser(),
        max_body_bytes=config.capture.max_body_bytes,
    ) as db:
        skey = db.resolve_service_key(name)
        if not skey:
            if as_json:
                click.echo(_json.dumps({"error": f"Service '{name}' not found."}))
            else:
                click.echo(f"Service '{name}' not found.")
            raise click.Abort()

        results = db.search_exchanges(
            service_key=skey,
            method=None,
            status=None,
            host=None,
            path_contains=endpoint,
            limit=max(1, int(limit)),
        )
        redactor = get_redactor()
        for r in results:
            if "url" in r and r["url"]:
                r["url"] = redactor.redact_url(str(r["url"]))
            if "query" in r and r["query"]:
                r["query"] = redactor.redact_query_string(str(r["query"]))

        if as_json:
            click.echo(_json.dumps(results, ensure_ascii=False, default=str))
            return

        if not results:
            click.echo("No exchanges found.")
            return
        click.echo(
            f"Recent exchanges for {skey}" + (f" (filtered: {endpoint})" if endpoint else "")
        )
        click.echo("=" * 60)
        for r in results:
            click.echo(
                f"{r['id']:>6} {r['status']!s:>3} {r['method']:<6} "
                f"{r.get('host', '')}{r.get('path', '')}"
            )


@services.command()
@click.argument("name")
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON")
def auth(name: str, as_json: bool):
    """Show auth snapshot for a service (DB-backed)."""
    import json as _json

    config = get_config()
    with ExchangeDB(
        Path(config.capture.exchange_db_path).expanduser(),
        max_body_bytes=config.capture.max_body_bytes,
    ) as db:
        skey = db.resolve_service_key(name)
        if not skey:
            if as_json:
                click.echo(_json.dumps({"error": f"Service '{name}' not found."}))
            else:
                click.echo(f"Service '{name}' not found.")
            raise click.Abort()

        snap = db.latest_auth_snapshot(skey)

        if as_json:
            click.echo(_json.dumps(snap, ensure_ascii=False, default=str))
            return

        click.echo(f"Auth: {skey}")
        click.echo("=" * 40)
        if not snap:
            click.echo("No auth snapshot available yet.")
            return
        headers = snap.get("headers") or {}
        click.echo(f"Snapshot id: {snap.get('id')}")
        click.echo(f"Last seen: {snap.get('ts')}")
        click.echo(f"Headers ({len(headers)}):")
        for k in headers:
            click.echo(f"  {k}")


@services.command()
@click.argument("name")
@click.confirmation_option(prompt="Delete this service?")
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON")
def delete(name: str, as_json: bool):
    """Delete a captured service."""
    import json as _json

    config = get_config()
    with ExchangeDB(
        Path(config.capture.exchange_db_path).expanduser(),
        max_body_bytes=config.capture.max_body_bytes,
    ) as db:
        stats = db.delete_service(name)
        if as_json:
            click.echo(_json.dumps(stats, ensure_ascii=False))
        else:
            click.echo(f"Deleted {name}: {stats}")


@services.command()
@click.confirmation_option(prompt="Delete ALL captured services?")
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON")
def clear(as_json: bool):
    """Delete all captured services."""
    import json as _json

    config = get_config()
    with ExchangeDB(
        Path(config.capture.exchange_db_path).expanduser(),
        max_body_bytes=config.capture.max_body_bytes,
    ) as db:
        stats = db.clear_all()
        if as_json:
            click.echo(_json.dumps(stats, ensure_ascii=False))
        else:
            click.echo(f"Deleted all: {stats}")
