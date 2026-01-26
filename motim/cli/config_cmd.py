"""Configuration commands for MOTIM CLI."""

import click
import yaml

from ..config import CONFIG_FILE, Config, get_config, reload_config


@click.group()
def config():
    """Manage MOTIM configuration.

    Configuration is stored in ~/.motim/config.yaml

    Examples:
        motim config show           # Show current config
        motim config edit           # Open in editor
        motim config path           # Show config file path
    """
    pass


@config.command()
@click.option("--raw", is_flag=True, help="Show raw YAML")
def show(raw: bool):
    """Show current configuration."""
    cfg = get_config()

    if raw:
        click.echo(yaml.dump(cfg.to_dict(), default_flow_style=False))
        return

    click.echo("MOTIM Configuration")
    click.echo("=" * 40)

    # Defaults
    click.echo("\nDefaults:")
    click.echo(f"  Profile: {cfg.defaults.profile}")
    click.echo(f"  Timeout: {cfg.defaults.timeout}s")
    click.echo(f"  Retries: {cfg.defaults.retries}")
    click.echo(f"  Verify SSL: {cfg.defaults.verify_ssl}")

    # Profiles
    click.echo(f"\nHeader Profiles ({len(cfg.profiles)}):")
    for name, profile in cfg.profiles.items():
        click.echo(f"  {name}:")
        if profile.include:
            click.echo(f"    include: {profile.include}")
        if profile.exclude:
            click.echo(f"    exclude: {profile.exclude}")

    # Service overrides
    if cfg.services:
        click.echo(f"\nService Overrides ({len(cfg.services)}):")
        for name, settings in cfg.services.items():
            parts = []
            if settings.profile:
                parts.append(f"profile={settings.profile}")
            if settings.timeout:
                parts.append(f"timeout={settings.timeout}")
            if settings.retries:
                parts.append(f"retries={settings.retries}")
            click.echo(f"  {name}: {', '.join(parts) if parts else '(empty)'}")

    # Capture settings
    click.echo("\nCapture Settings:")
    click.echo(f"  Skip headers: {len(cfg.capture.skip_headers)}")
    click.echo(f"  Skip domains: {len(cfg.capture.skip_domains)}")
    click.echo(f"  Max samples/endpoint: {cfg.capture.max_samples_per_endpoint}")
    click.echo(f"  Max samples total: {cfg.capture.max_samples_total}")


@config.command()
def path():
    """Show configuration file path."""
    click.echo(CONFIG_FILE)
    if CONFIG_FILE.exists():
        click.echo("(exists)")
    else:
        click.echo("(not created - using defaults)")


@config.command()
def edit():
    """Open configuration in default editor."""
    import os
    import subprocess

    if not CONFIG_FILE.exists():
        # Create with defaults
        from ..config import DEFAULT_CONFIG_FILE

        if DEFAULT_CONFIG_FILE.exists():
            CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
            CONFIG_FILE.write_text(DEFAULT_CONFIG_FILE.read_text())
            click.echo(f"Created: {CONFIG_FILE}")
        else:
            # Create from current config
            cfg = get_config()
            cfg.save()
            click.echo(f"Created: {CONFIG_FILE}")

    editor = os.environ.get("EDITOR", "nano")
    try:
        subprocess.run([editor, str(CONFIG_FILE)], check=True)
        reload_config()
        click.echo("Configuration reloaded.")
    except subprocess.CalledProcessError:
        click.echo("Editor exited with error.", err=True)
    except FileNotFoundError:
        click.echo(f"Editor not found: {editor}", err=True)
        click.echo(f"Edit manually: {CONFIG_FILE}")


@config.command()
def reset():
    """Reset configuration to defaults."""
    from ..config import DEFAULT_CONFIG_FILE

    if CONFIG_FILE.exists():
        if not click.confirm("Reset configuration to defaults?"):
            raise click.Abort()

    if DEFAULT_CONFIG_FILE.exists():
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.write_text(DEFAULT_CONFIG_FILE.read_text())
        click.echo(f"Reset: {CONFIG_FILE}")
    else:
        cfg = Config()
        cfg.save()
        click.echo(f"Created default: {CONFIG_FILE}")

    reload_config()


@config.command()
@click.argument("key")
@click.argument("value")
def set(key: str, value: str):
    """Set a configuration value.

    KEY uses dot notation: defaults.timeout, capture.max_samples_total

    Examples:
        motim config set defaults.timeout 60
        motim config set defaults.profile full
    """
    cfg = get_config()

    parts = key.split(".")
    if len(parts) != 2:
        click.echo("Key must be in format: section.key")
        click.echo("Examples: defaults.timeout, defaults.profile")
        raise click.Abort()

    section, attr = parts

    if section == "defaults":
        if attr == "timeout":
            cfg.defaults.timeout = float(value)
        elif attr == "retries":
            cfg.defaults.retries = int(value)
        elif attr == "profile":
            if value not in cfg.profiles:
                click.echo(f"Unknown profile: {value}")
                click.echo(f"Available: {list(cfg.profiles.keys())}")
                raise click.Abort()
            cfg.defaults.profile = value
        elif attr == "verify_ssl":
            cfg.defaults.verify_ssl = value.lower() in ("true", "1", "yes")
        else:
            click.echo(f"Unknown setting: defaults.{attr}")
            raise click.Abort()

    elif section == "capture":
        if attr == "max_samples_per_endpoint":
            cfg.capture.max_samples_per_endpoint = int(value)
        elif attr == "max_samples_total":
            cfg.capture.max_samples_total = int(value)
        else:
            click.echo(f"Unknown setting: capture.{attr}")
            raise click.Abort()

    else:
        click.echo(f"Unknown section: {section}")
        click.echo("Available: defaults, capture")
        raise click.Abort()

    cfg.save()
    reload_config()
    click.echo(f"Set {key} = {value}")
