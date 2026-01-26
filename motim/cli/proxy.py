"""Proxy management commands for MOTIM CLI."""

import os
import subprocess
from pathlib import Path

import click

MOTIM_DIR = Path.home() / ".motim"
PID_FILE = MOTIM_DIR / "proxy.pid"
CA_CERT = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"


@click.group()
def proxy():
    """Manage the MOTIM proxy server.

    The proxy intercepts HTTP(S) traffic and captures API specs.

    Examples:
        motim proxy start           # Start on default port 8080
        motim proxy start -p 9090   # Start on custom port
        motim proxy stop            # Stop the proxy
        motim proxy status          # Check if running
    """
    pass


@proxy.command()
@click.option(
    "--port",
    "-p",
    default=8080,
    type=click.IntRange(1, 65535),
    help="Proxy port (default: 8080)",
)
@click.option("--verbose", "-v", is_flag=True, help="Show all requests (including skipped)")
def start(port: int, verbose: bool):
    """Start the proxy server.

    The proxy will capture HTTP(S) traffic and generate API specs
    in ~/.motim/specs/

    Configure your browser or system to use localhost:PORT as proxy.
    """
    if PID_FILE.exists():
        pid = int(PID_FILE.read_text().strip())
        try:
            subprocess.run(["kill", "-0", str(pid)], check=True, capture_output=True)
            click.echo(f"Proxy already running (PID {pid})")
            click.echo("Stop it first: motim proxy stop")
            return
        except subprocess.CalledProcessError:
            PID_FILE.unlink()

    if not CA_CERT.exists():
        click.echo("CA certificate not found. Run 'motim init' first.")
        raise click.Abort()

    # Find addon path - now in proxy/ submodule
    addon_path = Path(__file__).parent.parent / "proxy" / "addon.py"
    if not addon_path.exists():
        # Fallback to old location during transition
        addon_path = Path(__file__).parent.parent / "addon.py"

    if not addon_path.exists():
        click.echo(f"Addon not found: {addon_path}")
        raise click.Abort()

    click.echo(f"Starting proxy on localhost:{port}")
    click.echo("Configure your browser/system to use this as HTTP(S) proxy")
    click.echo("Press Ctrl+C to stop\n")

    env = os.environ.copy()
    if verbose:
        env["MOTIM_VERBOSE"] = "1"

    try:
        process = subprocess.Popen(
            [
                "mitmdump",
                "--mode",
                "regular",
                "--listen-host",
                "127.0.0.1",
                "--listen-port",
                str(port),
                "-s",
                str(addon_path),
                "--set",
                "stream_large_bodies=2m",
                "--quiet",
            ],
            env=env,
        )
        PID_FILE.write_text(str(process.pid))
        process.wait()
    except KeyboardInterrupt:
        click.echo("\nStopping proxy...")
    except FileNotFoundError:
        click.echo("mitmdump not found. Install mitmproxy: pip install mitmproxy")
        raise click.Abort()
    finally:
        if PID_FILE.exists():
            PID_FILE.unlink()


@proxy.command()
def stop():
    """Stop the proxy server."""
    if not PID_FILE.exists():
        click.echo("Proxy not running")
        return

    pid = int(PID_FILE.read_text().strip())
    try:
        subprocess.run(["kill", str(pid)], check=True)
        click.echo(f"Stopped proxy (PID {pid})")
    except subprocess.CalledProcessError:
        click.echo("Proxy not running")
    finally:
        if PID_FILE.exists():
            PID_FILE.unlink()


@proxy.command()
def status():
    """Check proxy status."""
    if PID_FILE.exists():
        pid = int(PID_FILE.read_text().strip())
        try:
            subprocess.run(["kill", "-0", str(pid)], check=True, capture_output=True)
            click.echo(f"Proxy running (PID {pid})")
        except subprocess.CalledProcessError:
            click.echo("Proxy not running (stale PID file)")
            PID_FILE.unlink()
    else:
        click.echo("Proxy not running")

    # Show cert status
    if CA_CERT.exists():
        click.echo(f"CA certificate: {CA_CERT}")
    else:
        click.echo("CA certificate: not generated (run 'motim init')")


@proxy.command("trust-cert")
def trust_cert():
    """Generate and trust the mitmproxy CA certificate.

    This is automatically done during 'motim init', but you can
    run it separately if needed.
    """
    import platform
    import time

    # Generate cert if needed
    if not CA_CERT.exists():
        click.echo("Generating CA certificate...")
        try:
            process = subprocess.Popen(
                ["mitmdump", "--quiet"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(2)
            process.terminate()
            process.wait(timeout=5)
        except Exception as e:
            click.echo(f"Failed to generate certificate: {e}", err=True)
            raise click.Abort()

    if not CA_CERT.exists():
        click.echo("Certificate generation failed", err=True)
        raise click.Abort()

    click.echo(f"Certificate: {CA_CERT}")

    # Trust based on platform
    system = platform.system()

    if system == "Darwin":
        click.echo("Installing to System keychain (requires sudo)...")
        try:
            subprocess.run(
                [
                    "sudo",
                    "security",
                    "add-trusted-cert",
                    "-d",
                    "-r",
                    "trustRoot",
                    "-k",
                    "/Library/Keychains/System.keychain",
                    str(CA_CERT),
                ],
                check=True,
            )
            click.echo("✓ Certificate trusted")
            click.echo("\nNote: You may need to restart your browser.")
        except subprocess.CalledProcessError as e:
            click.echo(f"Failed: {e}", err=True)
            raise click.Abort()

    elif system == "Linux":
        ca_dest = Path("/usr/local/share/ca-certificates/mitmproxy-ca-cert.crt")
        click.echo("Installing certificate (requires sudo)...")
        try:
            subprocess.run(["sudo", "cp", str(CA_CERT), str(ca_dest)], check=True)
            subprocess.run(["sudo", "update-ca-certificates"], check=True)
            click.echo("✓ Certificate trusted")
        except subprocess.CalledProcessError as e:
            click.echo(f"Failed: {e}", err=True)
            raise click.Abort()

    elif system == "Windows":
        click.echo("Please manually trust the certificate:")
        click.echo(f"  1. Double-click: {CA_CERT}")
        click.echo("  2. Click 'Install Certificate'")
        click.echo("  3. Select 'Local Machine', click Next")
        click.echo("  4. Select 'Place all certificates in the following store'")
        click.echo("  5. Browse → 'Trusted Root Certification Authorities'")
        click.echo("  6. Click Next, then Finish")

    else:
        click.echo(f"Unknown platform: {system}")
        click.echo(f"Please manually trust: {CA_CERT}")
