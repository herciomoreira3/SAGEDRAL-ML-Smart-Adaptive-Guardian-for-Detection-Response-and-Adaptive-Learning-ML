"""
Click CLI Command Line Interface for SAGEDRAL-ML tool.
"""

import os
import sys
import json
import click
import requests
from sagedral_ml import __version__
from sagedral_ml.config import get_config, load_config, generate_default_toml_string, DEFAULT_CONFIG_PATH
from sagedral_ml.ips.response import validate_ip


API_BASE = "http://localhost:8000/api/v1"


@click.group()
@click.version_option(__version__, message="SAGEDRAL-ML version %(version)s")
def main():
    """SAGEDRAL-ML — Smart Adaptive Guardian for Detection, Response, and Adaptive Learning - ML NIDPS System."""
    pass


# ================= SERVICE COMMANDS =================

@main.command()
@click.option("--daemon/--no-daemon", default=False, help="Run as background daemon process")
@click.option("--no-capture", is_flag=True, help="Disable network packet capture (for development/testing)")
def start(daemon, no_capture):
    """Start SAGEDRAL-ML NIDPS service."""
    from sagedral_ml.main import run_app

    click.echo("Starting SAGEDRAL-ML system...")
    if daemon:
        click.echo("Daemon mode activated.")
    run_app(enable_capture=not no_capture)


@main.command()
def stop():
    """Stop running SAGEDRAL-ML service."""
    click.echo("Stopping SAGEDRAL-ML service...")
    # Send SIGTERM to process if running
    os.system("pkill -f 'sagedral-ml start' || true")
    click.echo("Stop command issued.")


@main.command()
def status():
    """Check running status of SAGEDRAL-ML service."""
    try:
        r = requests.get(f"{API_BASE}/status", timeout=2)
        if r.status_code == 200:
            data = r.json()
            click.secho("SAGEDRAL-ML Service: RUNNING", fg="green", bold=True)
            click.echo(f"  Interface:         {data.get('interface')}")
            click.echo(f"  Uptime:            {data.get('uptime_seconds')}s")
            click.echo(f"  Active Blocked IPs:{data.get('blocked_ips_count')}")
            click.echo(f"  ML Model Loaded:   {data.get('ml_model_loaded')}")
            return
    except Exception:
        pass
    click.secho("SAGEDRAL-ML Service: STOPPED / UNREACHABLE", fg="red", bold=True)


@main.command()
def restart():
    """Restart SAGEDRAL-ML service."""
    stop.callback()
    start.callback(daemon=True, no_capture=False)


# ================= CONFIG COMMANDS =================

@main.group()
def config():
    """Configuration management subcommands."""
    pass


@config.command("show")
def config_show():
    """Show current active configuration."""
    cfg = get_config()
    click.echo(json.dumps(cfg.to_dict(), indent=2))


@config.command("template")
def config_template():
    """Generate default config.toml template to stdout."""
    click.echo(generate_default_toml_string())


@config.command("validate")
def config_validate():
    """Validate configuration file."""
    cfg = get_config()
    errors = cfg.validate()
    if errors:
        click.secho("Configuration Validation FAILED:", fg="red", bold=True)
        for err in errors:
            click.echo(f"  - {err}")
        sys.exit(1)
    else:
        click.secho("Configuration is VALID.", fg="green", bold=True)


# ================= IP MANAGEMENT COMMANDS =================

@main.command()
@click.argument("ip")
@click.option("--duration", default=3600, help="Block duration in seconds (0 = permanent)")
@click.option("--reason", default="Manual CLI block", help="Reason for block")
def block(ip, duration, reason):
    """Manually block an IP address in firewall."""
    try:
        clean_ip = validate_ip(ip)
    except ValueError as e:
        click.secho(f"Error: {e}", fg="red")
        return

    try:
        r = requests.post(f"{API_BASE}/blocked-ips", json={
            "ip": clean_ip, "reason": reason, "duration_seconds": duration
        }, timeout=3)
        if r.status_code == 200:
            click.secho(f"Successfully blocked IP {clean_ip}", fg="green")
        else:
            click.secho(f"Failed: {r.json().get('detail', r.text)}", fg="red")
    except Exception as e:
        click.secho(f"API request failed: {e}", fg="red")


@main.command()
@click.argument("ip")
def unblock(ip):
    """Manually unblock an IP address from firewall."""
    try:
        clean_ip = validate_ip(ip)
    except ValueError as e:
        click.secho(f"Error: {e}", fg="red")
        return

    try:
        r = requests.delete(f"{API_BASE}/blocked-ips/{clean_ip}", timeout=3)
        if r.status_code == 200:
            click.secho(f"Successfully unblocked IP {clean_ip}", fg="green")
        else:
            click.secho(f"Failed: {r.json().get('detail', r.text)}", fg="red")
    except Exception as e:
        click.secho(f"API request failed: {e}", fg="red")


# ================= ALERTS COMMANDS =================

@main.group()
def alerts():
    """Alert management subcommands."""
    pass


@alerts.command("list")
@click.option("--limit", default=20, help="Number of alerts to display")
def alerts_list(limit):
    """List recent security alerts."""
    try:
        r = requests.get(f"{API_BASE}/alerts?limit={limit}", timeout=3)
        if r.status_code == 200:
            data = r.json().get("data", [])
            if not data:
                click.echo("No alerts recorded.")
                return

            click.echo(f"{'TIME':<20} {'SRC IP':<16} {'DST IP':<16} {'ATTACK TYPE':<15} {'SEVERITY':<10} {'ACTION':<10}")
            click.echo("-" * 90)
            for a in data:
                import datetime
                t_str = datetime.datetime.fromtimestamp(a["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
                click.echo(f"{t_str:<20} {a['src_ip']:<16} {a['dst_ip']:<16} {a['attack_type']:<15} {a['severity']:<10} {a['action_taken']:<10}")
            return
    except Exception as e:
        click.secho(f"API request failed: {e}", fg="red")


# ================= MODEL COMMANDS =================

@main.group()
def model():
    """ML model management subcommands."""
    pass


@model.command("info")
def model_info():
    """Show details of loaded ML models."""
    try:
        r = requests.get(f"{API_BASE}/model/info", timeout=3)
        if r.status_code == 200:
            click.echo(json.dumps(r.json(), indent=2))
            return
    except Exception as e:
        click.secho(f"API request failed: {e}", fg="red")


if __name__ == "__main__":
    main()
