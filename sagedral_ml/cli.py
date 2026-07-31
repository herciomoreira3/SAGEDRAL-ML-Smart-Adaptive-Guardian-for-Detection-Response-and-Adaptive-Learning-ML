"""
Click CLI Command Line Interface for SAGEDRAL-ML tool.
"""

import sagedral_ml
import os
import sys
import json
import time
import tarfile
import shutil
import click
import requests
from pathlib import Path
from typing import List, Tuple
from sagedral_ml import __version__
from sagedral_ml.config import get_config, load_config, generate_default_toml_string, DEFAULT_CONFIG_PATH
from sagedral_ml.ips.response import validate_ip, validate_ip_or_network


API_BASE = os.environ.get(
    "SAGEDRAL_API_BASE", "http://localhost:8000/api/v1"
).rstrip("/")
TOKEN_PATH = Path.home() / ".config" / "sagedral" / "api-token"


def _api_headers() -> dict:
    token = os.environ.get("SAGEDRAL_API_TOKEN", "").strip()
    if not token:
        try:
            token = TOKEN_PATH.read_text(encoding="utf-8").strip()
        except OSError:
            token = ""
    return {"Authorization": "Bearer %s" % token} if token else {}


def _require_api_token() -> dict:
    headers = _api_headers()
    if not headers:
        _cli_error(
            "Authentication token not found. Run 'sagedral-ml login' or set SAGEDRAL_API_TOKEN."
        )
    return headers


def _cli_error(msg: str, exit_code: int = 1) -> None:
    click.secho(f"ERROR: {msg}", fg="red", bold=True)
    sys.exit(exit_code)


def _cli_warn(msg: str) -> None:
    click.secho(f"WARNING: {msg}", fg="yellow")


def _cli_ok(msg: str) -> None:
    click.secho(msg, fg="green", bold=True)


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
    try:
        from sagedral_ml.main import run_app

        click.echo("Starting SAGEDRAL-ML system...")
        if daemon:
            click.echo("Daemon mode activated.")
        run_app(enable_capture=not no_capture)
    except ImportError as e:
        _cli_error(f"Failed to import runtime module: {e}")
    except Exception as e:
        _cli_error(f"Failed to start service: {e}")


@main.command("login")
@click.option("--username", prompt="Naran uzuariu", help="SAGEDRAL username")
@click.option(
    "--password",
    prompt=True,
    hide_input=True,
    confirmation_prompt=False,
    help="SAGEDRAL password",
)
def cli_login(username, password):
    """Authenticate CLI and store a mode-0600 API token."""
    try:
        response = requests.post(
            f"{API_BASE}/auth/login",
            data={"username": username, "password": password},
            timeout=10,
        )
        if response.status_code != 200:
            _cli_error(
                "Login failed: %s"
                % response.json().get("detail", response.text)
            )
        token = response.json()["access_token"]
        TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(
            str(TOKEN_PATH),
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            0o600,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(token)
        try:
            os.chmod(str(TOKEN_PATH), 0o600)
        except OSError:
            pass
        _cli_ok("Login successful. Token saved to %s" % TOKEN_PATH)
    except click.exceptions.Exit:
        raise
    except Exception as exc:
        _cli_error("Login request failed: %s" % exc)


@main.command("logout")
def cli_logout():
    """Remove the locally stored API token."""
    try:
        requests.post(
            f"{API_BASE}/auth/logout",
            headers=_api_headers(),
            timeout=5,
        )
    except Exception:
        pass
    try:
        TOKEN_PATH.unlink()
    except FileNotFoundError:
        pass
    _cli_ok("Local API session removed.")


@main.command()
def health():
    """Check liveness/readiness with monitoring-friendly exit status."""
    root = API_BASE.rsplit("/api/v1", 1)[0]
    try:
        response = requests.get(root + "/healthz", timeout=5)
        click.echo(json.dumps(response.json(), indent=2))
        if response.status_code != 200:
            raise click.exceptions.Exit(1)
    except click.exceptions.Exit:
        raise
    except Exception as exc:
        _cli_error("Health check failed: %s" % exc)


@main.command()
def stop():
    """Stop running SAGEDRAL-ML service."""
    try:
        click.echo("Stopping SAGEDRAL-ML service...")
        os.system("pkill -f 'sagedral-ml start' || true")
        click.echo("Stop command issued.")
    except Exception as e:
        _cli_error(f"Error issuing stop command: {e}")


@main.command()
def status():
    """Check running status of SAGEDRAL-ML service."""
    headers = _api_headers()
    details_auth_rejected = False
    try:
        if headers:
            details_response = requests.get(
                f"{API_BASE}/status/details",
                headers=headers,
                timeout=5,
            )
            if details_response.status_code == 200:
                data = details_response.json()
                click.secho("SAGEDRAL-ML Service: RUNNING", fg="green", bold=True)
                click.echo(f"  Interface:         {data.get('interface')}")
                click.echo(f"  Uptime:            {data.get('uptime_seconds')}s")
                click.echo(f"  Active Blocked IPs: {data.get('blocked_ips_count')}")
                click.echo(f"  ML Model Loaded:   {data.get('ml_model_loaded')}")
                return
            details_auth_rejected = details_response.status_code in (401, 403)
            if not details_auth_rejected:
                click.secho(
                    "Detailed status unavailable (HTTP %d); checking public status."
                    % details_response.status_code,
                    fg="yellow",
                )

        # The public endpoint intentionally needs no JWT. This distinguishes an
        # expired/missing CLI login from a service that is actually stopped.
        public_response = requests.get(f"{API_BASE}/status", timeout=5)
        if public_response.status_code == 200:
            data = public_response.json()
            click.secho(
                "SAGEDRAL-ML Service: RUNNING",
                fg="green",
                bold=True,
            )
            click.echo(f"  Version:           {data.get('version', 'unknown')}")
            click.echo(f"  Uptime:            {data.get('uptime_seconds', 0)}s")
            if not headers:
                click.echo(
                    "  Details:           login required; run 'sagedral-ml login'"
                )
            elif details_auth_rejected:
                click.echo(
                    "  Details:           token rejected/expired; run 'sagedral-ml login'"
                )
            else:
                click.echo(
                    "  Details:           detailed endpoint temporarily unavailable"
                )
            return

        click.secho(
            "SAGEDRAL-ML Service: UNHEALTHY (HTTP %d)"
            % public_response.status_code,
            fg="red",
            bold=True,
        )
        raise click.exceptions.Exit(1)
    except click.exceptions.Exit:
        raise
    except requests.RequestException as exc:
        click.secho(
            "SAGEDRAL-ML Service: STOPPED / UNREACHABLE",
            fg="red",
            bold=True,
        )
        click.echo("  API: %s" % API_BASE)
        click.echo("  Error: %s" % exc)
        raise click.exceptions.Exit(1)
    except (AttributeError, TypeError, ValueError, KeyError) as exc:
        _cli_error("Invalid status response from API: %s" % exc)


@main.command()
def restart():
    """Restart SAGEDRAL-ML service."""
    try:
        stop.callback()
        start.callback(daemon=True, no_capture=False)
    except Exception as e:
        _cli_error(f"Error during restart: {e}")


# ================= CONFIG COMMANDS =================

@main.group()
def config():
    """Configuration management subcommands."""
    pass


@config.command("show")
def config_show():
    """Show current active configuration."""
    try:
        cfg = get_config()
        click.echo(json.dumps(cfg.to_safe_dict(), indent=2))
    except Exception as e:
        _cli_error(f"Failed to load config: {e}")


@config.command("template")
def config_template():
    """Generate default config.toml template to stdout."""
    try:
        click.echo(generate_default_toml_string())
    except Exception as e:
        _cli_error(f"Failed to generate template: {e}")


@config.command("validate")
def config_validate():
    """Validate configuration file."""
    try:
        cfg = get_config()
        errors = cfg.validate()
        if errors:
            click.secho("Configuration Validation FAILED:", fg="red", bold=True)
            for err in errors:
                click.echo(f"  - {err}")
            sys.exit(1)
        else:
            click.secho("Configuration is VALID.", fg="green", bold=True)
    except Exception as e:
        _cli_error(f"Validation error: {e}")


# ================= DATABASE / BACKUP COMMANDS =================


@main.group()
def database():
    """Database schema migration commands."""
    pass


@database.command("migrate")
def database_migrate():
    """Apply all bundled Alembic migrations."""
    try:
        from sagedral_ml.database.connection import run_alembic_migrations

        if not run_alembic_migrations():
            _cli_error("Database migration did not complete; inspect the log.")
        _cli_ok("Database migration completed.")
    except Exception as exc:
        _cli_error("Database migration failed: %s" % exc)


@database.command("revision")
@click.option("--message", required=True, help="Short migration description")
def database_revision(message):
    """Create an autogenerated schema revision for developers."""
    try:
        from alembic import command
        from alembic.config import Config as AlembicConfig

        root = Path(__file__).resolve().parents[1]
        alembic_config = AlembicConfig(str(root / "alembic.ini"))
        command.revision(alembic_config, message=message, autogenerate=True)
    except Exception as exc:
        _cli_error("Could not create migration revision: %s" % exc)


# ================= BACKUP COMMANDS =================

@main.group()
def backup():
    """Backup & restore configuration and database."""
    pass


@backup.command("create")
@click.option("--output", "output_path", default=None, help="Output tar.gz archive path (default: ./sagedral-backup-<timestamp>.tar.gz)")
def backup_create(output_path):
    """Create compressed backup archive of config and database."""
    try:
        cfg = get_config()
        db_path = cfg.get("database", "path", "/var/lib/sagedral-ml/sagedral.db")
        data_dir = cfg.get("general", "data_dir", "/var/lib/sagedral-ml")
        model_dir = cfg.get("ml", "model_dir", "/var/lib/sagedral-ml/models")

        candidates = []
        for p in (DEFAULT_CONFIG_PATH, Path.home() / ".config" / "sagedral" / "config.toml"):
            try:
                if Path(p).exists():
                    candidates.append(str(p))
                    break
            except Exception:
                pass
        if not candidates:
            _cli_warn("No config.toml file found on disk; backing up in-memory config snapshot only.")

        sources: List[Tuple[str, str]] = []
        for file_path in candidates:
            sources.append((file_path, os.path.basename(file_path)))

        from sagedral_ml.database.backup import DatabaseBackupManager

        managed_db_backup = DatabaseBackupManager(cfg).run_full_backup()
        if managed_db_backup:
            sources.append(
                (
                    managed_db_backup,
                    "database/%s" % os.path.basename(managed_db_backup),
                )
            )
        elif os.path.exists(db_path):
            sources.append((db_path, f"database/{os.path.basename(db_path)}"))

        if os.path.isdir(model_dir):
            for root, _, files in os.walk(model_dir):
                for f in files:
                    src_full = os.path.join(root, f)
                    rel = os.path.relpath(src_full, os.path.dirname(model_dir) or data_dir)
                    sources.append((src_full, f"models/{rel}"))

        if not output_path:
            ts = time.strftime("%Y%m%d-%H%M%S")
            output_path = os.path.join(os.getcwd(), f"sagedral-backup-{ts}.tar.gz")

        output_path = os.path.abspath(output_path)
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

        click.echo(f"Creating backup archive -> {output_path}")
        count = 0
        with tarfile.open(output_path, "w:gz") as tar:
            for src_full, arc_name in sources:
                try:
                    tar.add(src_full, arcname=arc_name)
                    count += 1
                    click.echo(f"  + {arc_name}")
                except Exception as e:
                    _cli_warn(f"Skip {src_full}: {e}")

            manifest = {
                "created_at": time.time(),
                "version": __version__,
                "config_snapshot": cfg.to_dict(),
                "entries": [a for _, a in sources],
            }
            import io
            manifest_bytes = json.dumps(manifest, indent=2).encode("utf-8")
            info = tarfile.TarInfo(name="manifest.json")
            info.size = len(manifest_bytes)
            tar.addfile(info, io.BytesIO(manifest_bytes))
            count += 1

        archive_size = os.path.getsize(output_path)
        try:
            os.chmod(output_path, 0o600)
        except OSError:
            pass
        _cli_ok(f"Backup complete: {output_path} ({count} files, {archive_size} bytes)")
        return
    except click.exceptions.Exit:
        raise
    except Exception as e:
        _cli_error(f"Backup creation failed: {e}")


@backup.command("list")
def backup_list():
    """List available managed database backups."""
    try:
        from sagedral_ml.database.backup import DatabaseBackupManager

        manager = DatabaseBackupManager(get_config())
        backups = manager._list_backups()
        if not backups:
            click.echo("No managed backups found.")
            return
        for path in backups:
            stat_info = path.stat()
            click.echo(
                "%s  %10d bytes  %s"
                % (
                    time.strftime(
                        "%Y-%m-%d %H:%M:%S",
                        time.localtime(stat_info.st_mtime),
                    ),
                    stat_info.st_size,
                    path,
                )
            )
    except Exception as exc:
        _cli_error("Backup list failed: %s" % exc)


@backup.command("restore")
@click.option("--source", "source_path", required=True, type=click.Path(exists=True, dir_okay=False), help="Path to backup tar.gz archive")
@click.option("--confirm", is_flag=True, default=False, help="Confirm destructive restore operation")
def backup_restore(source_path, confirm):
    """Restore configuration and database from backup archive."""
    try:
        source_path = os.path.abspath(source_path)
        if not confirm:
            click.secho(
                "WARNING: Restore will OVERWRITE existing database and model files. Re-run with --confirm to proceed.",
                fg="yellow",
                bold=True,
            )
            sys.exit(2)

        cfg = get_config()
        db_path = cfg.get("database", "path", "/var/lib/sagedral-ml/sagedral.db")
        data_dir = cfg.get("general", "data_dir", "/var/lib/sagedral-ml")
        model_dir = cfg.get("ml", "model_dir", "/var/lib/sagedral-ml/models")

        click.echo(f"Restoring from backup: {source_path}")

        manifest = None
        try:
            with tarfile.open(source_path, "r:gz") as tar:
                if "manifest.json" in tar.getnames():
                    mbr = tar.getmember("manifest.json")
                    f = tar.extractfile(mbr)
                    if f:
                        manifest = json.loads(f.read().decode("utf-8"))
                        click.echo(f"  Manifest: version={manifest.get('version')}, created={manifest.get('created_at')}")
        except Exception as e:
            _cli_warn(f"Could not read manifest.json: {e}")

        extract_dir = os.path.join(data_dir, f"restore-{int(time.time())}")
        os.makedirs(extract_dir, exist_ok=True)

        try:
            with tarfile.open(source_path, "r:gz") as tar:
                extract_root = os.path.realpath(extract_dir)
                safe_members = []
                for member in tar.getmembers():
                    target = os.path.realpath(
                        os.path.join(extract_root, member.name)
                    )
                    if not (
                        target == extract_root
                        or target.startswith(extract_root + os.sep)
                    ):
                        raise ValueError(
                            "Unsafe archive path: %s" % member.name
                        )
                    if member.issym() or member.islnk():
                        raise ValueError(
                            "Archive links are not allowed: %s" % member.name
                        )
                    safe_members.append(member)
                tar.extractall(path=extract_dir, members=safe_members)
        except Exception as e:
            shutil.rmtree(extract_dir, ignore_errors=True)
            _cli_error(f"Failed to extract archive: {e}")
            return

        restored = 0
        try:
            extracted_db = os.path.join(extract_dir, "database", os.path.basename(db_path))
            if os.path.exists(extracted_db):
                os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
                if os.path.exists(db_path):
                    bak = f"{db_path}.before-restore-{int(time.time())}"
                    shutil.copy2(db_path, bak)
                    click.echo(f"  Existing DB backed up: {bak}")
                shutil.copy2(extracted_db, db_path)
                restored += 1
                click.echo(f"  Restored database -> {db_path}")

            extracted_models = os.path.join(extract_dir, "models")
            if os.path.isdir(extracted_models):
                os.makedirs(model_dir, exist_ok=True)
                for root, _, files in os.walk(extracted_models):
                    for fname in files:
                        src = os.path.join(root, fname)
                        rel = os.path.relpath(src, extracted_models)
                        dst = os.path.join(model_dir, rel)
                        os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)
                        shutil.copy2(src, dst)
                        restored += 1
                click.echo(f"  Restored models -> {model_dir}")

            for cfg_name in ("config.toml",):
                cfg_src = os.path.join(extract_dir, cfg_name)
                if os.path.exists(cfg_src):
                    target = str(DEFAULT_CONFIG_PATH)
                    try:
                        os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
                        if os.path.exists(target):
                            bak = f"{target}.before-restore-{int(time.time())}"
                            shutil.copy2(target, bak)
                            click.echo(f"  Existing config backed up: {bak}")
                        shutil.copy2(cfg_src, target)
                        restored += 1
                        click.echo(f"  Restored config -> {target}")
                    except Exception as e:
                        _cli_warn(f"Could not write config to {target}: {e}")
        except Exception as e:
            _cli_error(f"Restore phase failed: {e}")
        finally:
            shutil.rmtree(extract_dir, ignore_errors=True)

        if restored == 0:
            _cli_warn("No recognized backup files were restored. Check archive contents.")
        else:
            _cli_ok(f"Restore complete: {restored} item(s). Restart service to apply changes.")
        return
    except click.exceptions.Exit:
        raise
    except Exception as e:
        _cli_error(f"Backup restore failed: {e}")


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
        _cli_error(str(e))
        return

    try:
        r = requests.post(f"{API_BASE}/blocked-ips", json={
            "ip": clean_ip, "reason": reason, "duration_seconds": duration
        }, headers=_require_api_token(), timeout=3)
        if r.status_code == 200:
            _cli_ok(f"Successfully blocked IP {clean_ip}")
        else:
            _cli_error(f"{r.json().get('detail', r.text)}")
    except Exception as e:
        _cli_error(f"API request failed: {e}")


@main.command()
@click.argument("ip")
def unblock(ip):
    """Manually unblock an IP address from firewall."""
    try:
        clean_ip = validate_ip(ip)
    except ValueError as e:
        _cli_error(str(e))
        return

    try:
        r = requests.delete(
            f"{API_BASE}/blocked-ips/{clean_ip}",
            headers=_require_api_token(),
            timeout=3,
        )
        if r.status_code == 200:
            _cli_ok(f"Successfully unblocked IP {clean_ip}")
        else:
            _cli_error(f"{r.json().get('detail', r.text)}")
    except Exception as e:
        _cli_error(f"API request failed: {e}")


@main.group()
def whitelist():
    """Manage protected single IP/CIDR whitelist entries."""
    pass


@whitelist.command("list")
def whitelist_list():
    try:
        response = requests.get(
            f"{API_BASE}/blocked-ips/whitelist",
            headers=_require_api_token(),
            timeout=5,
        )
        if response.status_code != 200:
            _cli_error(response.text)
        for item in response.json().get("data", []):
            click.echo(
                "%-45s %s" % (item.get("ip", ""), item.get("note", ""))
            )
    except click.exceptions.Exit:
        raise
    except Exception as exc:
        _cli_error("Whitelist request failed: %s" % exc)


@whitelist.command("add")
@click.argument("entry")
@click.option("--note", default="", help="Administrative note")
def whitelist_add(entry, note):
    try:
        clean_entry = validate_ip_or_network(entry)
        response = requests.post(
            f"{API_BASE}/blocked-ips/whitelist",
            json={"ip": clean_entry, "note": note},
            headers=_require_api_token(),
            timeout=5,
        )
        if response.status_code != 200:
            _cli_error(response.text)
        _cli_ok("Whitelist entry added: %s" % clean_entry)
    except click.exceptions.Exit:
        raise
    except Exception as exc:
        _cli_error("Whitelist add failed: %s" % exc)


@whitelist.command("remove")
@click.argument("entry")
def whitelist_remove(entry):
    try:
        clean_entry = validate_ip_or_network(entry)
        response = requests.delete(
            f"{API_BASE}/blocked-ips/whitelist/{clean_entry}",
            headers=_require_api_token(),
            timeout=5,
        )
        if response.status_code != 200:
            _cli_error(response.text)
        _cli_ok("Whitelist entry removed: %s" % clean_entry)
    except click.exceptions.Exit:
        raise
    except Exception as exc:
        _cli_error("Whitelist remove failed: %s" % exc)


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
        r = requests.get(
            f"{API_BASE}/alerts?limit={limit}",
            headers=_require_api_token(),
            timeout=3,
        )
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
        else:
            _cli_error(f"API returned {r.status_code}: {r.text}")
    except Exception as e:
        _cli_error(f"API request failed: {e}")


# ================= MODEL COMMANDS =================

@main.group()
def model():
    """ML model management subcommands."""
    pass


@model.command("init")
@click.option("--force", is_flag=True, help="Overwrite existing model files with fresh fallback models")
@click.option("--model-dir", default=None, help="Override model directory path (default: from config)")
def model_init(force, model_dir):
    """Initialize / regenerate ML detection models (installs fallback models if none exist)."""
    try:
        cfg = get_config()
        resolved_dir = model_dir if model_dir else cfg.get("ml", "model_dir", "/var/lib/sagedral-ml/models")
        enabled = cfg.get("ml", "enabled", True)
        anomaly_threshold = float(cfg.get("ml", "anomaly_threshold", 0.7))
        classifier_threshold = float(cfg.get("ml", "classifier_threshold", 0.6))

        if force:
            for fname in (
                "anomaly_detector.pkl",
                "attack_classifier.pkl",
                "feature_names.json",
                "model_profile.json",
                "model_metadata.json",
            ):
                fp = os.path.join(resolved_dir, fname)
                if os.path.exists(fp):
                    try:
                        os.remove(fp)
                    except OSError as e:
                        _cli_warn(f"could not remove {fp}: {e}")
            pointer = os.path.join(resolved_dir, "active_model.json")
            if os.path.exists(pointer):
                try:
                    os.remove(pointer)
                except OSError as e:
                    _cli_warn(f"could not remove {pointer}: {e}")

        click.echo(f"Initializing ML models in {resolved_dir} ...")
        from sagedral_ml.detection.ml_engine import MLEngine, resolve_model_artifact_dir
        engine = MLEngine(
            model_dir=resolved_dir,
            anomaly_threshold=anomaly_threshold,
            classifier_threshold=classifier_threshold,
            enabled=enabled,
        )

        if engine.model_loaded:
            artifact_dir = resolve_model_artifact_dir(resolved_dir)
            _cli_ok(f"[OK] ML models ready. loaded={engine.model_loaded} version={engine.version}")
            click.echo(f"  anomaly_model.pkl : {os.path.exists(os.path.join(artifact_dir, 'anomaly_detector.pkl'))}")
            click.echo(f"  attack_classifier : {os.path.exists(os.path.join(artifact_dir, 'attack_classifier.pkl'))}")
            if "rulebased" in engine.version:
                _cli_warn("rule-based fallback active. Install lightgbm+scikit-learn for trained models.")
            elif "fallback" in engine.version:
                _cli_warn("synthetic data fallback active. Train on real dataset for production accuracy.")
            sys.exit(0)
        else:
            _cli_error("Could not initialize ML models. Check logs above.")
    except click.exceptions.Exit:
        raise
    except Exception as e:
        _cli_error(f"Model init failed: {e}")


@model.command("info")
def model_info():
    """Show details of loaded ML models."""
    try:
        offline_info = None
        try:
            cfg = get_config()
            resolved_dir = cfg.get("ml", "model_dir", "/var/lib/sagedral-ml/models")
            from sagedral_ml.detection.ml_engine import MLEngine
            engine = MLEngine(
                model_dir=resolved_dir,
                anomaly_threshold=float(cfg.get("ml", "anomaly_threshold", 0.7)),
                classifier_threshold=float(cfg.get("ml", "classifier_threshold", 0.6)),
                enabled=cfg.get("ml", "enabled", True),
            )
            offline_info = {
                "enabled": cfg.get("ml", "enabled", True),
                "loaded": engine.model_loaded,
                "model_dir": resolved_dir,
                "model_version": engine.version,
                "local": True,
            }
        except Exception as e:
            offline_info = {"error": str(e), "local": True}

        try:
            r = requests.get(
                f"{API_BASE}/model/info",
                headers=_api_headers(),
                timeout=2,
            )
            if r.status_code == 200:
                online = r.json()
                online["local"] = False
                click.echo(json.dumps(online, indent=2))
                return
        except Exception:
            pass

        if offline_info is not None:
            click.echo(json.dumps(offline_info, indent=2))
        else:
            _cli_error("Service not running and local engine unavailable.")
    except click.exceptions.Exit:
        raise
    except Exception as e:
        _cli_error(f"Model info failed: {e}")


@main.command()
@click.option("--dataset", "dataset_path", required=True, type=click.Path(exists=True, file_okay=True, dir_okay=True), help="CSV file or directory tree containing CICIDS CSV files")
@click.option("--save-dir", default=None, type=click.Path(file_okay=False), help="Directory to write trained model artifacts (default: ml.model_dir)")
@click.option("--train-test-split", default=0.2, type=click.FloatRange(0.05, 0.5), help="Validation fraction (0.05-0.5)")
@click.option("--max-rows-per-class", default=100000, type=int, help="Deterministic per-class cap (0 disables; high RAM)")
@click.option("--hot-reload", is_flag=True, default=False, help="After training, notify running API to reload models via restart hint")
def train(dataset_path, save_dir, train_test_split, hot_reload, max_rows_per_class):
    """Train LightGBM anomaly detector & attack classifier from dataset CSV."""
    try:
        dataset_path = os.path.abspath(dataset_path)
        if not save_dir:
            save_dir = get_config().get(
                "ml", "model_dir", "/var/lib/sagedral-ml/models"
            )
        save_dir = os.path.abspath(save_dir)
        os.makedirs(save_dir, exist_ok=True)

        click.echo(f"Dataset    : {dataset_path}")
        click.echo(f"Save dir   : {save_dir}")
        click.echo(f"Hot reload : {hot_reload}")

        try:
            from sagedral_ml.scripts.train_model import train_models
        except ImportError as e:
            _cli_error(f"train_models module unavailable: {e}. Ensure numpy/pandas/lightgbm/scikit-learn installed.")
            return

        try:
            train_models(
                dataset_path=dataset_path,
                output_dir=save_dir,
                validation_split=train_test_split,
                max_rows_per_class=max_rows_per_class,
            )
        except Exception as e:
            _cli_error(f"Training pipeline failed: {e}")
            return

        from sagedral_ml.detection.ml_engine import resolve_model_artifact_dir
        artifact_dir = resolve_model_artifact_dir(save_dir)
        required_files = ["anomaly_detector.pkl", "attack_classifier.pkl", "feature_names.json"]
        missing = [f for f in required_files if not os.path.exists(os.path.join(artifact_dir, f))]
        if missing:
            _cli_warn(f"Training finished but missing expected artifacts: {missing}")
        else:
            _cli_ok(f"Training complete. Models saved to {save_dir}")

        if hot_reload:
            click.echo("Hot reload requested: attempting to notify service (service restart recommended).")
            try:
                r = requests.post(
                    f"{API_BASE}/model/reload",
                    headers=_require_api_token(),
                    timeout=10,
                )
                if r.status_code == 200 and r.json().get("success"):
                    _cli_ok("Running service reloaded the trained model.")
                else:
                    _cli_warn(f"Model reload returned {r.status_code}: {r.text}")
            except Exception as e:
                _cli_warn(f"Service unreachable for hot reload notification: {e}")
            click.echo("  Tip: set ml.model_dir in config to the trained save-dir, then restart or reload.")
        return
    except click.exceptions.Exit:
        raise
    except Exception as e:
        _cli_error(f"Train command failed: {e}")


# ================= SELF-TEST COMMANDS (Sniffer + Capture Debug WSL) =================

@main.group()
def selftest():
    """Self-test diagnostics: capture sniffer, models, IPS firewalls."""
    pass


def _cli_detect_primary_iface_and_ip():
    import re, subprocess
    try:
        out = subprocess.check_output(["ip", "-4", "-o", "addr", "show"], text=True)
        ifaces = []
        for line in out.splitlines():
            m = re.search(r"^\d+:\s+(\S+?)(@\S+)?\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
            if not m:
                continue
            iface, ip, cidr = m.group(1), m.group(3), int(m.group(4))
            if iface == "lo":
                continue
            prio = 0 if iface == "wifi0" else (1 if iface == "eth0" else 2)
            ifaces.append((prio, iface, ip, cidr))
        ifaces.sort()
        return ifaces[0][1], ifaces[0][2], ifaces[0][3]
    except Exception:
        return "any", "127.0.0.1", 8


@selftest.command("capture")
@click.option("--iface", default=None, help="Override interface to test (default: auto detect wifi0)")
@click.option("--duration", type=int, default=8, help="Seconds to run capture probe")
@click.option("--external-ip", default="8.8.8.8", help="External dst IP to force packet exit via real NIC")
def selftest_capture(iface, duration, external_ip):
    """
    PROOF sniffer SAGEDRAL & interface OK.
    Teknik: Kirim 80+ UDP + TCP + ICMP ke EXTERNAL IP (8.8.8.8) melalui default route wifi0.
    Paket KELUAR interface BENAR → AF_PACKET menangkap → tcpdump/scapy BISA baca.
    Output: Packet count per interface + rekomendasi interface capture terbaik.
    """
    try:
        import random, socket, subprocess, threading, tempfile, time
        try:
            if os.geteuid() != 0:
                _cli_error("SELFTEST CAPTURE BUTUH ROOT. Jalankan sudo.")
                sys.exit(2)
        except AttributeError:
            _cli_warn("Cannot detect UID; assuming Windows/non-POSIX. Capture tests may require elevated privileges.")

        iface_auto, primary_ip, cidr = _cli_detect_primary_iface_and_ip()
        iface = iface or iface_auto

        click.secho(f"=== SAGEDRAL SELFTEST: CAPTURE INTERFACE ===", bold=True)
        click.echo(f"  Primary interface  : {iface} (IP={primary_ip})")
        click.echo(f"  External dst IP    : {external_ip} (paket keluar via real NIC WiFi0)")
        click.echo(f"  Duration           : {duration}s")
        click.echo(f"  Teknik             : UDP/TCP/ICMP keluar via default route → AF_PACKET capture.")

        candidates = ["any", iface, "lo"]
        candidates = list(dict.fromkeys(candidates))
        procs = {}
        outfiles = {}
        try:
            for i in candidates:
                tf = tempfile.NamedTemporaryFile(delete=False, suffix=f".cap{i}.txt")
                tf.close()
                outfiles[i] = tf.name
                try:
                    p = subprocess.Popen(
                        ["tcpdump", "-ni", i, "-c", "1500", "-Q", "out",
                         f"(udp or tcp or icmp) and dst host {external_ip}"],
                        stdout=open(tf.name, "w", encoding="utf-8"),
                        stderr=subprocess.DEVNULL,
                    )
                    procs[i] = p
                except Exception as e:
                    _cli_warn(f"tcpdump gagal iface {i}: {e}")
            click.echo(f"\n[*] Tunggu 1.5d tcpdump ready...")
            time.sleep(1.5)

            def _send():
                try:
                    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    for _ in range(50):
                        try:
                            payload = bytes([random.randint(0,255) for _ in range(random.randint(64, 512))])
                            u.sendto(payload, (external_ip, random.choice([53, 5353, 123, 67, 80, 443])))
                        except Exception:
                            pass
                        time.sleep(0.001)
                    u.close()
                except Exception:
                    pass
                for _ in range(25):
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(0.03)
                        s.setblocking(False)
                        try: s.connect_ex((external_ip, random.choice([80,443,22,53,8080])))
                        except Exception: pass
                        try: s.close()
                        except Exception: pass
                    except Exception:
                        pass
                    time.sleep(0.005)
                try:
                    for _ in range(10):
                        subprocess.run(["ping", "-c", "1", "-W", "1", external_ip],
                                       capture_output=True, timeout=3, check=False)
                except Exception:
                    pass
                click.echo(f"\n  [SEND OK] 85+ probe packets keluar menuju {external_ip} via wifi0 default route.")
            t_send = threading.Thread(target=_send, daemon=True)
            t_send.start()
            t_send.join(timeout=duration)

            time.sleep(2.5)
        finally:
            for i, p in procs.items():
                try:
                    p.terminate()
                    try: p.wait(timeout=2)
                    except Exception: p.kill()
                except Exception:
                    pass

        click.echo(f"\n{'─'*60}")
        click.secho("HASIL: Packet COUNT tertangkap per interface (outgoing ke %s):\n" % external_ip, bold=True)
        click.echo(f"  {'Interface':15s}  Packets  Status")
        click.echo(f"  {'─'*15}  ───────  ───────────")
        scored = []
        for i, fpath in outfiles.items():
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    lines = [ln for ln in f.readlines() if ln.strip() and "listening on" not in ln and "tcpdump:" not in ln]
                count = len(lines)
            except Exception:
                count = -1
            mark = "✅ CAPTURE OK (>20)" if count >= 20 else ("⚠️  (<20)" if count > 0 else "❌ TIDAK ADA PAKET")
            click.echo(f"  {i:15s}  {count:>7d}  {mark}")
            scored.append((i, count))
            try: os.unlink(fpath)
            except Exception: pass

        scored_sorted = sorted(scored, key=lambda x: (-x[1], 0 if x[0]!="any" else 1))
        best_name, best_cnt = scored_sorted[0]
        click.echo(f"\n[REKOMENDASI] capture.interface = {best_name}  (packets={best_cnt})")

        if best_cnt < 20:
            click.secho("\n[WARN] Packet capture < 20! WSL network mungkin firewall luar blokir atau route tidak ke wifi0.", fg="yellow", bold=True)
            click.echo("   Solusi:")
            click.echo("     1. Pastikan Windows host Anda terkoneksi Internet aktif (WiFi/Hotspot HP).")
            click.echo("     2. Coba ganti --external-ip=1.1.1.1 / --external-ip=208.67.222.222.")
            click.echo("     3. Pastikan WSL mirror mode auto-proxy TIDAK memblock paket UDP/ICMP keluar.")
            click.echo("     4. Jika tetap 0 → firewall Windows/antivirus blocking. Untuk test sementara gunakan inject_flow_simulator.py.")
            sys.exit(3)
        else:
            _cli_ok(f"[✅] SNIFFER SAGEDRAL BISA MENANGKAP PAKET di interface {best_name}.")
            click.echo("   Sekarang Anda bisa jalankan attack script yang menargetkan IP EXTERNAL + SNAT spoof src IP.")
            click.echo(f"   Silakan lanjut ke: sudo python3 sagedral_full_test_wsl.py --iface {best_name}")
            sys.exit(0)
    except click.exceptions.Exit:
        raise
    except Exception as e:
        _cli_error(f"Selftest capture failed: {e}")


@selftest.command("sniffer-status")
def selftest_sniffer_status():
    """Query live packet count & capture stats dari SAGEDRAL API (service harus jalan)."""
    try:
        r = requests.get(f"{API_BASE}/status", timeout=2.5)
        if r.status_code != 200:
            _cli_error(f"Service OFFLINE. Start dulu: sagedral-ml start (HTTP {r.status_code})")
            sys.exit(1)
        data = r.json()
        click.secho("Live capture status:", bold=True)
        for k in ("interface", "uptime_seconds", "blocked_ips_count", "ml_model_loaded",
                  "packets_captured_total", "flows_processed", "alerts_total_count"):
            if k in data:
                click.echo(f"  {k:35s} = {data[k]}")
    except click.exceptions.Exit:
        raise
    except Exception as e:
        _cli_error(f"Gagal query API: {e}. Jalankan service dulu: sagedral-ml start")
