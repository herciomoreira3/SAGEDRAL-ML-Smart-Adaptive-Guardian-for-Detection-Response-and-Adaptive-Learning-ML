"""Enterprise integrations: GeoIP, SIEM CEF, webhooks, email, and Telegram."""

import json
import logging
import smtplib
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from email.message import EmailMessage
from typing import Any, Dict, List, Optional, Tuple
from urllib import parse, request

from sagedral_ml.config import get_config

logger = logging.getLogger("sagedral_ml.integrations")

SEVERITY_RANK = {
    "DEBUG": 0,
    "INFO": 1,
    "LOW": 2,
    "MEDIUM": 3,
    "HIGH": 4,
    "CRITICAL": 5,
}


def _severity_allowed(severity: str, minimum: str) -> bool:
    return SEVERITY_RANK.get(str(severity).upper(), 0) >= SEVERITY_RANK.get(
        str(minimum).upper(), 3
    )


class GeoIPResolver:
    """Optional MaxMind resolver with a zero-dependency fallback."""

    def __init__(self, config=None) -> None:
        self.config = config or get_config()
        self._reader = None
        if not self.config.get("geolocation", "enabled", False):
            return
        path = self.config.get(
            "geolocation", "db_path", "/usr/share/GeoIP/GeoLite2-Country.mmdb"
        )
        try:
            import geoip2.database

            self._reader = geoip2.database.Reader(path)
        except Exception as exc:
            logger.warning("GeoIP unavailable (%s); country fields remain unknown.", exc)

    def country(self, ip: str) -> Tuple[Optional[str], Optional[str]]:
        if self._reader is None:
            return None, None
        try:
            result = self._reader.country(ip)
            return result.country.name, result.country.iso_code
        except Exception:
            return None, None

    def close(self) -> None:
        if self._reader is not None:
            try:
                self._reader.close()
            except Exception:
                pass


class SIEMExporter:
    """Send CEF events through syslog UDP/TCP and generic HTTPS webhooks."""

    def __init__(self, config=None) -> None:
        self.config = config or get_config()
        self._executor = ThreadPoolExecutor(
            max_workers=2,
            thread_name_prefix="sagedral-siem",
        )

    def _cef(self, alert: Dict[str, Any]) -> str:
        severity = str(alert.get("severity", "MEDIUM")).upper()
        cef_severity = {
            "LOW": 3,
            "MEDIUM": 5,
            "HIGH": 8,
            "CRITICAL": 10,
        }.get(severity, 5)
        def clean(value: Any) -> str:
            return (
                str(value if value is not None else "")
                .replace("\\", "\\\\")
                .replace("\r", " ")
                .replace("\n", " ")
                .replace("=", "\\=")
                .replace("|", "\\|")
            )

        extension = (
            "src=%s dst=%s spt=%s dpt=%s act=%s cs1=%s cs1Label=AlertId"
            % (
                clean(alert.get("src_ip", "")),
                clean(alert.get("dst_ip", "")),
                clean(alert.get("src_port", 0) or 0),
                clean(alert.get("dst_port", 0) or 0),
                clean(alert.get("action_taken", "")),
                clean(alert.get("alert_id", "")),
            )
        )
        return "CEF:0|SAGEDRAL|ML-NIDPS|1.0|1001|%s|%s|%s" % (
            clean(alert.get("attack_type", "Network Threat")),
            cef_severity,
            extension,
        )

    def send(self, alert: Dict[str, Any]) -> None:
        if not self.config.get("siem", "enabled", False):
            return
        minimum = self.config.get("siem", "minimum_severity", "MEDIUM")
        if not _severity_allowed(alert.get("severity", ""), minimum):
            return
        self._executor.submit(self._send_sync, dict(alert))

    def _send_sync(self, alert: Dict[str, Any]) -> None:
        cef = self._cef(alert)
        host = str(self.config.get("siem", "syslog_host", "") or "")
        port = int(self.config.get("siem", "syslog_port", 514) or 514)
        protocol = str(
            self.config.get("siem", "syslog_protocol", "udp") or "udp"
        ).lower()
        if host:
            try:
                sock_type = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
                with socket.socket(socket.AF_INET, sock_type) as sock:
                    sock.settimeout(5)
                    if protocol == "tcp":
                        sock.connect((host, port))
                        sock.sendall((cef + "\n").encode("utf-8"))
                    else:
                        sock.sendto(cef.encode("utf-8"), (host, port))
            except Exception as exc:
                logger.error("SIEM syslog delivery failed: %s", exc)
        for url in self.config.get("siem", "webhook_urls", []) or []:
            target = str(url)
            if "hooks.slack.com" in target:
                payload = {"text": cef}
            elif "webhook.office.com" in target or "logic.azure.com" in target:
                payload = {
                    "@type": "MessageCard",
                    "@context": "https://schema.org/extensions",
                    "summary": "SAGEDRAL-ML security alert",
                    "themeColor": "D32F2F",
                    "text": cef,
                }
            else:
                payload = {
                    "source": "sagedral-ml",
                    "cef": cef,
                    "alert": alert,
                }
            self._post_json(target, payload)

    def close(self) -> None:
        self._executor.shutdown(wait=False)

    def _post_json(self, url: str, payload: Dict[str, Any]) -> None:
        try:
            timeout = int(
                self.config.get("siem", "webhook_timeout_seconds", 5) or 5
            )
            data = json.dumps(payload, default=str).encode("utf-8")
            req = request.Request(
                url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with request.urlopen(req, timeout=timeout) as response:
                if int(response.status) >= 400:
                    raise RuntimeError("webhook HTTP %s" % response.status)
        except Exception as exc:
            logger.error("SIEM webhook delivery failed for %s: %s", url, exc)


class NotificationManager:
    """Dispatch high-severity notifications outside the processing hot loop."""

    def __init__(self, config=None) -> None:
        self.config = config or get_config()
        self._executor = ThreadPoolExecutor(
            max_workers=4,
            thread_name_prefix="sagedral-notification",
        )

    def submit(self, alert: Dict[str, Any]) -> None:
        if not self.config.get("notifications", "enabled", False):
            return
        minimum = self.config.get("notifications", "minimum_severity", "HIGH")
        if not _severity_allowed(alert.get("severity", ""), minimum):
            return
        self._executor.submit(self._deliver, dict(alert))

    def close(self) -> None:
        self._executor.shutdown(wait=False)

    def _message(self, alert: Dict[str, Any]) -> str:
        return (
            "[ALERTA %s] SAGEDRAL-ML\n"
            "Tipu: %s\nOrigem: %s\nDestinu: %s:%s\nSkor: %.2f\nAsaun: %s"
            % (
                alert.get("severity", "HIGH"),
                alert.get("attack_type", "Unknown"),
                alert.get("src_ip", ""),
                alert.get("dst_ip", ""),
                alert.get("dst_port", 0) or 0,
                float(alert.get("final_score", 0.0) or 0.0),
                alert.get("action_taken", ""),
            )
        )

    def _deliver(self, alert: Dict[str, Any]) -> None:
        message = self._message(alert)
        self._telegram(message)
        self._email(message, alert)

    def _telegram(self, message: str) -> None:
        token = str(
            self.config.get("notifications", "telegram_bot_token", "") or ""
        )
        chat_id = str(
            self.config.get("notifications", "telegram_chat_id", "") or ""
        )
        if not token or not chat_id:
            return
        try:
            url = "https://api.telegram.org/bot%s/sendMessage" % token
            body = parse.urlencode(
                {"chat_id": chat_id, "text": message}
            ).encode("utf-8")
            req = request.Request(url, data=body, method="POST")
            with request.urlopen(req, timeout=8):
                pass
        except Exception as exc:
            logger.error("Telegram notification failed: %s", exc)

    def _email(self, message: str, alert: Dict[str, Any]) -> None:
        host = str(self.config.get("notifications", "smtp_host", "") or "")
        recipients = self.config.get("notifications", "email_recipients", []) or []
        sender = str(self.config.get("notifications", "email_sender", "") or "")
        if not host or not recipients or not sender:
            return
        mail = EmailMessage()
        mail["Subject"] = "[SAGEDRAL] %s - %s" % (
            alert.get("severity", "HIGH"),
            alert.get("attack_type", "Network Threat"),
        )
        mail["From"] = sender
        mail["To"] = ", ".join(str(item) for item in recipients)
        mail.set_content(message)
        port = int(self.config.get("notifications", "smtp_port", 587) or 587)
        username = str(
            self.config.get("notifications", "smtp_username", "") or ""
        )
        password = str(
            self.config.get("notifications", "smtp_password", "") or ""
        )
        try:
            with smtplib.SMTP(host, port, timeout=10) as smtp:
                if self.config.get("notifications", "smtp_starttls", True):
                    smtp.starttls(context=ssl.create_default_context())
                if username:
                    smtp.login(username, password)
                smtp.send_message(mail)
        except Exception as exc:
            logger.error("Email notification failed: %s", exc)


geoip_resolver = GeoIPResolver()
siem_exporter = SIEMExporter()
notification_manager = NotificationManager()
