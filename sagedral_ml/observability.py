"""Dependency-free Prometheus metrics and health state for SAGEDRAL-ML.

The registry deliberately implements only the small subset of the Prometheus
text format needed by this service.  This keeps the runtime compatible with
Python 3.8 and makes metrics available even when optional monitoring packages
are not installed.
"""

import os
import threading
import time
from collections import defaultdict
from typing import Dict, Iterable, Optional, Tuple


def _label_key(labels: Optional[Dict[str, object]]) -> Tuple[Tuple[str, str], ...]:
    if not labels:
        return ()
    return tuple(sorted((str(k), str(v)) for k, v in labels.items()))


def _format_labels(labels: Tuple[Tuple[str, str], ...]) -> str:
    if not labels:
        return ""
    escaped = []
    for key, value in labels:
        safe = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
        escaped.append('%s="%s"' % (key, safe))
    return "{" + ",".join(escaped) + "}"


class MetricsRegistry:
    """Thread-safe counter/gauge registry."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._counters = defaultdict(float)  # type: Dict[Tuple[str, Tuple], float]
        self._gauges = defaultdict(float)  # type: Dict[Tuple[str, Tuple], float]
        self._started_at = time.time()

    def inc(
        self,
        name: str,
        value: float = 1.0,
        labels: Optional[Dict[str, object]] = None,
    ) -> None:
        with self._lock:
            self._counters[(name, _label_key(labels))] += float(value)

    def set(
        self,
        name: str,
        value: float,
        labels: Optional[Dict[str, object]] = None,
    ) -> None:
        with self._lock:
            self._gauges[(name, _label_key(labels))] = float(value)

    def get(self, name: str, labels: Optional[Dict[str, object]] = None) -> float:
        key = (name, _label_key(labels))
        with self._lock:
            if key in self._counters:
                return self._counters[key]
            return self._gauges.get(key, 0.0)

    def render(self) -> str:
        lines = [
            "# HELP sagedral_uptime_seconds Process uptime in seconds.",
            "# TYPE sagedral_uptime_seconds gauge",
            "sagedral_uptime_seconds %.3f" % (time.time() - self._started_at),
        ]
        with self._lock:
            counter_items = sorted(self._counters.items(), key=lambda item: str(item[0]))
            gauge_items = sorted(self._gauges.items(), key=lambda item: str(item[0]))
        emitted = set()
        for (name, labels), value in counter_items:
            if name not in emitted:
                lines.extend(
                    [
                        "# TYPE %s counter" % name,
                    ]
                )
                emitted.add(name)
            lines.append("%s%s %.6f" % (name, _format_labels(labels), value))
        for (name, labels), value in gauge_items:
            if name not in emitted:
                lines.extend(
                    [
                        "# TYPE %s gauge" % name,
                    ]
                )
                emitted.add(name)
            lines.append("%s%s %.6f" % (name, _format_labels(labels), value))
        return "\n".join(lines) + "\n"


metrics = MetricsRegistry()


def process_memory_rss_bytes() -> float:
    """Return RSS without requiring psutil."""
    try:
        import psutil

        return float(psutil.Process(os.getpid()).memory_info().rss)
    except Exception:
        return 0.0

