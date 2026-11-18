"""Zero-dependency Prometheus text-format v0.0.4 metrics registry for VForge API."""

from __future__ import annotations

import re
import threading
from collections import defaultdict

_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_NUMERIC_SEGMENT_RE = re.compile(r"/\d+(?=/|$)")
_MAX_ROUTE_LABELS = 256


def normalize_route_label(path: str) -> str:
    """Collapse IDs & query strings for low-cardinality PII-free metric labels."""
    clean = path.split("?", 1)[0].strip() or "/"
    clean = _UUID_RE.sub("{id}", clean)
    clean = _NUMERIC_SEGMENT_RE.sub("/{n}", clean)
    if len(clean) > 120:
        return clean[:120]
    return clean


def _escape_label_value(val: str) -> str:
    return val.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "")


class PrometheusMetricsRegistry:
    """Thread-safe in-process Prometheus exposition metrics collector."""

    def __init__(self, *, max_route_labels: int = _MAX_ROUTE_LABELS) -> None:
        self._lock = threading.Lock()
        self._max_route_labels = max(max_route_labels, 8)
        self._known_routes: set[str] = set()
        self._http_requests: dict[tuple[str, str, str], int] = defaultdict(int)
        self._http_duration_sum: dict[tuple[str, str], float] = defaultdict(float)
        self._http_duration_count: dict[tuple[str, str], int] = defaultdict(int)
        self._security_denials: dict[str, int] = defaultdict(int)
        self._rate_limit_hits: int = 0
        self._dr_drills_passed: int = 0
        self._dr_drills_failed: int = 0
        self._key_rotations_total: int = 0

    def reset(self) -> None:
        with self._lock:
            self._known_routes.clear()
            self._http_requests.clear()
            self._http_duration_sum.clear()
            self._http_duration_count.clear()
            self._security_denials.clear()
            self._rate_limit_hits = 0
            self._dr_drills_passed = 0
            self._dr_drills_failed = 0
            self._key_rotations_total = 0

    def observe_http_request(
        self,
        *,
        method: str,
        path: str,
        status_code: int,
        duration_seconds: float,
    ) -> None:
        route = normalize_route_label(path)
        m = method.upper()[:16]
        code = str(status_code)
        with self._lock:
            if route not in self._known_routes:
                if len(self._known_routes) >= self._max_route_labels:
                    route = "__overflow__"
                else:
                    self._known_routes.add(route)
            self._http_requests[(m, route, code)] += 1
            self._http_duration_sum[(m, route)] += max(duration_seconds, 0.0)
            self._http_duration_count[(m, route)] += 1
            if status_code == 429:
                self._rate_limit_hits += 1
            elif status_code in {401, 403}:
                self._security_denials[f"http_{code}"] += 1

    def record_security_denial(self, reason: str) -> None:
        clean_reason = re.sub(r"[^a-zA-Z0-9_]", "_", reason.strip().lower())[:48] or "unspecified"
        with self._lock:
            self._security_denials[clean_reason] += 1

    def record_dr_drill(self, *, passed: bool) -> None:
        with self._lock:
            if passed:
                self._dr_drills_passed += 1
            else:
                self._dr_drills_failed += 1

    def record_key_rotation(self) -> None:
        with self._lock:
            self._key_rotations_total += 1

    def render_prometheus_text(self, *, phase: int = 15) -> str:
        """Render Prometheus exposition format v0.0.4 without PII, tokens, or tenant IDs."""
        with self._lock:
            lines: list[str] = [
                "# HELP vforge_build_info Static VForge API build and active phase metadata.",
                "# TYPE vforge_build_info gauge",
                f'vforge_build_info{{service="vforge-api",phase="{phase}"}} 1',
                "# HELP vforge_http_requests_total Total HTTP requests by normalized route.",
                "# TYPE vforge_http_requests_total counter",
            ]
            for (method, route, code), count in sorted(self._http_requests.items()):
                lines.append(
                    f'vforge_http_requests_total{{method="{_escape_label_value(method)}",'
                    f'route="{_escape_label_value(route)}",'
                    f'status="{_escape_label_value(code)}"}} {count}'
                )

            lines.extend(
                [
                    "# HELP vforge_http_request_duration_seconds Request latency.",
                    "# TYPE vforge_http_request_duration_seconds summary",
                ]
            )
            for (method, route), total in sorted(self._http_duration_sum.items()):
                cnt = self._http_duration_count[(method, route)]
                m_esc = _escape_label_value(method)
                r_esc = _escape_label_value(route)
                sum_metric = (
                    f'vforge_http_request_duration_seconds_sum{{method="{m_esc}",'
                    f'route="{r_esc}"}} {total:.6f}'
                )
                cnt_metric = (
                    f'vforge_http_request_duration_seconds_count{{method="{m_esc}",'
                    f'route="{r_esc}"}} {cnt}'
                )
                lines.append(sum_metric)
                lines.append(cnt_metric)

            lines.extend(
                [
                    "# HELP vforge_security_denials_total Security denial counts.",
                    "# TYPE vforge_security_denials_total counter",
                ]
            )
            for reason, cnt in sorted(self._security_denials.items()):
                reason_esc = _escape_label_value(reason)
                lines.append(f'vforge_security_denials_total{{reason="{reason_esc}"}} {cnt}')

            lines.extend(
                [
                    "# HELP vforge_rate_limit_hits_total Total HTTP 429 rate-limit rejections.",
                    "# TYPE vforge_rate_limit_hits_total counter",
                    f"vforge_rate_limit_hits_total {self._rate_limit_hits}",
                    "# HELP vforge_dr_drills_total DR verification drill outcomes.",
                    "# TYPE vforge_dr_drills_total counter",
                    f'vforge_dr_drills_total{{outcome="passed"}} {self._dr_drills_passed}',
                    f'vforge_dr_drills_total{{outcome="failed"}} {self._dr_drills_failed}',
                    "# HELP vforge_key_rotations_total Total key rotation / re-wrap operations.",
                    "# TYPE vforge_key_rotations_total counter",
                    f"vforge_key_rotations_total {self._key_rotations_total}",
                ]
            )
            return "\n".join(lines) + "\n"


metrics_registry = PrometheusMetricsRegistry()
