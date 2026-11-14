"""Hardened dummy scanner verifying `/work/in` read-only mount and `/work/out` artifact output."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path


def main() -> int:
    work_in = Path("/work/in")
    work_out = Path("/work/out")
    manifest_file = work_in / "manifest.json"
    manifest = (
        json.loads(manifest_file.read_text(encoding="utf-8")) if manifest_file.exists() else {}
    )

    probe_url = os.environ.get("VFORGE_PROBE_URL", "").strip()
    probe_status: str = "skipped"
    if probe_url:
        try:
            req = urllib.request.Request(probe_url, method="GET")  # noqa: S310
            with urllib.request.urlopen(req, timeout=5.0) as resp:  # noqa: S310
                probe_status = f"http_{resp.status}"
        except (urllib.error.URLError, OSError) as exc:
            probe_status = f"blocked_or_error:{type(exc).__name__}"

    output = {
        "schema": "vforge.dummy-scanner.v1",
        "job_id": os.environ.get("VFORGE_JOB_ID", ""),
        "scan_run_id": os.environ.get("VFORGE_SCAN_RUN_ID", ""),
        "tool_id": os.environ.get("VFORGE_TOOL_ID", "vforge-dummy-scanner"),
        "network_profile": os.environ.get("VFORGE_NETWORK_PROFILE", "none"),
        "manifest_kind": manifest.get("kind", "unknown"),
        "probe_status": probe_status,
        "status": "completed",
    }
    work_out.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(output, sort_keys=True, indent=2)
    (work_out / "result.json").write_text(serialized, encoding="utf-8")
    print(json.dumps({"job_id": output["job_id"], "status": "completed"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
