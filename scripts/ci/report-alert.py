#!/usr/bin/env python3
"""Emit human-readable CI annotations from a structured report JSON.

This helper intentionally exits 0 so alert extraction never masks the original job result.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def annotation(level: str, message: str) -> int:
    level = level.lower()
    if level not in {"error", "warning", "notice"}:
        level = "notice"
    print(f"::{level}::{message}")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: report-alert.py <profile> <report-path>", file=sys.stderr)
        return 2

    profile = argv[1]
    report_path = Path(argv[2])
    if not report_path.is_file():
        return annotation("warning", f"{profile} report missing at {report_path}")

    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return annotation("error", f"{profile} report unreadable at {report_path}: {exc}")

    status = str(data.get("status", "unknown"))
    outcome = str(data.get("outcome", "unknown"))
    message = str(data.get("message", "unknown"))
    schema_version = str(data.get("schema_version", "1"))

    if profile == "submodule-freshness":
        exit_code = data.get("exit_code", "unknown")
        if status == "fail":
            return annotation("error", f"submodule freshness failed schema={schema_version} outcome={outcome} exit_code={exit_code} message={message}")
        if status == "skip":
            return annotation("warning", f"submodule freshness skipped schema={schema_version} outcome={outcome} message={message}")
        return annotation("notice", f"submodule freshness passed schema={schema_version} outcome={outcome}")

    if profile == "governance":
        if status == "fail":
            return annotation("error", f"governance check failed schema={schema_version} outcome={outcome} message={message}")
        if status == "skip":
            return annotation("warning", f"governance check skipped schema={schema_version} outcome={outcome} message={message}")
        return annotation("notice", f"governance check passed schema={schema_version} outcome={outcome}")

    if profile == "shell-coverage":
        coverage = data.get("coverage_percent", "unknown")
        threshold = data.get("threshold_percent", "unknown")
        if status != "pass":
            return annotation("error", f"shell coverage failed coverage={coverage}% threshold={threshold}%")
        return annotation("notice", f"shell coverage passed coverage={coverage}% threshold={threshold}%")

    if profile == "ci-debug":
        stage = str(data.get("stage", "unknown"))
        failed_command = str(data.get("failed_command", "unknown"))
        if status != "pass":
            return annotation("error", f"ci:debug failed stage={stage} command={failed_command} message={message}")
        return annotation("notice", "ci:debug status=pass")

    if profile == "propagate":
        outcome = str(data.get("outcome", "unknown"))
        tiers_failed = data.get("tiers_failed", "unknown")
        tiers_skipped = data.get("tiers_skipped", "unknown")
        unit_status = str(data.get("unit_status", "unknown"))
        integration_status = str(data.get("integration_status", "unknown"))
        e2e_status = str(data.get("e2e_status", "unknown"))
        if status == "fail":
            return annotation(
                "error",
                "propagation pyramid failed "
                f"outcome={outcome} tiers_failed={tiers_failed} "
                f"unit={unit_status} integration={integration_status} e2e={e2e_status} "
                f"message={message}",
            )
        if status == "skip":
            return annotation(
                "warning",
                "propagation pyramid skipped "
                f"outcome={outcome} tiers_skipped={tiers_skipped} "
                f"unit={unit_status} integration={integration_status} e2e={e2e_status} "
                f"message={message}",
            )
        return annotation(
            "notice",
            "propagation pyramid passed "
            f"outcome={outcome} unit={unit_status} integration={integration_status} e2e={e2e_status}",
        )

    return annotation("warning", f"unknown report-alert profile={profile} report={report_path}")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
