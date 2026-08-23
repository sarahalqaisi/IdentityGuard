#!/usr/bin/env python3
"""Run IdentityGuard analysis against synthetic demo data or a local JSON file."""

import argparse
import json
import sys
from pathlib import Path

from app.seed import demo_dataset
from app.services.analyzer import analyze
from app.services.importer import DatasetImportError, load_dataset


LEVELS = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description="Analyze synthetic/local identity data")
    value.add_argument("--input", type=Path, help="Local JSON identity dataset")
    value.add_argument("--json", type=Path, dest="json_output", help="Export complete analysis as JSON")
    value.add_argument("--fail-on", choices=LEVELS, help="Exit 2 when this severity or higher is found")
    return value


def main() -> int:
    args = parser().parse_args()
    try:
        dataset = load_dataset(args.input) if args.input else demo_dataset()
    except DatasetImportError as exc:
        print(f"Input error: {exc}", file=sys.stderr)
        return 1
    result = analyze(dataset)
    print("IdentityGuard analysis (synthetic data)" if not args.input else "IdentityGuard local dataset analysis")
    print(f"Identities: {result.summary['total_identities']}")
    print(f"Findings: {len(result.findings)}")
    print(f"Potential access paths: {len(result.attack_paths)}")
    print(f"Authentication anomalies: {len(result.auth_anomalies)}")
    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(result.model_dump_json(indent=2), encoding="utf-8")
        print(f"JSON export: {args.json_output}")
    if args.fail_on:
        threshold = LEVELS[args.fail_on]
        if any(LEVELS[finding.severity] >= threshold for finding in result.findings):
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
