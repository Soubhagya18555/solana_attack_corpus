#!/usr/bin/env python3
"""
validate_corpus.py

Validates all YAML attack entries in attacks/ against schema/attack_entry.schema.json.
Exits non-zero on validation failure. Suitable for CI pre-commit hooks.

Usage:
    python scripts/validate_corpus.py
    python scripts/validate_corpus.py --attacks-dir attacks --schema schema/attack_entry.schema.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    print("error: PyYAML required. Install with: pip install pyyaml", file=sys.stderr)
    sys.exit(2)

try:
    import jsonschema
    from jsonschema import Draft202012Validator
except ImportError:
    print("error: jsonschema required. Install with: pip install jsonschema", file=sys.stderr)
    sys.exit(2)

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ATTACKS_DIR = REPO_ROOT / "attacks"
DEFAULT_SCHEMA_PATH = REPO_ROOT / "schema" / "attack_entry.schema.json"

def load_yaml(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)

def load_schema(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)

def collect_yaml_files(attacks_dir: Path) -> list[Path]:
    if not attacks_dir.is_dir():
        raise FileNotFoundError(f"attacks directory not found: {attacks_dir}")
    files = sorted(attacks_dir.glob("*.yaml")) + sorted(attacks_dir.glob("*.yml"))
    if not files:
        raise FileNotFoundError(f"no YAML files in {attacks_dir}")
    return files

def validate_entry(
    entry_path: Path,
    entry_data: Any,
    validator: Draft202012Validator,
) -> list[str]:
    errors: list[str] = []
    if not isinstance(entry_data, dict):
        return [f"{entry_path.name}: root must be a mapping"]

    try:
        validator.validate(entry_data)
    except jsonschema.ValidationError as exc:
        path = ".".join(str(p) for p in exc.absolute_path) or "(root)"
        errors.append(f"{entry_path.name}: [{path}] {exc.message}")

    entry_id = entry_data.get("id")
    if entry_id and entry_path.stem != entry_id:
        errors.append(
            f"{entry_path.name}: filename stem '{entry_path.stem}' must match id '{entry_id}'"
        )

    return errors

def validate_cross_references(
    entries: dict[str, dict],
) -> list[str]:
    errors: list[str] = []
    known_ids = set(entries.keys())

    for entry_id, data in entries.items():
        related = data.get("related_entries") or []
        for related_id in related:
            if related_id not in known_ids:
                errors.append(
                    f"{entry_id}: related_entries references unknown id '{related_id}'"
                )

    return errors

def main() -> int:
    parser = argparse.ArgumentParser(description="Validate Solana attack corpus YAML entries.")
    parser.add_argument(
        "--attacks-dir",
        type=Path,
        default=DEFAULT_ATTACKS_DIR,
        help="Directory containing attack YAML files",
    )
    parser.add_argument(
        "--schema",
        type=Path,
        default=DEFAULT_SCHEMA_PATH,
        help="Path to attack_entry.schema.json",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print success line per validated file",
    )
    args = parser.parse_args()

    schema = load_schema(args.schema)
    validator = Draft202012Validator(schema)

    yaml_files = collect_yaml_files(args.attacks_dir)
    all_errors: list[str] = []
    entries: dict[str, dict] = {}

    for yaml_path in yaml_files:
        try:
            data = load_yaml(yaml_path)
        except yaml.YAMLError as exc:
            all_errors.append(f"{yaml_path.name}: YAML parse error: {exc}")
            continue

        file_errors = validate_entry(yaml_path, data, validator)
        all_errors.extend(file_errors)

        if isinstance(data, dict) and "id" in data:
            entry_id = data["id"]
            if entry_id in entries:
                all_errors.append(f"duplicate id '{entry_id}' in {yaml_path.name}")
            else:
                entries[entry_id] = data

        if args.verbose and not file_errors:
            print(f"ok: {yaml_path.name}")

    all_errors.extend(validate_cross_references(entries))

    if all_errors:
        print("validation failed:", file=sys.stderr)
        for err in all_errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print(f"validated {len(yaml_files)} attack entries against {args.schema.name}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
