#!/usr/bin/env python3
"""
Directory scaffold + docs generator for a DIRSPEC.yaml standard.

Features
- Reads DIRSPEC.yaml (path configurable) describing directory layout.
- Creates directories, adds per-directory README.md with rules.
- Generates a top-level DIRECTORY_STANDARD.md with a Mermaid flow diagram.
- Emits a machine-readable DIRMANIFEST.json for CI validation or audits.
- Optional validation mode: checks existing files against `allow` patterns.

Usage
    python dirspec_generator.py \
        --spec DIRSPEC.yaml \
        --root . \
        --validate            # optional, only validate; do not create

    python dirspec_generator.py --spec DIRSPEC.yaml --root /path/to/Cell_Line_ONT

Notes
- `allow` in DIRSPEC is a list of glob patterns. If empty/missing, any files are allowed.
- `notes` are copied into per-directory README.md files for quick hints.
- `flow` edges (e.g., "data/fastq/raw -> data/fastq/trimmed") render into a Mermaid diagram.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import shutil
from pathlib import Path
import sys
from typing import Dict, List, Any, Iterable, Tuple

try:
    import yaml  # pyyaml
except Exception as e:
    print("[ERROR] PyYAML is required. Install with: pip install pyyaml", file=sys.stderr)
    raise


# ------------------------------
# Data loading & schema helpers
# ------------------------------

def load_spec(spec_path: Path) -> Dict[str, Any]:
    """
    Load the directory specification from the YML file DIRSPEC.yml
    """
    if not spec_path.exists():
        raise FileNotFoundError(f"DIRSPEC not found: {spec_path}")

    with spec_path.open() as f:
        spec = yaml.safe_load(f)

    # Light validation, just two keys
    for key in ("project", "stages"):
        if key not in spec:
            raise ValueError(f"DIRSPEC missing required key: {key}")
    # Another validation
    for stage in spec["stages"]:
        if "id" not in stage or "dirs" not in stage:
            raise ValueError("Each stage must have 'id' and 'dirs' list")
    return spec


def iter_all_dirs(spec: Dict[str, Any]) -> Iterable[Tuple[str, Dict[str, Any], Dict[str, Any]]]:
    """
    Yield [sid, stage, d] for all dirs in all stages
    """
    for stage in spec.get("stages", []):
        sid = stage.get("id")
        for d in stage.get("dirs", []):
            yield sid, stage, d  # Use yield to return these once per iteration; effectively making this function a generator

# ------------------------------
# Filesystem ops
# ------------------------------

def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

def check_script_loc() -> bool:
    if (Path("..") / "scripts").is_dir():
        return True
    return False

def build_mermaid(flow_edges: List[str]) -> str:
    out = ["```mermaid", "flowchart LR"]
    for edge in flow_edges:
        if "->" not in edge:
            # ignore malformed
            continue
        a, b = [s.strip() for s in edge.split("->", 1)]
        out.append(f"    {a.replace('/', '_')}[\"{a}\"] --> {b.replace('/', '_')}[\"{b}\"]")
    out.append("```")
    return "\n".join(out)

def write_per_directory_readmes(root: Path, spec: Dict[str, Any]) -> None:
    """
    Write a README.md into each directory defined in the DIRSPEC.

    Each README includes:
      - Stage ID and description
      - Relative directory path
      - Optional notes from DIRSPEC
      - Allowed file patterns ('allow' list)
      - Associated script (if provided)

    Parameters
    ----------
    root : Path
        The project root path where directories are created.
    spec : dict
        The loaded DIRSPEC YAML as a Python dictionary.
    """
    for sid, stage, d in iter_all_dirs(spec):
        rel = d.get("path")
        if not rel:
            print(f"[WARN] No path specified in stage {sid}; skipping README.")
            continue

        dir_abs = root / rel
        dir_abs.mkdir(parents=True, exist_ok=True)

        stage_desc = (stage.get("desc") or "").strip()
        notes = (d.get("notes") or "").strip()
        allow = d.get("allow", [])
        script = d.get("script")

        # Build allow section
        if allow and isinstance(allow, list):
            allow_lines = "\n".join(f"- `{pat}`" for pat in allow)
            allow_section = (
                "### Allowed file patterns\n"
                "Only files matching **any** of the glob patterns below are allowed:\n\n"
                f"{allow_lines}\n\n"
                "_Files not matching these patterns will be flagged by `--validate`._"
            )
        else:
            allow_section = (
                "### Allowed file patterns\n"
                "No restrictions: **any files are allowed** here."
            )

        # Build script section
        script_section = ""
        if script:
            script_section = (
                "### Associated script\n"
                f"This directory is associated with the script: `scripts/{script}`\n"
                "If run from the standard project layout, this script is copied here automatically.\n"
            )

        # Compose README content
        readme_md = f"""# {rel}

        **Stage:** `{sid}`{f" — {stage_desc}" if stage_desc else ""}

        This directory is defined in the project’s `DIRSPEC.yaml`.  
        See the top-level [`DIRECTORY_STANDARD.md`](../DIRECTORY_STANDARD.md) for overall layout and flow.

        {("### Notes\n" + notes + "\n") if notes else ""}{allow_section}

        {script_section}
        """

        # Write README.md
        (dir_abs / "README.md").write_text(readme_md, encoding="utf-8")


def write_directory_standard_md(root: Path, spec: Dict[str, Any]) -> None:
    md = []
    title = "Directory Standard"
    md.append(f"# {title}")
    if spec.get("description"):
        md.append("")
        md.append(spec["description"].strip())
    md.append("")

    flow = spec.get("flow", [])
    if flow:
        md.append("## Processing flow")
        md.append(build_mermaid(flow))
        md.append("")

    md.append("## Stages")
    for stage in spec.get("stages", []):
        md.append(f"- **{stage.get('id')}** — {stage.get('desc','').strip()}")
    md.append("")

    (root / "DIRECTORY_STANDARD.md").write_text("\n".join(md) + "\n")

# ------------------------------
# Validation
# ------------------------------

def _list_all_files(dir_path: Path) -> List[Path]:
    files = []
    for base, _dirs, fnames in os.walk(dir_path):
        for name in fnames:
            files.append(Path(base) / name)
    return files


def validate_against_allow(root: Path, spec: Dict[str, Any]) -> int:
    """Return the number of warnings found."""
    warnings = 0
    for _sid, _stage, d in iter_all_dirs(spec):
        rel = d.get("path")
        if not rel:
            print("[WARN] Dir spec without path; skipping")
            warnings += 1
            continue
        allow = d.get("allow", [])
        dir_abs = (root / rel).resolve()
        if not dir_abs.exists():
            print(f"[WARN] Missing directory: {dir_abs}")
            warnings += 1
            continue
        # skip rule files
        skip_names = {"README.md"}
        files = [p for p in _list_all_files(dir_abs) if p.name not in skip_names]
        if not allow:
            # everything allowed
            continue
        for f in files:
            rel_name = f.name
            if any(fnmatch.fnmatch(rel_name, pat) for pat in allow):  # Check for matching allowed patterns
                continue
            print(f"[WARN] File does not match allow-patterns: {f} (allowed: {allow})")
            warnings += 1
    return warnings


# ------------------------------
# Main create operation
# ------------------------------

def create_scaffold(root: Path, spec: Dict[str, Any]) -> None:
    """
    Function that creates the actual directoy hierarchy.
    """
    # Create dirs and write hints
    for sid, stage, d in iter_all_dirs(spec):
        rel = d.get("path")
        if not rel:
            print(f"[WARN] Skipping empty path in stage {sid}")
            continue

        script = d.get("script")
        if script is None:
            print(f"[WARN] Skipping empty script in stage {sid}")
            continue

        dir_abs = root / rel
        ensure_dir(dir_abs)  # make dir

        if check_script_loc():
            script_path = Path("..") / "scripts" / script
            print(f"[INFO] Moving script {script_path} to {dir_abs} ")
            shutil.copy(script_path, dir_abs)
        else:
            print(f"[WARN] Couldn't find script directory from current working dir, skipping copy.")
        # copy script to dir
    # Top-level docs + manifest
    write_directory_standard_md(root, spec)
    write_per_directory_readmes(root, spec)

# ------------------------------
# CLI
# ------------------------------

def parse_args(argv: List[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Generate directory structure, docs, and manifest from DIRSPEC.yaml")
    ap.add_argument("--spec", default="DIRSPEC.yaml", type=str, help="Path to DIRSPEC.yaml")
    ap.add_argument("--root", default=".", type=str, help="Project root where directories will be created/validated")
    ap.add_argument("--validate", action="store_true", help="Validate existing files against allow patterns (no creation)")
    return ap.parse_args(argv)


def main(argv: List[str] | None = None) -> int:
    """
    Main function to parse command line arguments and generate scaffold.
    """
    ns = parse_args(argv or sys.argv[1:])
    spec_path = Path(ns.spec)
    root = Path(ns.root)

    try:
        spec = load_spec(spec_path) # Load the YML into a dict
    except Exception as e:
        print(f"[ERROR] Failed to load spec: {e}", file=sys.stderr)
        return 2

    # If DIRSPEC.project differs from --root name, we still allow it; just warn.
    expected = spec.get("project")
    if expected and (Path(expected).name != Path(root).name):
        print(f"[INFO] Spec project '{expected}' != root basename '{root.name}'. Proceeding anyway.")

    # If --validate is specified, just validate and return, no dirs are created
    if ns.validate:
        warnings = validate_against_allow(root, spec)
        if warnings:
            print(f"Validation completed with {warnings} warning(s).")
            return 1 # return
        print("Validation passed: all files match allowed patterns.")
        return 0 # return

    # Create scaffold
    create_scaffold(root, spec)
    print(f"Scaffold complete under: {root.resolve()}")
    print("- Wrote DIRECTORY_STANDARD.md")
    print("- Wrote DIRMANIFEST.json")
    print("- Wrote per-directory README.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main()) # Clean exit with code returned by main

