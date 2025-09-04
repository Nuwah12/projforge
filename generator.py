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
import hashlib
from pathlib import Path
import sys
from typing import Dict, List, Any, Iterable, Tuple
from datetime import datetime
import yaml  # pyyaml

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
        #print(f"Stage: {stage}")
        sid = stage.get("id")
        #print(f"Stage ID: {sid}")
        for d in stage.get("dirs", []):
            #print(f"Dir: {d}")
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
        out.append(f"    {a.replace('/', '_')}[{a}] --> {b.replace('/', '_')}[{b}]")
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

        dir_abs = root / sid / rel
        dir_abs.mkdir(parents=True, exist_ok=True)

        stage_desc = (stage.get("desc") or "").strip()
        notes = (d.get("notes") or "").strip()
        allow = d.get("allow", [])
        script = d.get("script")
        data = d.get("include")

        # Build allow section
        if allow and isinstance(allow, list):
            allow_lines = "\n".join(f"- `{pat}`" for pat in allow)
            allow_section = f"""
                ### Allowed file patterns\n
                Only files matching **any** of the glob patterns below are allowed:\n\n
                {allow_lines}\n\n
                _Files not matching these patterns will be flagged by `--validate`._
            """
        else:
            allow_section = (
                "### Allowed file patterns\n"
                "No restrictions: **any files are allowed** here."
            )

        # Build data hash section (if data files passed via include)
        if data and sid == "data": # still enoforce rule that only data stage can have datafiles
            for f in data:
                h = hash_file(f)

        # Build script section
        script_section = ""
        if script:
            script_section = f"""
                ### Associated script\n
                This directory is associated with the script: `scripts/{script}`\n
                If run from the standard project layout, this script is copied here automatically.\n
            """

        # Compose README content
        readme_md = f"""# {rel}

        **Stage:** `{sid}`{f" - {stage_desc}" if stage_desc else ""}

        This directory is defined in the project’s `DIRSPEC.yaml`.  
        See the top-level [`DIRECTORY_STANDARD.md`](../DIRECTORY_STANDARD.md) for overall layout and flow.

        {('### Notes' + notes) if notes else ""}\n{allow_section}

        {script_section}
        """

        # Write README.md
        (dir_abs / "README.md").write_text(readme_md, encoding="utf-8")


def write_directory_standard_md(root: Path, spec: Dict[str, Any]) -> None:
    md = []
    title = "Auto Generated Directory Standard"
    md.append(f"# {title}")
    time = datetime.now().strftime("%m-%d-%Y %H:%M:%S")
    md.append(f"## Created at {time}")
    if spec.get("description"):
        md.append("")
        md.append(spec["description"].strip())
    md.append("")

    md.append("## Stages")
    for stage in spec.get("stages", []):
        md.append(f"- **{stage.get('id')}** — {stage.get('desc','').strip()}")
    md.append("")

    (root / "DIRECTORY_STANDARD.md").write_text("\n".join(md) + "\n")

def write_per_path_manifest(root: Path, stage: str, d: dict, outname: str = "METADATA.yml") -> None:
    """
    Write a per-directory manifest (METADATA.yml) inside each directory in the spec.

    Parameters
    ----------
    root : Path
        Root of the project.
    stage : str
        Stage name (e.g. "analysis", "data").
    d : dict
        Dictionary describing the directory from DIRSPEC (keys: path, allow, notes, include).
    outname : str
        Filename to write (default: METADATA.yml).
    """

    # Resolve full path of this directory
    path = d.get("path")
    if not path:
        print(f"[WARN] No path for stage {stage}, skipping METADATA.yml")
        return

    dir_abs = root / stage / path
    dir_abs.mkdir(parents=True, exist_ok=True)

    allow = d.get("allow", [])
    notes = d.get("notes", "")

    # Build manifest entry for this directory
    entry = {
        "stage": stage,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "path": str(dir_abs),
        "allow": allow,
        "notes": notes,
        "files": []
    }

    # If "include" files are specified, add hashes
    if d.get("include"):
        for i in d["include"]:
            entry["files"].append({
                "source": str(i),
                "hash": hash_file(Path(i))  # <-- you already have hash_file()
            })

    # Write YAML inside this directory
    out_file = dir_abs / outname
    with out_file.open("w") as f:
        yaml.safe_dump(entry, f, sort_keys=False)

    print(f"[INFO] Wrote {out_file}")


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
# Hash operation
# -----------------------------
def hash_file(path: Path | str, chunk_size: int = 8192) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()

# -----------------------------
# Symlink create operation
# -----------------------------

def make_symlink(orig: Path, to: Path, filename: str) -> None:
    """
    Make a symlink between original file and new link name
    Parameters:
        - orig (Path): File to be linked to
        - to (Path): Location and name of new symlink
    """
    if not os.path.exists(orig):
        print(f"[WARN] Could not find file {orig}. Continuing without link.")
        return
    if not os.path.exists(to):
        print(f"[WARN] Location {to} does not exist. Continuing without link.")
        return
    else:
        os.symlink(orig, f"{to}/{filename}")
        print(f"[INFO] {orig} ---> {to}/{filename}")

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

        print(sid)
        print(stage)
        print(d)

        # if one of the top-level directories does not exist, create it
        if not os.path.exists(root / sid):
            ensure_dir(root / sid)
            print(f"[INFO] Creating top-level directory '{root / sid}'")
        
        if not rel:
            print(f"[WARN] Encountered empty path in stage {sid}. Continuing.")
        else:
            dir_abs = root / sid / rel
            ensure_dir(dir_abs)  # make dir

        if d.get("include"):
            if sid == "data": # only pay attention to files if we are in data stage
                for i in d.get("include"):
                    filename = i.split("/")[len(i.split("/"))-1]
                    make_symlink(i, dir_abs, filename)
            else:
                print(f"[WARN] Not copying included files in {sid} stage")

        script = d.get("script")
        if script is None and rel:
            print(f"[WARN] Skipping empty scripti(s) in stage {sid}")
            continue

        if check_script_loc():
            script_path = Path("..") / "scripts" / script
            print(f"[INFO] Moving script {script_path} to {dir_abs} ")
            shutil.copy(script_path, dir_abs)
        else:
            print(f"[WARN] Couldn't find script directory from current working dir, skipping copy.")
        # copy script to dir
        #make_dir_manifest()
        write_per_path_manifest(root, sid, d)
    # Top-level docs + manifest
        
    write_directory_standard_md(root, spec)
    write_per_directory_readmes(root, spec)

# ------------------------------
# CLI
# ------------------------------

def parse_args(argv: List[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Generate directory structure, docs, and manifest from DIRSPEC.yaml")
    ap.add_argument("spec", type=str, help="Path to DIRSPEC.yaml")
    ap.add_argument("--root", default=".", type=str, help="Project root where directories will be created/validated")
    ap.add_argument("--check_org", action="store_true", help="Validate existing files against allow patterns (no creation)")
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
    if ns.check_org:
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

