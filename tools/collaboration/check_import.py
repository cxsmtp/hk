"""Check the initial import without importing application modules or printing source."""
import ast
import hashlib
import json
from pathlib import Path
import sys

root = Path(__file__).resolve().parents[2]
manifest = json.loads((root / "docs/collaboration/source-manifest.json").read_text())
dependency_manifest = json.loads((root / "docs/collaboration/dependency-manifest.json").read_text())
rows = manifest["files"] + dependency_manifest["files"]
recovery_path = root / "docs/collaboration/recovery-manifest.json"
recovery = json.loads(recovery_path.read_text())["files"] if recovery_path.exists() else []
rows += recovery
changes_path = root / "docs/collaboration/reviewed-changes.json"
changes = json.loads(changes_path.read_text())["files"] if changes_path.exists() else []
originals = {row["path"]: row for row in rows}
overrides = {}
for change in changes:
    original = originals.get(change["path"])
    if original is None or original["sha256"] != change["original_sha256"]:
        raise SystemExit("Reviewed change does not match original import provenance")
    if change["path"] in overrides:
        raise SystemExit("Duplicate reviewed change")
    overrides[change["path"]] = change
errors = []
parsed = 0
for row in rows:
    rel = Path(row["path"])
    if rel.is_absolute() or ".." in rel.parts:
        errors.append((row["path"], "unsafe manifest path"))
        continue
    p = root / rel
    if not p.is_file() or p.is_symlink():
        errors.append((row["path"], "missing or nonregular file"))
        continue
    data = p.read_bytes()
    expected = overrides.get(row["path"], row)
    if len(data) != expected["bytes"] or hashlib.sha256(data).hexdigest() != expected["sha256"]:
        errors.append((row["path"], "import bytes differ"))
    if p.suffix == ".py":
        try:
            ast.parse(data, filename=rel.as_posix())
            parsed += 1
        except (SyntaxError, ValueError):
            errors.append((row["path"], "Python parse failed"))
print(json.dumps({"imported_source_files": len(manifest["files"]), "dependency_config_files": len(dependency_manifest["files"]), "python_files_parsed": parsed, "errors": errors, "application_build_tested": False}, indent=2))
sys.exit(bool(errors))
