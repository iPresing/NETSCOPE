#!/usr/bin/env python3
"""
NETSCOPE — Script de bump de version.

Met à jour la version dans tous les fichiers du projet.
Usage:
    python scripts/bump_version.py <nouvelle_version>
    python scripts/bump_version.py 0.3.0
    python scripts/bump_version.py 0.3.0 --dry-run
"""

import argparse
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
NETSCOPE_DIR = PROJECT_ROOT / "netscope"

VERSION_FILE = NETSCOPE_DIR / "VERSION"

# Fichiers source avec "Version: X.Y.Z" dans les commentaires
JS_FILES = [
    NETSCOPE_DIR / "app" / "static" / "js" / "api.js",
    NETSCOPE_DIR / "app" / "static" / "js" / "main.js",
    NETSCOPE_DIR / "app" / "static" / "js" / "toasts.js",
]

# Fichiers de test contenant la version en assertions
TEST_FILES = [
    NETSCOPE_DIR / "tests" / "unit" / "test_app_factory.py",
    NETSCOPE_DIR / "tests" / "unit" / "test_version_service.py",
    NETSCOPE_DIR / "tests" / "unit" / "test_update_service.py",
    NETSCOPE_DIR / "tests" / "unit" / "test_ota_update.py",
    NETSCOPE_DIR / "tests" / "integration" / "test_update_check.py",
    NETSCOPE_DIR / "tests" / "integration" / "test_update_apply.py",
    NETSCOPE_DIR / "tests" / "integration" / "test_backup_update.py",
    NETSCOPE_DIR / "tests" / "integration" / "test_rollback_update.py",
    NETSCOPE_DIR / "tests" / "e2e" / "test_update_check_e2e.py",
    NETSCOPE_DIR / "tests" / "e2e" / "test_update_apply_e2e.py",
]

SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")


def read_current_version() -> str:
    return VERSION_FILE.read_text(encoding="utf-8").strip()


def replace_in_file(path: Path, old: str, new: str, dry_run: bool) -> int:
    if not path.exists():
        return 0
    content = path.read_text(encoding="utf-8")
    count = content.count(old)
    if count > 0 and not dry_run:
        path.write_text(content.replace(old, new), encoding="utf-8")
    return count


def bump(new_version: str, dry_run: bool = False):
    current = read_current_version()

    if current == new_version:
        print(f"Version deja a {new_version}, rien a faire.")
        return

    print(f"Bump version: {current} -> {new_version}")
    if dry_run:
        print("(dry-run — aucune modification)")
    print()

    total_replacements = 0
    all_files = [VERSION_FILE] + JS_FILES + TEST_FILES

    for f in all_files:
        rel = f.relative_to(PROJECT_ROOT)
        count = replace_in_file(f, current, new_version, dry_run)
        if count > 0:
            status = "(dry-run)" if dry_run else "OK"
            print(f"  {rel}: {count} remplacement(s) {status}")
            total_replacements += count
        elif not f.exists():
            print(f"  {rel}: ABSENT")

    print(f"\n{total_replacements} remplacement(s) dans {len(all_files)} fichiers.")

    if not dry_run:
        print(f"\nVersion mise a jour: {new_version}")
        print("Prochaines etapes:")
        print(f"  git add -A && git commit -m \"chore: bump version {current} -> {new_version}\"")
        print(f"  git push origin main")
        print(f"  gh release create v{new_version} --title \"Release v{new_version}\" --target main")


def main():
    parser = argparse.ArgumentParser(description="NETSCOPE — Bump de version")
    parser.add_argument("version", help="Nouvelle version (ex: 0.3.0)")
    parser.add_argument("--dry-run", action="store_true", help="Simuler sans modifier")
    args = parser.parse_args()

    if not SEMVER_RE.match(args.version):
        print(f"Erreur: '{args.version}' n'est pas un semver valide (X.Y.Z)")
        sys.exit(1)

    bump(args.version, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
