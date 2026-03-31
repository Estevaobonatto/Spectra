#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def read_current_version() -> str:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'(?m)^version = "(\d+\.\d+\.\d+)"$', pyproject)
    if not match:
        raise RuntimeError("Nao foi possivel localizar a versao em pyproject.toml")
    return match.group(1)


def bump_version(version: str, part: str) -> str:
    major, minor, patch = (int(piece) for piece in version.split("."))
    if part == "major":
        return f"{major + 1}.0.0"
    if part == "minor":
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def replace_once(path: Path, pattern: str, replacement: str) -> None:
    content = path.read_text(encoding="utf-8")
    updated, count = re.subn(pattern, replacement, content, count=1, flags=re.MULTILINE)
    if count != 1:
        raise RuntimeError(f"Falha ao atualizar versao em {path.relative_to(ROOT)}")
    path.write_text(updated, encoding="utf-8")


def update_version_files(new_version: str) -> None:
    replace_once(
        ROOT / "pyproject.toml",
        r'^(version = ")\d+\.\d+\.\d+(")$',
        rf'\g<1>{new_version}\g<2>',
    )
    replace_once(
        ROOT / "setup.py",
        r"^(\s*version=')\d+\.\d+\.\d+(',)$",
        rf"\g<1>{new_version}\g<2>",
    )
    replace_once(
        ROOT / "spectra" / "__init__.py",
        r'^(Version: )\d+\.\d+\.\d+$',
        rf'\g<1>{new_version}',
    )
    replace_once(
        ROOT / "spectra" / "__init__.py",
        r'^(__version__ = ")\d+\.\d+\.\d+(")$',
        rf'\g<1>{new_version}\g<2>',
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Atualiza a versao do projeto Spectra")
    parser.add_argument(
        "--part",
        choices=("major", "minor", "patch"),
        default="patch",
        help="Segmento semver a incrementar quando --set-version nao for informado",
    )
    parser.add_argument(
        "--set-version",
        help="Define explicitamente a nova versao em vez de incrementar a atual",
    )
    args = parser.parse_args()

    current_version = read_current_version()
    new_version = args.set_version or bump_version(current_version, args.part)

    if new_version == current_version:
        print(new_version)
        return

    update_version_files(new_version)
    print(new_version)


if __name__ == "__main__":
    main()