#!/usr/bin/env python3
"""Build a standalone mal-ko executable with PyInstaller.

Creates/uses a local virtual environment at <repo>/.venv, installs
PyInstaller there (never into the system Python), then runs:

    pyinstaller --onefile --name mal-ko --clean mal-ko.py

Result: dist/mal-ko.exe (Windows) or dist/mal-ko (Linux).
The venv is only a build tool — mal-ko itself has no dependencies.
"""

import shutil
import subprocess
import sys
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VENV_DIR = ROOT / ".venv"
EXE_NAME = "mal-ko.exe" if sys.platform == "win32" else "mal-ko"


def venv_python():
    if sys.platform == "win32":
        return VENV_DIR / "Scripts" / "python.exe"
    return VENV_DIR / "bin" / "python"


def run(command, **kwargs):
    print("+", " ".join(str(c) for c in command), flush=True)
    return subprocess.run(command, cwd=ROOT, **kwargs)


def main():
    if not venv_python().exists():
        print(f"creating virtual environment in {VENV_DIR} ...")
        venv.create(VENV_DIR, with_pip=True)

    print("installing PyInstaller into the venv ...")
    result = run([str(venv_python()), "-m", "pip", "install", "pyinstaller"])
    if result.returncode != 0:
        print(
            "error: could not install PyInstaller. Check your internet "
            "connection and pip availability, then retry.",
            file=sys.stderr,
        )
        return 1

    print("building the executable ...")
    result = run(
        [
            str(venv_python()), "-m", "PyInstaller",
            "--onefile", "--name", "mal-ko", "--clean", "mal-ko.py",
        ]
    )
    if result.returncode != 0:
        print("error: PyInstaller build failed (see output above).",
              file=sys.stderr)
        return 1

    exe = ROOT / "dist" / EXE_NAME
    if not exe.exists():
        print(f"error: expected output not found: {exe}", file=sys.stderr)
        return 1
    size_mb = exe.stat().st_size / (1024 * 1024)
    print(f"\nbuild OK: {exe} ({size_mb:.1f} MB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
