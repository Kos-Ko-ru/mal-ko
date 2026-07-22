#!/usr/bin/env python3
"""Standalone entry point for mal-ko (used by the PyInstaller build).

Equivalent to `python -m malko`.
"""

import sys

from malko.cli import main

if __name__ == "__main__":
    sys.exit(main())
