"""Entry point: python -m malko"""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
