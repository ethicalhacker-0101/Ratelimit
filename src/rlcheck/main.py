#!/usr/bin/env python3
"""RLCheck Pro — Main entry point.

Delegates all CLI handling to cli.py which is built with Click.
"""
import sys

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32":
    try:
        if sys.stdout and hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if sys.stderr and hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from rlcheck.cli import cli


def main():
    """Top-level entry point invoked by the console-script."""
    cli(standalone_mode=True)


if __name__ == "__main__":
    sys.exit(main())
