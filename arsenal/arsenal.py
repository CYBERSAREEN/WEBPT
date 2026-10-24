#!/usr/bin/env python3
"""Convenience launcher: ./arsenal.py full https://target   |   ./arsenal.py --js-extract URL OUT_DIR"""
import sys
from arsenal.cli import main

sys.exit(main())
