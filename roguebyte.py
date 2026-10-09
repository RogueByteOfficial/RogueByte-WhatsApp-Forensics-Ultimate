#!/usr/bin/env python3
"""
RogueByte WhatsApp Forensics Ultimate - Standalone Command-Line Tool
Brand: RogueByteOfficial
"""

import sys
import os

# Add root directory to PYTHONPATH
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from roguebyte_forensics.cli import main

if __name__ == "__main__":
    main()
