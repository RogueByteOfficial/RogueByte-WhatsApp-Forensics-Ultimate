#!/usr/bin/env bash
# ==============================================================================
# RogueByte WhatsApp Forensics Ultimate v2.0 - Fast Launcher Script
# Brand: RogueByteOfficial
# ==============================================================================

set -e

if [ "$1" == "--gui" ] || [ "$1" == "-g" ]; then
    echo "[*] Launching RogueByte Forensic Desktop Workstation..."
    npm run dev
elif [ "$1" == "--test" ] || [ "$1" == "-t" ]; then
    echo "[*] Executing Full Forensic Verification Suite..."
    PYTHONPATH=. python3 -m unittest discover roguebyte_forensics/tests -v
elif [ "$1" == "--benchmark" ] || [ "$1" == "-b" ]; then
    echo "[*] Running Synthetic Ground-Truth Benchmark..."
    PYTHONPATH=. python3 roguebyte.py benchmark
elif [ -z "$1" ]; then
    # Interactive mode by default if no arguments provided
    PYTHONPATH=. python3 roguebyte.py -i
else
    # Forward all arguments to the roguebyte CLI engine
    PYTHONPATH=. python3 roguebyte.py "$@"
fi
