#!/bin/bash
set -x
PROGRAM="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -z "$PROGRAM" ]; then
    echo "Usage: ./instrument_program <program_name>"
    echo "<program_name> could be one of base64,md5sum,uniq,who"
    exit 1
fi

cd ../
CURRENT_FOLDER=$(pwd)
cd Instrumentator
source .venv/bin/activate

IN_PATH="$CURRENT_FOLDER/LAVA-M-testbench/$PROGRAM/"
OUT_PATH="$SCRIPT_DIR"
OUT_FILE="$PROGRAM.grp"
python3 instrument.py -p "$IN_PATH" -s "$PROGRAM" -o "$OUT_FILE"

mv "$IN_PATH$OUT_FILE" "$OUT_PATH"

