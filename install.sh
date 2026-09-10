#!/bin/bash

GRAPE_FOLDER="patch_what_she_said"

if [ ! -d "$GRAPE_FOLDER" ]; then
    echo "GRAPE is not cloned..."
    git clone https://github.com/mark-2389/patch_what_she_said
fi

cd Instrumentator
python3 -m venv .venv
source .venv/bin/activate
echo "[+] installed python virtual environment"
pip install -e ../patch_what_she_said/herpatcher/
echo "[+] installed GRAPE dependencies"

mkdir executables
gcc -shared -fPIC -o executables/libforkserver.so libforkserver.c
echo "[+] project folders installed"
