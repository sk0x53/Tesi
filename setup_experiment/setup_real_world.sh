#!/bin/bash
set -x
cd ../
ROOT_DIR="$(pwd)"

cd testbench/real_world_zafl/

echo "Copy the source binary into test folder"
cp bsdtar/bsdtar readelf/readelf sfconvert/sfconvert tcpdump/tcpdump unrtf/unrtf "$ROOT_DIR/tests/experiment1/"

cd "$ROOT_DIR/tests"
mkdir experiment1

cd "$ROOT_DIR/Instrumentator/"
source .venv/bin/activate

echo "Instrumenting bsdtar"
python3 instrument.py -p "$ROOT_DIR/testbench/real_world_zafl/bsdtar/" -s bsdtar -o bsdtar.mine
echo "Instrumenting readelf"
python3 instrument.py -p "$ROOT_DIR/testbench/real_world_zafl/readelf/" -s readelf -o readelf.mine
echo "Instrumenting sfconvert"
python3 instrument.py -p "$ROOT_DIR/testbench/real_world_zafl/sfconvert/" -s sfconvert -o sfconvert.mine
echo "Instrumenting unrtf"
python3 instrument.py -p "$ROOT_DIR/testbench/real_world_zafl/unrtf/" -s unrtf -o unrtf.mine
echo "Instrumenting tcpdump"
python3 instrument.py -p "$ROOT_DIR/testbench/real_world_zafl/tcpdump/" -s tcpdump -o tcpdump.mine

echo "Move the instrumented binaries into the test folder"
cd "$ROOT_DIR/testbench/real_world_zafl/"
mv bsdtar/bsdtar.mine readelf/readelf.mine sfconvert/sfconvert.mine tcpdump/tcpdump.mine unrtf/unrtf.mine "$ROOT_DIR/tests/experiment1/
