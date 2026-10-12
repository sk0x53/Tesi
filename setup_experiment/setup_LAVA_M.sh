#!/bin/bash
set -x

cd ../
ROOT_DIR=$(pwd)
cd Instrumentator
source .venv/bin/activate

echo "Making the folders"
cd "$ROOT_DIR/tests/"
mkdir experiment2
cd experiment2
mkdir base64 md5sum uniq who
cd "$ROOT_DIR/Instrumentator/"

IN_PATH="$ROOT_DIR/testbench/LAVA-M-testbench"
OUT_PATH="$ROOT_DIR/tests/experiment2"

echo "Instrument base64"
python3 instrument.py -p "$IN_PATH/base64/" -s base64 -o base64.mine
echo "Instrument md5sum"
python3 instrument.py -p "$IN_PATH/md5sum/" -s md5sum -o md5sum.mine
echo "Instrument uniq"
python3 instrument.py -p "$IN_PATH/uniq/" -s uniq -o uniq.mine
echo "Instrument who"
python3 instrument.py -p "$IN_PATH/who/" -s who -o who.mine

cd "$IN_PATH"

mv base64/base64.mine "$OUT_PATH/base64"
mv md5sum/md5sum.mine "$OUT_PATH/md5sum"
mv uniq/uniq.mine "$OUT_PATH/uniq"
mv who/who.mine "$OUT_PATH/who"

cd "$ROOT_DIR"
echo "Preparing afl++"
sudo apt update
sudo apt install -y git build-essential python3-dev \
    automake cmake flex bison libglib2.0-dev \
    libpixman-1-dev python3-setuptools
sudo apt install -y clang llvm lld
git clone https://github.com/AFLplusplus/AFLplusplus.git
cd AFLplusplus
make -j"$(nproc)"
sudo make install
