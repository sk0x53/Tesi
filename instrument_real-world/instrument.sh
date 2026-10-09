#!/bin/bash

cd ../Instrumentator
source .venv/bin/activate

echo "Instrumenting bsdtar"
python3 instrument.py -p /home/edoardo/materiale_tesi/Tesi/testbench/real_world_zafl/bsdtar/ -s bsdtar -o bsdtar.mine
echo "Instrumenting readelf"
python3 instrument.py -p /home/edoardo/materiale_tesi/Tesi/testbench/real_world_zafl/readelf/ -s readelf -o readelf.mine
echo "Instrumenting sfconvert"
python3 instrument.py -p /home/edoardo/materiale_tesi/Tesi/testbench/real_world_zafl/sfconvert/ -s sfconvert -o sfconvert.mine
echo "Instrumenting tcpdump"
python3 instrument.py -p /home/edoardo/materiale_tesi/Tesi/testbench/real_world_zafl/tcpdump/ -s tcpdump -o tcpdump.mine
echo "Instrumenting unrtf"
python3 instrument.py -p /home/edoardo/materiale_tesi/Tesi/testbench/real_world_zafl/unrtf/ -s unrtf -o unrtf.mine
