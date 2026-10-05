#! /bin/bash
echo "original"
./sfconvert test.wav prova_out.aiff format aiff > output.original

echo "mine"
./sfconvert.mine test.wav prova_out.aiff format aiff > output.mine

