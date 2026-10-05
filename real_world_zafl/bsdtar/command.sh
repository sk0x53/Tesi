#!/bin/bash



echo "original"
./bsdtar -tvf sample.tar
echo "mine"
./bsdtar.mine -tvf sample.tar
