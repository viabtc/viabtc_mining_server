#!/bin/bash

killall -s SIGQUIT bitpeer.exe
sleep 1
./bitpeer.exe config.json
