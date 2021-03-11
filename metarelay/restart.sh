#!/bin/bash

killall -s SIGQUIT metarelay.exe
sleep 1
./metarelay.exe config.json
