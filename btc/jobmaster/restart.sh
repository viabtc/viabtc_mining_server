#!/bin/bash

killall -s SIGQUIT jobmaster.exe
sleep 1
./jobmaster.exe config.json
