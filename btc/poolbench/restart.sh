#!/bin/bash

killall -s SIGQUIT poolbench.exe
sleep 1
./poolbench.exe config.json
