#!/bin/bash

killall -s SIGQUIT blockmaster.exe
sleep 1
./blockmaster.exe config.json
