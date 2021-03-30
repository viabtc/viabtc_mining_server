#!/bin/bash

killall -s SIGQUIT gateway.exe
sleep 1
./gateway.exe config.json
