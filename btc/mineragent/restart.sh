#!/bin/bash

killall -s SIGQUIT mineragent.exe
sleep 1
./mineragent.exe config.json
