#!/bin/bash

killall -s SIGQUIT btc_mineragent.exe
sleep 1
./btc_mineragent.exe config.json
