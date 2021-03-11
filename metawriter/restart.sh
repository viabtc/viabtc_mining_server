#!/bin/bash

killall -s SIGQUIT metawriter.exe
sleep 3
./metawriter.exe config.json
