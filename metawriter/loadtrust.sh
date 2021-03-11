#!/bin/bash

TRUST_PATH=trust.json
echo "loadtrust $TRUST_PATH" | nc 127.0.0.1 4001
