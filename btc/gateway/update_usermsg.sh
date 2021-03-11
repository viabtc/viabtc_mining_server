#!/bin/bash

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games

cd `dirname $0`
cd ..

filepath="/data/viabtc_pool_server/btc/gateway/usermsg.json"
api="http://112.74.164.155:8000/tools/coinbase/message/btc/api/"
/data/viabtc_pool_server/btc/gateway/update_usermsg.py $api $filepath

UPDATE_STATUS=`/data/viabtc_pool_server/btc/gateway/update_usermsg.py $api $filepath`
if [ $UPDATE_STATUS == 'true' ]
then
    echo "loadcoinbase $filepath" | nc -q1 127.0.0.1  7001
    echo "loadcoinbase $filepath" | nc -q1 127.0.0.1  7002
fi
