# Viabtc Mining Server
viabtc mining server是一个高性能的分布式比特币矿池服务器，我们对比特币区块及交易广播做了很多优化，能够有效降低矿池的孤块率


# 整体架构
![Architecture](https://user-images.githubusercontent.com/36882284/112812184-639f6880-90af-11eb-8c0f-f5168d426848.jpg)

## 代码结构
**Required systems**
* Redis: 用来保存矿工的算力数据

**Base library**
* network: An event base and high performance network programming library, easily supporting [1000K TCP connections](http://www.kegel.com/c10k.html). Include TCP/UDP/UNIX SOCKET server and client implementation, a simple timer, state machine, thread pool. 

* utils: Some basic library, including log, config parse, some data structure and http/websocket/rpc server implementation.

**Modules**
1. jobmaster，部署在矿池服务器端，可以部署多个
  * 从比特币节点和联合挖矿节点获取挖矿任务，并下发给gateway
  * 接受bitpeer跟poolbench的指令，生成空块任务
  * 如果成功挖到新区块，提交到节点，同时交由blockmaster对外广播
2. gateway，部署在矿池服务器端，可以任意横向扩展
  * 实现了stratum标准协议，jobmaster下发任务后，转发给矿工，接收并验证矿工提交的算力
  * 实现了自定义的代理协议，jobmaster下发任务后，转发给mineragent，接收并验证mineragent的算力
  * 聚合并向metawriter或者metarelay提交算力
3. mineragent，主要用于拥有大量矿机的矿厂，部署在矿场内部，可有效节约带宽，提升性能
  * 实现了stratum标准协议，向矿工派发任务，接收并验证矿工提交的算力
  * 实现了自定义的代理协议，从gateway接收挖矿任务，并向gateway提交算力
4. blockmaster, 可以部署任意多个
  * 实现了瘦区块功能，加快节点区块同步速度
  * jobmaster收到新挖出的区块后，向多个blockmaster及bitpeer广播，加快区块广播速度
5. bitpeer，可以理解为一个特殊的bitcoin节点，部署任意多个
  * 实现了bitcoin p2p协议，可以连接多个bitcoin节点
  * 接受blockmaster的区块提交后向所连接的bitcoin的节点广播区块
  * 发现所连接的节点的区块更新后，提示jobmaster开始挖空块
6. poolbench
  * 监控各个矿池的任务更新情况
  * 如果其他矿池的任务的高度进行了更新，提示jobmaster开始挖空块
7. metawriter，接收gateway提交或者metarelay转发的算力数据，聚合后，写入redis
8. metarelay, 接收gateway提交的算力数据，转发到metawriter
9. alertcenter: A simple server that writes FATAL level log to redis list so we can send alert emails


## Redis数据格式
There are 3 type of keys.

1. event

* list of keys:
  
```
newblock
newevent
newworker
```

* example:
  
```
When new block found
newblock: {"name": "BTC", "hash": "0000000000000000032aee4bb112977ae8f4fb3614e0df196893285aa9c2adc0", "user": "haiyang", "worker": "example"}

list of event: connected, disconnected, When new connection connected or disconnected
newevent: {"user": "haiyang", "worker": "example", "coin": "BTC", "peer": "47.88.87.29", "event": "connected"}

When new worker connected
newworker: {"user": "haiyang", "worker": "example", "coin": "BTC"}
```

* read example: (python code)

```
while True:
    try:
        r = redis_master.blpop('newblock', 60)
    except:
        time.sleep(1)
        continue
    if not r:
        continue
    try:
        data = json.loads(r[1])
    except:
        continue
```

2. Minint data

* key format:

```
<coin>:<t>:<user>(:<worker>(:reject))

coin: btc
t:
    s: share count ( count of submit shares)
    p: pow count (pow * 2^32 means how many hash have calculate)
    g: pow goal, 统计用户算力对于挖出一个区块的贡献值，1表示已经提交能够挖出一个区块的算力

1) type: hash
2) key: unix timestamp, integer, multiple of 60, example: 1482252540 , represent the summary 3) of result in that minute.
4) value: integer or float(pow goal)
```

* example:

```
btc:s:haiyang  means user haiyang valid submit share count every minute
btc:s:haiyang:reject means user haiyang invalid submit share count every minute
btc:p:haiyang means user haiyang valid work every minute

btc:s:haiyang:example  means user haiyang, worker example valid submit share count every minute
btc:s:haiyang:example:reject means user haiyang, worker example invalid submit share count every minute
btc:p:haiyang:example means user haiyang, worker example valid work every minute
```

3. System data

* key format:

```
<coin>:<type>:<key>

coin: btc
type:
    m: monitor data
    mh: monitor data of spec host

1) type: hash
2) key: unix timestamp, integer
3) value: integer
```

* example:
  
```
btc:m:pow means the hole mining pool work every minute. use this calculate pool hashrate
btc:mh:47.89.182.198:pow means gateway 47.89.182.198 total work every minute.
```

* important key:

```
btc:m:pow
btc:m:share
btc:m:reject
btc:m:block
btc:m:connections

set key: monitor:keys is a set of all keys
use redis command: SMEMBERS monitor:keys  to get all keys

set key: <coin>:mk:<key> is a set of all host of special key,
example: SMEMBERS btc:mk:pow
1) "192.168.2.17"
2) "192.168.2.18"

```

## Compile and Install

**Operating system**

Ubuntu 16.04 or Ubuntu 18.04 or Ubuntu 20.04. Not yet tested on other systems.

**Requirements**

See [requirements](https://github.com/viabtc/viabtc_mining_server/wiki/requirements). Install the mentioned system or library.

You MUST use the depends/hiredis to install the hiredis library. Or it may not be compatible.

**Compilation**

Compile network and utils first. The rest all are independent.

**Deployment**

Please do not install every instance on the same machine.

Every process runs in deamon and starts with a watchdog process. It will automatically restart within 1s when crashed.

The best practice of deploying the instance is in the following directory structure:

```
gateway
|---bin
|   |---gateway.exe
|---log
|   |---gateway.log
|---conf
|   |---config.json
|---shell
|   |---restart.sh
|   |---check_alive.sh
