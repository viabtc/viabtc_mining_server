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



## Compile and Install

**Operating system**

Ubuntu 16.04 or Ubuntu 18.04 or Ubuntu 20.04. Not yet tested on other systems.

**Requirements**

See [requirements](https://github.com/viabtc/viabtc_mining_server/wiki/requirements). Install the mentioned system or library.

You MUST use the depends/hiredis to install the hiredis library. Or it may not be compatible.

**Compilation**

Compile network and utils first. The rest all are independent.

**Deployment**

One single instance is given for matchengine, marketprice and alertcenter, while readhistory, accesshttp and accwssws can have multiple instances to work with loadbalancing.

Please do not install every instance on the same machine.

Every process runs in deamon and starts with a watchdog process. It will automatically restart within 1s when crashed.

The best practice of deploying the instance is in the following directory structure:

```
matchengine
|---bin
|   |---matchengine.exe
|---log
|   |---matchengine.log
|---conf
|   |---config.json
|---shell
|   |---restart.sh
|   |---check_alive.sh
