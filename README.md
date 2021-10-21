# NMRVS - SEANet

**Name Mapping Resolution Verification System** for **SEANet**

- *All right reserved by 3NMedia.*

## Description

> This project is made for verifying the **NMR** system

## How to use

- Firstly, you should install python3(ver>3.6). Then run the following command,

```shell
$ python3 -m pip install --upgrade pip
$ pip3 install -r requirement.txt
```

### 1. controller.py

```shell
# start the script:
$ python3 controller.py

# start some nodes you can tap in : 
start Node_1 Node_2 / start 1 2 / start 1-4

# kill some nodes you can tap in: 
kill Node_3 Node198 Node4 / kill 3 4 / kill 5-7

# stop some nodes you can tap in: 
stop Node_1 Node_2 / stop 1 2 3 4 / stop 1-4

# handle simulation nodes you can tap in:
s start Node_1 Node_2 / s start 1-2 / simulation stop 1-4

# If you have done all the control, input 'exit' or press the 'enter' button to stop the input process
exit
```

### 2. delay_gen.py

```shell
# start the script:
$ python3 delay_gen.py

# For example, create delay of two nodes you can tap in : 
Node_1 Node_2 <delay> or 1 2 <delay>

# Create delay of Simulation nodes, you can tap in:
s <Node_ID> <Node_level> <delay_l1> <delay_l2> <delay_l3>

# Create p2p delay of Simulation nodes, you can tap in:
s s <ID1-ID2> <delay>

# The first letter 's' can be replaced by 'S' or "simulation", Node_ID can be replaced by just ID(number)
# delay_l1~delay_l3 is the common delay of level1~3 nodes, these three parameter can be omitted, default is [100,50,10].
```

### 3. topologyCollector.py

```shell
# 启动拓扑监听之前需要启动mysql并在数据库中建立"nmrvs"数据表

# 执行topoCollector进行拓扑收集：

$ python3 topoCollector.py
```

### 4. topoShow.py

```shell
# 使用当前数据库中的数据构建拓扑并生成html文件用于展示

# 执行以下命令：

$ python3 topoShow.py

# 将生成的html文件打开即可
```

### 5. client.py

```shell
# python版本的模拟客户端，用于向解析节点发送各种udp报文，验证功能

# 执行以下命令：

$ python3 client.py -i <IP> -p <port> -c <command> -n <number>
``` 

- 参数设定：

  **`-h`** : help 查看帮助文档 (非必须参数)

  **`-i`** : 发送到的目的IP地址，支持*IPv4*和*IPv6* **(必须参数)**

  **`-p`** : 发送到的目的端口号，默认值为*10061*，即解析节点*Level1*的监听端口 **(必须参数)**

  **`-c`** : 发送的请求报文类型，具体包括：

       注册报文：'register' or 'r'
       注销报文：'deregister' or 'd' 
       批量注销报文： 'batch-deregister' or 'bd' 
       EID解析报文： 'eid' ,默认使用 "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"作为EID 
       tlv解析报文： 'tlv' ,默认使用 "0000000000000000000000000000000000000000"作为EID, 使用"010101020102"作为tlv 
       rnl获取报文： 'rnl', 从解析节点获取RNL
       连接接入代理： 'agent', 连接接入代理，从接入代理获取RNL以及其他信息
       时延测量报文： 'dm', 测试从客户端到解析节点的时延
       用户自定义报文： 'custom' (默认值)，一般配合 -m < msg > 参数使用 

  **`-m`** : 输入自定义的完整报文的UDP payload

  **`-n`** : 发送的报文数目，默认为**1**，**当`n < 0`时设置为持续发包**，需要强制退出程序才能结束。

  **`-s`** : 发送的数据包的速率(pps)，默认为**不限制**，**需要在`-n=-1`且`--force`条件下才生效**。

  **`--force`** : 强制发送报文，不等待接收返回报文，一般配合 `-n` 使用，pps可达**80000**左右

  **`--detail`** : 解析返回报文，以更加详细清晰的方式展示给用户

  **`-er`** : 发送自定义EID注册报文，tlv为可选项，使用：`-er  <EID+NA>  <tlv>`

  **`-ecr`** : 发送自定义EID+CID注册报文，tlv为可选项，使用：`-ecr <EID+CID+NA> <tlv>`

  **`-eq`** : 发送自定义EID解析报文，使用：`-eq <EID> `

  **`-tq`** : 发送自定义Tag解析报文，使用：`-tq <tlv> `

  **`-ecq`** : 发送自定义EID+CID解析报文，有两个必须参数，**queryType**_{**0**：EID查IP **1**：EID查CID **2**：CID查IP **3**：EID+CID查IP **4**：tag查EID+CID+IP}。使用：`-ecq <queryType> <EID>/<CID>/<TAG> `

  **`-ed`** : 发送自定义EID注销报文，使用：`-ed <EID + NA> `

  **`-ecd`** : 发送自定义EID+CID注销报文，使用：`-ecd <EID+CID+NA> `

  **`-ebd`** : 发送自定义批量注销报文，使用：`-ebd <NA> `

  **`-ecbd`** : 发送自定义批量注销报文(支持EID+CID版本)，使用：`-ebcd <NA> `

### 6. pktAnalyzer.py

```shell
# 用于分析抓包pcap文件，查看解析的数据包时延信息和超时个数等信息

# 执行以下命令：

$ python3 pktAnalyzer.py test.pcap
``` 

- 其中时延趋势参考图可在生成的`len_delay.html`中查看 横坐标标记数量可在`conf.yml`配置文件中进行修改
