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
# For example, 
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
# For example, create delay of two nodes you can tap in : 
Node_1 Node_2 <delay> or 1 2 <delay>
# Create delay of Simulation nodes, you can tap in:
s <Node_ID> <Node_level> <delay_l1> <delay_l2> <delay_l3>
# letter 's' can be replaced by 'S' or "simulation", Node_ID can be replaced by just ID(number)
# delay_l1~delay_l3 is the common delay of level1~3 nodes, these three parameter can be omitted, default is [100,50,10].
```

### 3. topologyCollector.py

```shell
# 启动拓扑监听之前需要启动mysql并在数据库中建立"nmrvs"数据表
# 执行topoCollector进行拓扑收集：
python3 topoCollector.py
```

### 4. topoShow.py

```shell
# 使用当前数据库中的数据构建拓扑并生成html文件用于展示
# 执行以下命令：
python3 topoShow.py
# 将生成的html文件打开即可
```

### 5. client.py

```shell
# python版本的模拟客户端，用于向解析节点发送各种udp报文，验证功能
# 执行以下命令：
python3 client.py -i <IP> -p <port> -c <command> -n <number>
``` 
- 参数设定：
  
    **-h** : help 查看帮助文档 (非必须参数) 
  
     **-i** : 发送到的目的IP地址，支持IPv4和IPv6 **(必须参数)**
  
    **-p** : 发送到的目的端口号，默认值为10061，即解析节点Level1的监听端口 **(必须参数)** 
     
    **-c** : 发送的请求报文类型，(非必须参数) 具体包括：
  
       注册报文：'register' or 'r'
       注销报文：'deregister' or 'd' 
       批量注销报文： 'multi-deregister' or 'md' 
       EID解析报文： 'eid' ,默认使用 "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"作为EID 
       tlv解析报文： 'tlv' ,默认使用 "0000000000000000000000000000000000000000"作为EID, 使用"010101020102"作为tlv 
       rnl获取报文： 'rnl', 从解析节点获取RNL 
       用户自定义报文： 'custom' (默认值)，一般配合 -m < msg > 参数使用 
  
    **-m** : 输入自定义的完整报文payload (非必须参数) 
  
    **-n** : 发送的报文数目，默认为**1** (非必须参数) 
  
    **-er** : 发送自定义EID注册报文(非必须参数) ，使用：-er + < EID + NA > 
  
    **-eq** : 发送自定义EID解析报文(非必须参数) ，使用：-eq + < EID > 
  
    **-ed** : 发送自定义EID注销报文(非必须参数) ，使用：-ed + < EID + NA > 