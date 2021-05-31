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