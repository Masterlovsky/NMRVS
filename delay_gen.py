#! /usr/bin/python3
"""
By mzl 2021.03.10 version 1.0
Used to start Node
"""
import re
import paramiko
import pandas as pd
import os

ENS_HOME = "/home/resolution/ens/"
SIMULATION_HOME = "/home/resolution/ens/"
SIMULATION_DEFAULT_DELAY = ["100", "50", "10"]


class Remote(object):

    def __init__(self, host, name, password, port=22):
        self.host = host
        self.port = port
        self.name = name
        self.password = password

    def my_connect(self):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(
            paramiko.AutoAddPolicy())  # 指定当对方主机没有本机公钥的情况时应该怎么办，AutoAddPolicy表示自动在对方主机保存下本机的秘钥
        ssh.connect(self.host, self.port, self.name, self.password)
        return ssh

    def send_command(self, command):
        ssh = self.my_connect()
        stdin, stdout, stderr = ssh.exec_command(command)  # 这三个得到的都是类文件对象
        out_msg, err_msg = stdout.read(), stderr.read()
        # print(out_msg.decode())
        ssh.close()
        return out_msg.decode(), err_msg.decode()


class Properties(object):
    properties = ''

    def __init__(self, properties):
        self.properties = properties

    def getProperties(self):
        proper_dict = {}
        for line in self.properties.split("\n"):
            if line.find('=') > 0:
                val = line.split('=')
                proper_dict[val[0]] = val[1]
        return proper_dict

    # def getRemoteProperties(self, host, name, password, port=22):
    #     Remote(host, name, password)


def getNodeLocation_pd(node_na_file):
    csv = pd.read_csv(node_na_file)
    return csv


def readNa(node_str):
    """
    根据节点读取配置文件中对应的NA
    @param node_str:
    @return:
    """
    if "node" in node_str or "Node" in node_str:
        filename = node_str + ".properties"
    elif re.match(r"\d+", node_str):
        filename = "Node_" + node_str + ".properties"
    else:
        filename = ""
    properties = Properties(filename).getProperties()
    nodeNA = properties["NODE_NA"]
    nodeNA_list = nodeNA.split(":")
    result = ""
    for i in nodeNA_list:
        if len(i) < 4:
            result += '0' * (4 - len(i)) + i
        else:
            result += i
    return result


def readNa_remote(node_str, node_na_csv="Node_NA.csv") -> str:
    """
    根据节点读取配置文件中对应的NA为纯数字格式
    @param node_na_csv: 读取的配置文件
    @param node_str: Node ID
    @return: like: 2400dd01103702010192016800470198
    """
    # 读取ip地址并建立连接
    if "node" in node_str or "Node" in node_str:
        filename = node_str + ".properties"
    elif re.match(r"\d+", node_str):
        filename = "Node_" + node_str + ".properties"
        node_str = "Node_" + node_str
    else:
        filename = ""
    node_na_pd = getNodeLocation_pd(node_na_csv)
    # print(node_na_pd["Node"].tolist())
    result = ""
    if node_str in node_na_pd["Node"].tolist():
        host = "".join(node_na_pd["NA"][node_na_pd["Node"] == node_str].values)
        name = "".join(node_na_pd["Name"][node_na_pd["Node"] == node_str].values)
        password = "".join(node_na_pd["Password"][node_na_pd["Node"] == node_str].values)
        remote = Remote(host, name, password)
        command = "cd /home/resolution/ens && cat " + filename
        out_msg, err_msg = remote.send_command(command)
        properties = Properties(out_msg).getProperties()
        nodeNA = properties["NODE_NA"].strip()
        nodeNA_list = nodeNA.split(":")
        for i in nodeNA_list:
            if len(i) < 4:
                result += '0' * (4 - len(i)) + i
            else:
                result += i
    return result


def welCome(node_na_csv="Node_NA.csv"):
    print("Welcome to delay-generate script Ver1.0")
    print("=" * 50)
    print("Input some delay messages if you want to create delay file.\n"
          "For example, create delay of two nodes you can tap in : Node_1 Node_2 <delay> or 1 2 <delay>\n"
          "Create delay of Simulation nodes, you can tap in: s <Node_ID> <Node_level> <delay_l1> <delay_l2> <delay_l3>")
    print("If you have created all the delay message, press the 'enter' button to stop the input process")
    print("=" * 50)
    print("All possible nodes are list as follows: " + getAllNodes(node_na_csv))


def getAllNodes(node_na_csv):
    csv = pd.read_csv(node_na_csv)
    return "[" + ", ".join(csv["Node"].values) + "]"


def getInputMsg():
    """
    获取用户输入的信息
    @return:
    """
    flag = 1
    all_msg = []
    while flag:
        msg = input()
        all_msg.append(msg)
        if msg == "" or msg == "exit":
            flag = 0
    return all_msg[:-1]


def getInputMsgFromFile(file) -> list:
    """
    从配置文件读取时延信息
    @return:
    """
    lines = []
    with open(file, "r") as f:
        all_input = f.read()
        lines = all_input.split("\n")
    return lines


def handle(input_msgs, delay_path="./"):
    simulationFlag = False
    initSimulation(delay_path)
    config_nodes = set()
    output = delay_path + "delay.txt"
    f = open(output, 'w')
    if not isinstance(input_msgs, list):
        return
    for msg in input_msgs:
        msg = str(msg).strip()
        msg_list = msg.split(" ")
        if len(msg_list) < 3 or len(msg_list) > 6:
            continue
        if msg.startswith("S") or msg.startswith("s") or msg.startswith("simulation"):
            simulationFlag = True
            handleSimulationNode(msg, delay_path)
            continue
        node_A = msg.split(" ")[0]
        node_B = msg.split(" ")[1]
        if node_A == node_B:
            print("Warning! Don't create delay message by the same Node!")
            continue
        delay = msg.split(" ")[2]
        if re.match(r"\d+", node_A):
            node_A = "Node_" + node_A
        if re.match(r"\d+", node_B):
            node_B = "Node_" + node_B
        config_nodes.add(node_A)
        config_nodes.add(node_B)
        try:
            line = readNa_remote(node_A) + "->" + readNa_remote(node_B) + " " + delay + "\n"
            f.write(line)
        except Exception as e:
            print("Error! NodeInfo can not be found!")
            print(str(e))
    f.close()
    if simulationFlag:
        print("simulation.txt file has been created!")
    return config_nodes


def sendDelayFile(local, remote, nodes, node_na_csv):
    csv = getNodeLocation_pd(node_na_csv)
    na_set = set()
    for node in nodes:
        na_set.add("".join(csv["NA"][csv["Node"] == node].values))
    # print(na_set)
    for na in na_set:
        name = "".join(csv["Name"][csv["NA"] == na].values[0])
        password = "".join(csv["Password"][csv["NA"] == na].values[0])
        sftp = Remote(na, name, password).my_connect().open_sftp()
        sftp.put(local, remote)
    print('=' * 50)
    print("Delay files are successfully sent to the server which contains the relevant configuration nodes")


def sendSimulationDelayFile(local, remote, node_na_csv):
    csv = getNodeLocation_pd(node_na_csv)
    name = csv["Name"][csv["Node"] == "Simulation"].values[0]
    password = csv["Password"][csv["Node"] == "Simulation"].values[0]
    na = csv["NA"][csv["Node"] == "Simulation"].values[0]
    sftp = Remote(na, name, password).my_connect().open_sftp()
    sftp.put(local, remote)
    print("Simulation Delay File is successfully sent to the server")


def initSimulation(path: str, file: str = "simulation_delay.txt") -> bool:
    file_list = os.listdir(path)
    if file in file_list:
        os.remove(path + file)
        return True
    else:
        return False


def handleSimulationNode(msg: str, delay_path: str):
    """
    处理仿真节点的时延请求
    生成文件格式为：
    <ID> <LEVEL> <DELAY1> <DELAY2> <DELAY3>
    """
    delay_1, delay_2, delay_3 = SIMULATION_DEFAULT_DELAY
    origin_msg_l = msg.strip().split(" ")
    node_ID = origin_msg_l[1]
    level = origin_msg_l[2]
    if len(origin_msg_l) == 4:
        delay_1 = origin_msg_l[3]
    elif len(origin_msg_l) == 5:
        delay_1 = origin_msg_l[3]
        delay_2 = origin_msg_l[4]
    elif len(origin_msg_l) == 6:
        delay_1 = origin_msg_l[3]
        delay_2 = origin_msg_l[4]
        delay_3 = origin_msg_l[5]
    if "Node_" in node_ID:
        node_ID = node_ID.replace("Node_", "")
    if "Node" in node_ID:
        node_ID = node_ID.replace("Node", "")
    line = node_ID + " " + level + " " + delay_1 + " " + delay_2 + " " + delay_3 + " " + "\n"
    output = delay_path + "simulation_delay.txt"
    with open(output, "a") as f:
        f.write(line)


if __name__ == '__main__':
    welCome()
    all_input = getInputMsg()
    delayPath = os.getcwd() + "/"
    used_nodes = handle(all_input, delayPath)
    print("File delay.txt has been created!")
    local_path = delayPath + "delay.txt"
    remote_path = ENS_HOME + "delay.txt"
    remote_s_path = ENS_HOME + "simulation_delay.txt"
    local_s_path = delayPath + "simulation_delay.txt"
    sendDelayFile(local_path, remote_path, used_nodes, "Node_NA.csv")
    sendSimulationDelayFile(local_s_path, remote_s_path, "Node_NA.csv")
