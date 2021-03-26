#! /usr/bin/python3
"""
By mzl 2021.03.10 version 1.0
Used to start Node, stop Node and kill Node
"""
import re
import sys
import time
import socket

import pandas as pd
import paramiko

ENS_HOME = "/home/resolution/ens/"


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


class Controller(Remote):

    def __init__(self, node_str, host, name, password, port=22):
        super(Controller, self).__init__(host, name, password, port)
        self.node = node_str

    def startNode(self):
        """
        Start a NMM NODE
        """
        properties_file = getPropertyFileName(self.node)
        command = "cd " + ENS_HOME + " && nohup java -jar ens.jar " + properties_file + " 2>&1 >log/" \
                  + str(self.node).replace(".properties", "") + " &\n"
        ssh = self.my_connect()
        shell = ssh.invoke_shell()
        shell.send(command)
        print("send to " + self.node + " : " + command.strip() + " ...")
        print(str(self.node) + " is started")
        time.sleep(3)
        ssh.close()

    def stopNode(self):
        """
        stop a NMM node, send TCP packet to stop and kill process.
        """
        command = "cd /home/resolution/ens && cat " + getPropertyFileName(self.node)
        out_msg, err_msg = self.send_command(command)
        properties = Properties(out_msg).getProperties()
        node_id = properties["NODE_ID"]
        node_NA = properties["NODE_NA"].strip()
        node_port = int(properties["BASIC_PORT"]) + int(properties["NODE_LEVEL"])
        s = socket.socket(family=socket.AF_INET6, type=socket.SOCK_STREAM)
        # print(self.host)
        s.connect((node_NA, node_port))
        stop_command_str = "59" + node_id + "11111111"
        s.send(bytes.fromhex(stop_command_str))
        recv = s.recv(1024).hex()
        if recv.startswith("5a"):
            print("response message is: " + recv + ", successfully stop " + self.node)
        s.close()
        time.sleep(3)
        self.killNode()

    def killNode(self):
        """
        kill a NMM Node process
        """
        command = "ps -aux |grep java"
        out_msg, error_msg = self.send_command(command)
        processes = ""
        for line in out_msg.split("\n"):
            if "ens.jar" in line and getPropertyFileName(self.node) in line:
                key_list = [x for x in line.split(' ') if x]
                process_num = key_list[1]
                processes += process_num + " "
        kill_str = "kill -9 " + processes
        print("killing process: " + processes + "...")
        _, err_ = self.send_command(kill_str)
        if err_ == '':
            print(self.node + " has been killed")
        else:
            print(err_)


def getArgNum():
    return len(sys.argv) - 1


def getPropertyFileName(node_str):
    # property_name = ""
    if "Node" in node_str or "node" in node_str:
        property_name = node_str + ".properties"
    elif re.match(r"\d*", node_str):
        property_name = "Node_" + node_str + ".properties"
    else:
        raise ValueError("Warning! Node name input format is wrong!")
    return property_name


def getInformationFromNodeStr(node_str, node_na_file="Node_NA.csv"):
    csv = pd.read_csv(node_na_file)
    node_na = csv["NA"][csv["Node"] == node_str].values[0]
    hostname = csv["Name"][csv["Node"] == node_str].values[0]
    host_password = csv["Password"][csv["Node"] == node_str].values[0]
    return node_na, hostname, host_password


def getAllNodes(node_na_csv="Node_NA.csv"):
    csv = pd.read_csv(node_na_csv)
    return "[" + ", ".join(csv["Node"].values) + "]"


def welCome():
    print("Welcome to Node controller script Ver1.0")
    print("=" * 50)
    print("This script can be use to start, stop or kill some ENS nodes\n"
          "For example, \n"
          "start two nodes you can tap in : start Node_1 Node_2 or start 1 2 \n"
          "kill Some nodes you can tap in: kill Node_3 Node198 Node4 or kill 3 4 \n"
          "stop some nodes you can tap in: stop 1 2 3 4")
    print("If you have done all the control, press the 'enter' button to stop the input process")
    print("=" * 50)


def handleInput():
    flag = True
    while flag:
        msg = input()
        if msg == "" or msg == "exit":
            flag = False
        msg_list = msg.strip().split(" ")
        if len(msg_list) < 2:
            continue
        if msg_list[0] == "start":
            start_node_final_list = []
            start_node_list = msg_list[1:]
            for node in start_node_list:
                if "-" in node:
                    for i in range(int(node.split("-")[0]), int(node.split("-")[1]) + 1):
                        start_node_final_list.append(str(i))
                else:
                    start_node_final_list.append(node)
            for node in start_node_final_list:
                node_str = getPropertyFileName(node).replace(".properties", "")
                host_na, host_name, host_password = getInformationFromNodeStr(node_str)
                node_controller = Controller(node_str, host_na, host_name, host_password)
                node_controller.startNode()

        elif msg_list[0] == "stop":
            stop_node_final_list = []
            stop_node_list = msg_list[1:]
            for node in stop_node_list:
                if "-" in node:
                    for i in range(int(node.split("-")[0]), int(node.split("-")[1]) + 1):
                        stop_node_final_list.append(str(i))
                else:
                    stop_node_final_list.append(node)
            for node in stop_node_final_list:
                node_str = getPropertyFileName(node).replace(".properties", "")
                host_na, host_name, host_password = getInformationFromNodeStr(node_str)
                node_controller = Controller(node_str, host_na, host_name, host_password)
                node_controller.stopNode()

        elif msg_list[0] == "kill":
            kill_node_list = msg_list[1:]
            kill_node_final_list = []
            for node in kill_node_list:
                if "-" in node:
                    for i in range(int(node.split("-")[0]), int(node.split("-")[1]) + 1):
                        kill_node_final_list.append(str(i))
                else:
                    kill_node_final_list.append(node)
            for node in kill_node_final_list:
                node_str = getPropertyFileName(node).replace(".properties", "")
                host_na, host_name, host_password = getInformationFromNodeStr(node_str)
                node_controller = Controller(node_str, host_na, host_name, host_password)
                node_controller.killNode()
        else:
            print("Valid command!")
            continue
    print("All commands have been committed! Bye ~")


def handleInput_simple(command, node_list):
    if len(node_list) < 1:
        return
    if command == "start":
        for node in node_list:
            node_str = getPropertyFileName(node).replace(".properties", "")
            host_na, host_name, host_password = getInformationFromNodeStr(node_str)
            node_controller = Controller(node_str, host_na, host_name, host_password)
            node_controller.startNode()

    elif command == "stop":
        for node in node_list:
            node_str = getPropertyFileName(node).replace(".properties", "")
            host_na, host_name, host_password = getInformationFromNodeStr(node_str)
            node_controller = Controller(node_str, host_na, host_name, host_password)
            node_controller.stopNode()

    elif command == "kill":
        for node in node_list:
            node_str = getPropertyFileName(node).replace(".properties", "")
            host_na, host_name, host_password = getInformationFromNodeStr(node_str)
            node_controller = Controller(node_str, host_na, host_name, host_password)
            node_controller.killNode()
    else:
        print("Valid command!")
        return


if __name__ == '__main__':
    if len(sys.argv) > 1:
        handleInput_simple(sys.argv[1], [x for x in sys.argv[2:]])
    else:
        welCome()
        print("All possible nodes are list as follows: " + getAllNodes("Node_NA.csv"))
        handleInput()
