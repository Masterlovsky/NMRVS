#! /usr/bin/python3
"""
By mzl 2021.06.09 version 1.0
Used to send message to NMR nodes
"""
import socket
import argparse


def getparser():
    parser = argparse.ArgumentParser(description="NMR client python version")
    parser.add_argument('-i', '--ip', required=True, type=str, help="IPv4/IPv6 address of NMR node")
    parser.add_argument('--port', '-p', required=True, default=10061, type=int,
                        help="port of NMR node, 10061 for level 1; 10062 for level 2; 10063 for level 3")
    parser.add_argument('--command', '-c', required=True, type=str,
                        choices=['register', 'deregister', 'resolve', 'resolve+tlv', 'rnl', 'custom'],
                        help="Which kind of message to send")
    parser.add_argument('--number', '-n', required=False, default=1, type=int, help="Number of packets to send.")
    parser.add_argument('--message', '-m', required=False, type=str,
                        help="custom packet payload, use as -c custom -m 6f1112121232...")
    return parser


def checkIP(ip: str):
    if ":" in ip:
        return socket.AF_INET6
    elif "." in ip:
        return socket.AF_INET
    else:
        raise Exception("ip input wrong")


def getMsg(command: str):
    """
    从输入指令判断对应的注册、注销、解析、RNL获取等报文
    :param command:  用户输入的指令string
    :return: 报文， 返回报文标志位的起始位置，用于判断指令是否执行成功
    """
    position = 0  # 标记返回报文成功的标志位的起始位置
    if command == "register" or command == "r":
        position = 10
        msg = "6f34653039bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb99999999999999999999999999999999" \
              "030100d79df05b0006010101020102"
    elif command == "deregister" or command == "d":
        position = 10
        msg = "733465303900bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb999999999999999999999999999999995f6061f4"
    elif command == "resolve" or command == "e" or command == "eid":
        position = 2
        msg = "7100000663653962bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb5f5896b3010101020102"
    elif command == "resolve+tlv" or command == "tlv":
        position = 2
        msg = "710000061234123400000000000000000000000000000000000000005f5896b3010101020102"
    elif command == "rnl":
        position = 10
        msg = "0d8888888812345678"
    elif command == "r+":
        # todo
        position = 10
        msg = "0d8888888812345678"
    else:
        msg = ""
    return msg, position


def run():
    parser = getparser()
    args = parser.parse_args()
    IP = args.ip
    port = args.port
    ADDRESS = (IP, port)
    family = checkIP(IP)  # check IPv4/IPv6
    command = args.command
    if command == "custom":
        msg = args.message
        if msg is None:
            print("Custom message is empty, please add '-m <msg>'.")
            return
        p = 0
    else:
        msg, p = getMsg(command)
    number = args.number
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.settimeout(3)
    for i in range(number):
        if msg == "":
            break
        s.sendto(bytes.fromhex(msg), ADDRESS)
        try:
            recv, addr = s.recvfrom(1024)
            if p != 0:
                isSuccess = "success" if recv.hex()[p:p + 2] == "01" else "failed"
            else:
                isSuccess = "success"
            print("receive msg from " + str(addr[:2]) + " : " + recv.hex() + ", status: " + isSuccess)
        except socket.timeout:
            print("Can't receive msg! Socket timeout")
    s.close()


if __name__ == '__main__':
    run()
