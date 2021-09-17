#! /usr/bin/python3
"""
By mzl 2021.06.09 version 1.0
Used to send message to NMR nodes
"""
import argparse
import random
import socket
import time


def getTimeStamp() -> str:
    timeStamp = int(time.time())
    return hex(timeStamp)[-8:]


def getparser():
    parser = argparse.ArgumentParser(description="NMR client python version")
    parser.add_argument('-i', '--ip', required=True, type=str, help="IPv4/IPv6 address of NMR node")
    parser.add_argument('--port', '-p', required=True, default=10061, type=int,
                        help="port of NMR node, 10061 for level 1; 10062 for level 2; 10063 for level 3")
    parser.add_argument('--command', '-c', type=str, default="custom",
                        choices=['r', 'd', 'bd', 'eid', 'tlv', 'rnl',
                                 'dm', 'agent', 'custom', 'gr', 'gd', 'ge', 'gbd'],
                        help="Input what kind of message to send, "
                             "'r' -> register; "
                             "'d' -> deregister; "
                             "'bd' -> batch-deregister; "
                             "'eid' -> eid resolve simple, use EID: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb; "
                             "'gr' -> batch-deregister; "
                             "'gd' -> globalDeregister; "
                             "'gbd' -> globalBatchDeregister; "
                             "'ge' -> globalResolve; eid global resolve simple, use EID: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb; "
                             "'tlv' -> tlv resolve, use EID: 0000000000000000000000000000000000000000; "
                             "'rnl' -> get rnl response from resolve node; "
                             "'agent' -> get rnl response from server-agent; "
                             "'dm' -> delay measure from client to resolve node; "
                             "'custom' -> user defined payload message, use with parameter -m <msg>; ")
    parser.add_argument('--EIDQuery', '-eq', required=False, type=str,
                        help="resolve self defined EID, use: -eq <EID>")
    parser.add_argument('--TagQuery', '-tq', required=False, type=str,
                        help="resolve self defined Tag, use: -tq <tlv>")
    parser.add_argument('--EIDRegister', '-er', required=False, type=str, nargs='+',
                        help="register self defined EID+NA and optional tag, use: -er <EID+NA> <tag>")
    parser.add_argument('--sequence', required=False, action="store_true", default=False,
                        help="register sequence EID from 0 to set number + NA"
                             "Only when there are -n parameters without n=-1 in effect.")
    parser.add_argument('--EIDDeregister', '-ed', required=False, type=str,
                        help="deregister self defined EID+NA,  use: -ed <EID+NA>")
    parser.add_argument('--EIDBatchDeregister', '-ebd', required=False, type=str,
                        help="Batch-deregister from self defined NA,  use: -ebd <NA>")
    parser.add_argument('--number', '-n', required=False, default=1, type=int,
                        help="Number of packets to send. set n = -1 if number is infinite")
    parser.add_argument('--speed', '-s', required=False, default=-1, type=int,
                        help="packets sending speed(pps). Only when there are --force parameters in effect")
    parser.add_argument('--force', required=False, action="store_true", default=False,
                        help="force send message without waiting response, use to increase PPS")
    parser.add_argument('--message', '-m', required=False, type=str,
                        help="custom packet payload, use as -c custom -m 6f1112121232...")
    parser.add_argument('--detail', '-d', required=False, action="store_true", default=False,
                        help="analyze response message and show detail. (Only has effect in normal mode)")
    return parser


def checkIP(ip: str):
    """
    check IPv4 or IPv6
    :param ip: ip address
    :return: socket family
    """
    if ":" in ip:
        return socket.AF_INET6
    elif "." in ip:
        return socket.AF_INET
    else:
        raise Exception("ip input wrong")


def getRequestID() -> str:
    """
    :return: return random requestID(4 byte hex string)
    """
    return hex(random.randint(268435456, 4294967295))[2:]


def getRandomEID() -> str:
    """
    :return: return random EID(20 byte hex string, length = 40)
    """
    s = ""
    for i in range(40):
        num_hex = hex(random.randint(0, 15))
        s = s + num_hex[2:]
    return s


def getSequenceEID(end: int = 1):
    """
    :return: return random EID(20 byte hex string, length = 40)
    """
    if end == 1:
        return ["b" * 40]
    eid_list = []
    for i in range(end):
        s = "b" * (40 - len(str(i))) + str(i)
        eid_list.append(s)
    return eid_list


def getSequenceMsg(num: int, command: str):
    NA = "99999999999999999999999999999999"
    position = 10  # 标记返回报文成功的标志位的起始位置
    msg = []
    if num >= 0:
        eid_list = getSequenceEID(num)
        for i in range(num):
            timeStamp = getTimeStamp()
            requestID = getRequestID()
            if command == "r" or command == "register":
                msg.append("6f" + requestID + eid_list[i] + NA + "030100" + timeStamp + "0000")
            elif command == 'gr':
                msg.append("0b" + requestID + eid_list[i] + NA + "010100" + timeStamp + "0000")
            else:
                print("Warning! Don't support this kind of sequence msg.")
    return msg, position


def getMsg(command: str, content: str = ""):
    """
    从输入指令判断对应的注册、注销、解析、RNL获取等报文
    :param content: if command is EIDQuery and EIDRegister, content is EID or EID+NA
    :param command:  用户输入的指令string
    :return: msg: 请求报文;
             position: 返回报文标志位的起始位置，用于判断指令是否执行成功
    """
    position = 0  # 标记返回报文成功的标志位的起始位置
    timeStamp = getTimeStamp()
    requestID = getRequestID()
    if command == "register" or command == "r":
        position = 10
        msg = "6f" + requestID + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb99999999999999999999999999999999" \
                                 "030100" + timeStamp + "0006010101020102"
    elif command == "deregister" or command == "d":
        position = 10
        msg = "73" + requestID + "00" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb99999999999999999999999999999999" + timeStamp
    elif command == "resolve" or command == "e" or command == "eid":
        position = 2
        msg = "71000000" + requestID + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" + timeStamp
    elif command == "resolve+tlv" or command == "tlv":
        position = 2
        msg = "71000006" + requestID + "0000000000000000000000000000000000000000" + timeStamp + "010101020102"
    elif command == "batchDeregister" or command == "batch-deregister" or command == "bd":
        position = 10
        msg = "73" + requestID + "01" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb99999999999999999999999999999999" + timeStamp
    elif command == "globalRegister" or command == "gr":
        position = 10
        msg = "0b" + requestID + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb99999999999999999999999999999999" \
                                 "010100" + timeStamp + "0000"
    elif command == "globalResolve" or command == "ge":
        position = 2
        msg = "0d000000" + requestID + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" + timeStamp
    elif command == "globalDeregister" or command == "gd":
        position = 10
        msg = "0f" + requestID + "00" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb99999999999999999999999999999999" + timeStamp
    elif command == "globalBatchDeregister" or command == "gbd":
        position = 10
        msg = "0f" + requestID + "01" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb99999999999999999999999999999999" + timeStamp
    elif command == "EIDQuery" or command == "eq":
        position = 2
        msg = "71000000" + requestID + content + timeStamp
    elif command == "TagQuery" or command == "tq":
        tlv_len = hex(int(len(content) / 2))[2:]
        tlv_len_str = "0" * (4 - len(tlv_len)) + tlv_len
        position = 2
        msg = "7100" + tlv_len_str + requestID + "0" * 40 + timeStamp + content
    elif command == "EIDRegister" or command == "er":
        eid_na = content[:72]
        tlv = content[72:]
        tlv_len = hex(int(len(tlv) / 2))[2:]
        tlv_len_str = "0" * (4 - len(tlv_len)) + tlv_len
        position = 10
        msg = "6f" + requestID + eid_na + "030100" + timeStamp + tlv_len_str + tlv
    elif command == "EIDDeregister" or command == "ed":
        position = 10
        msg = "73" + requestID + "00" + content + timeStamp
    elif command == "EIDBatchDeregister" or command == "ebd":
        position = 10
        msg = "73" + requestID + "01bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" + content + timeStamp
    elif command == "rnl":
        position = 10
        msg = "0d" + requestID + timeStamp
    elif command == "connect" or command == "agent":
        position = 10
        msg = "1d" + requestID + timeStamp
    elif command == "dm" or command == "delay-measure":
        msg = "03" + timeStamp
        position = 9999  # 选一个比较大的数当做标识
    else:
        # todo : 批量随机注册实现？
        msg = ""
    return msg, position


def show_details(receive_message: str):
    # 注册响应报文
    if receive_message[:2] == "70":
        request_id = receive_message[2:10]
        status_dict = {"01": "registered_successful", "02": "parameter_error", "03": "internal_error",
                       "04": "storage_is_full", "05": "other_errors"}
        status = status_dict[receive_message[10:12]]
        time_stamp = receive_message[12:20]
        print("=== response details ===:\n[request_id]: {}, [register status]: {}, [timestamp]: {}".format(request_id,
                                                                                                           status,
                                                                                                           time_stamp))
    # 注销响应报文
    elif receive_message[:2] == "74":
        request_id = receive_message[2:10]
        status_dict = {"01": "delete_successful", "02": "parameter_error", "03": "internal_error",
                       "04": "storage_is_full", "05": "other_errors"}
        status = status_dict[receive_message[10:12]]
        time_stamp = receive_message[12:20]
        print("=== response details ===:\n[request_id]: {}, [register status]: {}, [timestamp]: {}".format(request_id,
                                                                                                           status,
                                                                                                           time_stamp))
    # 解析响应报文
    elif receive_message[:2] == "72":
        status_dict = {"01": "resolve_successful", "00": "resolve_failed"}
        status = status_dict[receive_message[2:4]]
        request_id = receive_message[8:16]
        time_stamp = receive_message[16:24]
        num = int(receive_message[24:28], 16)
        index = 28
        print("=== response details ===:\n[request_id]: {}, [resolve status]: {}, [timestamp]: {}".format(request_id,
                                                                                                          status,
                                                                                                          time_stamp))
        print("[resolving_entry_number]: {}".format(num))
        for i in range(num):
            print("[{}] EID: {}, NA: {}".format(i, receive_message[index:index + 40],
                                                receive_message[index + 40:index + 72]))
            index += 72

    # rnl响应报文 -客户端
    elif receive_message[:2] == "1e":
        request_id = receive_message[2:10]
        status_dict = {"01": "get_rnl_successful", "00": "get_rnl_failed"}
        status = status_dict[receive_message[10:12]]
        global_resolution_addr = receive_message[12:44]
        log_collection_system_addr = receive_message[44:76]
        # 解析时延等级
        delay_level_number = int(receive_message[76:78], 16)
        level_delay_list = []
        p = 78
        for i in range(delay_level_number):
            level_delay_list.append((int(receive_message[p:p + 2], 16), int(receive_message[p + 2:p + 4], 16)))
            p += 4
        # 解析节点
        resolve_node_number = int(receive_message[p:p + 2])
        p += 2
        resolve_node_list = []
        for i in range(resolve_node_number):
            resolve_node_list.append((receive_message[p:p + 8], receive_message[p + 8:p + 40],
                                      int(receive_message[p + 40:p + 42], 16), receive_message[p + 42:p + 44]))
            p += 44
        # 子节点
        child_node_number = int(receive_message[p:p + 2], 16)
        p += 2
        child_node_list = []
        for i in range(child_node_number):
            child_node_list.append((receive_message[p:p + 8], receive_message[p + 8:p + 40],
                                    int(receive_message[p + 40:p + 42], 16), receive_message[p + 42:p + 44]))
            p += 44
        # 时延邻居节点
        delay_neighbor_node_number = int(receive_message[p:p + 2], 16)
        p += 2
        delay_neighbor_node_list = []
        for i in range(delay_neighbor_node_number):
            delay_neighbor_node_list.append((receive_message[p:p + 8], receive_message[p + 8:p + 40],
                                             int(receive_message[p + 40:p + 42], 16), receive_message[p + 42:p + 44]))
            p += 44
        # 地理邻居节点
        geo_neighbor_node_number = int(receive_message[p:p + 2], 16)
        p += 2
        geo_neighbor_node_list = []
        for i in range(geo_neighbor_node_number):
            geo_neighbor_node_list.append((receive_message[p:p + 8], receive_message[p + 8:p + 40],
                                           int(receive_message[p + 40:p + 42], 16), receive_message[p + 42:p + 44]))
            p += 44
        # 索引邻居节点
        index_neighbor_node_number = int(receive_message[p:p + 2], 16)
        p += 2
        index_neighbor_node_list = []
        for i in range(index_neighbor_node_number):
            index_neighbor_node_list.append((receive_message[p:p + 8], receive_message[p + 8:p + 40],
                                             int(receive_message[p + 40:p + 42], 16), receive_message[p + 42:p + 44]))
            p += 44
        print("=== response details ===:\n[request_id]: {}, [resolve status]: {}".format(request_id, status))
        print("[global_resolution_address]: " + global_resolution_addr +
              "\t[log_collection_system_address]: " + log_collection_system_addr)
        for ld in level_delay_list:
            print("level: {} - delay: {}ms".format(ld[0], ld[1]), sep="\t")
        print("--- resolve nodes ---")
        for i, node in enumerate(resolve_node_list):
            print("[{}] ID:{}, NA:{}, level:{}, isReal:{}".format(i, node[0], node[1], node[2], node[3]))
        print("--- child nodes ---")
        for i, node in enumerate(child_node_list):
            print("[{}] ID:{}, NA:{}, level:{}, isReal:{}".format(i, node[0], node[1], node[2], node[3]))
        print("--- delay neighbor nodes ---")
        for i, node in enumerate(delay_neighbor_node_list):
            print("[{}] ID:{}, NA:{}, level:{}, isReal:{}".format(i, node[0], node[1], node[2], node[3]))
        print("--- geo neighbor nodes ---")
        for i, node in enumerate(geo_neighbor_node_list):
            print("[{}] ID:{}, NA:{}, level:{}, isReal:{}".format(i, node[0], node[1], node[2], node[3]))
        print("--- index neighbor nodes ---")
        for i, node in enumerate(index_neighbor_node_list):
            print("[{}] ID:{}, NA:{}, level:{}, isReal:{}".format(i, node[0], node[1], node[2], node[3]))

    # rnl响应报文 -接入代理
    elif receive_message[:2] == "0e":
        request_id = receive_message[2:10]
        status_dict = {"01": "get_rnl_successful", "00": "get_rnl_failed"}
        status = status_dict[receive_message[10:12]]
        # 解析时延等级
        delay_level_number = int(receive_message[12:14], 16)
        level_delay_list = []
        p = 14
        for i in range(delay_level_number):
            level_delay_list.append((int(receive_message[p:p + 2], 16), int(receive_message[p + 2:p + 4], 16)))
            p += 4
        # 解析节点
        resolve_node_number = int(receive_message[p:p + 2])
        p += 2
        resolve_node_list = []
        for i in range(resolve_node_number):
            resolve_node_list.append((receive_message[p:p + 8], receive_message[p + 8:p + 40],
                                      int(receive_message[p + 40:p + 42], 16), receive_message[p + 42:p + 44]))
            p += 44
        # 子节点
        child_node_number = int(receive_message[p:p + 2], 16)
        p += 2
        child_node_list = []
        for i in range(child_node_number):
            child_node_list.append((receive_message[p:p + 8], receive_message[p + 8:p + 40],
                                    int(receive_message[p + 40:p + 42], 16), receive_message[p + 42:p + 44]))
            p += 44
        time_stamp = receive_message[p:p + 8]
        print("=== response details ===:\n[request_id]: {}, [resolve status]: {}, [timeStamp]: {}"
              .format(request_id, status, time_stamp))
        for ld in level_delay_list:
            print("level: {} - delay: {}ms".format(ld[0], ld[1]), sep="\t")
        print("--- resolve nodes ---")
        for i, node in enumerate(resolve_node_list):
            print("[{}] ID:{}, NA:{}, level:{}, isReal:{}".format(i, node[0], node[1], node[2], node[3]))
        print("--- child nodes ---")
        for i, node in enumerate(child_node_list):
            print("[{}] ID:{}, NA:{}, level:{}, isReal:{}".format(i, node[0], node[1], node[2], node[3]))


def run():
    parser = getparser()
    args = parser.parse_args()
    IP = args.ip
    port = args.port
    ADDRESS = (IP, port)
    family = checkIP(IP)  # check IPv4/IPv6
    command = args.command
    infFlag = False
    if args.EIDQuery is not None:
        EID = args.EIDQuery
        if len(EID) != 40:
            print("EID length error!")
            return
        msg, p = getMsg("EIDQuery", EID)
    elif args.TagQuery is not None:
        tlv_msg = args.TagQuery
        msg, p = getMsg("TagQuery", tlv_msg)
    elif args.EIDRegister is not None:
        if len(args.EIDRegister) > 1:
            EIDNA = args.EIDRegister[0]
            tag = args.EIDRegister[1]
        else:
            EIDNA = args.EIDRegister[0]
            tag = ""
        if len(EIDNA) != 72:
            print("EID+NA length error!")
            return
        msg, p = getMsg("EIDRegister", EIDNA + tag)
    elif args.EIDDeregister is not None:
        EIDNA = args.EIDDeregister
        if len(EIDNA) != 72:
            print("EID+NA length error!")
            return
        msg, p = getMsg("EIDDeregister", EIDNA)
    elif args.EIDBatchDeregister is not None:
        NA = args.EIDBatchDeregister
        if len(NA) != 32:
            print("NA length error!")
            return
        msg, p = getMsg("EIDBatchDeregister", NA)
    else:
        # batch register only for eid like: bbb...bb19210
        if (command == 'register' or command == 'r' or command == 'gr') and args.sequence:
            msg, p = getSequenceMsg(args.number, command)
        elif command == "custom":
            msg = args.message
            if msg is None:
                print("Custom message is empty, please add '-m <msg>' or -er <EID+NA> or -eq <EID> "
                      "or -ed <EID+NA> or -ebd <NA>.")
                return
            p = 0
        else:
            msg, p = getMsg(command)
    if msg == "":
        print("Getting message is none!")
        return
    number = args.number
    speed = args.speed
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.settimeout(3)
    if number < 0:
        infFlag = True
    startMsgSendTime = time.time()
    while not infFlag:
        # 发送一批数据包
        lastCheckTime = startMsgSendTime
        for i in range(number):
            sendTimeStamp = time.time()
            if type(msg) == str:
                s.sendto(bytes.fromhex(msg), ADDRESS)
            else:
                s.sendto(bytes.fromhex(msg[i]), ADDRESS)
            if args.force:
                if speed > 0 and number >= 10000 and i % (number // 20) == 0:
                    sleepTime = (number // 20) / speed - (time.time() - lastCheckTime)
                    time.sleep(sleepTime if sleepTime > 0 else 0)
                    lastCheckTime = time.time()
                if i != 0 and i % (number // 5) == 0:
                    delay = round((time.time() - startMsgSendTime) * 1000, 3)
                    pps = int(i / delay * 1000)
                    print("Already send " + str(i) + " packets, use: " + str(delay) + " ms, pps: " + str(pps))
                continue
            try:
                recv, addr = s.recvfrom(1024)
                delay = round((time.time() - sendTimeStamp) * 1000, 3)
                if p != 0 and p != 9999:
                    isSuccess = "success" if recv.hex()[p:p + 2] == "01" else "failed"
                else:
                    isSuccess = "success"
                if p == 9999:
                    print("receive delay measure response msg, status: " + isSuccess + ", delay: " + str(delay) + "ms")
                else:
                    print("receive msg from " + str(addr[:2]) + " : " + recv.hex() + ", status: " + isSuccess)
                    if args.detail:
                        show_details(recv.hex())
            except socket.timeout:
                print("Can't receive msg! Socket timeout")
        break
    else:
        # 循环不间断发送数据包
        if type(msg) != str:
            print("Error! register sequence EID only supported in limited packet numbers.")
            return
        count = 0
        lastCheckTime = startMsgSendTime
        while True:
            s.sendto(bytes.fromhex(msg), ADDRESS)
            count += 1
            if args.force:
                if speed > 0 and count % 5000 == 0:
                    sleepTime = 5000 / speed - (time.time() - lastCheckTime)
                    time.sleep(sleepTime if sleepTime > 0 else 0)
                    lastCheckTime = time.time()
                if count % 50000 == 0:
                    delay = round((time.time() - startMsgSendTime) * 1000, 3)
                    pps = int(count / delay * 1000)
                    print("Already send " + str(count) + " packets, use: " + str(delay) + " ms, pps: " + str(pps))
                continue
            try:
                recv, addr = s.recvfrom(1024)
                if p != 0 and p != 9999:
                    isSuccess = "success" if recv.hex()[p:p + 2] == "01" else "failed"
                    print("receive msg from " + str(addr[:2]) + " : " + recv.hex() + ", status: " + isSuccess)
                else:
                    print("receive delay measure response msg, status: success")
            except socket.timeout:
                print("Can't receive msg! Socket timeout")
    if args.force:
        delay = round((time.time() - startMsgSendTime) * 1000, 3)
        print("send " + str(number) + " packets successful, total use: " + str(delay) + "ms, pps: " +
              str(int(number / delay * 1000)))
    s.close()


if __name__ == '__main__':
    run()
