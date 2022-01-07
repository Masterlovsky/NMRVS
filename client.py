#! /usr/bin/python3
"""
By mzl 2021.06.09 version 1.0
Used to send message to NMR nodes
"""
import argparse
import random
import socket
import time
import uuid

EID_STR_LEN = 40
CID_STR_LEN = 64
CID_NA_STR_LEN = 96
EID_NA_STR_LEN = 72
EID_CID_STR_LEN = 104
EID_CID_NA_STR_LEN = 136
FLAG_ECID_QUERY = 2000
FLAG_DELAY_MEASURE = 9999
burst_size = 2000  # 当发包数量大于100000个或发包数量不限时生效，规定burst_size


def getTimeStamp() -> str:
    timeStamp = int(time.time())
    return hex(timeStamp)[-8:]


def getparser():
    parser = argparse.ArgumentParser(description="NMR client python version")
    parser.add_argument('-i', '--ip', required=True, type=str, help="IPv4/IPv6 address of NMR node")
    parser.add_argument('-p', '--port', required=True, default=10061, type=int,
                        help="port of NMR node, 10061 for level 1; 10062 for level 2; 10063 for level 3; 10090 for global resolution")
    parser.add_argument('-c', '--command', type=str, default="custom",
                        choices=['r', 'd', 'bd', 'eid', 'tlv', 'rnl', 'rcid', 'ecid', 'dcid',
                                 'dm', 'agent', 'custom', 'gr', 'gd', 'ge', 'gbd'],
                        help="Input what kind of message to send,           "
                             "'r' -> register;                              "
                             "'d' -> deregister;                            "
                             "'bd' -> batch-deregister;                     "
                             "'eid' -> eid resolve simple, use EID: bbb..bb;"
                             "'rcid' -> eid+cid register simple.            "
                             "'ecid' -> eid+cid resolve simple              "
                             "'dcid' -> eid+cid deregister simple           "
                             "'gr' -> global-register;                      "
                             "'gd' -> global-deregister;                    "
                             "'gbd' -> global-batchDeregister;              "
                             "'ge' -> global-resolve; eid global resolve simple; "
                             "'tlv' -> tlv resolve, use EID: 000...00;      "
                             "'rnl' -> get rnl response from resolve node;  "
                             "'agent' -> get rnl response from server-agent;"
                             "'dm' -> delay measure from client to resolve node;"
                             "'custom' -> user defined payload message, use with parameter -m <msg>;")
    parser.add_argument('-eq', '--EIDQuery', required=False, type=str, metavar="EID(HexStr)",
                        help="resolve self defined EID, use: -eq <EID>")
    parser.add_argument('-ecq', '--EIDCIDQuery', required=False, type=str, nargs=2, metavar=("QueryType", "Content"),
                        help="resolve self defined EID, CID, Tag, QueryType{0:eid->ip; 1:eid->cid; 2:cid->ip; 3:eid+cid->ip; 4:tag->eid+cid+ip}."
                             " use: -ecq <QueryType> <EID>/<CID>/<Tag>")
    parser.add_argument('-tq', '--TagQuery', required=False, type=str, metavar="TLV(HexStr)",
                        help="resolve self defined Tag, use: -tq <tlv>")
    parser.add_argument('-er', '--EIDRegister', required=False, type=str, nargs='+', metavar=("EID+NA", "TAG(opt)"),
                        help="register self defined EID+NA and optional tag, use: -er <EID+NA> <tag>")
    parser.add_argument('-ecr', '--EIDCIDRegister', required=False, type=str, nargs='+',
                        metavar=("EID+CID+NA", "TAG(opt)"),
                        help="register self defined EID+CID+NA and optional tag, use: -er <EID+CID+NA> <tag>")
    parser.add_argument('-ed', '--EIDDeregister', required=False, type=str, metavar="EID+NA",
                        help="deregister self defined EID+NA,  use: -ed <EID+NA>")
    parser.add_argument('-ecd', '--EIDCIDDeregister', required=False, type=str, metavar="EID+CID+NA",
                        help="deregister self defined EID+CID+NA,  use: -ecd <EID+CID+NA>")
    parser.add_argument('-ebd', '--EIDBatchDeregister', required=False, type=str, metavar="NA",
                        help="Batch-deregister from self defined NA,  use: -ebd <NA>")
    parser.add_argument('-ecbd', '--EIDCIDBatchDeregister', required=False, type=str, metavar="NA",
                        help="EID+CID Batch-deregister from self defined NA,  use: -ecbd <NA>")
    parser.add_argument('--sequence', required=False, action="store_true", default=False,
                        help="register sequence EID from 0 to set number + NA"
                             "Only when there are -n parameters without n=-1 in effect.")
    parser.add_argument('-n', '--number', required=False, default=1, type=int,
                        help="Number of packets to send. set n = -1 if number is infinite")
    parser.add_argument('-s', '--speed', required=False, default=-1, type=int,
                        help="packets sending speed(pps). Only when there are --force parameters in effect")
    parser.add_argument('--force', required=False, action="store_true", default=False,
                        help="force send message without waiting response, use to increase PPS")
    parser.add_argument('--random', required=False, action="store_true", default=False,
                        help="Use random requestID when sending multiple message")
    parser.add_argument('-m', '--message', required=False, type=str, metavar="custom message",
                        help="custom packet payload, use as -c custom -m 6f1112121232...")
    parser.add_argument('-d', '--detail', required=False, action="store_true", default=False,
                        help="analyze response message and show detail. (Only has effect in normal mode)")
    parser.add_argument('-b', '--burstSize', required=False, type=int, default=2000,
                        help="The number of concurrent packets. Delay adjustment is triggered after each concurrent burst_size of packets. "
                             "(Only has effect when use '-n -1' or '-n 100000+')")
    return parser


def formatTime(t: float) -> str:
    """
    :param t: an integer value with millisecond unit
    :rtype: value in adaptive string time unit
    """
    f_time = ""
    if t > 3600000:
        # hour
        h = t // 3600000
        t -= h * 3600000
        f_time += str(int(h)) + "hour, "
    if t > 60000:
        # min
        m = t // 60000
        t -= m * 60000
        f_time += str(int(m)) + "min, "
    if t > 1000:
        # s
        s = t // 1000
        t -= s * 1000
        f_time += str(int(s)) + "s, "
    f_time += str(round(t, 3)) + " ms"
    return f_time


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
    return str(uuid.uuid4())[:8]


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


def getMsg(command: str, content: str = "", num: int = 1, flag_random_reqID: bool = False):
    """
    从输入指令判断对应的注册、注销、解析、RNL获取等报文，获取带有随机requestID的报文列表
    :param flag_random_reqID: 是否使用随机requestID，默认不使用
    :param num: 发送报文个数，默认只发送一个
    :param content: if command is EIDQuery and EIDRegister, content is EID or EID+NA
    :param command:  用户输入的指令string
    :return: msg_l: 请求报文列表;
             position: 返回报文标志位的起始位置，用于判断指令是否执行成功
    """
    msg_l = []
    position = 0  # 标记返回报文成功的标志位的起始位置
    flag = not flag_random_reqID  # 标记是否是普通消息（不需要random requestID）
    while num != 0:
        msg = ""
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

        elif command == "register_cid" or command == "rcid":
            position = 10
            msg = "6f" + requestID + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" + "c" * 64 + "99999999999999999999999999999999" \
                                                                                             "030100" + timeStamp + "0000"
        elif command == "deregister_cid" or command == "dcid":
            position = 10
            msg = "73" + requestID + "00" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" + "c" * 64 + "99999999999999999999999999999999" + timeStamp
        elif command == "resolve_cid" or command == "ecid":
            position = FLAG_ECID_QUERY
            msg = "7100000000" + requestID + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" + "0" * 64 + timeStamp

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
        elif command == "EIDCIDQuery" or command == "ecq":
            position = FLAG_ECID_QUERY
            queryType = content[:1]
            origin_content = content[1:]
            if queryType == "0" or queryType == "1":
                msg = "7100" + "0" + queryType + "0000" + requestID + origin_content + "0" * CID_STR_LEN + timeStamp
            elif queryType == "2":
                msg = "7100" + "02" + "0000" + requestID + "0" * EID_STR_LEN + origin_content + timeStamp
            elif queryType == "3":
                msg = "7100" + "03" + "0000" + requestID + origin_content + timeStamp
            elif queryType == "4":
                tlv_len = hex(int(len(origin_content) / 2))[2:]
                tlv_len_str = "0" * (4 - len(tlv_len)) + tlv_len
                msg = "7100" + "04" + tlv_len_str + requestID + "0" * EID_CID_STR_LEN + timeStamp + origin_content
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
        elif command == "EIDCIDRegister" or command == "ecr":
            eid_cid_na = content[:136]
            tlv = content[136:]
            tlv_len = hex(int(len(tlv) / 2))[2:]
            tlv_len_str = "0" * (4 - len(tlv_len)) + tlv_len
            position = 10
            msg = "6f" + requestID + eid_cid_na + "030100" + timeStamp + tlv_len_str + tlv
        elif command == "EIDDeregister" or command == "ed":
            position = 10
            msg = "73" + requestID + "00" + content + timeStamp
        elif command == "EIDCIDDeregister" or command == "ecd":
            position = 10
            msg = "73" + requestID + "00" + content + timeStamp
        elif command == "EIDBatchDeregister" or command == "ebd":
            position = 10
            msg = "73" + requestID + "01" + "b" * EID_STR_LEN + content + timeStamp
        elif command == "EIDCIDBatchDeregister" or command == "ecbd":
            position = 10
            msg = "73" + requestID + "01" + "b" * EID_CID_STR_LEN + content + timeStamp
        elif command == "rnl":
            position = 10
            msg = "0d" + requestID + timeStamp
        elif command == "connect" or command == "agent":
            position = 10
            msg = "1d" + requestID + timeStamp
        elif command == "dm" or command == "delay-measure":
            msg = "03" + timeStamp
            position = FLAG_DELAY_MEASURE  # 选一个比较大的数当做标识
        else:
            # todo : 批量随机注册实现？
            msg = ""
        if flag or num < 0:
            return msg, position
        if msg != "":
            msg_l.append(msg)
        num -= 1
    return msg_l, position


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


def show_details_ecid(receive_message: str):
    # eid+cid 解析响应报文
    if receive_message[:2] != "72":
        return
    status_dict = {"01": "resolve_successful", "00": "resolve_failed"}
    content_len_dict = {"00": EID_NA_STR_LEN, "01": EID_CID_STR_LEN, "02": CID_NA_STR_LEN, "03": EID_CID_NA_STR_LEN,
                        "04": EID_CID_NA_STR_LEN}
    status = status_dict[receive_message[2:4]]
    queryType = receive_message[4:6]
    content_length = content_len_dict[queryType]
    request_id = receive_message[10:18]
    time_stamp = receive_message[18:26]
    num = int(receive_message[26:30], 16)
    index = 30
    print("=== response details ===:\n[request_id]: {}, [resolve status]: {}, [timestamp]: {}".format(request_id,
                                                                                                      status,
                                                                                                      time_stamp))
    print("[resolving_entry_number]: {}".format(num))
    if queryType == "00":
        for i in range(num):
            print("[{}] EID: {}, NA: {}".format(i, receive_message[index:index + EID_STR_LEN],
                                                receive_message[index + EID_STR_LEN:index + EID_NA_STR_LEN]))
            index += EID_NA_STR_LEN
    elif queryType == "01":
        for i in range(num):
            print("[{}] EID: {}, CID: {}".format(i, receive_message[index:index + EID_STR_LEN],
                                                 receive_message[index + EID_STR_LEN:index + EID_CID_STR_LEN]))
            index += EID_CID_STR_LEN
    elif queryType == "02":
        for i in range(num):
            print("[{}] CID: {}, NA: {}".format(i, receive_message[index:index + CID_STR_LEN],
                                                receive_message[index + CID_STR_LEN:index + CID_NA_STR_LEN]))
            index += EID_CID_STR_LEN
    elif queryType == "03" or queryType == "04":
        for i in range(num):
            print("[{}] EID: {}, CID: {}, NA: {}".format(i, receive_message[index:index + EID_STR_LEN],
                                                         receive_message[index + EID_STR_LEN:index + EID_CID_STR_LEN],
                                                         receive_message[
                                                         index + EID_CID_STR_LEN:index + EID_CID_NA_STR_LEN]))
            index += EID_CID_NA_STR_LEN


def run():
    parser = getparser()
    args = parser.parse_args()
    IP = args.ip
    port = args.port
    ADDRESS = (IP, port)
    family = checkIP(IP)  # check IPv4/IPv6
    command = args.command
    infFlag = False
    number = args.number
    speed = args.speed
    burstSize = args.burstSize
    flag_random_requestID = args.random

    if args.EIDQuery is not None:
        EID = args.EIDQuery
        if len(EID) != EID_STR_LEN:
            print("EID length error!")
            return
        msg, p = getMsg("EIDQuery", EID, number, flag_random_requestID)

    elif args.EIDCIDQuery is not None:
        queryType = args.EIDCIDQuery[0]
        content = args.EIDCIDQuery[1]
        if ((queryType == "0" or queryType == "1") and len(content) == EID_STR_LEN) \
                or (queryType == "2" and len(content) == CID_STR_LEN) \
                or (queryType == "3" and len(content) == EID_CID_STR_LEN) \
                or (queryType == "4"):
            content = queryType + content
        else:
            print("invalid input <EID>/<CID>/<TAG> length error!")
            return
        msg, p = getMsg("EIDCIDQuery", content, number, flag_random_requestID)

    elif args.TagQuery is not None:
        tlv_msg = args.TagQuery
        msg, p = getMsg("TagQuery", tlv_msg, number, flag_random_requestID)

    elif args.EIDRegister is not None:
        if len(args.EIDRegister) > 1:
            EIDNA = args.EIDRegister[0]
            tag = args.EIDRegister[1]
        else:
            EIDNA = args.EIDRegister[0]
            tag = ""
        if len(EIDNA) != EID_NA_STR_LEN:
            print("EID+NA length error! Should be EID(40 hexStr) + NA(32 hexStr)")
            return
        msg, p = getMsg("EIDRegister", EIDNA + tag, number, flag_random_requestID)

    elif args.EIDCIDRegister is not None:
        if len(args.EIDCIDRegister) > 1:
            EIDCIDNA = args.EIDCIDRegister[0]
            tag = args.EIDCIDRegister[1]
        else:
            EIDCIDNA = args.EIDCIDRegister[0]
            tag = ""
        if len(EIDCIDNA) != EID_CID_NA_STR_LEN:
            print("EID+CID+NA length error! Should be EID(40 hexStr) + CID(64 hexStr) + NA(32 hexStr)")
            return
        msg, p = getMsg("EIDCIDRegister", EIDCIDNA + tag, number, flag_random_requestID)

    elif args.EIDDeregister is not None:
        EIDNA = args.EIDDeregister
        if len(EIDNA) != EID_NA_STR_LEN:
            print("EID+NA length error!")
            return
        msg, p = getMsg("EIDDeregister", EIDNA, number, flag_random_requestID)

    elif args.EIDCIDDeregister is not None:
        EIDCIDNA = args.EIDCIDDeregister
        if len(EIDCIDNA) != EID_CID_NA_STR_LEN:
            print("EID+CID+NA length error! Should be EID(40 hexStr) + CID(64 hexStr) + NA(32 hexStr)")
            return
        msg, p = getMsg("EIDCIDDeregister", EIDCIDNA, number, flag_random_requestID)

    elif args.EIDBatchDeregister is not None:
        NA = args.EIDBatchDeregister
        if len(NA) != 32:
            print("NA length error!")
            return
        msg, p = getMsg("EIDBatchDeregister", NA)

    elif args.EIDCIDBatchDeregister is not None:
        NA = args.EIDCIDBatchDeregister
        if len(NA) != 32:
            print("NA length error!")
            return
        msg, p = getMsg("EIDCIDBatchDeregister", NA)

    else:
        # batch register only for eid like: bbb...bb19210
        if (command == 'register' or command == 'r' or command == 'gr') and args.sequence:
            msg, p = getSequenceMsg(args.number, command)
        elif command == "custom":
            msg = args.message
            if msg is None:
                print("Custom message is empty, please add '-m <msg>'")
                return
            p = 0
        else:
            msg, p = getMsg(command, "", number, flag_random_requestID)
    if msg == "" or len(msg) == 0:
        print("Getting message is none!")
        return

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
                if speed > 0:
                    if number < 100000:
                        if i != 0 and i % (number // 20) == 0:  # 100000个包以内每发number/20个包调整一次时延，共调整20次。
                            sleepTime = (number // 20) / speed - (time.time() - lastCheckTime)
                            if sleepTime > 0:
                                time.sleep(sleepTime)
                            lastCheckTime = time.time()
                    else:
                        if i != 0 and i % burstSize == 0:  # 100000个包以上每发burst_size个包调整一次时延，共调整number/burst_size次。
                            sleepTime = burstSize / speed - (time.time() - lastCheckTime)
                            if sleepTime > 0:
                                time.sleep(sleepTime)
                            lastCheckTime = time.time()
                # 打印输出当前的发包速率
                if i != 0 and number <= 10000 and i % (number // 5) == 0:
                    delay = round((time.time() - startMsgSendTime) * 1000, 3)
                    pps = int(i / delay * 1000)
                    print("Already send " + str(i) + " packets, use: " + formatTime(delay) + " , pps: " + str(pps))
                elif i != 0 and number <= 100000 and i % (number // 10) == 0:
                    delay = round((time.time() - startMsgSendTime) * 1000, 3)
                    pps = int(i / delay * 1000)
                    print("Already send " + str(i) + " packets, use: " + formatTime(delay) + " , pps: " + str(pps))
                elif i != 0 and i % 20000 == 0:
                    delay = round((time.time() - startMsgSendTime) * 1000, 3)
                    pps = int(i / delay * 1000)
                    print("Already send " + str(i) + " packets, use: " + formatTime(delay) + " , pps: " + str(pps))
                continue
            try:
                recv, addr = s.recvfrom(1024)
                delay = round((time.time() - sendTimeStamp) * 1000, 3)
                if p == 0 or p == FLAG_DELAY_MEASURE:
                    isSuccess = "success"
                elif p == FLAG_ECID_QUERY:
                    isSuccess = "success" if recv.hex()[2:4] == "01" else "failed"
                else:
                    isSuccess = "success" if recv.hex()[p:p + 2] == "01" else "failed"
                if p == FLAG_DELAY_MEASURE:
                    print("receive delay measure response msg, status: " + isSuccess + ", delay: " + str(delay) + "ms")
                else:
                    print("receive msg from " + str(addr[:2]) + " : " + recv.hex() + ", status: " + isSuccess)
                    if args.detail:
                        if p == FLAG_ECID_QUERY:
                            show_details_ecid(recv.hex())
                        else:
                            show_details(recv.hex())
            except socket.timeout:
                print("Can't receive msg! Socket timeout")
        break
    else:
        # 循环不间断发送数据包
        if type(msg) != str:
            print('Error! "random requestID mode" / "sequence EID mode" only supported in limited packet numbers.')
            return
        count = 0
        lastCheckTime = startMsgSendTime
        while True:
            s.sendto(bytes.fromhex(msg), ADDRESS)
            count += 1
            if args.force:
                if speed > 0 and count % burstSize == 0:
                    sleepTime = burstSize / speed - (time.time() - lastCheckTime)
                    if sleepTime > 0:
                        time.sleep(sleepTime)
                    lastCheckTime = time.time()
                if count % (speed * 3) == 0:
                    delay = round((time.time() - startMsgSendTime) * 1000, 3)
                    pps = int(count / delay * 1000)
                    print("Already send " + str(count) + " packets, use: " + formatTime(delay) + " , pps: " + str(pps))
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
