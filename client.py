#! /usr/bin/python3
"""
BY Masterlovsky 2021.06.09 version 1.0
Used to send message to NMR nodes
update 2023.8.8 version 2.3
"""
import argparse
import sys
import random
import socket
import time
import uuid
import ipaddress
from ctypes import *

VERSION = "2.3"
EID_STR_LEN = 40
NA_STR_LEN = 32
CID_STR_LEN = 64
CID_NA_STR_LEN = 96
EID_NA_STR_LEN = 72
EID_CID_STR_LEN = 104
EID_CID_NA_STR_LEN = 136
FLAG_ECID_QUERY = 2000
FLAG_CUCKOO_QUERY = 3000
FLAG_DELAY_MEASURE = 9999
burst_size = 2000  # burst_size takes effect when the number of packets sent is greater than 100000 or unlimited


class ShowProcess(object):
    """
    The class that displays the processing progress
    Calling the related functions of this class can realize the display of the processing progress
    """

    # The initialization function needs to know the total number of processing times
    def __init__(self, max_steps):
        self.max_steps = max_steps
        self.max_arrow = 50  # the length of the progress bar
        self.i = 0  # current progress

    # shows: [>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>]100.00%
    def show_process(self, i=None):
        if i is not None:
            self.i = i
        num_arrow = int(self.i * self.max_arrow / self.max_steps)
        num_line = self.max_arrow - num_arrow
        percent = self.i * 100.0 / self.max_steps
        process_bar = '\r' + '[' + '>' * num_arrow + '-' * num_line + ']' + '%.2f' % percent + '%'
        sys.stdout.write(process_bar)
        sys.stdout.flush()
        self.i += 1

    def close(self, words='done'):
        print('')
        print(words)
        self.i = 1


class SEAHash(object):

    def __init__(self, c_lib_path="./lib/lib_sea_eid.so") -> None:
        # check lib_sea_eid.so exist
        try:
            with open(c_lib_path, "rb") as f:
                pass
        except FileNotFoundError:
            print("lib_sea_eid.so not found! Please check the path of lib_sea_eid.so => default: /lib/lib_sea_eid.so")
            sys.exit(1)
        self.lib_eid = CDLL(c_lib_path)

    def get_SEA_Hash_EID(self, uri: str) -> str:
        self.lib_eid.calculate_eid.argtypes = [c_char_p, c_char_p]
        ll = create_string_buffer(20)
        self.lib_eid.calculate_eid(ll, c_char_p(uri.encode("UTF-8")))
        s = "".join([bytes.hex(i) for i in ll])
        return s


def ip2NAStr(ip: str) -> str:
    # Handle IP addresses, discuss IPv6 and IPv4 separately, and return directly if it is already NA_STR
    result = ip
    try:
        ipaddr = ipaddress.ip_address(ip)
        if ipaddr.version == 4:
            result = "0" * 24 + hex(int(ipaddr))[2:].zfill(8)
        elif ipaddr.version == 6:
            result = ipaddr.exploded.replace(":", "")
        return result
    except ValueError:
        return result


def na_to_ip(na_str: str) -> str:
    # Handle NA_STR(32 len hex string) and return IP address
    result = ""
    if na_str == "":
        return result
    if len(na_str) == 32:
        if na_str[0:24] == "0" * 24:
            for i in range(0, 32, 4):
                result += str(int(na_str[i:i + 4], 16)) + "."
            result = result[:-1]
        else:
            for i in range(0, 32, 4):
                result += na_str[i:i + 4] + ":"
            result = result[:-1]
    else:
        result = na_str

    # check if result is a valid ip address
    try:
        result_ip = ipaddress.ip_address(result)
        return str(result_ip.compressed)
    except ValueError:
        # print("NA_STR not a valid IP address!")
        return na_str


def getTimeStamp() -> str:
    # get ms time stamp
    time_stamp = int(time.time() * 1000)
    return hex(time_stamp)[-8:]


def hex_ms_tm_to_real(ms_time_hex: str) -> str:
    # convert ms hex time stamp to real time
    ms_hex_tm_full = "0x" + "189" + ms_time_hex
    ms_hex_tm = int(ms_hex_tm_full, 16)
    real_tm = time.strftime("%Y-%m-%d %H:%M:%S.{}".format(ms_hex_tm % 1000), time.localtime(ms_hex_tm // 1000))
    return real_tm


def getparser():
    parser = argparse.ArgumentParser(description="NMR client python version {}".format(VERSION))
    parser.add_argument('-v', '--version', action="version", version=VERSION, help="Print version.")
    parser.add_argument('-i', '--ip', required=True, type=str, help="IPv4/IPv6 address of NMR node")
    parser.add_argument('-p', '--port', required=True, default=10061, type=int,
                        help="port number of NMR node, "
                             "10061 -> level1; "
                             "10062 -> level2; "
                             "10063 -> level3; "
                             "10090 -> global")
    parser.add_argument('-c', '--command', type=str, default="custom",
                        choices=['r', 'd', 'bd', 'eid', 'tlv', 'rnl', 'rcid', 'ecid', 'dcid', 'dm',
                                 'agent', 'custom', 'gr', 'gd', 'ge', 'gbd', 'gcr', 'gcd', 'gce', 'rcc', 'dcc', 'qcc'],
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
                             "'ge' -> global-resolve; eid global resolve simple; "
                             "'gbd' -> global-batchDeregister;              "
                             "'gcr' -> global-register with cid;            "
                             "'gcd' -> global-deregister with cid;          "
                             "'gce' -> global-resolve with cid;             "
                             "'rcc' -> register for cuckoo filter version   "
                             "'dcc' -> deregister for cuckoo filter version "
                             "'qcc' -> eid query for cuckoo filter version  "
                             "'tlv' -> tlv resolve, use EID: 000...00;      "
                             "'rnl' -> get rnl response from resolve node;  "
                             "'agent' -> get rnl response from server-agent;"
                             "'dm' -> delay measure from client to resolve node;"
                             "'custom' -> user defined payload message, use with parameter -m <msg>;")
    parser.add_argument('-eq', '--EIDQuery', required=False, type=str, metavar="EID(HexStr)",
                        help="resolve self defined EID, use: -eq <EID>")
    parser.add_argument('-ecq', '--EIDCIDQuery', required=False, type=str, nargs='+', metavar="qType/content/g[opt]",
                        help="resolve self defined EID, CID, Tag, "
                             "QueryType:"
                             "0:eid->ip;"
                             "1:eid->cid;"
                             "2:cid->ip;"
                             "3:eid+cid->ip;"
                             "4:tag->eid+cid+ip;"
                             "5:cid->eid}."
                             "use: -ecq <qType> <content>{<EID>,<CID>,<Tag>} <g[opt]>")
    parser.add_argument('-tq', '--TagQuery', required=False, type=str, metavar="TLV(HexStr)",
                        help="resolve self defined Tag, use: -tq <tlv>")
    parser.add_argument('-er', '--EIDRegister', required=False, type=str, nargs='+', metavar=("EID+NA", "TAG(opt)"),
                        help="register self defined EID+NA and optional tag, use: -er <EID+NA> <tag>")
    parser.add_argument('-ecr', '--EIDCIDRegister', required=False, type=str, nargs='+', metavar="content/tag/g[opt]",
                        help="register self defined EID+CID+NA and optional tag, use: -er <EID+CID+NA> <tag> g[opt]")
    parser.add_argument('-ed', '--EIDDeregister', required=False, type=str, metavar="EID+NA",
                        help="deregister self defined EID+NA,  use: -ed <EID+NA>")
    parser.add_argument('-ecd', '--EIDCIDDeregister', required=False, type=str, nargs='+', metavar="content_g[opt]",
                        help="deregister self defined EID+CID+NA,  use: -ecd <EID+CID+NA> g[opt]")
    parser.add_argument('-ebd', '--EIDBatchDeregister', required=False, type=str, metavar="NA",
                        help="Batch-deregister from self defined NA,  use: -ebd <NA>")
    parser.add_argument('-ecbd', '--EIDCIDBatchDeregister', required=False, type=str, metavar="NA",
                        help="EID+CID Batch-deregister from self defined NA,  use: -ecbd <NA>")
    parser.add_argument('-ccr', '--CuckooRegister', required=False, type=str, nargs=2, metavar="URI IP",
                        help="CuckooRegister from self defined URI and NA,  use: -ccr <uri ip>")
    parser.add_argument('-ccd', '--CuckooDeregister', required=False, type=str, nargs=2, metavar="URI IP",
                        help="CuckooDeregister from self defined URI and NA,  use: -ccd <uri ip>")
    parser.add_argument('-ccq', '--CuckooQuery', required=False, type=str, metavar="URI",
                        help="CuckooQuery from self defined URI,  use: -ccq <uri>")
    parser.add_argument('--seq', required=False, action="store_true", default=False,
                        help="register sequence EID from 0 to set number + NA"
                             "Only when there are -n parameters without n=-1 in effect.")
    parser.add_argument('--seqc', required=False, action="store_true", default=False,
                        help="register sequence CID from 0 to set number + NA"
                             "Only when there are -n parameters without n=-1 in effect.")
    parser.add_argument('--seqt', required=False, action="store_true", default=False,
                        help="register sequence with fixed TLV('010101020102')"
                             "Only when there are -n parameters without n=-1 in effect.")
    parser.add_argument('--seqT', required=False, action="store_true", default=False,
                        help="register sequence with Random TLV"
                             "Only when there are -n parameters without n=-1 in effect.")
    parser.add_argument('-n', '--number', required=False, default=1, type=int,
                        help="Number of packets to send. set n = -1 if number is infinite")
    parser.add_argument('-s', '--speed', required=False, default=-1, type=int,
                        help="packets sending speed(pps). Only when there are --force parameters in effect")
    parser.add_argument('--force', required=False, action="store_true", default=False,
                        help="force send message without waiting response, use to increase PPS")
    parser.add_argument('--ranReqID', required=False, action="store_true", default=False,
                        help="Use random requestID when sending multiple message")
    parser.add_argument('--ranAll', required=False, action="store_true", default=False,
                        help="Use random possible fields(EID, CID, NA, ReqID, TLV, ...) when sending multiple message")
    parser.add_argument('-m', '--message', required=False, type=str, metavar="custom message",
                        help="custom packet payload, use as -c custom -m 6f1112121232...")
    parser.add_argument('-d', '--detail', required=False, action="store_true", default=False,
                        help="analyze response message and show detail. (Only has effect in normal mode)")
    parser.add_argument('-b', '--burstSize', required=False, type=int, default=2000,
                        help="The number of concurrent packets. "
                             "Delay adjustment is triggered after each concurrent burst_size of packets. "
                             "(Only has effect when use '-n -1' or '-n 100000+')")
    parser.add_argument('-uh', '--uriHash', required=False, type=str, metavar="SEAHash",
                        help="calculate SEAHash of custom defined URI to EID")
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
        f_time += str(int(h)) + "hour,"
    if t > 60000:
        # min
        m = t // 60000
        t -= m * 60000
        f_time += str(int(m)) + "min,"
    if t > 1000:
        # s
        s = t // 1000
        t -= s * 1000
        f_time += str(int(s)) + "s,"
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


def getRandomHexStr(length: int) -> str:
    """
    :return: return random hexString without "0x"
    """
    s = ""
    for i in range(length):
        num_hex = hex(random.randint(0, 15))
        s = s + num_hex[2:]
    return s


def getRandomEID() -> str:
    """
    :return: return random EID(20 byte hex string, length = 40)
    """
    return getRandomHexStr(40)


def getRandomCID() -> str:
    """
    :return: return random CID(32 byte hex string, length = 64)
    """
    return getRandomHexStr(64)


def getRandomNA() -> str:
    """
    :return: return random NA(16 byte hex string, length = 32)
    """
    return getRandomHexStr(32)


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


def getSequenceCID(end: int = 1):
    """
    :return: return random EID(20 byte hex string, length = 40)
    """
    if end == 1:
        return ["c" * 64]
    cid_list = []
    for i in range(end):
        s = "c" * (64 - len(str(i))) + str(i)
        cid_list.append(s)
    return cid_list


def getRandomTLVStr(tag: str = "03") -> str:
    """
    :return: return random tlv(4 byte tlv_len + tlv)
    """
    _tag = tag
    _len = random.randint(1, 5)
    _val = str(uuid.uuid4())[:_len]
    if len(_val) % 2 != 0:
        _val = "0" + _val
    _lenStr = "0" + str(len(_val) // 2)
    tlv = _tag + _lenStr + _val
    tlv_str = "0" * (4 - len(hex(len(tlv) // 2)[2:])) + hex(len(tlv) // 2)[2:] + tlv
    return tlv_str


def getRandomAllMsg(num: int, command: str):
    print("Get RandomALL message...")
    position = 10  # Mark the starting position of the successful flag bit of the returned message
    msg = []
    if num >= 0:
        process_bar = ShowProcess(num - 1)
        for i in range(num):
            process_bar.show_process()
            time_stamp = getTimeStamp()
            request_id = getRequestID()
            eid = getRandomEID()
            na = getRandomNA()
            tag = getRandomTLVStr()
            cid = getRandomCID()
            if command == "rcc":
                msg.append("6f" + request_id + eid + na + time_stamp)
            elif command == "dcc":
                msg.append("73" + request_id + eid + na + time_stamp)
            elif command == "qcc":
                msg.append("71" + request_id + eid + time_stamp)
            elif command == "r":
                msg.append("6f" + request_id + eid + na + "030100" + time_stamp + tag)
            elif command == "rcid":
                msg.append("6f" + request_id + eid + cid + na + "030100" + time_stamp + tag)
            elif command == "d":
                msg.append("73" + request_id + "00" + eid + na + time_stamp)
            elif command == "dcid":
                msg.append("73" + request_id + "00" + eid + cid + na + time_stamp)
            elif command == "eid":
                msg.append("71" + "000000" + request_id + eid + time_stamp)
            # todo: 暂时不支持 ecid 全随机
            else:
                print("getRandomAllMsg() value error!")
                return
        process_bar.close()
    print("Get getRandomAll message done!")
    return msg, position


def getSequenceMsg(num: int, command: str, extra_num: int):
    print("Get Sequence message...")
    na = "9" * NA_STR_LEN
    eid = "b" * EID_STR_LEN
    cid = "c" * CID_STR_LEN
    eid_list = []
    cid_list = []
    position = 10
    msg = []
    extra_cmd = ""
    if extra_num != 0:
        extra_cmd = command[-extra_num:]
    if num >= 0:
        process_bar = ShowProcess(num - 1)
        if "e" in extra_cmd:
            eid_list = getSequenceEID(num)
        if "c" in extra_cmd:
            cid_list = getSequenceCID(num)
        for i in range(num):
            process_bar.show_process()
            time_stamp = getTimeStamp()
            request_id = getRequestID()
            msg_str = ""
            if command == "re" or command == "registere":
                msg.append("6f" + request_id + eid_list[i] + na + "030100" + time_stamp + "0000")
            elif command == "rT" or command == "registerT":
                msg.append("6f" + request_id + eid + na + "030100" + time_stamp + getRandomTLVStr())
            elif command == 'ret' or command == "registeret":
                msg.append("6f" + request_id + eid_list[i] + na + "030100" + time_stamp + "0006010101020102")
            elif command == 'reT' or command == "registereT":
                msg.append("6f" + request_id + eid_list[i] + na + "030100" + time_stamp + getRandomTLVStr())
            elif command == 'gre':
                msg.append("0b" + request_id + eid_list[i] + na + "010100" + time_stamp + "0000")
            elif command == 'rcce':
                msg.append("6f" + request_id + eid_list[i] + "1" * 32 + time_stamp)
            elif command[:-extra_num] == "rcid":
                eid = eid
                cid = cid
                tlv = "0000"
                if "e" in extra_cmd:
                    eid = eid_list[i]
                if "c" in extra_cmd:
                    cid = cid_list[i]
                if "t" in extra_cmd:
                    tlv = "0006010101020102"
                if "T" in extra_cmd:
                    tlv = getRandomTLVStr()
                msg_str = "6f" + request_id + eid + cid + na + "030100" + time_stamp + tlv
                msg.append(msg_str)
            else:
                print("Warning! Don't support this kind of sequence msg.")
                exit(1)
        process_bar.close()
    print("Get Sequence message done!")
    return msg, position


def getMsg(command: str, content: str = "", num: int = 1, flag_random_reqID: bool = False):
    """
    Judging the corresponding registration, deregistration, resolution, rnl acquisition and other messages
    from the input command, and obtaining a list of messages with random request ids
    :param flag_random_reqID: Whether to use random request id, "False" by default
    :param num: The number of packets to send, "one" is sent by default
    :param content: if command is EIDQuery and EIDRegister, content is EID or EID+NA
    :param command:  user command in string
    :return: (msg_l, p)
             msg_l: request message list;
             p: Returns the starting position of the message flag bit,
             which is used to judge whether the command is executed successfully
    """
    msg_l = []
    position = 0
    flag = not flag_random_reqID  # Whether the flag is a normal message (no random request id required)
    while num != 0:
        msg = ""
        time_stamp = getTimeStamp()
        request_id = getRequestID()
        if command == "register" or command == "r":
            position = 10
            msg = "6f" + request_id + "b" * EID_STR_LEN + "9" * NA_STR_LEN + "030100" + time_stamp + "0006010101020102"
        elif command == "deregister" or command == "d":
            position = 10
            msg = "73" + request_id + "00" + "b" * EID_STR_LEN + "9" * NA_STR_LEN + time_stamp
        elif command == "resolve" or command == "e" or command == "eid":
            position = 2
            msg = "71000000" + request_id + "b" * 40 + time_stamp
        elif command == "resolve+tlv" or command == "tlv":
            position = 2
            msg = "71000006" + request_id + "0" * EID_STR_LEN + time_stamp + "010101020102"
        elif command == "batchDeregister" or command == "batch-deregister" or command == "bd":
            position = 10
            msg = "73" + request_id + "01" + "b" * EID_STR_LEN + "9" * NA_STR_LEN + time_stamp
        elif command == "register_cid" or command == "rcid":
            position = 10
            msg = "6f" + request_id + "b" * EID_STR_LEN + "c" * CID_STR_LEN + "9" * NA_STR_LEN + "030100" + time_stamp + "0000"
        elif command == "deregister_cid" or command == "dcid":
            position = 10
            msg = "73" + request_id + "00" + "b" * EID_STR_LEN + "c" * CID_STR_LEN + "9" * NA_STR_LEN + time_stamp
        elif command == "resolve_cid" or command == "ecid":
            position = FLAG_ECID_QUERY
            msg = "7100000000" + request_id + "b" * EID_STR_LEN + "0" * CID_STR_LEN + time_stamp
        elif command == "globalRegister" or command == "gr":
            position = 10
            msg = "0b" + request_id + "b" * EID_STR_LEN + "9" * NA_STR_LEN + "010100" + time_stamp + "0000"
        elif command == "globalResolve" or command == "ge":
            position = 2
            msg = "0d000000" + request_id + "b" * EID_STR_LEN + time_stamp
        elif command == "globalDeregister" or command == "gd":
            position = 10
            msg = "0f" + request_id + "00" + "b" * EID_STR_LEN + "9" * NA_STR_LEN + time_stamp
        elif command == "globalBatchDeregister" or command == "gbd":
            position = 10
            msg = "0f" + request_id + "01" + "b" * EID_STR_LEN + "9" * NA_STR_LEN + time_stamp
        elif command == "gcr":
            position = 10
            msg = "0b" + request_id + "b" * EID_STR_LEN + "c" * CID_STR_LEN + "9" * NA_STR_LEN + "010100" + time_stamp + "0003010101"
        elif command == "gce":
            position = FLAG_ECID_QUERY
            msg = "0d00000000" + request_id + "b" * EID_STR_LEN + "c" * CID_STR_LEN + time_stamp
        elif command == "gcd":
            position = 10
            msg = "0f" + request_id + "00" + "b" * EID_STR_LEN + "c" * CID_STR_LEN + "9" * NA_STR_LEN + time_stamp
        elif command == "rcc":
            position = 10
            msg = "6f" + request_id + "b" * EID_STR_LEN + "1" * NA_STR_LEN + time_stamp
        elif command == "dcc":
            position = 10
            msg = "73" + request_id + "b" * EID_STR_LEN + "1" * NA_STR_LEN + time_stamp
        elif command == "qcc":
            position = FLAG_CUCKOO_QUERY
            msg = "71" + request_id + "b" * EID_STR_LEN + time_stamp
        elif command == "EIDQuery" or command == "eq":
            position = 2
            msg = "71000000" + request_id + content + time_stamp
        elif command == "EIDCIDQuery" or command == "ecq":
            position = FLAG_ECID_QUERY
            msg_type = content[:2]
            query_type = content[2]
            origin_content = content[3:]
            if query_type == "0" or query_type == "1":
                msg = msg_type + "00" + "0" + query_type + "0000" + request_id + origin_content + "0" * CID_STR_LEN + time_stamp
            elif query_type == "2":
                msg = msg_type + "00" + "02" + "0000" + request_id + "0" * EID_STR_LEN + origin_content + time_stamp
            elif query_type == "3":
                msg = msg_type + "00" + "03" + "0000" + request_id + origin_content + time_stamp
            elif query_type == "4":
                tlv_len = hex(int(len(origin_content) / 2))[2:]
                tlv_len_str = "0" * (4 - len(tlv_len)) + tlv_len
                msg = msg_type + "00" + "04" + tlv_len_str + request_id + "0" * EID_CID_STR_LEN + time_stamp + origin_content
            elif query_type == "5":
                msg = msg_type + "00" + "05" + "0000" + request_id + "0" * EID_STR_LEN + origin_content + time_stamp
        elif command == "TagQuery" or command == "tq":
            tlv_len = hex(int(len(content) / 2))[2:]
            tlv_len_str = "0" * (4 - len(tlv_len)) + tlv_len
            position = 2
            msg = "7100" + tlv_len_str + request_id + "0" * EID_STR_LEN + time_stamp + content
        elif command == "CuckooRegister" or command == "ccr":
            position = 10
            msg = "6f" + request_id + content + time_stamp
        elif command == "CuckooDeregister" or command == "ccd":
            position = 10
            msg = "73" + request_id + content + time_stamp
        elif command == "CuckooQuery" or command == "ccq":
            position = FLAG_CUCKOO_QUERY
            msg = "71" + request_id + content + time_stamp
        elif command == "EIDRegister" or command == "er":
            eid_na = content[:EID_NA_STR_LEN]
            tlv = content[EID_NA_STR_LEN:]
            tlv_len = hex(int(len(tlv) / 2))[2:]
            tlv_len_str = "0" * (4 - len(tlv_len)) + tlv_len
            position = 10
            msg = "6f" + request_id + eid_na + "030100" + time_stamp + tlv_len_str + tlv
        elif command == "EIDCIDRegister" or command == "ecr":
            msg_type = content[:2]
            eid_cid_na = content[2:EID_CID_NA_STR_LEN + 2]
            tlv = content[2 + EID_CID_NA_STR_LEN:]
            tlv_len = hex(int(len(tlv) / 2))[2:]
            tlv_len_str = "0" * (4 - len(tlv_len)) + tlv_len
            position = 10
            msg = msg_type + request_id + eid_cid_na + "030100" + time_stamp + tlv_len_str + tlv
        elif command == "EIDDeregister" or command == "ed":
            position = 10
            msg = "73" + request_id + "00" + content + time_stamp
        elif command == "EIDCIDDeregister" or command == "ecd":
            msg_type = content[:2]
            position = 10
            msg = msg_type + request_id + "00" + content[2:] + time_stamp
        elif command == "EIDBatchDeregister" or command == "ebd":
            position = 10
            msg = "73" + request_id + "01" + "b" * EID_STR_LEN + content + time_stamp
        elif command == "EIDCIDBatchDeregister" or command == "ecbd":
            position = 10
            msg = "73" + request_id + "01" + "b" * EID_CID_STR_LEN + content + time_stamp
        elif command == "rnl":
            position = 10
            msg = "0d" + request_id + time_stamp
        elif command == "connect" or command == "agent":
            position = 10
            msg = "1d" + request_id + time_stamp
        elif command == "dm" or command == "delay-measure":
            msg = "03" + time_stamp
            position = FLAG_DELAY_MEASURE
        else:
            msg = ""
        if flag or num < 0:
            return msg, position
        if msg != "":
            msg_l.append(msg)
        num -= 1
    return msg_l, position


def show_details(receive_message: str):
    # Registration Response Message
    if receive_message[:2] == "70" or receive_message[:2] == "0c":
        request_id = receive_message[2:10]
        status_dict = {"01": "registered_successful", "02": "parameter_error", "03": "internal_error",
                       "04": "storage_is_full", "05": "other_errors"}
        status = status_dict[receive_message[10:12]]
        time_stamp = hex_ms_tm_to_real(receive_message[12:20])
        print("=== response details ===:\n[request_id]: {}, [register status]: {}, [timestamp]: {}".format(request_id,
                                                                                                           status,
                                                                                                           time_stamp))
    # Deregistration Response Message
    elif receive_message[:2] == "74" or receive_message[:2] == "10":
        request_id = receive_message[2:10]
        status_dict = {"01": "delete_successful", "02": "parameter_error", "03": "internal_error",
                       "04": "storage_is_full", "05": "other_errors"}
        status = status_dict[receive_message[10:12]]
        time_stamp = hex_ms_tm_to_real(receive_message[12:20])
        print("=== response details ===:\n[request_id]: {}, [deregister status]: {}, [timestamp]: {}".format(request_id,
                                                                                                             status,
                                                                                                             time_stamp))
    # Resolution Response Message
    elif receive_message[:2] == "72":
        status_dict = {"01": "resolve_successful", "00": "resolve_failed"}
        status = status_dict[receive_message[2:4]]
        request_id = receive_message[8:16]
        time_stamp = hex_ms_tm_to_real(receive_message[16:24])
        num = int(receive_message[24:28], 16)
        index = 28
        print("=== response details ===:\n[request_id]: {}, [resolve status]: {}, [timestamp]: {}".format(request_id,
                                                                                                          status,
                                                                                                          time_stamp))
        print("[resolving_entry_number]: {}".format(num))
        for i in range(num):
            eid = receive_message[index:index + 40]
            na = receive_message[index + 40:index + 72]
            print("[{}] EID: {}, NA: {}".format(i, eid, na_to_ip(na)))
            index += 72

    # RNL Response Message - Client
    elif receive_message[:2] == "1e":
        request_id = receive_message[2:10]
        status_dict = {"01": "get_rnl_successful", "00": "get_rnl_failed"}
        status = status_dict[receive_message[10:12]]
        global_resolution_addr = receive_message[12:44]
        log_collection_system_addr = receive_message[44:76]
        # Resolution delay
        delay_level_number = int(receive_message[76:78], 16)
        level_delay_list = []
        p = 78
        for i in range(delay_level_number):
            level_delay_list.append((int(receive_message[p:p + 2], 16), int(receive_message[p + 2:p + 4], 16)))
            p += 4
        resolve_node_number = int(receive_message[p:p + 2])
        p += 2
        resolve_node_list = []
        for i in range(resolve_node_number):
            resolve_node_list.append((receive_message[p:p + 8], receive_message[p + 8:p + 40],
                                      int(receive_message[p + 40:p + 42], 16), receive_message[p + 42:p + 44]))
            p += 44
        child_node_number = int(receive_message[p:p + 2], 16)
        p += 2
        child_node_list = []
        for i in range(child_node_number):
            child_node_list.append((receive_message[p:p + 8], receive_message[p + 8:p + 40],
                                    int(receive_message[p + 40:p + 42], 16), receive_message[p + 42:p + 44]))
            p += 44
        # delay_neighbor_node
        delay_neighbor_node_number = int(receive_message[p:p + 2], 16)
        p += 2
        delay_neighbor_node_list = []
        for i in range(delay_neighbor_node_number):
            delay_neighbor_node_list.append((receive_message[p:p + 8], receive_message[p + 8:p + 40],
                                             int(receive_message[p + 40:p + 42], 16), receive_message[p + 42:p + 44]))
            p += 44
        # geo_neighbor_node
        geo_neighbor_node_number = int(receive_message[p:p + 2], 16)
        p += 2
        geo_neighbor_node_list = []
        for i in range(geo_neighbor_node_number):
            geo_neighbor_node_list.append((receive_message[p:p + 8], receive_message[p + 8:p + 40],
                                           int(receive_message[p + 40:p + 42], 16), receive_message[p + 42:p + 44]))
            p += 44
        # index_neighbor_node
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

    # RNL Response Message - Agent
    elif receive_message[:2] == "0e":
        request_id = receive_message[2:10]
        status_dict = {"01": "get_rnl_successful", "00": "get_rnl_failed"}
        status = status_dict[receive_message[10:12]]
        delay_level_number = int(receive_message[12:14], 16)
        level_delay_list = []
        p = 14
        for i in range(delay_level_number):
            level_delay_list.append((int(receive_message[p:p + 2], 16), int(receive_message[p + 2:p + 4], 16)))
            p += 4
        resolve_node_number = int(receive_message[p:p + 2])
        p += 2
        resolve_node_list = []
        for i in range(resolve_node_number):
            resolve_node_list.append((receive_message[p:p + 8], receive_message[p + 8:p + 40],
                                      int(receive_message[p + 40:p + 42], 16), receive_message[p + 42:p + 44]))
            p += 44
        child_node_number = int(receive_message[p:p + 2], 16)
        p += 2
        child_node_list = []
        for i in range(child_node_number):
            child_node_list.append((receive_message[p:p + 8], receive_message[p + 8:p + 40],
                                    int(receive_message[p + 40:p + 42], 16), receive_message[p + 42:p + 44]))
            p += 44
        time_stamp = hex_ms_tm_to_real(receive_message[p:p + 8])
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
    # eid+cid resolve response message
    if receive_message[:2] not in ("72", "0e"):
        return
    status_dict = {"01": "resolve_successful", "00": "resolve_failed"}
    content_len_dict = {"00": EID_NA_STR_LEN, "01": EID_CID_STR_LEN, "02": CID_NA_STR_LEN, "03": EID_CID_NA_STR_LEN,
                        "04": EID_CID_NA_STR_LEN, "05": EID_CID_STR_LEN}
    status = status_dict[receive_message[2:4]]
    query_type = receive_message[4:6]
    try:
        content_length = content_len_dict[query_type]
    except KeyError:
        print("ERROR! Unknown queryType")
    request_id = receive_message[10:18]
    time_stamp = hex_ms_tm_to_real(receive_message[18:26])
    num = int(receive_message[26:30], 16)
    index = 30
    print("=== response details ===:\n[request_id]: {}, [resolve status]: {}, [timestamp]: {}".format(request_id,
                                                                                                      status,
                                                                                                      time_stamp))
    print("[resolving_entry_number]: {}".format(num))
    if query_type == "00":
        for i in range(num):
            eid = receive_message[index:index + EID_STR_LEN]
            na = na_to_ip(receive_message[index + EID_STR_LEN:index + EID_NA_STR_LEN])
            print("[{}] EID: {}, NA: {}".format(i, eid, na))
            index += EID_NA_STR_LEN
    elif query_type == "01":
        for i in range(num):
            eid = receive_message[index:index + EID_STR_LEN]
            cid = receive_message[index + EID_STR_LEN:index + EID_CID_STR_LEN]
            print("[{}] EID: {}, CID: {}".format(i, eid, cid))
            index += EID_CID_STR_LEN
    elif query_type == "02":
        for i in range(num):
            cid = receive_message[index:index + CID_STR_LEN]
            na = na_to_ip(receive_message[index + CID_STR_LEN:index + CID_NA_STR_LEN])
            print("[{}] CID: {}, NA: {}".format(i, cid, na))
            index += EID_CID_STR_LEN
    elif query_type == "03" or query_type == "04":
        for i in range(num):
            eid = receive_message[index:index + EID_STR_LEN]
            cid = receive_message[index + EID_STR_LEN:index + EID_CID_STR_LEN]
            na = na_to_ip(receive_message[index + EID_CID_STR_LEN:index + EID_CID_NA_STR_LEN])
            print("[{}] EID: {}, CID: {}, NA: {}".format(i, eid, cid, na))
            index += EID_CID_NA_STR_LEN
    elif query_type == "05":
        for i in range(num):
            cid = receive_message[index:index + CID_STR_LEN]
            eid = receive_message[index + CID_STR_LEN:index + EID_STR_LEN]
            print("[{}] CID: {}, EID: {}".format(i, cid, eid))
            index += EID_CID_STR_LEN


def show_details_cc_query(receive_message: str):
    # cuckoo filter based query response message
    if receive_message[:2] == "72":
        request_id = receive_message[2:10]
        status_dict = {"01": "resolve_successful", "00": "resolve_failed"}
        status = status_dict[receive_message[10:12]]
        time_stamp = hex_ms_tm_to_real(receive_message[12:20])
        num = int(receive_message[20:22], 16)
        index = 22
        print("=== response details ===:\n[request_id]: {}, [resolve status]: {}, [timestamp]: {}".format(request_id,
                                                                                                          status,
                                                                                                          time_stamp))
        print("[resolving_entry_number]: {}".format(num))
        for i in range(num):
            eid = receive_message[index:index + EID_STR_LEN]
            na = na_to_ip(receive_message[index + EID_STR_LEN:index + EID_NA_STR_LEN])
            print("[{}] EID: {}, NA: {}".format(i, eid, na))
            index += 72


def run():
    parser = getparser()
    args = parser.parse_args()
    ip = args.ip
    port = args.port
    address = (ip, port)
    family = checkIP(ip)  # check IPv4/IPv6
    command = args.command
    inf_flag = False
    number = args.number
    speed = args.speed
    burst_size = args.burstSize
    flag_random_request_id = args.ranReqID

    if args.uriHash is not None:
        seahash = SEAHash()
        eid = seahash.get_SEA_Hash_EID(args.uriHash)
        print('[SEAHash] uri: "{}", EID: {}'.format(args.uriHash, eid))
        return

    elif args.EIDQuery is not None:
        eid = args.EIDQuery
        if len(eid) != EID_STR_LEN:
            print("EID length error!")
            return
        msg, p = getMsg("EIDQuery", eid, number, flag_random_request_id)

    elif args.EIDCIDQuery is not None:
        m_type = "71"
        if len(args.EIDCIDQuery) == 3 and args.EIDCIDQuery[2] == 'g':
            m_type = "0d"
        query_type = args.EIDCIDQuery[0]
        content = args.EIDCIDQuery[1]
        if ((query_type == "0" or query_type == "1") and len(content) == EID_STR_LEN) \
                or (query_type == "2" and len(content) == CID_STR_LEN) \
                or (query_type == "5" and len(content) == CID_STR_LEN) \
                or (query_type == "3" and len(content) == EID_CID_STR_LEN) \
                or (query_type == "4"):
            content = m_type + query_type + content
        else:
            print("invalid input <EID>/<CID>/<TAG> length error!")
            return
        msg, p = getMsg("EIDCIDQuery", content, number, flag_random_request_id)

    elif args.TagQuery is not None:
        tlv_msg = args.TagQuery
        msg, p = getMsg("TagQuery", tlv_msg, number, flag_random_request_id)

    elif args.EIDRegister is not None:
        if len(args.EIDRegister) > 1:
            eidna = args.EIDRegister[0]
            tag = args.EIDRegister[1]
        else:
            eidna = args.EIDRegister[0]
            tag = ""
        if len(eidna) != EID_NA_STR_LEN:
            print("EID+NA length error! Should be EID(40 hexStr) + NA(32 hexStr)")
            return
        msg, p = getMsg("EIDRegister", eidna + tag, number, flag_random_request_id)

    elif args.EIDCIDRegister is not None:
        m_type = "6f"
        argc = len(args.EIDCIDRegister)
        if args.EIDCIDRegister[argc - 1] == 'g':
            m_type = "0b"
            argc -= 1
        if argc > 1:
            eidcidna = args.EIDCIDRegister[0]
            tag = args.EIDCIDRegister[1]
        else:
            eidcidna = args.EIDCIDRegister[0]
            tag = ""
        if len(eidcidna) != EID_CID_NA_STR_LEN:
            print("EID+CID+NA length error! Should be EID(40 hexStr) + CID(64 hexStr) + NA(32 hexStr)")
            return
        msg, p = getMsg("EIDCIDRegister", m_type + eidcidna + tag, number, flag_random_request_id)

    elif args.EIDDeregister is not None:
        eidna = args.EIDDeregister
        if len(eidna) != EID_NA_STR_LEN:
            print("EID+NA length error!")
            return
        msg, p = getMsg("EIDDeregister", eidna, number, flag_random_request_id)

    elif args.EIDCIDDeregister is not None:
        argc = len(args.EIDCIDDeregister)
        m_type = "73"
        if argc == 2 and args.EIDCIDDeregister[1] == 'g':
            m_type = "0f"
            argc -= 1
        eidcidna = args.EIDCIDDeregister[0]
        if len(eidcidna) != EID_CID_NA_STR_LEN:
            print("EID+CID+NA length error! Should be EID(40 hexStr) + CID(64 hexStr) + NA(32 hexStr)")
            return
        msg, p = getMsg("EIDCIDDeregister", m_type + eidcidna, number, flag_random_request_id)

    elif args.EIDBatchDeregister is not None:
        na = args.EIDBatchDeregister
        if len(na) != 32:
            print("NA length error!")
            return
        msg, p = getMsg("EIDBatchDeregister", na)

    elif args.EIDCIDBatchDeregister is not None:
        na = args.EIDCIDBatchDeregister
        if len(na) != 32:
            print("NA length error!")
            return
        msg, p = getMsg("EIDCIDBatchDeregister", na)

    elif args.CuckooRegister is not None:
        seahash = SEAHash()
        uri = args.CuckooRegister[0]
        ip = args.CuckooRegister[1]
        eidna = seahash.get_SEA_Hash_EID(uri) + ip2NAStr(ip)
        if len(eidna) != EID_NA_STR_LEN:
            print("EID+NA length error!")
            return
        msg, p = getMsg("CuckooRegister", eidna, number, flag_random_request_id)

    elif args.CuckooDeregister is not None:
        seahash = SEAHash()
        uri = args.CuckooDeregister[0]
        ip = args.CuckooDeregister[1]
        eidna = seahash.get_SEA_Hash_EID(uri) + ip2NAStr(ip)
        if len(eidna) != EID_NA_STR_LEN:
            print("EID+NA length error!")
            return
        msg, p = getMsg("CuckooDeregister", eidna, number, flag_random_request_id)

    elif args.CuckooQuery is not None:
        seahash = SEAHash()
        uri = args.CuckooQuery
        eid = seahash.get_SEA_Hash_EID(uri)
        if len(eid) != EID_STR_LEN:
            print("EID length error!")
            return
        msg, p = getMsg("CuckooQuery", eid, number, flag_random_request_id)

    else:
        # batch register only for eid like: bbb...bb19210
        extra_cm_num = 0
        if args.ranAll:
            msg, p = getRandomAllMsg(number, command)
        elif command in ('r', 'gr', 'register', 'rcid', 'rcc'):
            if args.seq:
                command += "e"
                extra_cm_num += 1
            if args.seqc:
                command += "c"
                extra_cm_num += 1
            if args.seqt:
                command += "t"
                extra_cm_num += 1
            elif args.seqT:
                command += "T"
                extra_cm_num += 1
            if extra_cm_num == 0:
                msg, p = getMsg(command, "", number, flag_random_request_id)
            else:
                msg, p = getSequenceMsg(args.number, command, extra_cm_num)
        elif command == "custom":
            msg = args.message
            if msg is None:
                print("Custom message is empty, please add '-m <msg>'")
                return
            p = 0
        else:
            msg, p = getMsg(command, "", number, flag_random_request_id)
    if msg == "" or len(msg) == 0:
        print("Getting message is none!")
        return

    s = socket.socket(family, socket.SOCK_DGRAM)
    s.settimeout(3)
    if number < 0:
        inf_flag = True
    start_msg_send_time = time.time()
    while not inf_flag:
        # send batch of packets
        last_check_time = start_msg_send_time
        for i in range(number):
            send_time_stamp = time.time()
            if type(msg) == str:
                s.sendto(bytes.fromhex(msg), address)
            else:
                s.sendto(bytes.fromhex(msg[i]), address)
            if args.force:
                if speed > 0:
                    # If bz is not set within 100000 packets, the delay will be adjusted every 20 packets, 20 times in total.
                    if number < 100000 and burst_size == 2000:
                        if i != 0 and i % (number // 20) == 0:
                            sleep_time = (number // 20) / speed - (time.time() - last_check_time)
                            if sleep_time > 0:
                                time.sleep(sleep_time)
                            last_check_time = time.time()
                    else:
                        # For more than 100,000 packets, the delay is adjusted once every burst size, number/burst_size times in total.
                        if i != 0 and i % burst_size == 0:
                            sleep_time = burst_size / speed - (time.time() - last_check_time)
                            if sleep_time > 0:
                                time.sleep(sleep_time)
                            last_check_time = time.time()
                # Print the current packet sending rate
                if i != 0 and number <= 10000 and i % (number // 5) == 0:
                    delay = round((time.time() - start_msg_send_time) * 1000, 3)
                    pps = int(i / delay * 1000)
                    print("Already send " + str(i) + " packets, use: " + formatTime(delay) + " , pps: " + str(pps))
                elif i != 0 and number <= 100000 and i % (number // 10) == 0:
                    delay = round((time.time() - start_msg_send_time) * 1000, 3)
                    pps = int(i / delay * 1000)
                    print("Already send " + str(i) + " packets, use: " + formatTime(delay) + " , pps: " + str(pps))
                elif i != 0 and i % 20000 == 0:
                    delay = round((time.time() - start_msg_send_time) * 1000, 3)
                    pps = int(i / delay * 1000)
                    print("Already send " + str(i) + " packets, use: " + formatTime(delay) + " , pps: " + str(pps))
                continue
            try:
                recv, addr = s.recvfrom(1024)
                delay = round((time.time() - send_time_stamp) * 1000, 3)
                if p == 0 or p == FLAG_DELAY_MEASURE:
                    is_success = "success"
                elif p == FLAG_ECID_QUERY:
                    is_success = "success" if recv.hex()[2:4] == "01" else "failed"
                elif p == FLAG_CUCKOO_QUERY:
                    is_success = "success" if recv.hex()[10:12] == "01" else "failed"
                else:
                    is_success = "success" if recv.hex()[p:p + 2] == "01" else "failed"
                if p == FLAG_DELAY_MEASURE:
                    print("receive delay measure response msg, status: " + is_success + ", delay: " + str(delay) + "ms")
                else:
                    print("receive msg from " + str(addr[:2]) + " : " + recv.hex() + ", status: " + is_success)
                    if args.detail:
                        if p == FLAG_ECID_QUERY:
                            show_details_ecid(recv.hex())
                        elif p == FLAG_CUCKOO_QUERY:
                            show_details_cc_query(recv.hex())
                        else:
                            show_details(recv.hex())
            except socket.timeout:
                print("Can't receive msg! Socket timeout")
        break
    else:
        # Send packets continuously in a loop
        if type(msg) != str:
            print('Error! "random requestID mode" / "sequence EID mode" only supported in limited packet numbers.')
            return
        count = 0
        last_check_time = start_msg_send_time
        while True:
            s.sendto(bytes.fromhex(msg), address)
            count += 1
            if args.force:
                if speed > 0 and count % burst_size == 0:
                    sleep_time = burst_size / speed - (time.time() - last_check_time)
                    if sleep_time > 0:
                        time.sleep(sleep_time)
                    last_check_time = time.time()
                if count % (speed * 3) == 0:
                    delay = round((time.time() - start_msg_send_time) * 1000, 3)
                    pps = int(count / delay * 1000)
                    print("Already send " + str(count) + " packets, use: " + formatTime(delay) + " , pps: " + str(pps))
                continue
            try:
                recv, addr = s.recvfrom(1024)
                if p != 0 and p != 9999:
                    is_success = "success" if recv.hex()[p:p + 2] == "01" else "failed"
                    print("receive msg from " + str(addr[:2]) + " : " + recv.hex() + ", status: " + is_success)
                else:
                    print("receive delay measure response msg, status: success")
            except socket.timeout:
                print("Can't receive msg! Socket timeout")
    if args.force:
        delay = round((time.time() - start_msg_send_time) * 1000, 3)
        print("send " + str(number) + " packets successful, total use: " + str(delay) + "ms, pps: " +
              str(int(number / delay * 1000)))
    s.close()


if __name__ == '__main__':
    run()
