#! /usr/bin/python3
"""
By mzl 2021.06.23 version 1.0
Used to Analyze pcap files.
"""

from queue import Queue

import yaml
from scapy.all import *


def readConf2Yml(path: str):
    with open(path, 'r') as f:
        return yaml.load(f.read(), Loader=yaml.FullLoader)


def getPacketTypeFromPacket(pkt_item):
    """
    get requestID field from different kinds of resolve packets.
    :param pkt_item: packet item resolve from scapy
    :return: packetType
    """
    if pkt_item.haslayer("UDP"):
        payload = pkt_item["UDP"].payload.original.hex()
        return payload[:2]
    return None


def getRequestIDFromPacket(pkt_item):
    """
    get requestID field from different kinds of resolve packets.
    :param pkt_item: packet item resolve from scapy
    :return: String of requestID
    """
    if pkt_item.haslayer("UDP"):
        payload = pkt_item["UDP"].payload.original.hex()
        return getRequestID(payload)
    return None


def getRequestID(payload: str):
    if payload[:2] == "71" or payload[:2] == "72":
        return payload[8:16]
    elif payload[:2] in ("6f", "70", "73", "74"):
        return payload[4:12]
    else:
        return None


def analyzeDelay(delay_list: list, time_out: int):
    n = len(delay_list)
    max_delay = max(delay_list)
    min_delay = min(delay_list)
    total = 0.0
    timeout_n = 0
    for dl in delay_list:
        total += dl
        if dl > time_out:
            timeout_n += 1
    average_delay = total / n
    print("packet-pair number: {}, min_delay: {}ms, max_delay: {}ms, average_delay: {}ms, timeout_n: {}"
          .format(n, min_delay, max_delay, average_delay, timeout_n))
    return average_delay


def run():
    yml = readConf2Yml("conf.yaml")
    timeout = yml["TIME_OUT"]
    packets = rdpcap(sys.argv[1])
    pkt_pair_time_dict = defaultdict(Queue)  # key: requestID； value: a queue of timestamp
    delay_l = []  # store each delay value of packet-pair
    for pkt in packets:
        pkt_type = getPacketTypeFromPacket(pkt)
        requestID = getRequestIDFromPacket(pkt)
        # 如果是请求报文，将requestID和对应的时间戳加入字典中
        if pkt_type in ("6f", "71", "73"):
            if requestID is not None:
                pkt_pair_time_dict[requestID].put(pkt.time)
        # 如果是响应报文，将对应的requestID和时间戳取出计算时延
        if pkt_type in ("70", "72", "74"):
            if requestID is not None:
                delay = 1000 * (pkt.time - pkt_pair_time_dict.get(requestID).get())  # delay: ms
                delay_l.append(delay)
                pkt_pair_time_dict.pop(requestID)
    analyzeDelay(delay_l, timeout)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("use this script: python3 pktAnalyzer.py <test.pcap>")
        exit(0)
    run()
