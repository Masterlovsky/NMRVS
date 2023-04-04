#! /usr/bin/python3
# -*- coding: utf-8 -*-
"""
This script is a simple server for the Enhanced Name Resolution System.
Only for client functionally testing. Not for production use and performance.
Powered by Masterlovsky, 2023.04.01. Version 0.1.0
"""
import signal
import sys
import socket
import threading
from collections import defaultdict
import time

VERSION = "0.1.0"
# define packet header
REGISTER_REQUEST = "6f"
REGISTER_RESPONSE = "70"
QUERY_REQUEST = "71"
QUERY_RESPONSE = "72"
DEREGISTER_REQUEST = "73"
DEREGISTER_RESPONSE = "74"
# create dict for EID(str) -> NA(set)
EID2NA = defaultdict(set)
CID2NA = defaultdict(set)
EID2CID = defaultdict(set)
ECID2NA = defaultdict(set)
CID2EID = defaultdict(set)


# todo: create dict for tag query

def get_ms_timestamp_str():
    # 8 len hex string
    return hex(int(time.time() * 1000))[-8:]


def get_req_type(req):
    return req[0:2]


def check_is_IP6(IP):
    # check if IP is ipv6
    return ":" in IP


def handle_register_request(req):
    # req packet: "6f" + request_id(4 bytes) + EID(20 bytes) + CID(32 bytes) + NA(16 bytes) + latency(1 byte) + ttl(1 bytes) + mflag(1 byte) + timestamp(4 bytes) + tlv_len(2 bytes) + tlv(0-1024 bytes)
    # resp packet: "70" + request_id(4 bytes) + status(1 byte) + timestamp(4 bytes)
    request_id = req[2:10]
    eid = req[10:50]
    cid = req[50:114]
    na = req[114:146]
    if eid != "0" * 40:
        EID2NA[eid].add(na)
    if cid != "0" * 64:
        CID2NA[cid].add(na)
    if eid != "0" * 40 and cid != "0" * 64:
        EID2CID[eid].add(cid)
        CID2EID[cid].add(eid)
        ECID2NA[eid + cid].add(na)
    status = "01"
    timestamp = get_ms_timestamp_str()
    resp = REGISTER_RESPONSE + request_id + status + timestamp
    return bytes.fromhex(resp)


def handle_resolve_request(req):
    # req packet: "71" + remote(1 byte) + query_type(1 byte) + length(2 bytes) + request_id(4 bytes) + EID(20 bytes) + CID(32 bytes) + timestamp(4 bytes) + tlv(0-1024 bytes)
    # resp packet: "72" + status(1 byte) + + query_type(1 byte) + format(1 byte) + more(1 byte) + request_id(4 bytes) + timestamp(4 bytes) + num(2 bytes) + E_C_NA
    request_id = req[10:18]
    query_type = req[4:6]
    status = "01"
    timestamp = get_ms_timestamp_str()
    eid = req[18:58]
    cid = req[58:122]
    resp = QUERY_RESPONSE + status + query_type + "01" + "00" + request_id + timestamp
    if query_type == "00":
        # EID -> NA
        res_list = EID2NA[eid]
        num = ("0000" + hex(len(res_list))[2:])[-4:]
        resp += num
        for na in res_list:
            resp += eid + na
    elif query_type == "01":
        # EID -> CID
        res_list = EID2CID[eid]
        num = ("0000" + hex(len(res_list))[2:])[-4:]
        resp += num
        for cid in res_list:
            resp += eid + cid
    elif query_type == "02":
        # CID -> NA
        res_list = CID2NA[cid]
        num = ("0000" + hex(len(res_list))[2:])[-4:]
        resp += num
        for na in res_list:
            resp += cid + na
    elif query_type == "03":
        # EID + CID -> NA
        res_list = ECID2NA[eid + cid]
        num = ("0000" + hex(len(res_list))[2:])[-4:]
        resp += num
        for na in res_list:
            resp += eid + cid + na
    elif query_type == "05":
        # CID -> EID
        res_list = CID2EID[cid]
        num = ("0000" + hex(len(res_list))[2:])[-4:]
        resp += num
        for eid in res_list:
            resp += cid + eid
    else:
        print("Error: unknown query type")
    return bytes.fromhex(resp)


def handle_deregister_request(req):
    # req packet: "73" + request_id(4 bytes) + pad(1 byte) + EID(20 bytes) + CID(32 bytes) + NA(16 bytes) + timestamp(4 bytes)
    # resp packet: "74" + request_id(4 bytes) + status(1 byte) + timestamp(4 bytes)
    request_id = req[2:10]
    pad = req[10:12]
    eid = req[12:52]
    cid = req[52:116]
    na = req[116:148]
    if pad == "00":
        EID2NA[eid].remove(na)
    elif pad == "01":
        # get all eid with na in na_list
        for eid in EID2NA:
            if na in EID2NA[eid]:
                EID2NA[eid].remove(na)
    status = "01"
    timestamp = get_ms_timestamp_str()
    resp = DEREGISTER_RESPONSE + request_id + status + timestamp
    return bytes.fromhex(resp)


class UDP_SERVER(object):

    def __init__(self, ip, port):
        if check_is_IP6(IP):
            self.server = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        else:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server.bind((IP, PORT))
        self.server.settimeout(5)
        self.running = True

    def start(self):
        print("IRS Server started at %s:%s" % (IP, PORT))
        while self.running:
            try:
                data, addr = self.server.recvfrom(1024)
                print("Received data from %s:%s" % (addr[0], addr[1]))
                print("Data: %s" % data.hex())
                thread = threading.Thread(target=self.process_packet, args=(data.hex(), addr))
                thread.start()
            except socket.timeout:
                pass
            except Exception as e:
                print("Error: %s" % e)
                self.running = False
        self.server.close()

    def process_packet(self, data, addr):
        req_type = get_req_type(data)
        if req_type == REGISTER_REQUEST:
            resp = handle_register_request(data)
            self.server.sendto(resp, addr)
        elif req_type == QUERY_REQUEST:
            resp = handle_resolve_request(data)
            self.server.sendto(resp, addr)
        elif req_type == DEREGISTER_REQUEST:
            resp = handle_deregister_request(data)
            self.server.sendto(resp, addr)
        else:
            print("Unknown request type.")

    def close(self):
        self.running = False
        print("IRS Server stopped.")


def _test():
    # test ---------------
    test_register = "6f34653039bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" + "c" * 64 + "99999999999999999999999999999999030100d79df05b0006010101020102"
    test_req = "710000000011111111" + "b" * 40 + "c" * 64 + get_ms_timestamp_str()
    print(handle_register_request(test_register).hex())
    print(handle_resolve_request(test_req).hex())


def signal_handler(sig, frame):
    print("Signal {} cached, Stop server...".format(signal))
    server.close()
    sys.exit(0)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python3 %s <IP> <PORT>" % sys.argv[0])
        sys.exit(1)
    # handle signal to stop server
    signal.signal(signal.SIGINT, signal_handler)
    IP, PORT = sys.argv[1], int(sys.argv[2])
    server = UDP_SERVER(IP, PORT)
    server.start()
