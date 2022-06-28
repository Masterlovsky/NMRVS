from scapy.all import *
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether

from client import ShowProcess


class IDP(Packet):
    name = "IDP Packet"
    fields_desc = [ByteField("nextHeader", 0x10),

                   ByteField("EID_Type", 0),
                   ShortField("reserved", 1),
                   XNBytesField("sourceEID", int("0" * 40, 16), 20),
                   XNBytesField("destEID", int("a" * 40, 16), 20),
                   ]


class IDPNRS(Packet):
    name = "IDP_NRS Packet"
    fields_desc = [ByteField("nextHeader", 0x01),

                   ByteEnumField("queryType", 0x01, {0x01: "register", 0x02: "deregister", 0x03: "register_resp",
                                                     0x04: "deregister_resp", 0x05: "resolve", 0x06: "resolve_w"}),
                   ByteField("BGPType", 0),
                   ByteEnumField("source", 0, {0: "format1", 1: "format2"}),
                   XNBytesField("na", int("0" * 32, 16), 16),
                   ]


def packet_creator(command: str, eid="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", dmac="A4:23:05:00:11:00"):
    # ! 模拟客户端给 controller 发包
    if command == "r":
        payload_register = "6f" + eid + ipv6ToHexString(USER_NA)
        pkt_r = Ether(dst=dmac) / IPv6(nh=0x99, src=USER_NA, dst="::") / IDP(
            destEID=int("0" * 40, 16)) / IDPNRS(queryType="register") / bytes.fromhex(payload_register)
        ret_pkt = pkt_r
    elif command == "eq":
        pkt_eq = Ether(dst=dmac) / IPv6(nh=0x99, src=USER_NA, dst="::") / IDP(
            destEID=int(eid, 16)) / IDPNRS(queryType="resolve")
        ret_pkt = pkt_eq
    elif command == "d":
        payload_deregister = "73" + eid + ipv6ToHexString(USER_NA)
        pkt_d = Ether(dst=dmac) / IPv6(nh=0x99, src=USER_NA, dst="::") / IDP(
            destEID=int("0" * 40, 16)) / IDPNRS(queryType="deregister") / bytes.fromhex(payload_deregister)
        ret_pkt = pkt_d

    # ! 模拟controller给bgp发包
    elif command == "br":
        payload_bgp_register = "6f" + eid + ipv6ToHexString(USER_NA) + ipv6ToHexString(
            CONTROLLER_NA) + "00000001" + ipv6ToHexString(BGP_NA)
        pkt_bgp_r = Ether(dst=dmac) / IPv6(nh=0x99, src=USER_NA, dst="::") / IDP(
            destEID=int("0" * 40, 16)) / IDPNRS(queryType="register") / bytes.fromhex(payload_bgp_register)
        ret_pkt = pkt_bgp_r
    elif command == "beq":
        pkt_bgp_eq = Ether(dst=dmac) / IPv6(nh=0x99, src=USER_NA, dst=BGP_NA) / IDP(
            destEID=int(eid, 16)) / IDPNRS(queryType="resolve", source="format1", na=int("0" * 40, 16))
        ret_pkt = pkt_bgp_eq
    elif command == "bd":
        payload_bgp_deregister = "73" + eid + ipv6ToHexString(USER_NA) + ipv6ToHexString(
            CONTROLLER_NA) + "00000001" + ipv6ToHexString(BGP_NA)
        pkt_bgp_d = Ether(dst=dmac) / IPv6(nh=0x99, src=USER_NA, dst="::") / IDP(
            destEID=int("0" * 40, 16)) / IDPNRS(queryType="deregister") / bytes.fromhex(payload_bgp_deregister)
        ret_pkt = pkt_bgp_d
    elif command == "beqw":
        pkt_bgp_eq_wrong = Ether(dst=dmac) / IPv6(nh=0x99, src=USER_NA, dst=BGP_NA) / IDP(
            destEID=int(eid, 16)) / IDPNRS(queryType="resolve_w", source="format1",
                                           na=int(ipv6ToHexString(CONTROLLER_NA), 16))
        ret_pkt = pkt_bgp_eq_wrong
    else:
        ret_pkt = None
    # ret_pkt.show()
    # hexdump(ret_pkt)
    return ret_pkt


def ipv6ToHexString(ipv6addr: str) -> str:
    colon = ipv6addr.count(":")
    ip6_complete = ipv6addr
    if colon < 7:
        index = ipv6addr.index("::")
        ip6_complete = ipv6addr[0:index] + ":" * (7 - colon) + ipv6addr[index:]
    ip_list = ip6_complete.split(":")
    hex_ip_str = ""
    for i in ip_list:
        hex_ip_str = hex_ip_str + "0" * (4 - len(i)) + i
    return hex_ip_str


def main(command):
    # pkt_r = Ether() / IPv6(dst="2400:dd01:1037:201:192:168:47:198")
    # pkt = [packet_creator("br"), packet_creator("br", "a"*40), packet_creator("br", "c"*40), packet_creator(
    #     "beq"), packet_creator("bd"), packet_creator("beq")]

    # *loop send different eid
    eid_l = ["b" * (40 - len(str(i))) + str(i) for i in range(1000)]
    pkts = []
    bar = ShowProcess(len(eid_l) - 1)
    for eid in eid_l:
        bar.show_process()
        pkts.append(packet_creator(command, eid=eid))
    bar.close()
    sendpfast(pkts, iface="p1p4", pps=1000)

    pkt = packet_creator(command)
    # pkt = packet_creator("br", "a"*40)
    # sendp(pkt, iface="p1p4", loop=1, inter=10) #* Send packets each 10 seconds.
    # sendp(pkt, iface="p1p4", count=30000)
    # sendpfast(pkt, iface="p1p4", pps=100000, loop=500000)
    # sendp(Ether(dst="00:00:00:01:02:03")/IPv6(dst="2400:dd01:1037:100:20::22")/UDP(dport=89), iface="p7p4", count=1)


if __name__ == '__main__':
    USER_NA = "2400:dd01:1037:9:222::222"
    CONTROLLER_NA = "2400:dd01:1037:9:10::10"
    BGP_NA = "2400:dd01:1037:10:20::20"
    # if len(sys.argv) != 2:
    #     print("argument must exist! use as: python3 sendRawPacket.py r/d/eq/")
    #     exit(1)
    # else:
    #     main(sys.argv[1])
    main("eq")
