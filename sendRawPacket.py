from scapy.all import *
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether


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


def packet_creator(command: str, eid="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"):
    payload_register = "6f" + eid + ipv6ToHexString(USER_NA)
    payload_deregister = "73" + eid + ipv6ToHexString(USER_NA)
    payload_bgp_register = "6f" + eid + ipv6ToHexString(USER_NA) + ipv6ToHexString(
        CONTROLLER_NA) + "00000001" + ipv6ToHexString(BGP_NA)
    payload_bgp_deregister = "73" + eid + ipv6ToHexString(USER_NA) + ipv6ToHexString(
        CONTROLLER_NA) + "00000001" + ipv6ToHexString(BGP_NA)

    # ! 模拟客户端给 controller 发包
    pkt_r = Ether(dst="A4:23:05:00:11:02") / IPv6(nh=0x99, src=USER_NA, dst="::") / IDP(
        destEID=int("0" * 40, 16)) / IDPNRS(queryType="register") / bytes.fromhex(payload_register)
    pkt_d = Ether(dst="A4:23:05:00:11:02") / IPv6(nh=0x99, src=USER_NA, dst="::") / IDP(
        destEID=int("0" * 40, 16)) / IDPNRS(queryType="deregister") / bytes.fromhex(payload_deregister)
    pkt_eq = Ether(dst="A4:23:05:00:11:02") / IPv6(nh=0x99, src=USER_NA,
                                                   dst="::") / IDP(
        destEID=int(eid, 16)) / IDPNRS(queryType="resolve")

    # ! 模拟controller给bgp发包
    pkt_bgp_eq = Ether(dst="A4:23:05:00:11:02") / IPv6(nh=0x99, src=USER_NA,
                                                       dst=BGP_NA) / IDP(
        destEID=int(eid, 16)) / IDPNRS(queryType="resolve", source="format1", na=int("0" * 40, 16))

    pkt_bgp_r = Ether(dst="A4:23:05:00:11:02") / IPv6(nh=0x99, src=USER_NA, dst="::") / IDP(
        destEID=int("0" * 40, 16)) / IDPNRS(queryType="register") / bytes.fromhex(payload_bgp_register)

    pkt_bgp_d = Ether(dst="A4:23:05:00:11:02") / IPv6(nh=0x99, src=USER_NA, dst="::") / IDP(
        destEID=int("0" * 40, 16)) / IDPNRS(queryType="deregister") / bytes.fromhex(payload_bgp_deregister)

    pkt_bgp_eq_wrong = Ether(dst="A4:23:05:00:11:02") / IPv6(nh=0x99, src=USER_NA,
                                                             dst=BGP_NA) / IDP(
        destEID=int(eid, 16)) / IDPNRS(queryType="resolve_w", source="format1",
                                       na=int(ipv6ToHexString(CONTROLLER_NA), 16))
    ret_pkt = None
    if command == "r":
        ret_pkt = pkt_r
    elif command == "eq":
        ret_pkt = pkt_eq
    elif command == "d":
        ret_pkt = pkt_d
    elif command == "br":
        ret_pkt = pkt_bgp_r
    elif command == "beq":
        ret_pkt = pkt_bgp_eq
    elif command == "bd":
        ret_pkt = pkt_bgp_d
    elif command == "beqw":
        ret_pkt = pkt_bgp_eq_wrong
    else:
        ret_pkt = None
    ret_pkt.show()
    hexdump(ret_pkt)
    return ret_pkt


def ipv6ToHexString(ipv6addr: str) -> str:
    maohao = ipv6addr.count(":")
    ip6_complete = ipv6addr
    if maohao < 7:
        index = ipv6addr.index("::")
        ip6_complete = ipv6addr[0:index] + ":" * (7 - maohao) + ipv6addr[index:]
    ip_list = ip6_complete.split(":")
    hexipstr = ""
    for i in ip_list:
        hexipstr = hexipstr + "0" * (4 - len(i)) + i
    return hexipstr


def main(command):
    # pkt_r = Ether() / IPv6(dst="2400:dd01:1037:201:192:168:47:198")
    # pkt = [packet_creator("br"), packet_creator("br", "a"*40), packet_creator("br", "c"*40), packet_creator(
    #     "beq"), packet_creator("bd"), packet_creator("beq")]
    pkt = packet_creator(command)
    # pkt = packet_creator("br", "a"*40)
    # sendp(pkt, iface="em4", loop=1, inter=0.2)
    sendp(pkt, iface="p4p4", count=1)
    # sendpfast(iface="p4p4", pps=10000, loop=10000)
    # sendp(Ether(dst="00:00:00:01:02:03")/IPv6(dst="2400:dd01:1037:100:20::22")/UDP(dport=89), iface="p7p4", count=1)


if __name__ == '__main__':
    USER_NA = "2400:dd01:1037:9:9::9"
    CONTROLLER_NA = "2400:dd01:1037:9:10::10"
    BGP_NA = "2400:dd01:1037:10:20::20"
    if len(sys.argv) != 2:
        print("argument must exist! use as: python3 sendRawPacket.py r/d/eq/")
        exit(1)
    else:
        main(sys.argv[1])
