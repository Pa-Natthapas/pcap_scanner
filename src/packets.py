from collections import defaultdict

from scapy.all import ICMP, IP, TCP, UDP, IPv6

from attempt import Attempt
from replyIndex import ReplyIndex
from constants import TCP_SYN, TCP_RST, TCP_ACK, SYN_ACK, RST



# We start from the flow abstraction of **RFC 5470**: a flow is identified by the 5-tuple:
# (src IP, src port, dst IP, dst port, protocol)`
# Note that a flow is directional
# A->B is not the same as B->A, it's a completely different flow.
# This function takes in 1 packet and construct a 5-tuple.
def five_tuple(pkt):
    """Return this packet's (src_ip, src_port, dst_ip, dst_port, proto), or None.

    Non-IP packets have no 5-tuple and return None so callers can skip them.
    ICMP has no ports, so its port fields come back as None.
    """
    if IP in pkt:
        src, dst = pkt[IP].src, pkt[IP].dst
    elif IPv6 in pkt:
        src, dst = pkt[IPv6].src, pkt[IPv6].dst
    else:
        return None

    if TCP in pkt:
        return (src, pkt[TCP].sport, dst, pkt[TCP].dport, "TCP")
    if UDP in pkt:
        return (src, pkt[UDP].sport, dst, pkt[UDP].dport, "UDP")
    if ICMP in pkt:
        return (src, None, dst, None, "ICMP")
    return (src, None, dst, None, pkt.lastlayer().name)

# This takes a pcap and loads each packet into a flow.
def group_into_flows(packets):
    """Group packets by 5-tuple. Returns {five_tuple: [pkt, ...]} in capture order."""
    flows = defaultdict(list)
    for pkt in packets:
        key = five_tuple(pkt)
        if key is not None:
            flows[key].append(pkt)
    return dict(flows)

def is_syn(pkt):
    """True for a bare opening SYN (client -> server): SYN set, ACK clear."""
    flags = int(pkt[TCP].flags)
    return bool(flags & TCP_SYN) and not (flags & TCP_ACK)

def is_syn_ack(pkt):
    """True for a SYN-ACK (server -> client): the service is alive and listening."""
    flags = int(pkt[TCP].flags)
    return bool(flags & TCP_SYN) and bool(flags & TCP_ACK)

def is_rst(pkt):
    """True for any RST (bare RST or RST-ACK): the port actively refused us."""
    return bool(int(pkt[TCP].flags) & TCP_RST)

def extract_attempts(flows):
    """Return every outbound TCP connection attempt (one per SYN), sorted by time."""
    attempts = []
    for (src, sport, dst, dport, proto), packets in flows.items():
        """Since the TRW works only for TCP"""
        if proto != "TCP":
            continue
        for pkt in packets:
            if is_syn(pkt):
                # print(pkt, is_syn(pkt))
                attempts.append(
                    Attempt(src=src, sport=sport, dst=dst, dport=dport, time=float(pkt.time))
                )
    attempts.sort(key=lambda a: a.time)
    return attempts

### Takes in the 5-tuple flow
def build_reply_index(flows):
    """Index every SYN-ACK and RST by its own (src, sport, dst, dport)."""
    index = ReplyIndex()
    for (src, sport, dst, dport, proto), packets in flows.items():
        if proto != "TCP":
            continue
        key = (src, sport, dst, dport)
        for pkt in packets:
            if is_syn_ack(pkt):
                index.add(key, float(pkt.time), SYN_ACK)
            elif is_rst(pkt):
                index.add(key, float(pkt.time), RST)
    index.finalize()
    return index