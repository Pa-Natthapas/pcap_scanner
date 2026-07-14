from dataclasses import dataclass

"""
Records one connection attempt. 

Goal: derive the two things the pcap does not give us directly --
  delta   : reply latency, time from this SYN to its first reply
  outcome : SUCCESS / REFUSED / SILENT
"""
@dataclass
class Attempt:
    """A single outbound TCP connection attempt (one SYN packet)."""

    src: str            # source IP    — the host we are judging
    sport: int          # source port  — ephemeral; only used to match the reply
    dst: str            # destination IP
    dport: int          # destination port
    time: float         # capture timestamp of the SYN, in seconds


    delta: float = None     # filled in by measure_reply_deltas(): seconds until the first reply
    outcome: str = None     # filled in by classify_attempt(): SUCCESS / REFUSED / SILENT
    

    @property # Makes it look like a property, also it's defined exactly once.
    def reply_key(self):
        #It is its own 4-tuple, flipped, because it's the shape the reply should be.
        """The key a reply to *this* attempt would be filed under: the tuple, reversed."""
        return (self.dst, self.dport, self.src, self.sport)