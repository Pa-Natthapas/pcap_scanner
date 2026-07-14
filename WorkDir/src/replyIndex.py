
from collections import defaultdict
from bisect import bisect_right

"""
ReplyIndex is a time-aware lookup table for the TCP replies, sorted. 

Goal: We want to solve the following problem:
    Given a SYN (src_ip:sp -> dst_ip:dp, at t = X), we want to know

    1. Did anyone answer?
    2. If they did, what did they say?
    3. Packets are huge, we don't want to waste an O(n) checks for every request.

So we index the replies up front, which takes the following shape:

key = (
(src_ip , sp, dst_ip, time) -> {(
    time = [10.2, 14.6, 880]
    kinds = [SYN-ACK, RST, SYN-ACK]
)}

Keeping separate list also allows bisect to work.

It answers, given a key and a t, what's the first request that comes right after this t.
"""
class ReplyIndex:
    """Time-ordered index of SYN-ACK / RST replies, keyed by reversed 4-tuple."""

    def __init__(self):
        # key -> ([timestamp, ...], [kind, ...]), kept parallel and sorted by timestamp
        self._times = defaultdict(list)
        self._kinds = defaultdict(list)

    def add(self, key, time, kind):
        self._times[key].append(time)
        self._kinds[key].append(kind)

    def finalize(self):
        """Sort each key's replies by time. Must be called before any lookup."""
        for key, times in self._times.items():
            order = sorted(range(len(times)), key=lambda i: times[i])
            self._times[key] = [times[i] for i in order]
            self._kinds[key] = [self._kinds[key][i] for i in order]

    # Binary search for first request right after t, given key. returns (timestamp, kind) otherwise, return None.
    def first_reply_after(self, key, time):
        times = self._times.get(key)
        if not times:
            return None
        i = bisect_right(times, time)
        if i == len(times):
            return None
        return times[i], self._kinds[key][i]
    


