
from collections import defaultdict
import numpy as np
from constants import SUCCESS, REFUSED, SILENT, SYN_ACK, RST

def measure_reply_deltas(attempts, reply_index):
    """Pass 1: record seconds-until-first-reply for each attempt (None if never answered).

    Deliberately applies NO time limit — this is what builds the population of
    latencies that tau will be derived from. (Refer to TAU_PERCENTILE)

    Returns {id(attempt): (delta_seconds, kind)} for the answered ones.
    """
    replies = {}
    for attempt in attempts:
        found = reply_index.first_reply_after(attempt.reply_key, attempt.time)
        if found is None:
            attempt.delta = None
            continue
        reply_time, kind = found
        attempt.delta = reply_time - attempt.time
        replies[id(attempt)] = (attempt.delta, kind)
    return replies


# Computes the Tau value.
def compute_tau(attempts, percentile):
    """tau = the given percentile of all observed reply latencies, in seconds."""
    deltas = [a.delta for a in attempts if a.delta is not None]
    print()
    if not deltas:
        raise ValueError("No replies at all in this capture — cannot derive tau.")
    return float(np.percentile(deltas, percentile))

def classify_attempt(reply, tau):
    # Pass 2: turn (reply, tau) into one of SUCCESS / REFUSED / SILENT.
    if reply is None:
        return SILENT

    delta, kind = reply
    if delta > tau:
        return SILENT
    if kind == SYN_ACK:
        return SUCCESS
    if kind == RST:
        return REFUSED
    return SILENT

def is_failure(outcome):
    """
    Y = 1 for a failure (REFUSED or SILENT)
    Y = 0 for a SUCCESS.
    """
    return outcome != SUCCESS


def classify_all(attempts, replies, tau):
    """Stamp every attempt with its outcome. Mutates in place; returns the tally."""
    counts = defaultdict(int)
    for attempt in attempts:
        attempt.outcome = classify_attempt(replies.get(id(attempt)), tau)
        counts[attempt.outcome] += 1
    return counts


def build_first_contacts(attempts):
    """Return {src_ip: [Attempt, ...]} — the earliest attempt to each NEW destination IP.

    Relies on `attempts` being sorted by time.
    """
    first_contacts = defaultdict(list)
    seen = set()   # (src, dst) pairs already contacted
    for attempt in attempts:
        pair = (attempt.src, attempt.dst)
        if pair in seen:
            continue
        seen.add(pair)
        first_contacts[attempt.src].append(attempt)
    return dict(first_contacts)
