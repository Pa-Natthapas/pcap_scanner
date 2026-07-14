

import math
from dataclasses import dataclass

import numpy as np

from config import EPS, FALLBACK_THETA_0, FALLBACK_THETA_1
from constants import BENIGN, EVIL, UNDETERMINED
from detect import is_failure

@dataclass
class Verdict:
    """The outcome of running the SPRT against one host."""

    src: str
    decision: str        # EVIL / BENIGN / UNDETERMINED
    observations: int    # how many first-contacts it took to decide
    available: int       # how many first-contacts the host had in total
    final_score: float   # the running log-likelihood ratio when we stopped
    trace: list          # the score after each observation, for plotting


def find_local_maxima(counts):
    """Indices of local maxima in a 1-D sequence of bin counts."""
    peaks = []
    n = len(counts)
    for i in range(n):
        if counts[i] == 0:
            continue
        taller_than_left = (i == 0) or (counts[i] > counts[i - 1])
        taller_than_right = (i == n - 1) or (counts[i] >= counts[i + 1])
        if taller_than_left and taller_than_right:
            peaks.append(i)
    return peaks


def find_xi(p_values, bins):
    """Locate the valley between the two tallest peaks of the failure-ratio histogram.

    Returns (xi, counts, edges). `xi` is None when the data offers no usable valley.
    """
    counts, edges = np.histogram(p_values, bins=bins, range=(0.0, 1.0))
    centers = (edges[:-1] + edges[1:]) / 2

    peaks = find_local_maxima(counts)
    if len(peaks) < 2:
        return None, counts, edges

    # The two dominant peaks, restored to left-to-right order.
    tallest = sorted(peaks, key=lambda i: counts[i], reverse=True)[:2]
    left, right = sorted(tallest)

    between = range(left + 1, right)
    if not between:
        return None, counts, edges     # adjacent peaks: no valley to find

    valley = min(between, key=lambda i: counts[i])
    return float(centers[valley]), counts, edges



def label_hosts(host_stats, xi):
    """Label each host Evil if its failure ratio exceeds xi, else Benign. Mutates in place."""
    for host in host_stats.values():
        host.label = EVIL if host.p > xi else BENIGN

def clamp_probability(value, eps=EPS):
    """Keep a probability strictly inside (0, 1) so its logarithm stays finite."""
    return min(max(value, eps), 1.0 - eps)


def pooled_success_rate(hosts):
    """Total successes / total first-contacts over a group of hosts. None if the group is empty."""
    total = sum(h.total for h in hosts)
    if total == 0:
        return None
    return sum(h.success for h in hosts) / total


def estimate_thetas(host_stats, xi):
    """Estimate (theta_0, theta_1) from the labeled hosts, else fall back to the paper's values.

    Returns (theta_0, theta_1, source) — `source` records which route was taken.
    Values are returned raw (unclamped) so the caller can see a degenerate 0.0.
    """
    if xi is None:
        return FALLBACK_THETA_0, FALLBACK_THETA_1, "fallback (no valley in histogram)"

    benign = [h for h in host_stats.values() if h.label == BENIGN]
    evil = [h for h in host_stats.values() if h.label == EVIL]

    theta_0 = pooled_success_rate(benign)
    theta_1 = pooled_success_rate(evil)

    if theta_0 is None:
        return FALLBACK_THETA_0, FALLBACK_THETA_1, "fallback (no host labeled Benign)"
    if theta_1 is None:
        return FALLBACK_THETA_0, FALLBACK_THETA_1, "fallback (no host labeled Evil)"

    return theta_0, theta_1, "estimated from labeled hosts"

def decision_bounds(alpha, beta):
    #Wald's SPRT bounds. Returns (eta_0, eta_1, log_eta_0, log_eta_1
    eta_1 = beta / alpha
    eta_0 = (1 - beta) / (1 - alpha)
    if not (eta_0 < 1 < eta_1):
        raise ValueError(f"Thresholds must straddle 1, got eta_0={eta_0}, eta_1={eta_1}")
    return eta_0, eta_1, math.log(eta_0), math.log(eta_1)

def log_likelihood_increments(theta_0, theta_1):
    """The two possible per-observation log-likelihood contributions.

    Returns (llr_success, llr_failure). llr_success is negative (evidence for Benign),
    llr_failure positive (evidence for Evil), given theta_1 < theta_0.
    """
    llr_success = math.log(theta_1 / theta_0)
    llr_failure = math.log((1 - theta_1) / (1 - theta_0))
    return llr_success, llr_failure


def sprt(src, contacts, llr_success, llr_failure, log_eta_0, log_eta_1):
    """Run Wald's SPRT over one host's first-contacts, stopping at the first crossing."""
    score = 0.0          # running log-likelihood ratio, log f(Y)
    trace = []

    for i, attempt in enumerate(contacts, start=1):
        score += llr_failure if is_failure(attempt.outcome) else llr_success
        trace.append(score)

        if score >= log_eta_1:
            return Verdict(src, EVIL, i, len(contacts), score, trace)
        if score <= log_eta_0:
            return Verdict(src, BENIGN, i, len(contacts), score, trace)

    # Ran out of evidence without crossing either bound.
    return Verdict(src, UNDETERMINED, len(contacts), len(contacts), score, trace)

def run_sprt_all(first_contacts, llr_success, llr_failure, log_eta_0, log_eta_1):
    """Run the SPRT for every host. Returns {src: Verdict}."""
    return {
        src: sprt(src, contacts, llr_success, llr_failure, log_eta_0, log_eta_1)
        for src, contacts in first_contacts.items()
    }
