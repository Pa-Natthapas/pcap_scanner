
import argparse
import sys
import numpy as np

from scapy.all import rdpcap
from collections import defaultdict
from config import TAU_PERCENTILE, HIST_BINS, ALPHA, BETA
from constants import BENIGN, EVIL, UNDETERMINED, SUCCESS, SILENT, REFUSED
from packets import group_into_flows, extract_attempts, build_reply_index
from detect import (measure_reply_deltas, compute_tau, classify_all,
                    build_first_contacts)
from hostStats import build_host_stats
from model import (find_xi, label_hosts, clamp_probability, estimate_thetas,
                   decision_bounds, log_likelihood_increments, run_sprt_all)

import os

def report(verdicts, host_stats):
    """Print the per-host verdict table, scanners first."""
    order = {EVIL: 0, UNDETERMINED: 1, BENIGN: 2}
    rows = sorted(verdicts.values(),
                  key=lambda v: (order[v.decision], -v.available))

    print(f"\n{'HOST':<18}{'VERDICT':<14}{'DECIDED IN':>11}{'OF':>6}"
          f"{'p':>8}{'SUCC':>6}{'REF':>5}{'SIL':>5}")
    print("-" * 71)
    for v in rows:
        h = host_stats[v.src]
        print(f"{v.src:<18}{v.decision:<14}{v.observations:>11}{v.available:>6}"
              f"{h.p:>8.3f}{h.success:>6}{h.refused:>5}{h.silent:>5}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Fast port-scan detection on a pcap, using sequential hypothesis testing (TRW)."
    )
    parser.add_argument("pcap",
                        help="path to the .pcap / .pcapng capture to analyse")
    args = parser.parse_args()
    if not os.path.isfile(args.pcap):
        sys.exit(f"error: capture file does not exist {args.pcap}")

    return args

def section(title):
    print(f"\n── {title} " + "─" * (71 - len(title) - 4))

def main():
    
    # Loding -----------------------------------------------
    args = parse_args()
    print(f"[*] reading {args.pcap}")
    pcap = rdpcap(args.pcap)

    flows = group_into_flows(pcap)
    attempts = extract_attempts(flows)
    reply_index = build_reply_index(flows)
    print(f"    {len(pcap):,} packets  ->  {len(flows):,} flows  ->  "
          f"{len(attempts):,} connection attempts")

    # Classify ---------------------------------------------
    section("Outcome Classification")
    first_replies = measure_reply_deltas(attempts, reply_index)
    answered = len(first_replies)
    tau = compute_tau(attempts, TAU_PERCENTILE)
    counts = classify_all(attempts, first_replies, tau)

    print(f"    tau       = {tau:.4f} s   ({TAU_PERCENTILE}th pct of reply latency)")
    print(f"    answered  = {answered:,} of {len(attempts):,}  "
          f"({answered / len(attempts):.1%})")
    print(f"    outcomes  = {counts[SUCCESS]:,} success   "
          f"{counts[REFUSED]:,} refused   {counts[SILENT]:,} silent")

    first_contacts = build_first_contacts(attempts)
    host_stats = build_host_stats(first_contacts)
    p_values = np.array([h.p for h in host_stats.values()])
    xi, _, _ = find_xi(p_values, HIST_BINS)

    if xi is not None:
        label_hosts(host_stats, xi)
        label_counts = defaultdict(int)
        for host in host_stats.values():
            label_counts[host.label] += 1
        print(f"  {BENIGN:6}: {label_counts[BENIGN]:3} hosts")
        print(f"  {EVIL:6}: {label_counts[EVIL]:3} hosts\n")
        for host in sorted(host_stats.values(), key=lambda h: -h.total)[:6]:
            print(f"  {host.src:16}  n={host.total:4}  -> {host.label}")
    else:
        print("There is < 2 peaks => undefined — skipping labeling (the fallback thetas need no labels).")

    theta_0_raw, theta_1_raw, _ = estimate_thetas(host_stats, xi)

    theta_0 = clamp_probability(theta_0_raw)
    theta_1 = clamp_probability(theta_1_raw)


    # Sequential test ------------------------------------------------
    _, _, log_eta_0, log_eta_1 = decision_bounds(ALPHA, BETA)

    llr_success, llr_failure = log_likelihood_increments(theta_0, theta_1)

    verdicts = run_sprt_all(first_contacts, llr_success, llr_failure, log_eta_0, log_eta_1)
    decision_counts = defaultdict(int)
    for verdict in verdicts.values():
        decision_counts[verdict.decision] += 1

    section("Results")
    report(verdicts, host_stats)

if __name__ == "__main__":
    main()