# portscan — User Manual

Practical guide to running the TRW port-scan detector. For *what it is and why*, see
[README.md](README.md).

---

## 1. Requirements

| | |
|---|---|
| **Python** | 3.9 or newer |
| **Dependencies** | `scapy` (pcap parsing), `numpy` (percentile, histogram) |
| **OS** | Any — macOS, Linux, Windows. Nothing platform-specific. |
| **Privileges** | **None.** It reads a file; it never opens a network interface. Do **not** run it with `sudo`. |

---

## 2. Installation

```bash
git clone git@github.com:Pa-Natthapas/pcap_scanner.git
cd pcap_scanner/

python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install scapy numpy
```

Check it worked:

```bash
cd src
python portscan.py --help
```

You should see the usage line. If you get `ModuleNotFoundError`, see §7.

---

## 3. Usage

```
python portscan.py <capture.pcap>
```

One positional argument: the capture to analyse. That is the whole interface.

| Option | Description |
|---|---|
| `<capture.pcap>` | **Required.** Path to the pcap/pcapng file. |

There are no modes and no flags. Everything else is tuned in `src/config.py` (§6).

---

## 4. Input format

**Accepts:** `.pcap` and `.pcapng` — anything `scapy.rdpcap()` can read. The extension is not checked.
The FIRST-2015 capture have no
extension at all (`snort.log.1428710407`) and work fine.

**What it looks at:** IPv4/IPv6 **TCP** packets only. UDP, ICMP and ARP are grouped into flows
for the protocol tally, then discarded.

**Your capture must contain both directions of traffic.** The detector works by matching each
SYN to the SYN-ACK or RST that came back. If the capture recorded only outbound packets, every
attempt looks like a timeout and **every host looks like a scanner.**

**It must contain some answered connections.** τ is derived from observing reply latencies and taking percentiles, so
a capture where nothing was ever answered cannot produce one.

---

## 5. Output fields

### The verdict table

```
HOST              VERDICT        DECIDED IN    OF       p  SUCC  REF  SIL
-------------------------------------------------------------------------
192.168.0.53      Evil                    3   340   0.876    42   20  278
```

| Field | Meaning |
|---|---|
| `HOST` | Source IP being judged. |
| `VERDICT` | `Evil` (scanner), `Benign`, or `Undetermined` — ran out of observations without crossing either bound. Not an error: it is the honest answer for a host you have barely seen. |
| `DECIDED IN` | **How many first-contacts the test needed** before committing. |
| `OF` | How many first-contacts the host made **in total**. |
| `p` | Failure ratio, `(total − success) / total`. |
| `SUCC` | First-contacts answered by a SYN-ACK within τ. |
| `REF` | First-contacts answered by a RST within τ (host up, port closed). |
| `SIL` | First-contacts that got nothing within τ. |

### The diagnostics above it

| Line | Meaning |
|---|---|
| `tau` | Reply-timeout deadline, in seconds. Derived from the current instance of capture file's own latencies. |
| `answered` | How many SYNs ever got a reply, at any delay. |
| `outcomes` | The SUCCESS / REFUSED / SILENT split across all attempts. |
| `Xi` | Labelling threshold. Hosts with `p > Ξ` are labelled Evil **only to estimate θ** — this is not the detection step. |
| `theta_0` | `Pr[success \| Benign]`, estimated from the labelled hosts. |
| `theta_1` | `Pr[success \| Evil]`. |

---

## 6. Configuration

All tunables live in **`src/config.py`**. No magic numbers anywhere else.

| Constant | Default | Effect |
|---|---|---|
| `ALPHA` | `0.01` | Target false-alarm rate. **Lower** → fewer false positives, but decisions need more evidence. |
| `BETA` | `0.99` | Target detection rate. **Higher** → catches more scanners, at the cost of more false alarms. |
| `TAU_PERCENTILE` | `99` | τ = this percentile of observed reply latencies. **Lower** it (e.g. 95) to be stricter about what counts as a timely reply. |
| `HIST_BINS` | `20` | Bins in the histogram whose valley gives Ξ. Too few and the peaks merge; too many and the histogram goes spiky and the valley wanders. |
| `EPS` | `1e-6` | Numerical guard keeping θ inside `(0, 1)`. **Do not change** unless you know why it exists. |

You never set the decision bounds directly. Wald's result derives them from `ALPHA` and `BETA`:

```
η₁ = β / α           = 99.0     → cross it, declare Evil
η₀ = (1−β) / (1−α)   = 0.0101   → cross it, declare Benign
```

---

## 7. Troubleshooting

**`ModuleNotFoundError: No module named 'scapy'`**
You are running a Python that lacks the dependencies. Find out which one:
```bash
python -c "import sys; print(sys.executable)"
```
Activate the venv (`source .venv/bin/activate`) or call its interpreter directly. In VS Code,
the active interpreter is shown bottom-right — fix it with **Cmd+Shift+P → Python: Select
Interpreter**. Note that installing scapy *again* will not help if the wrong interpreter is
selected; that is the usual reason this error survives three `pip install` attempts.

**`error: capture file does not exist <path>`**
The path is wrong. Paths are relative to the directory you run *from*, not to `src/`. Verify
with `ls <path>`.

**`zsh: command not found: python`**
Your system has `python3` but no `python`. Use `python3`, or activate the venv, which provides
both.

**Every host comes back `Evil`**
With no replies, every attempt is `SILENT`, every `p` is 1.0, and everyone looks
like a scanner. Use a pcap file with replies instead.

**Every host comes back `Undetermined`**
No host has enough first-contacts to reach a bound. Expected on a short capture, or one where
each host talks to only one or two destinations.

**Slow, or eating memory**
The whole capture is loaded into RAM. Split it first:
```bash
editcap -c 200000 big.pcap chunk.pcap
```

**A scanner I know about is not detected**
Check it is a *horizontal* scan (many destination **IPs**). A vertical scan, one target, many
ports - counts as a single first-contact and is invisible to this tool by design.

---

## 8. Interpreting results honestly

The tool will convict hosts with low evidence, and it tells you when it is doing so.

> **Rule: if the output says `1 consecutive failure(s) suffice to convict`, discard every
> verdict with a low `OF` count.**

Why this happens: most hosts in a real capture make exactly **one** first-contact, and a host
with `n = 1` can only score `p = 0.0` or `p = 1.0`. Those hosts pile into the two extreme bins,
which pins θ to the boundary — in the example below `θ₀` lands on exactly **1.0**, i.e. *"a
benign host never fails"*. One failure then becomes overwhelming evidence of guilt.

In practice: **`1 of 1` is noise. `3 of 340` is evidence.**

---

## 9. Worked example

2015-04-11 of the FIRST-2015 network-forensics set — a day containing a real scanner.

### Input

```bash
cd src
python portscan.py ./FIRST-2015_Hands-on_Network_Forensics_PCAP/2015-04-11/snort.log.1428710407
```

### Output

```
[*] reading ../../FIRST-2015_Hands-on_Network_Forensics_PCAP/2015-04-11/snort.log.1428710407
    206,629 packets  ->  12,532 flows  ->  4,821 connection attempts

── Outcome Classification ─────────────────────────────────────────────

    tau       = 0.5782 s   (99th pct of reply latency)
    answered  = 2,846 of 4,821  (59.0%)
    outcomes  = 2,725 success   92 refused   2,004 silent

  Benign:  27 hosts
  Evil  :   6 hosts

  192.168.0.53      n= 340  -> Evil
  192.168.0.54      n= 152  -> Evil
  192.168.0.51      n=  25  -> Benign

── Results ────────────────────────────────────────────────────────────

HOST              VERDICT        DECIDED IN    OF       p  SUCC  REF  SIL
-------------------------------------------------------------------------
192.168.0.53      Evil                    3   340   0.876    42   20  278
45.63.7.209       Evil                    1     1   1.000     0    0    1
24.104.251.238    Evil                    1     1   1.000     0    0    1
73.8.66.217       Evil                    1     1   1.000     0    0    1
72.181.102.235    Evil                    1     1   1.000     0    0    1
192.168.0.54      Benign                  5   152   0.164   127    2   23
192.168.0.51      Benign                  5    25   0.000    25    0    0
...

```

### Reading it

**`192.168.0.53` is a real scanner.** It first-contacted **340** distinct destinations. Only 42
answered, 20 refused, and **278 ignored it entirely** — a failure ratio of 0.876. The
sequential test convicted it after **3** observations. It was sweeping web ports (80, 443,
8080, 110) across hundreds of hosts.

**The other four `Evil` verdicts are false positives.** Each made exactly one first-contact
that timed out (`1 of 1`, `SIL = 1`). The warning at the bottom is firing precisely because of
them: with θ₀ pinned at 1.0, one failure convicts. Ignore them.

**`192.168.0.54` is the interesting one.** Step 1 *labelled* it Evil — its failure ratio of
0.164 exceeded Ξ = 0.075. But the sequential test looked at the actual **order** of its
outcomes, saw 127 of 152 succeed, and cleared it as **Benign** after 5 observations. The SPRT
overruled a bad bootstrap label. That is the test working.

### Takeaway

One real scanner, caught in 3 of its 340 attempts. Four pieces of noise, clearly marked
by their `1 of 1` counts and by the warning. **The verdict column alone is not the answer —
read it together with `DECIDED IN` and `OF`.**
