# TRW Port-Scan Detector

Detects port-scanning hosts in a packet capture using **Threshold Random Walk (TRW)** —
Wald's Sequential Probability Ratio Test applied to TCP connection outcomes.

Implements *"Fast Portscan Detection Using Sequential Hypothesis Testing"* (Jung, Paxson,
Berger & Balakrishnan, IEEE S&P 2004).

```bash
python portscan.py capture.pcap
```

---

## The idea

A benign host mostly knows where it is going: it connects to servers that exist and are
listening, so most of its connection attempts **succeed**. A scanner is guessing — it
sprays SYNs at addresses and prays that it returns something (It contains no prior knowledge of these addresses)
, so most of its attempts **fail**.

We use TRW (Threshold Random Walk)
For each source host we watch the outcome of every *first-contact* (the first time it ever talks to a given destination),
score it as success or failure, and accumulate evidence sequentially.
The moment the evidence crosses an upper bound we declare the host a scanner.
If it crosses a lower bound we declare it benign.
If it lands in between, we keep watching.

---

## How it works

### Step 1 — Estimate the two success rates

| Stage | What happens |
|---|---|
| **Flows** | Group packets by the RFC 5470 5-tuple `(src, sport, dst, dport, proto)` |
| **Attempts** | One record per SYN packet |
| **τ (tau)** | The reply-timeout deadline — the 99th percentile of *observed* reply latencies, so it adapts to the network the capture came from |
| **Outcomes** | Each attempt becomes `SUCCESS` (SYN-ACK within τ), `REFUSED` (RST within τ), or `SILENT` (nothing within τ) |
| **First-contacts** | Keep only the first attempt to each **new destination IP** per host. That is the observation sequence `Y₁…Yₙ` |
| **p** | Per host, the failure ratio `(total − success i.e. failure) / total` |
| **Ξ (Xi)** | The **valley** between the two tallest peaks of the histogram of `p` |
| **Labels** | `p > Ξ` → *Evil*, otherwise *Benign*. **These labels are an assumption, not ground truth** |
| **θ₀, θ₁** | Pooled success rates of the Benign and Evil groups |

- `θ₀ = Pr[Yᵢ = 0 | H₀]` — how often a benign host's first-contacts succeed
- `θ₁ = Pr[Yᵢ = 0 | H₁]` — how often a scanner's first-contacts succeed

### Step 2 — The sequential test

Two hypotheses: `H₀` the host is benign, `H₁` the host is a scanner.

You do **not** choose the decision bounds. You choose the two error rates you are willing
to accept, and Wald's result derives the bounds for you:

```
α = Pr[decide Evil | Benign]   (false alarm)  = 0.01
β = Pr[decide Evil | Evil]     (detection)    = 0.99

η₁ = β / α           = 99.0     → cross it, declare Evil
η₀ = (1−β) / (1−α)   = 0.0101   → cross it, declare Benign
```

For a host's observations, the likelihood ratio is

```
        n   Pr[Yᵢ | H₁]
f(Y) =  ∏  ────────────
       i=1  Pr[Yᵢ | H₀]
```

Because `Y` is binary, every factor is one of just **two constants** — `θ₁/θ₀` on a
success, `(1−θ₁)/(1−θ₀)` on a failure. We accumulate the **logarithm** of this ratio as a
running sum (a product over hundreds of observations would underflow), and after **each**
observation check whether it has crossed either bound. A host whose observations run out
without crossing either is reported **Undetermined** — not forced into a class.

---

## Usage

```bash
cd src
python portscan.py <capture.pcap>
```

Requires Python 3 with `scapy` and `numpy`. Reading a pcap needs **no root** — scapy only
needs privileges for live sniffing, which this tool never does.

### Example

```
── Verdicts ───────────────────────────────────────────────────────────
HOST              VERDICT        DECIDED IN    OF       p  SUCC  REF  SIL
-------------------------------------------------------------------------
192.168.0.53      Evil                    3   340   0.876    42   20  278
45.63.7.209       Evil                    1     1   1.000     0    0    1
...
192.168.0.54      Benign                  5   152   0.164   127    2   23
```

**Read the `DECIDED IN` and `OF` columns together.** `3 of 340` is a verdict backed by real
evidence — a host that made 340 probes, convicted on the third. `1 of 1` is a verdict from
a single observation, and is worth nothing (see *Limitations*).

---

## Limitations — read this before trusting the output

### The sequential test is sound. The bootstrap is not.

It caught a 340-destination scanner in 3 observations, and it correctly
**overruled a bad Step 1 label**: `192.168.0.54` was labelled *Evil* by Ξ
but the Sequential Probability Ratio Test looked at the actual sequence of
outcomes, saw success after success, and cleared it as *Benign*.

The fragile part is **Step 1**, which estimates `θ₀` and `θ₁` by thresholding a population
it merely *assumes* is bimodal.



### Other scope limits

- **TCP only.** TRW depends on the SYN / SYN-ACK / RST handshake. UDP and ICMP scans are not
  detected.
- **Horizontal scans.** First-contacts are keyed on destination **IP**, per the paper. A
  vertical scan (one host, many ports) registers as a single observation.
- **Offline.** Analyses a capture file; does not sniff live traffic.

---

## Project layout

```
src/
  config.py       tunable knobs      — τ percentile, histogram bins, α, β, EPS
  constants.py    domain vocabulary  — TCP flag bits, outcome and label names
  attempt.py      Attempt            — one SYN, plus its derived delta and outcome
  hostStats.py    HostStats          — a host's first-contact record, and its p
  replyIndex.py   ReplyIndex         — time-ordered reply lookup (binary search)
  packets.py      packet parsing     — 5-tuples, flags, attempts, reply index
  detect.py       classification     — τ, SUCCESS/REFUSED/SILENT, first-contacts
  model.py        the statistics     — Ξ, θ, η, and the SPRT walk
  portscan.py     pipeline + CLI     — the only file with a __main__
```

Dependencies point one way: `config` and `constants` import nothing, everything imports
them, and `portscan.py` wires the stages together.

---

## Two implementation details worth knowing

**Outcomes are resolved per *attempt*, not per flow.** A day-long capture has ephemeral
**source-port reuse**: two unrelated connections hours apart collapse into the same 5-tuple.
So every SYN becomes its own record, and finds its outcome by asking for the first reply that
arrived *after its own timestamp*. This also means a teardown RST arriving after a successful
handshake is correctly ignored — the SYN-ACK came first.

**τ genuinely requires two passes.** A reply latency only exists for an attempt that *got* a
reply, so τ cannot be applied while the latencies it is derived from are still being
collected. Pass 1 matches every attempt to its first reply with no time limit; pass 2 rejudges
every attempt against the resulting τ.

---

## A note on the sample data

`Portscan.pcap`, despite its name, **contains no port scan**. Every internal host in it
succeeds on essentially all of its first-contacts, and not one SYN in the entire capture is
answered by a RST. It is useful as a **negative control** — it shows what the detector does
when there is no scanner to find, which is to invent one.

The captures with real scanning activity are the April days of the FIRST-2015 set;
`2015-04-11` is the one used in the examples above.

---

## Reference

Jung, J., Paxson, V., Berger, A. W., & Balakrishnan, H. (2004).
*Fast Portscan Detection Using Sequential Hypothesis Testing.*
IEEE Symposium on Security and Privacy.
