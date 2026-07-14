

# --- Input ----------------------------------------------------------------
# Primary capture: contains a real scanner (192.168.0.53 sweeping web ports).
PCAP_PATH = "../FIRST-2015_Hands-on_Network_Forensics_PCAP/2015-04-11/snort.log.1428710407"


# --- Step 1: finding the labeling threshold Xi ---------------------------
# Bin count for the histogram of per-host failure ratios. Its two tallest peaks, and
# the valley between them, give us Xi.
HIST_BINS = 20


# --- Step 1: outcome classification --------------------------------------
# tau is the reply-timeout deadline. 
# A SYN whose reply arrives later than tau (or never arrives) counts as SILENT.
# We do not invent tau: we take it as a high percentile of the reply latencies that was actually
# observed in the whole records, so it adapts to whatever network the capture came from.
TAU_PERCENTILE = 99

"""
Definitions:
For a given host 'r', let n be the number of distinct destination that r first-contacts. We define Yi (for i in 1..n)
to be a bernoulli random variables that records the outcome of r's i-th first-contacts, such that Yi returns:

{
    0 if the connection attempt is a success,
    1 if the connection attempt is a failure.
}

We also consider 2 hypothesis:
H0 = given source r is benign
H1 = given source r is a scanner (evil)

Theta_0 = Pr[Yi = 0|H0] Probability that given a benign host, one of its first contact is successful
Theta_1 = Pr[Yi = 0|H1] Probability that given a scanner, one of its first contact is successful

NOTE * The probability of it being the same but failed to connect, is simply
1 - Pr[Yi = 0|Hj] = Pr[Yi = 1|Hj], for j in {0, 1}

"""


# If the histogram shows no two distinct peaks, Xi cannot be inferred from the data.
# We then skip labeling entirely and fall back to the success rates from the paper.
FALLBACK_THETA_0 = 0.8   # benign hosts succeed ~80% of the time
FALLBACK_THETA_1 = 0.2   # scanners succeed    ~20% of the time


# --- Step 2: sequential hypothesis testing -------------------------------
# We do NOT Nchoose the decision bounds directly, We choose any 2 erro rates which 
# we are willing to live with. 
# The paper cited Wald's result then derives the bound from them:
#
# eta_1 = beta / alpha (Upper bound, declare evil here)
# eta_0 = (1 - beta) / (1 - alpha) (Lower bound, declare benign here)

ALPHA = 0.01   # target false-alarm rate:  Pr[decide Evil | host is Benign]
BETA  = 0.99   # target detection rate:    Pr[decide Evil | host is Evil]


# --- Numerical safety -----------------------------------------------------
# The final value is a likelihood ratio, which is a series of product over observations, 
# thus, we computes it in a Logarithmic manner (For easier numerical manipulation) => log(0) is fatal to the program
# since theta_1 can legitimately come out as exactly 0.0 (if no host we labeled Evil ever
# succeeded i.e Pr[Yi = 0|H1] = 0.0). log(0) = -inf would poison the SPRT walk, so we clamp both thetas away
# from the open ends of [0, 1]. (A safe guard)
# we would get max(value, EPS) -> 0.000001 OR 0.9999999 for 0, 1 respectively
EPS = 1e-6 

