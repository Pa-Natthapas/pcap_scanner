
from collections import defaultdict
from dataclasses import dataclass

import pandas as pd

from constants import SUCCESS, REFUSED, SILENT

@dataclass
class HostStats:
    """A source host's first-contact record, and the failure ratio derived from it."""

    src: str
    total: int          # number of first-contacts
    success: int        # how many of them succeeded
    refused: int        # failure sub-type: actively refused
    silent: int         # failure sub-type: timed out
    label: str = None   # filled in by Section 7: "Benign" or "Evil"

    @property
    def failed(self):
        return self.total - self.success

    @property
    def p(self): #Fail / total
        """Failure ratio: (total - success) / total."""
        return self.failed / self.total
    


def build_host_stats(first_contacts):
    """Turn {src: [Attempt, ...]} into {src: HostStats}."""
    stats = {}
    for src, contacts in first_contacts.items():
        counts = defaultdict(int)
        for attempt in contacts:
            counts[attempt.outcome] += 1
        stats[src] = HostStats(
            src=src,
            total=len(contacts),
            success=counts[SUCCESS],
            refused=counts[REFUSED],
            silent=counts[SILENT],
        )
    return stats


def host_stats_frame(host_stats):
    """Render {src: HostStats} as a DataFrame, busiest hosts first."""
    return (pd.DataFrame([
        {"host": h.src, "total": h.total, "success": h.success, "refused": h.refused,
         "silent": h.silent, "p (fail ratio)": round(h.p, 3), "label": h.label}
        for h in host_stats.values()
    ]).sort_values("total", ascending=False).reset_index(drop=True))
