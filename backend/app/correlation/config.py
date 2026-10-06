"""Configuration for the correlation engine.

All values are LAB DEFAULTS chosen for this project.  They are not industry
standard thresholds and must be tuned/validated for any other environment.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import timedelta

# Accounts that are too common to act as the sole discriminating identity for
# automatic recurrence correlation (rule C3).  Lab default; configurable.
DEFAULT_GENERIC_ACCOUNTS = frozenset(
    {
        "root",
        "admin",
        "administrator",
        "ubuntu",
        "guest",
        "test",
        "user",
        "nobody",
        "daemon",
        "www-data",
    }
)


@dataclass(frozen=True)
class CorrelationConfig:
    # Rule windows (inclusive).
    c1_window: timedelta = timedelta(hours=24)
    c2_window: timedelta = timedelta(hours=24)
    c3_window: timedelta = timedelta(minutes=60)
    c4_window: timedelta = timedelta(minutes=60)

    # Investigation caps.
    max_investigation_span: timedelta = timedelta(hours=24)
    max_investigation_events: int = 20

    # Used by C3 only (compared case-insensitively).
    generic_accounts: frozenset = DEFAULT_GENERIC_ACCOUNTS

    # Empty by default.  Nothing is treated as infrastructure unless it is
    # explicitly configured here.
    infrastructure_ips: frozenset = frozenset()

    def __post_init__(self) -> None:
        for name in ("c1_window", "c2_window", "c3_window", "c4_window",
                     "max_investigation_span"):
            if getattr(self, name) < timedelta(0):
                raise ValueError(f"{name} must not be negative")
        if self.max_investigation_events < 1:
            raise ValueError("max_investigation_events must be at least 1")

        object.__setattr__(
            self,
            "generic_accounts",
            frozenset(str(a).strip().lower() for a in self.generic_accounts),
        )
        # Canonicalise configured infrastructure IPs; reject invalid entries.
        canonical = frozenset(
            str(ipaddress.ip_address(str(ip).strip())) for ip in self.infrastructure_ips
        )
        object.__setattr__(self, "infrastructure_ips", canonical)
