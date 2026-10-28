from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            raise ValueError(f"unknown severity: {value!r}") from exc


@dataclass(frozen=True)
class Finding:
    check_id: str  # stable rule id, e.g. "headers.csp-missing"
    title: str
    severity: Severity
    description: str
    remediation: str
    url: str
    evidence: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.name
        return d