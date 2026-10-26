from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from . import __version__, checks  # noqa: F401  (importing checks registers them)
from .core import REGISTRY, Context
from .http import Response
from .models import Finding


@dataclass
class ScanResult:
    target: str
    findings: "list[Finding]" = field(default_factory=list)
    errors: "list[str]" = field(default_factory=list)
    checks_run: "list[str]" = field(default_factory=list)
    duration: float = 0.0
    version: str = __version__


def scan(
    target: str,
    base: Response,
    *,
    only: Optional["list[str]"] = None,
    timeout: float = 10.0,
    verify: bool = True,
    delay: float = 0.0,
) -> ScanResult:
    ctx = Context(target=target, base=base, timeout=timeout, verify=verify, delay=delay)
    result = ScanResult(target=target)
    started = time.monotonic()
    for name, fn in REGISTRY.items():
        if only and name not in only:
            continue
        result.checks_run.append(name)
        try:
            result.findings.extend(fn(ctx))
        except Exception as exc:  # a broken check must never abort the whole audit
            result.errors.append(f"{name}: {type(exc).__name__}: {exc}")
    result.findings.sort(key=lambda f: (-int(f.severity), f.check_id))
    result.duration = time.monotonic() - started
    return result
