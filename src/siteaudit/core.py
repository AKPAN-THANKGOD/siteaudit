from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .http import Response
from .models import Finding


@dataclass
class Context:
    target: str
    base: Response
    timeout: float = 10.0
    verify: bool = True
    delay: float = 0.0


CheckFn = Callable[[Context], "list[Finding]"]
REGISTRY: "dict[str, CheckFn]" = {}


def register(name: str) -> Callable[[CheckFn], CheckFn]:
    def deco(fn: CheckFn) -> CheckFn:
        REGISTRY[name] = fn
        return fn

    return deco
