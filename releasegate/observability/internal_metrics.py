from __future__ import annotations

from collections import Counter
from threading import Lock
from typing import Dict


_lock = Lock()
_counters: Counter = Counter()


def incr(metric: str, value: int = 1) -> None:
    with _lock:
        _counters[metric] += int(value)


def snapshot() -> Dict[str, int]:
    with _lock:
        return dict(_counters)


def reset() -> None:
    with _lock:
        _counters.clear()
