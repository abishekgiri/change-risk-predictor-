from __future__ import annotations

from typing import Optional


ROLLOUT_MODE_FULL = "FULL"
ROLLOUT_MODE_CANARY = "CANARY"
ROLLOUT_MODES = {ROLLOUT_MODE_FULL, ROLLOUT_MODE_CANARY}

ROLLOUT_STATE_PLANNED = "PLANNED"
ROLLOUT_STATE_RUNNING = "RUNNING"
ROLLOUT_STATE_COMPLETED = "COMPLETED"
ROLLOUT_STATE_ROLLED_BACK = "ROLLED_BACK"
ROLLOUT_STATE_ABORTED = "ABORTED"
ROLLOUT_STATES = {
    ROLLOUT_STATE_PLANNED,
    ROLLOUT_STATE_RUNNING,
    ROLLOUT_STATE_COMPLETED,
    ROLLOUT_STATE_ROLLED_BACK,
    ROLLOUT_STATE_ABORTED,
}


def normalize_rollout_mode(value: Optional[str]) -> str:
    mode = str(value or ROLLOUT_MODE_FULL).strip().upper()
    if mode not in ROLLOUT_MODES:
        raise ValueError(f"invalid rollout mode: {value}")
    return mode


def normalize_canary_percent(mode: str, value: Optional[int]) -> int:
    normalized_mode = normalize_rollout_mode(mode)
    if normalized_mode == ROLLOUT_MODE_FULL:
        return 100
    try:
        percent = int(value if value is not None else 0)
    except (ValueError, TypeError) as exc:
        raise ValueError("canary_percent must be an integer") from exc
    if percent <= 0 or percent >= 100:
        raise ValueError("canary_percent must be between 1 and 99 for canary rollouts")
    return percent
