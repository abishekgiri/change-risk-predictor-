from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional


QUOTA_KIND_DECISIONS = "decisions"
QUOTA_KIND_ANCHORS = "anchors"
QUOTA_KIND_OVERRIDES = "overrides"


@dataclass(frozen=True)
class TenantQuotaLimits:
    max_decisions_per_month: Optional[int] = None
    max_anchors_per_day: Optional[int] = None
    max_overrides_per_month: Optional[int] = None
    quota_enforcement_mode: str = "HARD"


class TenantQuotaExceededError(ValueError):
    def __init__(
        self,
        *,
        tenant_id: str,
        quota_name: str,
        limit: int,
        current_usage: int,
        period_type: str,
        period_start: str,
    ) -> None:
        self.tenant_id = tenant_id
        self.quota_name = quota_name
        self.limit = int(limit)
        self.current_usage = int(current_usage)
        self.period_type = str(period_type)
        self.period_start = str(period_start)
        super().__init__(
            f"TENANT_QUOTA_EXCEEDED: tenant={tenant_id} quota={quota_name} "
            f"limit={self.limit} current_usage={self.current_usage}"
        )

    def to_http_detail(self) -> Dict[str, Any]:
        return {
            "error": "TENANT_QUOTA_EXCEEDED",
            "tenant_id": self.tenant_id,
            "quota": self.quota_name,
            "limit": self.limit,
            "current_usage": self.current_usage,
            "period_type": self.period_type,
            "period_start": self.period_start,
        }
