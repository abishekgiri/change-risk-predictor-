from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field


class AuthContext(BaseModel):
    tenant_id: str
    principal_id: str
    auth_method: str
    roles: List[str] = Field(default_factory=list)
    scopes: List[str] = Field(default_factory=list)
    key_id: Optional[str] = None
    integration_id: Optional[str] = None
