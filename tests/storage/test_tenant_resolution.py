import pytest

from releasegate.storage.base import resolve_tenant_id


def test_resolve_tenant_id_requires_value_by_default(monkeypatch):
    monkeypatch.setenv("RELEASEGATE_REQUIRE_TENANT_ID", "true")
    monkeypatch.delenv("RELEASEGATE_TENANT_ID", raising=False)
    with pytest.raises(ValueError, match="tenant_id is required"):
        resolve_tenant_id(None)


def test_resolve_tenant_id_allows_default_when_requirement_disabled(monkeypatch):
    monkeypatch.setenv("RELEASEGATE_REQUIRE_TENANT_ID", "false")
    monkeypatch.delenv("RELEASEGATE_TENANT_ID", raising=False)
    assert resolve_tenant_id(None) == "default"


def test_resolve_tenant_id_prefers_explicit_value(monkeypatch):
    monkeypatch.setenv("RELEASEGATE_REQUIRE_TENANT_ID", "true")
    monkeypatch.setenv("RELEASEGATE_TENANT_ID", "tenant-from-env")
    assert resolve_tenant_id("tenant-explicit") == "tenant-explicit"
