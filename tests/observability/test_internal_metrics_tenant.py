from releasegate.observability.internal_metrics import incr, reset, snapshot


def test_internal_metrics_are_tenant_scoped():
    reset()
    incr("transitions_evaluated", tenant_id="tenant-a")
    incr("transitions_evaluated", tenant_id="tenant-b")
    incr("transitions_evaluated", value=2, tenant_id="tenant-b")

    tenant_a = snapshot(tenant_id="tenant-a")
    tenant_b = snapshot(tenant_id="tenant-b")
    all_metrics = snapshot(include_tenants=True)

    assert tenant_a["transitions_evaluated"] == 1
    assert tenant_b["transitions_evaluated"] == 3
    assert all_metrics["transitions_evaluated"] == 4
    assert all_metrics["_by_tenant"]["tenant-a"]["transitions_evaluated"] == 1
    assert all_metrics["_by_tenant"]["tenant-b"]["transitions_evaluated"] == 3

