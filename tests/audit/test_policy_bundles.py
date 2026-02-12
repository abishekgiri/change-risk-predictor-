from releasegate.audit.policy_bundles import (
    get_latest_active_policy_bundle,
    get_policy_bundle,
    store_policy_bundle,
)


def test_policy_bundle_store_and_fetch_by_hash():
    snapshot = [{"policy_id": "P1", "policy_version": "1.0.0", "policy_hash": "abc"}]
    store_policy_bundle(
        tenant_id="tenant-alpha",
        policy_bundle_hash="bundle-hash-1",
        policy_snapshot=snapshot,
        is_active=True,
    )
    fetched = get_policy_bundle(tenant_id="tenant-alpha", policy_bundle_hash="bundle-hash-1")
    assert fetched is not None
    assert fetched["tenant_id"] == "tenant-alpha"
    assert fetched["policy_bundle_hash"] == "bundle-hash-1"
    assert fetched["policy_snapshot"] == snapshot


def test_policy_bundle_latest_active_is_tenant_scoped():
    store_policy_bundle(
        tenant_id="tenant-beta",
        policy_bundle_hash="bundle-b1",
        policy_snapshot=[{"policy_id": "P1", "policy_version": "1.0.0", "policy_hash": "x"}],
        is_active=True,
    )
    store_policy_bundle(
        tenant_id="tenant-gamma",
        policy_bundle_hash="bundle-g1",
        policy_snapshot=[{"policy_id": "P2", "policy_version": "1.0.0", "policy_hash": "y"}],
        is_active=True,
    )
    latest_beta = get_latest_active_policy_bundle(tenant_id="tenant-beta")
    latest_gamma = get_latest_active_policy_bundle(tenant_id="tenant-gamma")
    assert latest_beta["tenant_id"] == "tenant-beta"
    assert latest_beta["policy_bundle_hash"] == "bundle-b1"
    assert latest_gamma["tenant_id"] == "tenant-gamma"
    assert latest_gamma["policy_bundle_hash"] == "bundle-g1"

