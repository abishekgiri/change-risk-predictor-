import os
import json

import pytest

from releasegate.attestation.crypto import (
    current_key_id,
    load_private_key_from_env,
    public_key_pem_from_private,
)
from releasegate.security.rate_limit import reset_rate_limits


def pytest_configure(config):
    os.environ.setdefault("RELEASEGATE_TENANT_ID", "tenant-test")
    os.environ.setdefault("RELEASEGATE_JWT_SECRET", "test-jwt-secret")
    os.environ.setdefault("RELEASEGATE_JWT_ISSUER", "releasegate")
    os.environ.setdefault("RELEASEGATE_JWT_AUDIENCE", "releasegate-api")
    os.environ.setdefault("RELEASEGATE_RATE_LIMIT_TENANT_DEFAULT", "5000")
    os.environ.setdefault("RELEASEGATE_RATE_LIMIT_IP_DEFAULT", "5000")
    os.environ.setdefault("RELEASEGATE_RATE_LIMIT_TENANT_HEAVY", "5000")
    os.environ.setdefault("RELEASEGATE_RATE_LIMIT_IP_HEAVY", "5000")
    os.environ.setdefault("RELEASEGATE_RATE_LIMIT_TENANT_WEBHOOK", "5000")
    os.environ.setdefault("RELEASEGATE_RATE_LIMIT_IP_WEBHOOK", "5000")
    os.environ.setdefault(
        "RELEASEGATE_SIGNING_KEY",
        "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f9d1f1a2d46a1b8f12",
    )
    os.environ.setdefault(
        "RELEASEGATE_ROOT_SIGNING_KEY",
        "2b6f7db4a8d693f2e1e8e5c205f263f5bde1430f915f9fcb48b21f35bc95d5f3",
    )
    os.environ.setdefault("RELEASEGATE_ROOT_KEY_ID", "rg-root-test-2026-01")
    key_id = current_key_id()
    public_key = public_key_pem_from_private(load_private_key_from_env()).strip()
    os.environ.setdefault(
        "RELEASEGATE_ATTESTATION_PUBLIC_KEYS",
        json.dumps({key_id: public_key}),
    )


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    reset_rate_limits()
    yield
    reset_rate_limits()
