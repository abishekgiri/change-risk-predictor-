import os

import pytest

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


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    reset_rate_limits()
    yield
    reset_rate_limits()
