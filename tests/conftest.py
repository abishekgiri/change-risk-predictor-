import os


def pytest_configure(config):
    os.environ.setdefault("RELEASEGATE_TENANT_ID", "tenant-test")

