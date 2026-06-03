"""
Contract test: confirms that data files needed at runtime are reachable
from the installed package layout, not just from a dev checkout.

This catches the 2026-06-03 Tier 3 readiness-audit finding before it ever
recurs: `pip install git+...` was shipping only .py files; the attestation
schema JSON and all policy YAMLs silently dropped.  The customer-facing
Action ran green and produced no signed attestation.

We read each file the way the engine reads it at runtime, via
importlib.resources anchored on a real package.  Note the data
directories (schema/, compiled/, defaults/, .../soc2/) are data-only —
they have no __init__.py, so they are NOT importable packages.  The
correct importlib.resources pattern is therefore to anchor on the
nearest real package (e.g. `releasegate.attestation`, `releasegate`)
and traverse into the data subtree with joinpath — which is exactly how
releasegate/attestation/canonicalize.py loads the schema.

If pyproject.toml + MANIFEST.in fail to declare a data file, these
asserts fail — the same way the customer install fails.
"""
from __future__ import annotations

import importlib.resources as resources

import pytest


# (anchor_package, relative_path) pairs for data files the engine MUST be
# able to read at runtime.  The anchor must be a real package (has
# __init__.py); the relative path traverses into the data-only subtree.
# Adding a new data dependency without listing it here is intentionally a
# test failure — it forces the developer to update both pyproject.toml
# AND this test.
REQUIRED_PACKAGE_RESOURCES = [
    ("releasegate.attestation", "schema/release-attestation.v1.json"),
    # Relocated from a top-level schemas/ dir into the package
    # (fix/stateless-dsse-generation) so they ship in the wheel and load
    # via importlib.resources.  All four were repo-root-relative loads
    # that broke on `pip install`.
    ("releasegate.schemas", "compliance_report.schema.json"),
    ("releasegate.schemas", "policy_bundle.schema.json"),
    ("releasegate.schemas", "fix_suggestions_v1.json"),
    ("releasegate.schemas", "ai_explanation_v1.json"),
]


@pytest.mark.parametrize("anchor_package,relative_path", REQUIRED_PACKAGE_RESOURCES)
def test_runtime_data_file_is_packaged(anchor_package: str, relative_path: str) -> None:
    """The named data file must be reachable via importlib.resources.

    If this test fails after a pyproject.toml change, the packaging fix
    has regressed and customer installs will silently break.  See this
    module's docstring for context.
    """
    ref = resources.files(anchor_package).joinpath(relative_path)
    assert ref.is_file(), (
        f"Required runtime data file is not packaged: "
        f"{anchor_package}/{relative_path}.  Update pyproject.toml's "
        f"[tool.setuptools.package-data] (and/or MANIFEST.in) to include "
        f"this file."
    )


def test_attestation_schema_is_readable() -> None:
    """Beyond existence, the schema must be readable as valid JSON — the
    exact failure mode from the audit was a FileNotFoundError when the
    engine tried to open it during attestation generation.
    """
    import json

    ref = resources.files("releasegate.attestation").joinpath(
        "schema/release-attestation.v1.json"
    )
    data = json.loads(ref.read_text(encoding="utf-8"))
    assert isinstance(data, dict) and data, (
        "Attestation schema packaged but not valid non-empty JSON."
    )


def test_soc2_compiled_yamls_packaged() -> None:
    """At least the SOC 2 compiled YAMLs must ship — they back the
    'CC8.1 mapped' claim on the trust and pricing pages.  Anchored on
    the top-level `releasegate` package and traversed into the data
    subtree, since the leaf directory is data-only (no __init__.py).
    """
    soc2_dir = resources.files("releasegate").joinpath(
        "policy/compiled/standards/soc2"
    )
    assert soc2_dir.is_dir(), (
        "SOC 2 compiled policy directory not found in the installed "
        "package.  Customer evidence packs cannot claim CC8.1 without "
        "these.  Fix pyproject.toml's package-data globs."
    )
    yaml_names = [p.name for p in soc2_dir.iterdir() if p.name.endswith(".yaml")]
    assert yaml_names, (
        "No SOC 2 compiled policy YAMLs found in the installed package. "
        "Fix pyproject.toml's package-data globs."
    )
