from __future__ import annotations

import sys

from releasegate.cli import build_parser, main


def test_cli_parser_includes_anchor_tick():
    parser = build_parser()
    args = parser.parse_args(["anchor", "tick", "--tenant", "tenant-a", "--once", "--format", "json"])
    assert args.cmd == "anchor"
    assert args.anchor_cmd == "tick"
    assert args.tenant == "tenant-a"
    assert args.once is True
    assert args.format == "json"


def test_cli_anchor_tick_returns_zero_on_success(monkeypatch):
    import releasegate.anchoring.anchor_scheduler as scheduler_mod

    monkeypatch.setattr(
        scheduler_mod,
        "tick",
        lambda tenant_id=None: {
            "ok": True,
            "tenant_count": 1,
            "tenants": [{"tenant_id": tenant_id or "tenant-a"}],
        },
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["releasegate", "anchor", "tick", "--tenant", "tenant-a", "--format", "json"],
    )
    assert main() == 0


def test_cli_anchor_tick_returns_two_when_lock_not_acquired(monkeypatch):
    import releasegate.anchoring.anchor_scheduler as scheduler_mod

    monkeypatch.setattr(
        scheduler_mod,
        "tick",
        lambda tenant_id=None: {
            "ok": True,
            "skipped": True,
            "reason": "POSTGRES_LOCK_HELD",
        },
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["releasegate", "anchor", "tick", "--tenant", "tenant-a", "--format", "json"],
    )
    assert main() == 2


def test_cli_anchor_tick_returns_one_on_exception(monkeypatch):
    import releasegate.anchoring.anchor_scheduler as scheduler_mod

    def _raise(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(scheduler_mod, "tick", _raise)
    monkeypatch.setattr(
        sys,
        "argv",
        ["releasegate", "anchor", "tick", "--tenant", "tenant-a", "--format", "json"],
    )
    assert main() == 1
