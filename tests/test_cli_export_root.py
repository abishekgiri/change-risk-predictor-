from releasegate.cli import build_parser


def test_cli_parser_includes_export_root():
    parser = build_parser()
    args = parser.parse_args(["export-root", "--date", "2026-02-13", "--out", "roots/2026-02-13.json"])
    assert args.cmd == "export-root"
    assert args.date == "2026-02-13"
    assert args.out == "roots/2026-02-13.json"
