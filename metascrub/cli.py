"""METASCRUB command-line interface.

Subcommands:
  scan   FILE...            report identifying metadata (read-only)
  clean  FILE... [-o OUT]   write sanitized copy/copies (stripped metadata)

Exit codes:
  0  success, no findings (scan) / clean succeeded
  1  findings present (scan) or a file errored
  2  usage / argument error (argparse default)
"""

from __future__ import annotations

import argparse
import json
import sys

from . import TOOL_NAME, TOOL_VERSION
from .core import scan_file, clean_file, ScrubResult


def _print_table(results: list[ScrubResult], action: str) -> None:
    for r in results:
        header = f"[{r.fmt}] {r.path}"
        print(header)
        print("-" * len(header))
        if r.error:
            print(f"  ERROR: {r.error}")
        elif not r.findings:
            print("  no identifying metadata found")
        else:
            for f in r.findings:
                print(f"  - {f.kind:<14} {f.key}: {f.detail}  "
                      f"(-{f.bytes_removed}B)")
        if action == "clean" and r.cleaned:
            print(f"  => wrote {r.output_path} "
                  f"({len(r.findings)} item(s) stripped)")
        print()


def _print_json(results: list[ScrubResult], action: str) -> None:
    payload = {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "action": action,
        "results": [r.to_dict() for r in results],
        "total_findings": sum(len(r.findings) for r in results),
        "errors": sum(1 for r in results if r.error),
    }
    print(json.dumps(payload, indent=2))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Strip identifying metadata from documents and images "
                    "before release (PNG/JPEG/PDF). Defensive use only.",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    p.add_argument("--format", choices=("table", "json"), default="table",
                   help="output format (default: table)")

    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("scan", help="report metadata without modifying files")
    sp.add_argument("files", nargs="+")

    cp = sub.add_parser("clean", help="write sanitized copies with metadata removed")
    cp.add_argument("files", nargs="+")
    cp.add_argument("-o", "--output",
                    help="output path (only valid with a single input file)")
    cp.add_argument("--in-place", action="store_true",
                    help="overwrite the input file instead of writing a copy")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "clean" and args.output and len(args.files) > 1:
        print("error: -o/--output requires exactly one input file",
              file=sys.stderr)
        return 2

    results: list[ScrubResult] = []
    for path in args.files:
        if args.command == "scan":
            results.append(scan_file(path))
        else:
            results.append(
                clean_file(path, output_path=args.output,
                           in_place=args.in_place)
            )

    if args.format == "json":
        _print_json(results, args.command)
    else:
        _print_table(results, args.command)

    had_error = any(r.error for r in results)
    had_findings = any(r.findings for r in results)
    # scan: nonzero if anything to clean was found; clean: nonzero only on error.
    if had_error:
        return 1
    if args.command == "scan" and had_findings:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
