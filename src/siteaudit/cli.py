from __future__ import annotations

import argparse
import sys
from urllib.parse import urlsplit

from . import __version__
from .core import REGISTRY
from .http import fetch
from .models import Severity
from .report import RENDERERS
from .scanner import scan

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="siteaudit",
        description="Audit a web application for common security misconfigurations. "
                    "Only scan systems you own or are authorized to test.")
    p.add_argument("url", help="target URL (https:// is assumed if no scheme is given)")
    p.add_argument("-f", "--format", choices=sorted(RENDERERS), default="text")
    p.add_argument("-o", "--output", help="write the report to a file instead of stdout")
    p.add_argument("--fail-on", default="medium", metavar="SEVERITY",
                   help="exit 1 if any finding is at or above this severity "
                        "(info|low|medium|high|critical|none). Default: medium")
    p.add_argument("--checks", help=f"comma-separated subset of: {', '.join(sorted(REGISTRY))}")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--delay", type=float, default=0.0, help="seconds to wait between probes")
    p.add_argument("--insecure", action="store_true", help="do not verify TLS for page fetches")
    p.add_argument("--authorized", action="store_true",
                   help="confirm you are authorized to test a non-local target")
    p.add_argument("--version", action="version", version=f"siteaudit {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    target = args.url if "://" in args.url else f"https://{args.url}"
    host = urlsplit(target).hostname or ""

    if host not in LOCAL_HOSTS and not args.authorized:
        print("Refusing to scan a non-local target without --authorized.\n"
              "Only test systems you own or have written permission to test.", file=sys.stderr)
        return 2

    only = [c.strip() for c in args.checks.split(",")] if args.checks else None
    if only and (unknown := set(only) - set(REGISTRY)):
        print(f"Unknown check(s): {', '.join(sorted(unknown))}", file=sys.stderr)
        return 2
    try:
        threshold = None if args.fail_on.lower() == "none" else Severity.parse(args.fail_on)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2

    base = fetch(target, timeout=args.timeout, verify=not args.insecure)
    if base is None:
        print(f"Could not connect to {target}. If the certificate is invalid, "
              "retry with --insecure.", file=sys.stderr)
        return 3

    result = scan(target, base, only=only, timeout=args.timeout,
                  verify=not args.insecure, delay=args.delay)
    report = RENDERERS[args.format](result)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report)
        print(f"Wrote {args.format} report to {args.output} "
              f"({len(result.findings)} findings)", file=sys.stderr)
    else:
        print(report)

    if threshold is not None and any(f.severity >= threshold for f in result.findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())