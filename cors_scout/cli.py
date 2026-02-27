from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import httpx

from .checks import analyze_results
from .probes import build_default_origins, build_probe_set, run_probe
from .report import findings_to_json, print_findings_console
from .util import host_from_url, join_url, normalize_base_url


@dataclass
class Target:
    base: str
    urls: list[str]


def parse_paths(paths: str) -> list[str]:
    raw = [p.strip() for p in (paths or "").split(",") if p.strip()]
    if not raw:
        return ["/"]
    return raw


def load_targets(single: str | None, infile: str | None, paths: list[str]) -> list[Target]:
    bases: list[str] = []
    if single:
        bases.append(normalize_base_url(single))
    if infile:
        for line in Path(infile).read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            bases.append(normalize_base_url(line))

    # De-dupe
    bases = sorted(set([b for b in bases if b]))

    targets: list[Target] = []
    for b in bases:
        urls = [join_url(b, p) for p in paths]
        targets.append(Target(base=b, urls=urls))
    return targets


async def worker(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    url: str,
    origins: list[str],
    timeout: float,
):
    async with sem:
        probes = build_probe_set(url, origins)
        results = []
        for inp in probes:
            try:
                results.append(await run_probe(client, inp, timeout=timeout))
            except httpx.RequestError:
                # swallow; target may be flaky
                continue
        return results


async def run_scan(
    targets: list[Target],
    concurrency: int,
    timeout: float,
    insecure: bool,
    origins_override: list[str] | None,
) -> list:
    limits = httpx.Limits(max_keepalive_connections=concurrency, max_connections=concurrency)
    verify = not insecure

    async with httpx.AsyncClient(limits=limits, verify=verify, headers={"User-Agent": "artais-cors-scout/0.1.0"}) as client:
        sem = asyncio.Semaphore(concurrency)
        all_results = []

        tasks = []
        for t in targets:
            hostname = host_from_url(t.base)
            origins = origins_override or build_default_origins(hostname)
            for url in t.urls:
                tasks.append(worker(client, sem, url, origins, timeout))

        for coro in asyncio.as_completed(tasks):
            batch = await coro
            if batch:
                all_results.extend(batch)

        return all_results


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cors-scout",
        description="High-signal CORS misconfiguration and preflight auditor.",
    )
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("-u", "--url", help="Single base URL or host (e.g., https://example.com or example.com)")
    g.add_argument("-i", "--input", help="File with base URLs/hosts, one per line")

    p.add_argument("--paths", default="/", help="Comma-separated paths to test (default: /). Example: /api,/graphql")
    p.add_argument("--origin", action="append", dest="origins", help="Override/add Origin(s) to test (repeatable).")
    p.add_argument("-c", "--concurrency", type=int, default=50, help="Max concurrent requests (default: 50)")
    p.add_argument("-t", "--timeout", type=float, default=10.0, help="Request timeout seconds (default: 10)")
    p.add_argument("-k", "--insecure", action="store_true", help="Disable TLS verification")
    p.add_argument("--json", dest="json_out", help="Write JSON results to file (or '-' for stdout)")
    return p


def main() -> None:
    args = build_arg_parser().parse_args()

    paths = parse_paths(args.paths)
    targets = load_targets(args.url, args.input, paths)

    origins_override = None
    if args.origins:
        # if user passed any --origin, use exactly those (can include multiple)
        origins_override = args.origins

    results = asyncio.run(
        run_scan(
            targets=targets,
            concurrency=max(1, args.concurrency),
            timeout=max(1.0, args.timeout),
            insecure=bool(args.insecure),
            origins_override=origins_override,
        )
    )

    findings = analyze_results(results)

    # JSON output optional
    if args.json_out:
        out = findings_to_json(findings)
        if args.json_out.strip() == "-":
            print(out)
        else:
            Path(args.json_out).write_text(out, encoding="utf-8")

    # Console output
    print_findings_console(findings)
