from __future__ import annotations

import json
from dataclasses import asdict

from .checks import Finding, Severity

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
except Exception:  # pragma: no cover
    Console = None
    Table = None
    Panel = None


def findings_to_json(findings: list[Finding]) -> str:
    payload = []
    for f in findings:
        d = asdict(f)
        d["severity"] = str(f.severity)
        payload.append(d)
    return json.dumps({"findings": payload}, indent=2)


def print_findings_console(findings: list[Finding]) -> None:
    if Console is None or Table is None:
        # Fallback plain
        for f in findings:
            print(f"[{f.severity}] {f.title} :: {f.url} (Origin={f.origin})")
            for k, v in f.evidence.items():
                print(f"  {k}: {v}")
            print(f"  {f.description}")
            print(f"  Repro: {f.repro_curl}")
            print("")
        return

    console = Console()
    if not findings:
        console.print(Panel.fit("No CORS findings detected (based on current probes).", title="CORS Scout"))
        return

    table = Table(title="CORS Scout Findings", show_lines=False)
    table.add_column("Severity", style="bold")
    table.add_column("Title", style="bold")
    table.add_column("URL", overflow="fold")
    table.add_column("Origin", overflow="fold")

    sev_style = {
        Severity.HIGH: "bold red",
        Severity.MEDIUM: "bold orange3",
        Severity.LOW: "yellow",
        Severity.INFO: "cyan",
    }

    for f in findings:
        table.add_row(str(f.severity), f.title, f.url, f.origin, style=sev_style.get(f.severity, ""))

    console.print(table)
    console.print()

    # Print details grouped by finding
    for f in findings:
        lines = []
        for k, v in f.evidence.items():
            lines.append(f"[bold]{k}[/bold]: {v}")
        lines.append("")
        lines.append(f"{f.description}")
        lines.append("")
        lines.append(f"[bold]Repro[/bold]: {f.repro_curl}")

        console.print(Panel("\n".join(lines), title=f"{f.severity.upper()} • {f.title}", expand=False))
