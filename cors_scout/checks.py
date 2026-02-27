from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Optional

from .probes import ProbeResult
from .util import safe_lower


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class Finding:
    severity: Severity
    title: str
    url: str
    origin: str
    evidence: dict[str, str]
    description: str
    repro_curl: str


def _curl_repro(result: ProbeResult) -> str:
    h = result.header
    origin = result.inp.origin.replace('"', '\\"')
    if result.inp.preflight:
        acrm = result.inp.acr_method.replace('"', '\\"')
        acrh = result.inp.acr_headers.replace('"', '\\"')
        return (
            f'curl -i -s -X OPTIONS "{result.inp.url}" '
            f'-H "Origin: {origin}" '
            f'-H "Access-Control-Request-Method: {acrm}" '
            f'-H "Access-Control-Request-Headers: {acrh}"'
        )
    return f'curl -i -s "{result.inp.url}" -H "Origin: {origin}"'


def _get(h: dict[str, str], name: str) -> str:
    return h.get(name.lower(), "").strip()


def analyze_results(results: Iterable[ProbeResult]) -> list[Finding]:
    findings: list[Finding] = []

    for r in results:
        h = r.header
        acao = _get(h, "access-control-allow-origin")
        acac = _get(h, "access-control-allow-credentials")
        vary = _get(h, "vary")
        acam = _get(h, "access-control-allow-methods")
        acah = _get(h, "access-control-allow-headers")
        aceh = _get(h, "access-control-expose-headers")

        origin = r.inp.origin
        url = r.inp.url

        # Skip if no CORS headers at all (common and not a finding)
        if not acao and not acac and not acam and not acah:
            continue

        # 1) Wildcard + credentials (should be invalid, but seen in weird stacks/proxies)
        if acao == "*" and safe_lower(acac) == "true":
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    title="Wildcard ACAO with Credentials",
                    url=url,
                    origin=origin,
                    evidence={
                        "access-control-allow-origin": acao,
                        "access-control-allow-credentials": acac,
                    },
                    description=(
                        "Server returns Access-Control-Allow-Origin: * together with "
                        "Access-Control-Allow-Credentials: true. Browsers should reject this, "
                        "but it often indicates broken/unsafe CORS logic and can be exploitable "
                        "via intermediaries or misbehaving clients."
                    ),
                    repro_curl=_curl_repro(r),
                )
            )

        # 2) Reflected origin (exact match)
        if acao and acao == origin:
            # If credentials also allowed, this is often high impact
            if safe_lower(acac) == "true":
                sev = Severity.HIGH
                title = "Credentialed Reflected Origin"
                desc = (
                    "Server reflects the supplied Origin and allows credentials. "
                    "This can allow a malicious site to read authenticated responses "
                    "from the victim's browser if cookies/session are used."
                )
            else:
                sev = Severity.MEDIUM
                title = "Reflected Origin"
                desc = (
                    "Server reflects the supplied Origin. If sensitive endpoints are accessible, "
                    "this may allow cross-origin reads from attacker-controlled origins. "
                    "Impact increases significantly if credentials are allowed."
                )

            findings.append(
                Finding(
                    severity=sev,
                    title=title,
                    url=url,
                    origin=origin,
                    evidence={
                        "access-control-allow-origin": acao,
                        "access-control-allow-credentials": acac or "(absent)",
                    },
                    description=desc,
                    repro_curl=_curl_repro(r),
                )
            )

            # 3) Dynamic ACAO without Vary: Origin (cache poisoning / mix-up risk)
            # Heuristic: if it matches our origin and doesn't mention Origin in Vary.
            if vary and "origin" not in safe_lower(vary):
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        title="Dynamic ACAO without Vary: Origin",
                        url=url,
                        origin=origin,
                        evidence={
                            "access-control-allow-origin": acao,
                            "vary": vary,
                        },
                        description=(
                            "Response appears to set ACAO dynamically (reflects Origin) but "
                            "does not include 'Vary: Origin'. This can cause shared caches/CDNs "
                            "to serve a response with an attacker-origin ACAO to other clients."
                        ),
                        repro_curl=_curl_repro(r),
                    )
                )
            elif not vary:
                findings.append(
                    Finding(
                        severity=Severity.LOW,
                        title="Dynamic ACAO with missing Vary header",
                        url=url,
                        origin=origin,
                        evidence={
                            "access-control-allow-origin": acao,
                            "vary": "(absent)",
                        },
                        description=(
                            "Response reflects Origin but 'Vary' header is absent. "
                            "If any caching layer is involved, consider adding 'Vary: Origin'."
                        ),
                        repro_curl=_curl_repro(r),
                    )
                )

        # 4) Null origin acceptance can be risky (sandboxed iframes / file origins)
        if acao == "null" or (acao and safe_lower(acao) == "null"):
            findings.append(
                Finding(
                    severity=Severity.MEDIUM if safe_lower(acac) == "true" else Severity.LOW,
                    title="Allows 'null' Origin",
                    url=url,
                    origin=origin,
                    evidence={
                        "access-control-allow-origin": acao,
                        "access-control-allow-credentials": acac or "(absent)",
                    },
                    description=(
                        "Server allows Origin 'null'. This can be abused from sandboxed iframes "
                        "or certain opaque origins. If sensitive data is returned, restrict "
                        "to explicit trusted origins."
                    ),
                    repro_curl=_curl_repro(r),
                )
            )

        # 5) Preflight vs simple inconsistencies (informational / triage helper)
        if r.inp.preflight:
            # If server allows methods/headers broadly, point it out.
            if acam and ("*" in acam or "put" in safe_lower(acam)):
                findings.append(
                    Finding(
                        severity=Severity.INFO,
                        title="Preflight allows PUT (or wildcard methods)",
                        url=url,
                        origin=origin,
                        evidence={
                            "access-control-allow-methods": acam,
                            "access-control-allow-headers": acah or "(absent)",
                        },
                        description=(
                            "Preflight response indicates PUT is allowed (or methods wildcard). "
                            "Verify that state-changing endpoints are protected and CORS is constrained "
                            "to trusted origins."
                        ),
                        repro_curl=_curl_repro(r),
                    )
                )

        # 6) Exposed headers (info)
        if aceh:
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    title="Exposes response headers to JS",
                    url=url,
                    origin=origin,
                    evidence={"access-control-expose-headers": aceh},
                    description=(
                        "Response uses Access-Control-Expose-Headers. This is not inherently bad, "
                        "but increases what attacker JS could read if CORS is misconfigured."
                    ),
                    repro_curl=_curl_repro(r),
                )
            )

    # De-dupe: same title/url/origin (keep first)
    seen: set[tuple[str, str, str]] = set()
    unique: list[Finding] = []
    for f in findings:
        key = (f.title, f.url, f.origin)
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)

    # Sort by severity
    order = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2, Severity.INFO: 3}
    unique.sort(key=lambda x: (order.get(x.severity, 9), x.title))
    return unique
