from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

import httpx


@dataclass(frozen=True)
class ProbeInput:
    url: str
    origin: str
    method: str = "GET"
    # If preflight, we set OPTIONS and include Access-Control-Request-* headers
    preflight: bool = False
    acr_method: str = "GET"
    acr_headers: str = "authorization, content-type"


@dataclass
class ProbeResult:
    inp: ProbeInput
    status_code: int
    headers: dict[str, str]
    # we keep small body sample for debugging; not used in checks
    body_sample: str = ""

    @property
    def header(self) -> dict[str, str]:
        return {k.lower(): v for k, v in self.headers.items()}


async def run_probe(
    client: httpx.AsyncClient,
    inp: ProbeInput,
    timeout: float = 10.0,
) -> ProbeResult:
    headers = {"Origin": inp.origin}

    method = inp.method
    if inp.preflight:
        method = "OPTIONS"
        headers.update(
            {
                "Access-Control-Request-Method": inp.acr_method,
                "Access-Control-Request-Headers": inp.acr_headers,
            }
        )

    # Keep it safe: do not send credentials/cookies by default.
    resp = await client.request(
        method,
        inp.url,
        headers=headers,
        timeout=timeout,
        follow_redirects=True,
    )

    body = ""
    try:
        # small sample only
        text = resp.text
        body = text[:200]
    except Exception:
        body = ""

    return ProbeResult(
        inp=inp,
        status_code=resp.status_code,
        headers=dict(resp.headers),
        body_sample=body,
    )


def build_default_origins(hostname: str) -> list[str]:
    # High-signal origin set; keep small and relevant
    return [
        "https://evil.example",
        f"https://{hostname}.evil.example",
        "null",
        "http://localhost:3000",
        "file://",
    ]


def build_probe_set(url: str, origins: Iterable[str]) -> list[ProbeInput]:
    probes: list[ProbeInput] = []
    for o in origins:
        # Simple
        probes.append(ProbeInput(url=url, origin=o, method="GET", preflight=False))
        # Preflight for “interesting” headers/methods
        probes.append(
            ProbeInput(
                url=url,
                origin=o,
                method="OPTIONS",
                preflight=True,
                acr_method="PUT",
                acr_headers="authorization, content-type, x-requested-with",
            )
        )
    return probes
