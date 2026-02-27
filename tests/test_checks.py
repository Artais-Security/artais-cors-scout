from cors_scout.checks import analyze_results, Severity
from cors_scout.probes import ProbeInput, ProbeResult


def mk(inp: ProbeInput, headers: dict[str, str]) -> ProbeResult:
    return ProbeResult(inp=inp, status_code=200, headers=headers)


def test_credentialed_reflection_high():
    inp = ProbeInput(url="https://t.example/api", origin="https://evil.example")
    r = mk(
        inp,
        {
            "Access-Control-Allow-Origin": "https://evil.example",
            "Access-Control-Allow-Credentials": "true",
            "Vary": "Accept-Encoding",
        },
    )
    findings = analyze_results([r])
    assert any(f.severity == Severity.HIGH and "Credentialed" in f.title for f in findings)


def test_dynamic_without_vary_detected():
    inp = ProbeInput(url="https://t.example/api", origin="https://evil.example")
    r = mk(inp, {"Access-Control-Allow-Origin": "https://evil.example"})
    findings = analyze_results([r])
    assert any("missing Vary" in f.title.lower() for f in findings)
