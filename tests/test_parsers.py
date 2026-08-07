from pathlib import Path

from pentest.parsers import parse_nmap, parse_nuclei

REPO = Path(__file__).resolve().parents[1]


def test_parse_nuclei_returns_normalized_findings():
    findings = parse_nuclei(REPO / "samples" / "nuclei.jsonl")
    assert len(findings) == 12
    # All have the standard fields
    for f in findings:
        assert {
            "id",
            "title",
            "severity",
            "host",
            "scanner",
            "template_id",
            "raw",
        } <= set(f)
        assert f["scanner"] == "nuclei"
        assert f["severity"] in {"info", "low", "medium", "high", "critical"}


def test_parse_nuclei_finds_critical_xz_backdoor():
    findings = parse_nuclei(REPO / "samples" / "nuclei.jsonl")
    critical = [f for f in findings if f["severity"] == "critical"]
    assert any("xz-utils" in f["title"].lower() for f in critical)


def test_parse_nmap_flags_exposed_mysql_as_high():
    findings = parse_nmap(REPO / "samples" / "nmap.xml")
    sev_by_title = {f["title"]: f["severity"] for f in findings}
    mysql_keys = [k for k in sev_by_title if "MYSQL" in k.upper()]
    assert mysql_keys
    assert sev_by_title[mysql_keys[0]] == "high"


def test_parse_nmap_flags_outdated_openssh():
    findings = parse_nmap(REPO / "samples" / "nmap.xml")
    outdated = [
        f
        for f in findings
        if "outdated" in f["title"].lower() and "openssh" in f["title"].lower()
    ]
    assert outdated
    assert outdated[0]["severity"] in ("low", "medium")
