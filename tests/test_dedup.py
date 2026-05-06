from pentest.dedup import group_findings, severity_summary


def _f(template, sev, host, **kw):
    return {
        "id": f"{template}-{host}",
        "title": kw.get("title", template),
        "severity": sev,
        "host": host,
        "path": kw.get("path", "/"),
        "scanner": kw.get("scanner", "nuclei"),
        "template_id": template,
        "raw": kw.get("raw", {}),
    }


def test_dedup_collapses_same_template_across_hosts():
    findings = [
        _f("missing-headers", "info", "a.example.com"),
        _f("missing-headers", "info", "b.example.com"),
        _f("missing-headers", "info", "c.example.com"),
    ]
    grouped = group_findings(findings)
    assert len(grouped) == 1
    assert len(grouped[0]["affected_hosts"]) == 3


def test_dedup_keeps_different_severities_separate():
    findings = [
        _f("template-A", "high", "a.example.com"),
        _f("template-A", "medium", "b.example.com"),
    ]
    assert len(group_findings(findings)) == 2


def test_dedup_orders_by_severity_then_count():
    findings = [
        _f("low-1", "low", "a.example.com"),
        _f("low-1", "low", "b.example.com"),
        _f("high-1", "high", "x.example.com"),
        _f("crit-1", "critical", "y.example.com"),
    ]
    grouped = group_findings(findings)
    assert grouped[0]["severity"] == "critical"
    assert grouped[1]["severity"] == "high"
    assert grouped[2]["severity"] == "low"


def test_severity_summary_counts():
    findings = [
        _f("a", "high", "x"),
        _f("b", "medium", "x"),
        _f("c", "medium", "y"),
    ]
    grouped = group_findings(findings)
    counts = severity_summary(grouped)
    assert counts["high"] == 1
    assert counts["medium"] == 2
    assert counts["critical"] == 0
