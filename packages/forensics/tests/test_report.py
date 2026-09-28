from forensics.report import InvestigationReport


def _report(scores: dict[str, float], threshold: float = 10.0) -> InvestigationReport:
    return InvestigationReport(
        scores=scores,
        threshold=threshold,
        eps1=1e-4,
        n_observed=40,
        n_total_positions=147,
        n_erasures=3,
    )


def test_accused_sessions_only_above_threshold() -> None:
    report = _report({"S-0001": 15.0, "S-0002": 5.0, "S-0003": 12.0})
    assert report.accused_sessions == ["S-0001", "S-0003"]


def test_top_session_is_highest_scorer() -> None:
    report = _report({"S-0001": 15.0, "S-0002": 5.0})
    assert report.top_session == "S-0001"


def test_summary_reports_insufficient_evidence_when_nothing_clears_threshold() -> None:
    report = _report({"S-0001": 3.0, "S-0002": -1.0})
    summary = report.summary()
    assert "Insufficient evidence" in summary


def test_summary_names_top_session_and_any_additional_accused() -> None:
    report = _report({"S-0001": 15.0, "S-0002": 12.0, "S-0003": 5.0})
    summary = report.summary()
    assert "S-0001" in summary
    assert "S-0002" in summary
    assert "S-0003" not in summary
