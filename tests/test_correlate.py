import time
from datetime import UTC, datetime, timedelta

import pytest

from clawshield.core.correlate import correlate
from clawshield.core.models import Severity, TargetResult, Verdict

T0 = datetime(2026, 10, 6, 12, 0, 0, tzinfo=UTC)


def s(seconds: float) -> datetime:
    return T0 + timedelta(seconds=seconds)


def result(case_id: str, sent: float, received: float, session: str | None = None) -> TargetResult:
    return TargetResult(
        case_id=case_id, session_id=session, sent_at=s(sent), received_at=s(received),
        response_text="ok",
    )  # fmt: skip


def verdict(
    vid: str, at: float, session: str | None = None, connector: str = "openclaw"
) -> Verdict:
    return Verdict(
        id=vid, source="test", ts=s(at), connector=connector, direction="prompt",
        severity=Severity.HIGH, action="alert", session_id=session,
    )  # fmt: skip


def by_case(report: object) -> dict[str, tuple[str, tuple[str, ...], tuple[str, ...]]]:
    return {
        c.case_id: (c.method, c.verdict_ids, c.ambiguous_verdict_ids)
        for c in report.cases  # type: ignore[attr-defined]
    }


# --- session -------------------------------------------------------------------------------


def test_session_match_wins_over_time() -> None:
    results = [result("a", 0, 1, "sa"), result("b", 2, 3, "sb")]
    # v1 sits in b's time window but carries a's session id: it belongs to a.
    report = correlate(results, [verdict("v1", 2.5, "sa"), verdict("v2", 2.6, "sb")], grace_s=0)
    assert by_case(report) == {"a": ("session", ("v1",), ()), "b": ("session", ("v2",), ())}


def test_session_less_verdict_in_overlap_with_session_case_is_ambiguous() -> None:
    # Review finding: a's completion verdict logged without a session id lands in the
    # overlap with b. It must not be credited to b as a clean time_window match.
    results = [result("a", 0, 1, "sa"), result("b", 0.5, 1.5)]
    verdicts = [verdict("a-prompt", 0.2, "sa"), verdict("a-completion", 1.0)]
    report = correlate(results, verdicts, grace_s=1)
    assert by_case(report) == {
        "a": ("ambiguous", ("a-prompt",), ("a-completion",)),
        "b": ("ambiguous", (), ("a-completion",)),
    }


def test_session_less_verdict_only_in_session_case_window_is_kept() -> None:
    results = [result("a", 0, 1, "sa"), result("b", 10, 11)]
    verdicts = [verdict("a-completion", 1.5), verdict("a-prompt", 0.2, "sa")]
    report = correlate(results, verdicts, grace_s=1)
    assert by_case(report)["a"] == ("session", ("a-prompt", "a-completion"), ())
    assert report.unattributed_verdict_ids == ()


def test_shared_session_id_is_not_used_for_matching() -> None:
    results = [result("a", 0, 1, "same"), result("b", 10, 11, "same")]
    report = correlate(
        results, [verdict("v1", 0.5, "same"), verdict("v2", 10.5, "same")], grace_s=1
    )
    assert by_case(report) == {
        "a": ("time_window", ("v1",), ()),
        "b": ("time_window", ("v2",), ()),
    }


def test_foreign_session_verdict_falls_back_to_time_window() -> None:
    report = correlate([result("a", 0, 1, "sa")], [verdict("v1", 0.5, "other")], grace_s=1)
    assert by_case(report)["a"] == ("time_window", ("v1",), ())


# --- time windows ----------------------------------------------------------------------------


def test_window_bounds_are_inclusive_with_pre_and_grace() -> None:
    results = [result("a", 10, 11)]
    verdicts = [verdict("early", 9.0), verdict("late", 14.0), verdict("too-early", 8.99)]
    report = correlate(results, verdicts, grace_s=3, pre_s=1)
    assert by_case(report)["a"] == ("time_window", ("early", "late"), ())
    assert report.unattributed_verdict_ids == ("too-early",)


def test_overlapping_windows_mark_ambiguous_and_credit_nobody() -> None:
    # Shipped defaults: grace 3s, delay 1.5s -> neighbouring windows overlap.
    results = [result("a", 0, 1), result("b", 2.5, 3.5)]
    verdicts = [verdict("only-a", 0.5), verdict("overlap", 3.0), verdict("only-b", 5.0)]
    report = correlate(results, verdicts, grace_s=3)
    assert by_case(report) == {
        "a": ("ambiguous", ("only-a",), ("overlap",)),
        "b": ("ambiguous", ("only-b",), ("overlap",)),
    }
    assert report.coverage == 0.0
    assert report.by_method == {"session": 0, "time_window": 0, "ambiguous": 2, "none": 0}


def test_non_overlapping_windows_correlate_cleanly() -> None:
    # Recommended: inter-case delay >= grace + pre, so windows never overlap.
    results = [result(f"c{i}", i * 6, i * 6 + 1) for i in range(5)]
    verdicts = [verdict(f"v{i}", i * 6 + 0.5) for i in range(5)]
    report = correlate(results, verdicts, grace_s=3)
    assert report.coverage == 1.0
    assert all(c.method == "time_window" and c.verdict_ids == (f"v{i}",)
               for i, c in enumerate(report.cases))  # fmt: skip


def test_case_with_no_verdict_is_none() -> None:
    report = correlate([result("benign", 0, 1)], [], grace_s=3)
    assert by_case(report)["benign"] == ("none", (), ())
    assert report.coverage == 0.0 and report.unattributed_verdict_ids == ()


def test_multiple_verdicts_per_case_in_time_order() -> None:
    verdicts = [verdict("completion", 1.5), verdict("prompt", 0.2), verdict("tool", 0.9)]
    report = correlate([result("a", 0, 1)], verdicts, grace_s=1)
    assert by_case(report)["a"][1] == ("prompt", "tool", "completion")


def test_other_connectors_ignored_when_filtered() -> None:
    verdicts = [verdict("mine", 0.5), verdict("theirs", 0.6, connector="claudecode")]
    report = correlate([result("a", 0, 1)], verdicts, grace_s=1, connector="openclaw")
    assert by_case(report)["a"] == ("time_window", ("mine",), ())
    assert report.unattributed_verdict_ids == ()


def test_unsorted_inputs_and_long_windows() -> None:
    # A slow case (long window) earlier in the list must still be found by the bisect search.
    results = [result("fast", 100, 100.1), result("slow", 0, 60)]
    report = correlate(results, [verdict("v-slow", 59.0), verdict("v-fast", 100.05)], grace_s=0.5)
    assert by_case(report) == {
        "fast": ("time_window", ("v-fast",), ()),
        "slow": ("time_window", ("v-slow",), ()),
    }


def test_output_order_follows_results() -> None:
    results = [result("z", 20, 21), result("a", 0, 1)]
    assert [c.case_id for c in correlate(results, [], grace_s=1).cases] == ["z", "a"]


# --- input validation + performance -------------------------------------------------------


def test_duplicate_case_ids_rejected() -> None:
    with pytest.raises(ValueError, match="duplicate case ids"):
        correlate([result("a", 0, 1), result("a", 2, 3)], [], grace_s=1)


@pytest.mark.parametrize(("grace", "pre"), [(-1, 1), (1, -0.1)])
def test_negative_windows_rejected(grace: float, pre: float) -> None:
    with pytest.raises(ValueError, match=">= 0"):
        correlate([], [], grace_s=grace, pre_s=pre)


def test_empty_inputs() -> None:
    report = correlate([], [verdict("v", 0)], grace_s=1)
    assert report.cases == () and report.coverage == 0.0
    assert report.unattributed_verdict_ids == ("v",)


def test_scales_to_large_runs() -> None:
    results = [result(f"c{i}", i * 5, i * 5 + 1) for i in range(5000)]
    verdicts = [verdict(f"v{i}-{k}", i * 5 + 0.1 * k) for i in range(5000) for k in range(4)]
    started = time.monotonic()
    report = correlate(results, verdicts, grace_s=3)
    assert time.monotonic() - started < 5
    assert report.coverage == 1.0


# --- attribution rate (review finding 2) ------------------------------------------------------


def test_attribution_rate_is_not_lowered_by_verdictless_cases() -> None:
    # Benign cases with no verdict cut case coverage but not verdict attribution.
    results = [result("attack", 0, 1), *(result(f"benign{i}", 10 * (i + 1), 10 * (i + 1) + 1)
                                          for i in range(4))]  # fmt: skip
    report = correlate(results, [verdict("v", 0.5)], grace_s=1)
    assert report.coverage == 0.2
    assert report.attribution_rate == 1.0


def test_attribution_rate_counts_ambiguous_and_unattributed() -> None:
    results = [result("a", 0, 1), result("b", 0.5, 1.5)]
    verdicts = [verdict("clean", 0.0), verdict("overlap", 1.0), verdict("stray", 50)]
    report = correlate(results, verdicts, grace_s=1)
    # Windows a=[-1, 2] and b=[-0.5, 2.5] overlap, so "clean" (t=0) and "overlap" (t=1)
    # are both ambiguous and "stray" (t=50) is unattributed: nothing is credited.
    assert report.attribution_rate == 0.0
    late = correlate([result("a", 0, 1), result("b", 10, 11)], verdicts, grace_s=1)
    assert late.attribution_rate == 2 / 3  # clean + overlap credited to a; stray unattributed


def test_attribution_rate_with_no_verdicts() -> None:
    assert correlate([result("a", 0, 1)], [], grace_s=1).attribution_rate == 1.0
