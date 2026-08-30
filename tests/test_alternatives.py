from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

from ide_scanner.alternatives import (
    CAUTION,
    COMMUNITY,
    REPUTABLE,
    UNVETTED,
    assess_candidate,
    find_alternatives,
)


def _recent() -> str:
    return (datetime.now(UTC) - timedelta(days=10)).isoformat()


def _row(**overrides):
    row = {
        "extension_id": "acme.widget",
        "display_name": "Widget",
        "publisher": "acme",
        "publisher_verified": True,
        "install_count": 250_000,
        "rating_average": 4.6,
        "rating_count": 150,
        "last_updated": _recent(),
        "repository": "https://github.com/acme/widget.git",
        "executes_code": True,
    }
    row.update(overrides)
    return row


def _repo(**overrides):
    repo = {
        "found": True,
        "full_name": "acme/widget",
        "archived": False,
        "disabled": False,
        "stargazers_count": 800,
    }
    repo.update(overrides)
    return repo


class AssessCandidateTest(unittest.TestCase):
    def test_verified_publisher_with_healthy_source_is_reputable(self) -> None:
        assessment = assess_candidate(_row(), _repo())

        self.assertEqual(assessment.tier, REPUTABLE)
        self.assertEqual(assessment.score, 95)
        self.assertEqual(assessment.concerns, [])

    def test_unverified_publisher_cannot_reach_reputable(self) -> None:
        assessment = assess_candidate(_row(publisher_verified=False), _repo())

        self.assertEqual(assessment.tier, COMMUNITY)
        self.assertEqual(assessment.score, 70)

    def test_publisher_flag_alone_does_not_confer_verification(self) -> None:
        """The gallery stamps ``flags: verified`` on nearly every publisher, so the
        search row must only carry it through from isDomainVerified."""
        from ide_scanner.registry import _marketplace_publisher_verified

        self.assertFalse(_marketplace_publisher_verified({"flags": "verified", "isDomainVerified": False}))
        self.assertTrue(_marketplace_publisher_verified({"flags": "verified", "isDomainVerified": True}))

    def test_unresolvable_source_on_code_executing_extension_is_caution(self) -> None:
        assessment = assess_candidate(_row(publisher_verified=False), _repo(found=False))

        self.assertEqual(assessment.tier, CAUTION)
        self.assertIn("not auditable", " ".join(assessment.concerns))

    def test_missing_source_repository_is_caution(self) -> None:
        assessment = assess_candidate(_row(publisher_verified=False, repository=""), None)

        self.assertEqual(assessment.tier, CAUTION)
        self.assertIn("cannot be reviewed", " ".join(assessment.concerns))

    def test_high_installs_do_not_offset_absent_provenance(self) -> None:
        """A stale, sourceless extension with heavy adoption must stay low."""
        assessment = assess_candidate(
            _row(
                publisher_verified=False,
                repository="",
                install_count=185_320,
                rating_average=3.0,
                rating_count=5,
                last_updated="2018-05-12T00:00:00Z",
            ),
            None,
        )

        self.assertLess(assessment.score, 20)
        self.assertEqual(assessment.tier, CAUTION)

    def test_withdrawn_extension_scores_zero(self) -> None:
        assessment = assess_candidate(_row(), _repo(), withdrawn=True)

        self.assertEqual(assessment.score, 0)
        self.assertEqual(assessment.tier, CAUTION)

    def test_archived_repository_is_flagged(self) -> None:
        assessment = assess_candidate(_row(publisher_verified=False), _repo(archived=True))

        self.assertIn("archived", " ".join(assessment.concerns))

    def test_ratings_below_threshold_are_not_credited(self) -> None:
        assessment = assess_candidate(_row(rating_average=5.0, rating_count=3), _repo())
        signal = next(item for item in assessment.signals if item.name == "review_confidence")

        self.assertEqual(signal.points, 0)

    def test_unverified_publisher_with_weak_signals_is_unvetted(self) -> None:
        assessment = assess_candidate(
            _row(
                publisher_verified=False,
                install_count=1_200,
                rating_count=0,
                rating_average=0.0,
                last_updated="2022-12-23T00:00:00Z",
            ),
            _repo(stargazers_count=11),
        )

        self.assertEqual(assessment.tier, UNVETTED)


class FindAlternativesGateTest(unittest.TestCase):
    def test_gate_blocks_when_no_candidate_is_reputable(self) -> None:
        rows = [_row(extension_id="solo.plist", publisher_verified=False, repository="")]
        with patch("ide_scanner.alternatives.search_marketplace_extensions", return_value=rows):
            result = find_alternatives("plist", online=False)

        self.assertFalse(result["recommendation_allowed"])
        self.assertEqual(result["qualifying"], [])
        self.assertIn("no reputable option exists", result["advice"])

    def test_gate_opens_for_a_reputable_candidate(self) -> None:
        with patch("ide_scanner.alternatives.search_marketplace_extensions", return_value=[_row()]):
            with patch(
                "ide_scanner.alternatives._fetch_repository_metadata_many",
                return_value=({"https://github.com/acme/widget.git": _repo()}, []),
            ):
                with patch("ide_scanner.alternatives._fetch_removed_packages", return_value=({}, None)):
                    result = find_alternatives("widget")

        self.assertTrue(result["recommendation_allowed"])
        self.assertEqual(result["qualifying"], ["acme.widget"])

    def test_empty_search_reports_no_match_without_crashing(self) -> None:
        with patch("ide_scanner.alternatives.search_marketplace_extensions", return_value=[]):
            result = find_alternatives("nonexistent", online=False)

        self.assertFalse(result["recommendation_allowed"])
        self.assertEqual(result["candidates"], [])
        self.assertIn("No Marketplace extension matched", result["advice"])

    def test_result_declares_metadata_only_depth(self) -> None:
        """The screen must not be mistaken for code analysis."""
        with patch("ide_scanner.alternatives.search_marketplace_extensions", return_value=[]):
            result = find_alternatives("anything", online=False)

        self.assertEqual(result["analysis_depth"], "metadata_only")

    def test_candidates_are_ranked_by_score(self) -> None:
        rows = [
            _row(extension_id="weak.one", publisher_verified=False, repository=""),
            _row(extension_id="strong.two"),
        ]
        with patch("ide_scanner.alternatives.search_marketplace_extensions", return_value=rows):
            with patch(
                "ide_scanner.alternatives._fetch_repository_metadata_many",
                return_value=({"https://github.com/acme/widget.git": _repo()}, []),
            ):
                with patch("ide_scanner.alternatives._fetch_removed_packages", return_value=({}, None)):
                    result = find_alternatives("widget")

        self.assertEqual([item["extension_id"] for item in result["candidates"]], ["strong.two", "weak.one"])


if __name__ == "__main__":
    unittest.main()
