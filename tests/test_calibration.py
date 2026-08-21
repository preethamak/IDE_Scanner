from __future__ import annotations

import copy

import pytest

from ide_scanner.calibration import (
    _validate_calibration,
    calibrated_score,
    policy_version,
    scoring_calibration,
)


def test_packaged_calibration_is_valid_and_versioned() -> None:
    calibration = scoring_calibration()

    _validate_calibration(calibration)
    assert calibration["schema_version"] == "1"
    assert policy_version() == "3.1.0-calibration.2"


def test_authoritative_and_heuristic_scores_stay_below_their_safety_gates() -> None:
    assert calibrated_score("confirmed_intelligence", "known-bad-artifact") == 100
    assert calibrated_score("confirmed_intelligence", "malicious-npm-dependency") >= 90
    assert calibrated_score("correlated_behavior", "credential-exfiltration-chain") < 90
    assert calibrated_score("proven_observed_behavior", "observed-secret-exfil") < 90


@pytest.mark.parametrize("score", [-1, 101, True, 3.5, "90"])
def test_invalid_calibration_scores_fail_closed(score: object) -> None:
    calibration = copy.deepcopy(scoring_calibration())
    calibration["components"]["correlated_behavior"]["credential-exfiltration-chain"] = score

    with pytest.raises(ValueError, match="integer from 0 to 100"):
        _validate_calibration(calibration)


def test_missing_calibration_component_fails_closed() -> None:
    calibration = copy.deepcopy(scoring_calibration())
    del calibration["components"]["confirmed_intelligence"]

    with pytest.raises(ValueError, match="missing components"):
        _validate_calibration(calibration)
