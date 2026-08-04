from unittest.mock import sentinel, patch

from ide_scanner.core import ScanRequest, run_scan


def test_run_scan_forwards_exact_marketplace_identity_and_store() -> None:
    request = ScanRequest(
        marketplace_scan_ids=["publisher.extension"], marketplace_version="1.2.3",
        marketplace_target_platform="linux-x64", marketplace_artifact_store=sentinel.store,
    )
    with patch("ide_scanner.core.scan_targets", return_value={"extensions": []}) as scan:
        assert run_scan(request) == {"extensions": []}

    assert scan.call_args.kwargs["marketplace_version"] == "1.2.3"
    assert scan.call_args.kwargs["marketplace_target_platform"] == "linux-x64"
    assert scan.call_args.kwargs["marketplace_artifact_store"] is sentinel.store
