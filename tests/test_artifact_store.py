from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from ide_scanner.artifact_store import (
    ArtifactStoreError,
    FilesystemArtifactStore,
    artifact_store_from_environment,
)
from ide_scanner.cli import main


def test_preserve_deduplicates_and_records_platform_observations(tmp_path: Path) -> None:
    source = tmp_path / "download.vsix"
    source.write_bytes(b"PK\x03\x04exact marketplace bytes")
    store = FilesystemArtifactStore(tmp_path / "vault")

    first = store.preserve(source, extension_id="publisher.extension", version="1.2.3",
                           registry="vs-marketplace", target_platform="linux-x64")
    second = store.preserve(source, extension_id="publisher.extension", version="1.2.3",
                            registry="vs-marketplace", target_platform="darwin-x64")

    expected = hashlib.sha256(source.read_bytes()).hexdigest()
    assert first.sha256 == expected == second.sha256
    assert first.size_bytes == source.stat().st_size
    assert first.storage_key == f"sha256/{expected[:2]}/{expected}.vsix"
    assert first.path.read_bytes() == source.read_bytes()
    assert first.path.stat().st_mode & 0o777 == 0o400
    assert (tmp_path / "vault").stat().st_mode & 0o777 == 0o700
    assert (tmp_path / "vault" / "catalog.sqlite3").stat().st_mode & 0o777 == 0o600
    assert len(store.search(sha256=expected)) == 2
    assert store.search(target_platform="linux-x64")[0]["first_seen"] == first.first_seen


def test_repeated_observation_preserves_first_seen_and_updates_last_seen(tmp_path: Path) -> None:
    source = tmp_path / "source.vsix"
    source.write_bytes(b"same artifact")
    store = FilesystemArtifactStore(tmp_path / "vault")
    first = store.preserve(source, extension_id="a.b", version="1", registry="openvsx")
    second = store.preserve(source, extension_id="a.b", version="1", registry="openvsx")
    assert second.first_seen == first.first_seen
    assert second.last_seen >= first.last_seen
    assert len(store.search(extension_id="a.b", version="1", registry="openvsx")) == 1


def test_environment_configuration_is_optional(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("IDE_SCANNER_ARTIFACT_STORE", raising=False)
    assert artifact_store_from_environment() is None
    monkeypatch.setenv("IDE_SCANNER_ARTIFACT_STORE", str(tmp_path / "configured"))
    configured = artifact_store_from_environment()
    assert isinstance(configured, FilesystemArtifactStore)
    assert configured.root == (tmp_path / "configured").resolve()


def test_preserve_rejects_empty_invalid_platform_and_corrupt_object(tmp_path: Path) -> None:
    store = FilesystemArtifactStore(tmp_path / "vault")
    empty = tmp_path / "empty.vsix"
    empty.touch()
    with pytest.raises(ArtifactStoreError, match="empty"):
        store.preserve(empty, extension_id="a.b", version="1", registry="openvsx")

    source = tmp_path / "source.vsix"
    source.write_bytes(b"artifact")
    with pytest.raises(ArtifactStoreError, match="platform"):
        store.preserve(source, extension_id="a.b", version="1", registry="openvsx",
                       target_platform="linux-x64\ninjected=true")
    saved = store.preserve(source, extension_id="a.b", version="1", registry="openvsx")
    os.chmod(saved.path, 0o600)
    saved.path.write_bytes(b"corrupt!")
    with pytest.raises(ArtifactStoreError, match="integrity"):
        store.preserve(source, extension_id="a.b", version="1", registry="openvsx")


def test_artifacts_cli_searches_history(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    source = tmp_path / "source.vsix"
    source.write_bytes(b"artifact")
    store_path = tmp_path / "vault"
    FilesystemArtifactStore(store_path).preserve(
        source, extension_id="a.b", version="1", registry="openvsx", target_platform="linux-x64")
    assert main(["artifacts", "--store", str(store_path), "--extension-id", "a.b"]) == 0
    assert '"storage_key"' in capsys.readouterr().out
