from __future__ import annotations

import hashlib
import os
from pathlib import Path

from ide_scanner import runtime_dependencies


def _manifest() -> dict:
    return {
        "version": "0.0.1",
        "releaseTag": "test-release",
        "contributes": {"languages": [{"id": "rust"}]},
    }


def test_non_rust_extensions_do_not_require_sidecars(tmp_path: Path) -> None:
    target = tmp_path / "extension"
    target.mkdir()
    assert runtime_dependencies.provision_for_extension(target, {"version": "1.0"}) == []


def test_missing_rust_sidecar_is_explicit(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        runtime_dependencies,
        "RUNTIME_DEPENDENCY_LOCK",
        {"rust-analyzer:test-release": {
            "dependency": "rust-analyzer",
            "release_tag": "test-release",
            "version": "0.0.1",
            "platform": "linux-x86_64",
            "binary_sha256": "0" * 64,
            "cache_subpath": "rust-analyzer-test/rust-analyzer",
        }},
    )
    monkeypatch.setenv("GUARDRAILS_RUNTIME_CACHE", str(tmp_path / "cache"))
    result = runtime_dependencies.provision_for_extension(tmp_path / "extension", _manifest())
    assert result[0]["status"] == "missing-cache"
    assert result[0]["required"] is True


def test_rust_sidecar_is_hash_verified_before_copy(tmp_path: Path, monkeypatch) -> None:
    binary = b"guardrails-test-rust-analyzer"
    digest = hashlib.sha256(binary).hexdigest()
    monkeypatch.setattr(
        runtime_dependencies,
        "RUNTIME_DEPENDENCY_LOCK",
        {"rust-analyzer:test-release": {
            "dependency": "rust-analyzer",
            "release_tag": "test-release",
            "version": "0.0.1",
            "platform": "linux-x86_64",
            "binary_sha256": digest,
            "cache_subpath": "rust-analyzer-test/rust-analyzer",
        }},
    )
    cache_path = tmp_path / "cache" / "rust-analyzer-test" / "rust-analyzer"
    cache_path.parent.mkdir(parents=True)
    cache_path.write_bytes(binary)
    monkeypatch.setenv("GUARDRAILS_RUNTIME_CACHE", str(tmp_path / "cache"))

    target = tmp_path / "extension"
    result = runtime_dependencies.provision_for_extension(target, _manifest())

    copied = target / "server" / "rust-analyzer"
    assert result[0]["status"] == "provisioned"
    assert result[0]["sha256"] == digest
    assert copied.read_bytes() == binary
    assert os.access(copied, os.X_OK)


def test_rust_sidecar_hash_mismatch_does_not_execute(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        runtime_dependencies,
        "RUNTIME_DEPENDENCY_LOCK",
        {"rust-analyzer:test-release": {
            "dependency": "rust-analyzer",
            "release_tag": "test-release",
            "version": "0.0.1",
            "platform": "linux-x86_64",
            "binary_sha256": "0" * 64,
            "cache_subpath": "rust-analyzer-test/rust-analyzer",
        }},
    )
    cache_path = tmp_path / "cache" / "rust-analyzer-test" / "rust-analyzer"
    cache_path.parent.mkdir(parents=True)
    cache_path.write_bytes(b"wrong")
    monkeypatch.setenv("GUARDRAILS_RUNTIME_CACHE", str(tmp_path / "cache"))

    result = runtime_dependencies.provision_for_extension(tmp_path / "extension", _manifest())

    assert result[0]["status"] == "cache-hash-mismatch"
    assert not (tmp_path / "extension" / "server" / "rust-analyzer").exists()


def test_packaged_rust_sidecar_is_hash_verified(tmp_path: Path, monkeypatch) -> None:
    binary = b"packaged-but-wrong"
    monkeypatch.setattr(
        runtime_dependencies,
        "RUNTIME_DEPENDENCY_LOCK",
        {"rust-analyzer:test-release": {
            "dependency": "rust-analyzer",
            "release_tag": "test-release",
            "version": "0.0.1",
            "platform": "linux-x86_64",
            "binary_sha256": "0" * 64,
            "cache_subpath": "rust-analyzer-test/rust-analyzer",
        }},
    )
    target = tmp_path / "extension"
    packaged = target / "server" / "rust-analyzer"
    packaged.parent.mkdir(parents=True)
    packaged.write_bytes(binary)
    packaged.chmod(0o755)

    result = runtime_dependencies.provision_for_extension(target, _manifest())

    assert result[0]["status"] == "packaged-hash-mismatch"
    assert result[0]["actual_sha256"] == hashlib.sha256(binary).hexdigest()
