from __future__ import annotations

import hashlib
from pathlib import Path, PurePosixPath
from typing import Any
from zipfile import BadZipFile, ZipFile, ZipInfo


MAX_ARCHIVE_MEMBERS = 20_000
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 512 * 1024 * 1024
MAX_REPORTED_PATHS = 100


def compare_source_to_vsix(source: Path | str, vsix: Path | str) -> dict[str, Any]:
    """Compare source files with the published VSIX payload without extraction.

    This is provenance evidence, not a build reproducibility claim. Source-only
    files are common because packaging rules omit tests and development assets;
    artifact-only and changed files are the rows that deserve review.
    """
    source_root = Path(source).expanduser().resolve()
    vsix_path = Path(vsix).expanduser().resolve()
    if not source_root.is_dir():
        raise ValueError("Source comparison requires a readable source directory.")
    if not vsix_path.is_file() or vsix_path.suffix.lower() != ".vsix":
        raise ValueError("Source comparison requires a .vsix file.")

    source_files, skipped_symlinks = _source_files(source_root)
    try:
        with ZipFile(vsix_path) as archive:
            artifact_files, ignored_members = _artifact_members(archive)
            common = sorted(set(source_files) & set(artifact_files))
            changed: list[dict[str, str]] = []
            matching = 0
            for relative in common:
                source_digest = _file_sha256(source_files[relative])
                artifact_digest = _member_sha256(archive, artifact_files[relative])
                if source_digest == artifact_digest:
                    matching += 1
                else:
                    changed.append({"path": relative, "source_sha256": source_digest, "artifact_sha256": artifact_digest})
    except BadZipFile as exc:
        raise ValueError("Source comparison requires a valid VSIX ZIP archive.") from exc

    source_only = sorted(set(source_files) - set(artifact_files))
    artifact_only = sorted(set(artifact_files) - set(source_files))
    return {
        "schema_version": "1",
        "source": {"path": str(source_root), "file_count": len(source_files), "skipped_symlink_count": skipped_symlinks},
        "artifact": {
            "path": str(vsix_path),
            "sha256": _file_sha256(vsix_path),
            "extension_file_count": len(artifact_files),
            "ignored_member_count": ignored_members,
        },
        "comparison": {
            "common_file_count": len(common),
            "matching_file_count": matching,
            "changed_file_count": len(changed),
            "source_only_file_count": len(source_only),
            "artifact_only_file_count": len(artifact_only),
            "changed_files": changed[:MAX_REPORTED_PATHS],
            "source_only_files": source_only[:MAX_REPORTED_PATHS],
            "artifact_only_files": artifact_only[:MAX_REPORTED_PATHS],
            "path_list_truncated": any(len(items) > MAX_REPORTED_PATHS for items in (changed, source_only, artifact_only)),
        },
    }


def _source_files(root: Path) -> tuple[dict[str, Path], int]:
    files: dict[str, Path] = {}
    skipped_symlinks = 0
    for path in root.rglob("*"):
        if ".git" in path.relative_to(root).parts:
            continue
        if path.is_symlink():
            skipped_symlinks += 1
            continue
        if not path.is_file():
            continue
        files[path.relative_to(root).as_posix()] = path
    return files, skipped_symlinks


def _artifact_members(archive: ZipFile) -> tuple[dict[str, ZipInfo], int]:
    infos = archive.infolist()
    if len(infos) > MAX_ARCHIVE_MEMBERS:
        raise ValueError(f"VSIX has more than {MAX_ARCHIVE_MEMBERS} archive members.")
    if sum(info.file_size for info in infos) > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
        raise ValueError("VSIX exceeds the 512 MiB source-comparison size limit.")
    files: dict[str, ZipInfo] = {}
    ignored = 0
    for info in infos:
        if info.is_dir():
            continue
        name = info.filename.replace("\\", "/")
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("VSIX contains an unsafe archive member path.")
        mode = (info.external_attr >> 16) & 0o170000
        if mode == 0o120000:
            raise ValueError("VSIX contains a symbolic-link archive member.")
        if not name.startswith("extension/"):
            ignored += 1
            continue
        relative = name.removeprefix("extension/")
        if not relative:
            continue
        if relative in files:
            raise ValueError("VSIX contains duplicate extension payload paths.")
        files[relative] = info
    return files, ignored


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _member_sha256(archive: ZipFile, info: ZipInfo) -> str:
    digest = hashlib.sha256()
    with archive.open(info) as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()
