from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

TARGET_PLATFORM_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")


class ArtifactStoreError(RuntimeError):
    pass


@dataclass(frozen=True)
class StoredArtifact:
    path: Path
    backend: str
    storage_key: str
    sha256: str
    size_bytes: int
    extension_id: str
    version: str
    registry: str
    target_platform: str
    first_seen: str
    last_seen: str


class ArtifactStore(Protocol):
    def preserve(self, source: Path, *, extension_id: str, version: str, registry: str,
                 target_platform: str = "") -> StoredArtifact: ...


class FilesystemArtifactStore:
    """Private, content-addressed VSIX vault with an observation catalog."""

    def __init__(self, root: Path | str):
        self.root = Path(root).expanduser().resolve()
        self.objects = self.root / "sha256"
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.objects.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)
        os.chmod(self.objects, 0o700)
        self.catalog = self.root / "catalog.sqlite3"
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.catalog)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS artifacts (
                    sha256 TEXT PRIMARY KEY, size_bytes INTEGER NOT NULL,
                    storage_key TEXT NOT NULL UNIQUE, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS observations (
                    extension_id TEXT NOT NULL, version TEXT NOT NULL, registry TEXT NOT NULL,
                    target_platform TEXT NOT NULL, sha256 TEXT NOT NULL,
                    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
                    PRIMARY KEY (extension_id, version, registry, target_platform, sha256),
                    FOREIGN KEY (sha256) REFERENCES artifacts(sha256)
                );
            """)
        os.chmod(self.catalog, 0o600)

    def preserve(self, source: Path, *, extension_id: str, version: str, registry: str,
                 target_platform: str = "") -> StoredArtifact:
        platform = str(target_platform or "").strip().lower()
        if platform and not TARGET_PLATFORM_RE.fullmatch(platform):
            raise ArtifactStoreError("Artifact target platform is invalid.")
        source = Path(source)
        fd, staged_name = tempfile.mkstemp(prefix=".staging-", dir=self.root)
        digest = hashlib.sha256()
        size = 0
        try:
            with source.open("rb") as incoming, os.fdopen(fd, "wb") as staged:
                while chunk := incoming.read(1024 * 1024):
                    staged.write(chunk)
                    digest.update(chunk)
                    size += len(chunk)
                staged.flush()
                os.fsync(staged.fileno())
            if not size:
                raise ArtifactStoreError("Cannot preserve an empty artifact.")
            sha256 = digest.hexdigest()
            storage_key = f"sha256/{sha256[:2]}/{sha256}.vsix"
            destination = self.root / storage_key
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(destination.parent, 0o700)
            if destination.exists():
                self._verify(destination, sha256, size)
            else:
                os.replace(staged_name, destination)
                staged_name = ""
            os.chmod(destination, 0o400)
            self._verify(destination, sha256, size)
            now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            with self._connect() as db:
                db.execute("INSERT INTO artifacts VALUES (?, ?, ?, ?, ?) ON CONFLICT(sha256) DO UPDATE SET last_seen=excluded.last_seen",
                           (sha256, size, storage_key, now, now))
                db.execute("""INSERT INTO observations VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(extension_id, version, registry, target_platform, sha256)
                    DO UPDATE SET last_seen=excluded.last_seen""",
                           (extension_id, version, registry, platform, sha256, now, now))
                row = db.execute("""SELECT o.first_seen, o.last_seen FROM observations o
                    WHERE extension_id=? AND version=? AND registry=? AND target_platform=? AND sha256=?""",
                                 (extension_id, version, registry, platform, sha256)).fetchone()
            return StoredArtifact(destination, "filesystem", storage_key, sha256, size,
                                  extension_id, version, registry, platform, row[0], row[1])
        except ArtifactStoreError:
            raise
        except OSError as exc:
            raise ArtifactStoreError(f"Could not preserve artifact: {exc}") from exc
        finally:
            if staged_name:
                Path(staged_name).unlink(missing_ok=True)

    @staticmethod
    def _verify(path: Path, expected_hash: str, expected_size: int) -> None:
        digest = hashlib.sha256()
        size = 0
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
                size += len(chunk)
        if size != expected_size or digest.hexdigest() != expected_hash:
            raise ArtifactStoreError("Existing content-addressed artifact failed integrity validation.")

    def search(self, *, extension_id: str | None = None, version: str | None = None,
               registry: str | None = None, target_platform: str | None = None,
               sha256: str | None = None) -> list[dict[str, object]]:
        clauses, values = [], []
        for column, value in (("o.extension_id", extension_id), ("o.version", version),
                              ("o.registry", registry), ("o.target_platform", target_platform),
                              ("o.sha256", sha256)):
            if value is not None:
                clauses.append(f"{column} = ?")
                values.append(value)
        query = """SELECT o.extension_id,o.version,o.registry,o.target_platform,o.sha256,
                   a.size_bytes,a.storage_key,o.first_seen,o.last_seen
                   FROM observations o JOIN artifacts a ON a.sha256=o.sha256"""
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY o.last_seen DESC"
        with self._connect() as db:
            return [dict(row) for row in db.execute(query, values)]


def artifact_store_from_environment() -> FilesystemArtifactStore | None:
    configured = os.environ.get("IDE_SCANNER_ARTIFACT_STORE", "").strip()
    return FilesystemArtifactStore(configured) if configured else None
