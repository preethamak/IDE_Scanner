"""Reputation screening for extension *discovery*.

The scanner answers "is this artifact dangerous". This module answers the question
that comes first: "of the extensions that do this job, which one comes from a
source worth trusting, and is there one at all?"

It is deliberately metadata-only -- no VSIX is downloaded and no code is read, so
it is cheap enough to run before an agent recommends anything. That also bounds
what it may claim: a high reputation score means the provenance is checkable, not
that the code is safe. Code analysis stays with ``scan``.

The gate matters more than the ranking. ``recommendation_allowed`` is false when
no candidate clears the floor, so a caller that respects it says "no reputable
option exists for this need" instead of defaulting to whichever result ranked
first. Several real categories -- Apple plist editing among them -- have no
domain-verified publisher at all, and silently returning the most-installed
hobbyist extension is the failure this is built to prevent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from .registry import (
    _fetch_removed_packages,
    _fetch_repository_metadata_many,
    search_marketplace_extensions,
)

ALTERNATIVES_SCHEMA_VERSION = "1.0.0"

# A candidate must clear this to be recommendable without a human in the loop.
DEFAULT_REPUTATION_FLOOR = 60

REPUTABLE = "reputable"
COMMUNITY = "community"
UNVETTED = "unvetted"
CAUTION = "caution"
REPUTATION_TIERS = (REPUTABLE, COMMUNITY, UNVETTED, CAUTION)

_TIER_LABELS = {
    REPUTABLE: "Reputable · verified publisher with checkable source",
    COMMUNITY: "Community · maintained but unverified publisher",
    UNVETTED: "Unvetted · provenance could not be established",
    CAUTION: "Caution · withdrawn or unauditable",
}

STALE_DAYS = 730
AGING_DAYS = 365


@dataclass
class Signal:
    """One scored provenance check, carrying the evidence that produced it."""

    name: str
    points: int
    max_points: int
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "points": self.points,
            "max_points": self.max_points,
            "detail": self.detail,
        }


@dataclass
class CandidateAssessment:
    extension_id: str
    display_name: str
    publisher: str
    score: int
    tier: str
    tier_label: str
    signals: list[Signal] = field(default_factory=list)
    concerns: list[str] = field(default_factory=list)
    install_count: int = 0
    repository: str = ""
    executes_code: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "extension_id": self.extension_id,
            "display_name": self.display_name,
            "publisher": self.publisher,
            "score": self.score,
            "tier": self.tier,
            "tier_label": self.tier_label,
            "signals": [signal.to_dict() for signal in self.signals],
            "concerns": self.concerns,
            "install_count": self.install_count,
            "repository": self.repository,
            "executes_code": self.executes_code,
        }


def _days_since(value: Any) -> int | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return max(0, (datetime.now(UTC) - parsed).days)


def _score_publisher(row: dict[str, Any]) -> Signal:
    if row.get("publisher_verified"):
        return Signal("publisher_verified", 25, 25, "Publisher proved domain control.")
    return Signal(
        "publisher_verified",
        0,
        25,
        "Publisher is not domain-verified; the account name is self-asserted.",
    )


def _score_source(row: dict[str, Any], repo: dict[str, Any] | None) -> tuple[Signal, list[str]]:
    repository = str(row.get("repository") or "").strip()
    if not repository:
        return Signal("source_available", 0, 20, "No source repository is published."), [
            "No source repository, so the shipped code cannot be reviewed.",
        ]
    if repo is None:
        return Signal("source_available", 10, 20, f"Source link {repository} was not resolved."), []
    if not repo.get("found"):
        return Signal("source_available", 0, 20, f"Source link {repository} does not resolve."), [
            "Advertised source repository is missing or private, so the listing is not auditable.",
        ]
    return Signal("source_available", 20, 20, f"Source repository resolves: {repo.get('full_name')}."), []


def _score_maintenance(row: dict[str, Any]) -> tuple[Signal, list[str]]:
    days = _days_since(row.get("last_updated"))
    if days is None:
        return Signal("maintenance", 0, 20, "No last-updated date is available."), []
    if days > STALE_DAYS:
        years = days / 365
        return Signal("maintenance", 0, 20, f"Last updated {days} days ago."), [
            f"Unmaintained for about {years:.1f} years.",
        ]
    if days > AGING_DAYS:
        return Signal("maintenance", 10, 20, f"Last updated {days} days ago."), []
    return Signal("maintenance", 20, 20, f"Last updated {days} days ago."), []


def _score_repo_health(repo: dict[str, Any] | None) -> tuple[Signal, list[str]]:
    if not repo or not repo.get("found"):
        return Signal("repo_health", 0, 15, "No resolvable repository to assess."), []
    if repo.get("archived") or repo.get("disabled"):
        return Signal("repo_health", 0, 15, "Repository is archived or disabled."), [
            "Upstream repository is archived, so fixes are unlikely.",
        ]
    stars = int(repo.get("stargazers_count") or 0)
    points = 15 if stars >= 500 else 11 if stars >= 100 else 7 if stars >= 25 else 3 if stars >= 5 else 0
    return Signal("repo_health", points, 15, f"Repository has {stars} stars and is active."), []


def _score_reviews(row: dict[str, Any]) -> Signal:
    count = int(row.get("rating_count") or 0)
    average = float(row.get("rating_average") or 0)
    if count < 5:
        return Signal("review_confidence", 0, 10, f"Only {count} ratings; the average is not meaningful.")
    weight = 10 if count >= 100 else 7 if count >= 25 else 4
    points = int(round(weight * max(0.0, (average - 3.0) / 2.0)))
    return Signal("review_confidence", points, 10, f"Rated {average:.1f} across {count} ratings.")


def _score_adoption(row: dict[str, Any]) -> Signal:
    installs = int(row.get("install_count") or 0)
    points = 10 if installs >= 1_000_000 else 7 if installs >= 100_000 else 4 if installs >= 10_000 else 1 if installs >= 1_000 else 0
    return Signal("adoption", points, 10, f"{installs:,} reported installs.")


def _derive_tier(score: int, row: dict[str, Any], repo: dict[str, Any] | None, withdrawn: bool) -> str:
    if withdrawn:
        return CAUTION
    source_missing = not str(row.get("repository") or "").strip() or (repo is not None and not repo.get("found"))
    if source_missing and row.get("executes_code") is not False:
        # Code-executing extension whose source cannot be inspected at all.
        return CAUTION
    if score >= DEFAULT_REPUTATION_FLOOR and row.get("publisher_verified"):
        return REPUTABLE
    if score >= 40:
        return COMMUNITY
    return UNVETTED


def assess_candidate(
    row: dict[str, Any],
    repo: dict[str, Any] | None = None,
    withdrawn: bool = False,
) -> CandidateAssessment:
    """Score one search row. ``repo`` is the resolved GitHub metadata, or ``None``
    when the source link was never looked up."""
    concerns: list[str] = []
    signals = [_score_publisher(row)]

    source_signal, source_concerns = _score_source(row, repo)
    signals.append(source_signal)
    concerns.extend(source_concerns)

    maintenance_signal, maintenance_concerns = _score_maintenance(row)
    signals.append(maintenance_signal)
    concerns.extend(maintenance_concerns)

    health_signal, health_concerns = _score_repo_health(repo)
    signals.append(health_signal)
    concerns.extend(health_concerns)

    signals.append(_score_reviews(row))
    signals.append(_score_adoption(row))

    score = sum(signal.points for signal in signals)
    if withdrawn:
        score = 0
        concerns.append("Withdrawn from the Marketplace by Microsoft.")

    tier = _derive_tier(score, row, repo, withdrawn)
    return CandidateAssessment(
        extension_id=str(row.get("extension_id") or ""),
        display_name=str(row.get("display_name") or ""),
        publisher=str(row.get("publisher") or ""),
        score=score,
        tier=tier,
        tier_label=_TIER_LABELS[tier],
        signals=signals,
        concerns=concerns,
        install_count=int(row.get("install_count") or 0),
        repository=str(row.get("repository") or ""),
        executes_code=row.get("executes_code"),
    )


def find_alternatives(
    query: str,
    limit: int = 10,
    reputation_floor: int = DEFAULT_REPUTATION_FLOOR,
    online: bool = True,
) -> dict[str, Any]:
    """Search for extensions matching ``query`` and rank them by provenance.

    ``recommendation_allowed`` is the field a calling agent must honour: when it is
    false, no candidate established sufficient provenance, and the honest answer is
    that no reputable option exists -- not the top-ranked row."""
    rows = search_marketplace_extensions(query, page_size=limit)
    notes: list[str] = []
    repos: dict[str, dict[str, Any] | None] = {}
    withdrawn: dict[str, dict[str, str]] = {}

    if online and rows:
        repo_urls = [str(row.get("repository") or "") for row in rows if row.get("repository")]
        repos, repo_errors = _fetch_repository_metadata_many(repo_urls)
        notes.extend(f"Repository lookup failed for {error.get('repository')}." for error in repo_errors)
        removed, removed_error = _fetch_removed_packages()
        withdrawn = removed or {}
        if removed_error:
            notes.append(f"Withdrawn-package list unavailable: {removed_error}")
    elif rows:
        notes.append("Offline mode: source repositories and withdrawal status were not verified.")

    assessments = [
        assess_candidate(
            row,
            repos.get(str(row.get("repository") or "")) if online else None,
            str(row.get("extension_id") or "").lower() in withdrawn,
        )
        for row in rows
    ]
    assessments.sort(key=lambda item: (item.score, item.install_count), reverse=True)

    qualifying = [item for item in assessments if item.score >= reputation_floor and item.tier == REPUTABLE]
    best = assessments[0] if assessments else None

    if qualifying:
        advice = f"{qualifying[0].extension_id} clears the reputation floor. Scan the artifact before installing."
    elif best is None:
        advice = f"No Marketplace extension matched {query!r}."
    else:
        blocker = (
            "its publisher is not domain-verified"
            if best.score >= reputation_floor
            else f"it scores {best.score} against a floor of {reputation_floor}"
        )
        advice = (
            f"No extension for {query!r} qualifies as reputable. The strongest candidate is "
            f"{best.extension_id}, but {blocker}. Report that no reputable option exists "
            "rather than recommending this one."
        )

    return {
        "schema_version": ALTERNATIVES_SCHEMA_VERSION,
        "query": query,
        "reputation_floor": reputation_floor,
        "analysis_depth": "metadata_only",
        "candidates": [item.to_dict() for item in assessments],
        "qualifying": [item.extension_id for item in qualifying],
        "recommendation_allowed": bool(qualifying),
        "advice": advice,
        "notes": notes,
    }
