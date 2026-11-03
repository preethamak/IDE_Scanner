# Reputation gate for extension recommendations

`ide-scanner scan` answers "is this artifact dangerous". It only works once you
already know which extension you want. The question that comes first — "which
extension should I install for this job, and is any of them from a source worth
trusting" — is what `ide-scanner alternatives` answers.

```
python -m ide_scanner alternatives plist --limit 10
```

## Why this exists

Marketplace ranking is dominated by install count, which is the weakest available
trust signal: it is gameable, it lags for new-but-good extensions, and it accrues
to whoever arrived first. Searching `plist` at the time of writing returns 14
extensions, **none** of them from a domain-verified publisher. The second most
installed has 185,320 installs, no published source repository, and has not been
updated since 2018. Another advertises a GitHub repository that returns 404.

An agent that recommends "the top result" recommends that. The point of this
command is to make "no reputable option exists" an expressible answer.

## The gate

The field a caller must honour is `recommendation_allowed`. It is true only when
at least one candidate both clears the reputation floor and has a domain-verified
publisher.

```json
{
  "recommendation_allowed": false,
  "qualifying": [],
  "reputation_floor": 60,
  "analysis_depth": "metadata_only",
  "advice": "No extension for 'plist' qualifies as reputable. ..."
}
```

The process exits `3` when `recommendation_allowed` is false and `0` when it is
true, so a shell or CI caller can gate without parsing JSON.

An agent wired to this should treat exit 3 as "tell the user no reputable option
exists and stop", not as "pick the highest-scoring row anyway". The ranking is
there to explain the gap, not to be harvested for a recommendation.

## Scoring

100 points across six provenance signals. Every signal carries the evidence that
produced it, so a score can be explained rather than asserted.

| Signal | Max | What earns it |
| --- | --- | --- |
| `publisher_verified` | 25 | Publisher proved DNS control of a domain |
| `source_available` | 20 | A published source repository that actually resolves |
| `maintenance` | 20 | Updated within a year; zero past two years |
| `repo_health` | 15 | Stars, and not archived or disabled |
| `review_confidence` | 10 | Rating, discounted by how few ratings back it |
| `adoption` | 10 | Install count, as a tie-breaker only |

Tiers: `reputable`, `community`, `unvetted`, `caution`. `caution` is assigned
regardless of score when an extension is withdrawn from the Marketplace, or when
it executes code and its source cannot be inspected at all.

Two deliberate choices:

- **Install count is capped at 10 points.** It is the signal most likely to be
  mistaken for trust, so it cannot carry a candidate on its own. The 185k-install
  sourceless extension above scores 7/100.
- **Domain verification is required for `reputable`, not merely scored.** A
  candidate can reach the numeric floor on adoption and maintenance alone; that is
  not sufficient to recommend it unattended.

## What this does not tell you

`analysis_depth` is `metadata_only`. No VSIX is downloaded and no code is read,
which is what makes the check cheap enough to run before recommending. A high
score means the provenance is checkable, **not** that the code is safe. Scan the
artifact before installing:

```
python -m ide_scanner scan --extension-id publisher.name --online
```

## Note on `publisher_verified`

The Marketplace sets `flags: "verified"` on essentially every public publisher; it
does not mean the publisher was vetted. Only `isDomainVerified` reflects proven
domain control. All 14 plist publishers carry the `verified` flag and none is
domain-verified, so treating the flag as trust marks every anonymous single-author
account as verified.
