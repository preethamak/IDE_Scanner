# GitHub extension policy gate

Use this action in a repository that recommends VS Code extensions. It reads
`.vscode/extensions.json`, `*.code-workspace`, and Dev Container extension
lists, downloads the exact VSIX, then statically scans it. It never launches
extension code.

```yaml
name: Extension policy
on: [pull_request]
jobs:
  policy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: preethamak/IDE_Scanner@main
        with:
          policy: .ide-scanner/policy.json
          lock: .ide-scanner/extensions.lock.json
```

Generate a reviewed lock first with `python scripts/policy_gate.py --write-lock`.
`REVIEW` needs a version-and-hash approval or exception. `INCOMPLETE` fails.
`BLOCK` fails unless an explicit, expiring `allow_block_override` is present.

For continuous monitoring, copy
[`templates/ide-scanner-release-monitor.yml`](../templates/ide-scanner-release-monitor.yml)
into the consuming repository's `.github/workflows/` directory. Every six
hours it resolves the latest artifact, scans it statically, and opens one
GitHub issue when the approved version or SHA-256 changes.

```json
{
  "approvals": {
    "publisher.extension": {
      "version": "1.2.3",
      "sha256": "exact artifact sha256",
      "expires_at": "2027-01-01T00:00:00Z",
      "reason": "Reviewed by platform security"
    }
  }
}
```
