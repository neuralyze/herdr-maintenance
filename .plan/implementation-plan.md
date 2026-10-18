# Paired Herdr maintenance automation

## Goal
Maintain the tested Herdr and herdr-mirror patches through upstream releases, with visible update PRs, isolated regression CI, verified paired artifacts, and human-approved promotion. No production installation, Latz, or paid model calls.

## Design
- Public maintained forks owned by neuralyze; dedicated neuralyze/herdr-maintenance coordinator.
- Daily repository-scoped-token update workflows; conflict-safe explicit-base three-way squash imports preserve owned workflow policy and record exact upstream commits.
- Fork update PRs require review; coordinator pins approved maintained commits in a paired lock PR.
- Read-only build/test jobs execute upstream tests and a real private localhost pair fixture. Publisher validates artifacts without executing them.
- Candidate releases contain exact-source manifests and checksums. A required-reviewer environment gates promotion; previous approved pair remains the rollback target.
- Upstream patch-equivalence and release-note matches flag human retirement review only.

## Acceptance and validation
1. Real temporary Git fixtures cover clean updates, conflicts/abort, idempotence, downgrade prevention, owned workflow preservation and adoption detection.
2. Packaging checks identities, archive paths and binary hashes; tampering is rejected.
3. Actual localhost Herdr/mirror flow proves input consumption, acknowledged control/release, stable SSH stream and sibling survival; cleanup is verified.
4. Hosted fork/coordinator workflows are enabled and an actual hosted validation run is observed.
5. No secret-bearing or production state is published. No source history force-pushes, automatic conflict resolution or unattended production deployment.

## Status
- Scope/design: complete.
- Implementation: complete; reviewer findings on publisher source binding, interrupted promotion, approval-order rollback and missing PR validation recovery corrected.
- Local verification: 53 tests passed, one optional binary test skipped; the separate actual-binary localhost fixture passed in a credential-free, network-isolated container with same-stream control/release, source receipts, sibling continuity and complete cleanup. The live read-only paired watcher also returned up_to_date against both published maintained heads.
- Maintained forks and immutable caller pins: published. Hosted validation results are tracked in GitHub Actions; only successful main paired checks may publish candidates, and promotion requires the configured approval environment.

## Risks
Upstream API conflicts and platform/build changes must block candidates, not be hidden. Public GitHub fork permissions and environment protection must be observed. Upstream Herdr disallows unsolicited implementation PRs; automation targets only our forks. Rollback selects a previous approved pair; initial production adoption still requires operator backup and approval.
