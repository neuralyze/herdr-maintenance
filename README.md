# Herdr paired maintenance

Maintained Herdr and herdr-mirror patches, daily upstream-update PRs, isolated regression CI, and approval-gated paired releases.

- [Maintained Herdr](https://github.com/neuralyze/herdr/tree/maintained)
- [Maintained mirror](https://github.com/neuralyze/herdr-mirror/tree/maintained)
- [Paired validation and releases](https://github.com/neuralyze/herdr-maintenance/actions)

This repository does **not** connect to the production fleet, run paid model requests, install binaries, or restart services. Collie requires no source patch for the maintained-session changes.

## Update and approval flow

1. Each fork's daily `maintenance-update.yml` checks its upstream's latest stable GitHub release. Manual dispatch is also available.
2. A conflict-safe three-way import preserves local changes and the complete maintained workflow tree. The recorded upstream commit is the explicit merge base; synthetic merge ancestry is never published. Candidate commits have the real maintained head as their sole parent.
3. A clean import opens a review PR and explicitly dispatches `maintenance-check.yml` at that immutable candidate. Existing PRs reconcile missing review requests and validation dispatches. Existing failed checks require investigation, not an automatic retry loop.
4. A conflict, divergent history, or retargeted upstream tag stops the import and opens an assigned issue. Maintained source remains unchanged.
5. After a human approves and merges a fork PR, this coordinator's daily `pair-update.yml` proposes the two approved maintained heads in `config/pair.lock.json` and dispatches paired checks. It never selects unapproved update branches.
6. A successful paired check on **main** publishes an immutable candidate prerelease. PR checks and dispatched proposal branches cannot publish.
7. To approve a candidate, manually dispatch **Approve paired release promotion** from main with its complete candidate tag. The `release-approval` environment requires `neuralyze`'s explicit approval and allows only main. Administrator bypass is disabled. Self-review is permitted because the single owner may both initiate the workflow and give the separate environment approval.

Approval promotes release metadata; actual production installation remains a separate, deliberate operator action. There is no unattended deployment or auto-merge.

## What gets tested

The read-only build job checks out exact fork commits, respects Herdr's source-pinned Rust toolchain, runs Herdr's upstream `just ci`, mirror's upstream tests and Clippy, and explicit managed-session/output regression filters. Missing required regression tests fail rather than silently selecting zero tests. Mirror intentionally has no formatting gate, matching its upstream CI.

The private pair fixture starts actual Herdr and mirror binaries over foreground loopback OpenSSH, with fresh keys and private HOME/XDG/config/socket state. An echo-off raw terminal application records received input and prints source receipts. Ordinary mirror stdin acquires control, waits for actual acknowledgement, sends input, and releases control with Ctrl+backslash. Repeated cycles must preserve the SSH/remote CLI identities; a second pane must retain its stream and receive its own input and fresh heartbeat. Success requires verified exact-generation cleanup.

Fixture timings describe source receipt and the actual mirror `--dump` grid, not predictive echo or an LLM response. First input starts after initial Observe readiness; source regressions cover input before readiness. Separate bounded phase deadlines are not a universal fleet-latency guarantee. Neither these checks nor prior measurements prove every historical freeze eliminated.

The fixture creates one temporary `.herdr-pair-*` directory inside the test account's actual passwd home, so OpenSSH `StrictModes` can validate authorization-file ancestry. It removes that directory after confirmed shutdown. `/run/sshd` must already exist. No original SSH/config/auth files are modified. Linux `/proc`, pidfds, OpenSSH, and root or noninteractive sudo are required.

Environment isolation is **not** an adversarial filesystem sandbox. Run arbitrary candidate code only on disposable, credential-free workers/containers. Hosted jobs receive no production secrets, SSH keys, or LLM credentials. For local integration, use a disposable container with no network except its own loopback and mount only tools, test binaries, and an evidence directory.

## Pins, artifacts, and provenance

- `config/products.json`: approved repositories and maintained branches.
- Fork `.maintenance/upstream.json`: exact upstream base/tag and a retained local patch ledger.
- `config/pair.lock.json`: the exact approved fork/upstream commits of both products.
- Fork callers pin the reusable workflows **and** maintenance-tool checkout to the same full 40-hex tool commit. Updating coordinator code does not silently change those callers; deliberately render and review a new pin in both fork workflows when updating maintenance policy.
- Candidate tags contain both complete fork SHAs and the validator SHA. Existing tags/assets are verified, never force-pushed or overwritten.

A successful build produces exactly:

- `herdr-linux-x86_64.tar.gz`
- `herdr-mirror-linux-x86_64.tar.gz`
- `pair-manifest.json`
- `SHA256SUMS`

Each archive contains exactly one regular executable. The manifest records source/upstream/validator identities plus binary and archive hashes. Packaging rejects failed evidence, mismatched lock bytes, changed binaries, unsafe archive members, extra files, and symlinks. The isolated publisher never executes uploaded programs and independently binds the manifest to its trusted checked-out lock. Historical promotion binds to the exact lock at the recorded validator commit, not to a self-consistent uploaded claim.

Current hosted builds target Linux x86_64 on Ubuntu 24.04. Check the target host's GNU runtime/ABI before manual installation; the platform label alone does not establish compatibility with older distributions. Other platforms require corresponding builds and verification, not reuse of these binaries.

## Rollback

Promotion adds immutable `approval.json`. If an approved release already exists, it also adds `previous-approved-pair-manifest.json`, copied from the **currently latest approved** pair, not merely the most recently published candidate. Interrupted promotions retain and reconcile already-uploaded rollback identity. A first promotion explicitly records that no preceding approved pair exists.

To roll back, select the previous approved tag identified by the current approval record, obtain **both** binaries from that same release, verify `SHA256SUMS` and `pair-manifest.json`, and use the operator's normal backed-up installation procedure. Never independently mix a new mirror with an older Herdr lacking managed-terminal support. Preserve installed binaries/configuration before the first production cutover; until that cutover, the existing installation is the rollback baseline.

## Security updates and patch retirement

Security-related release-note matches prioritize the import PR and open an assigned issue. This is advisory keyword detection, **not** a vulnerability feed or security guarantee. Urgent fixes still require conflict resolution, regression verification, and approval. A conflict is not permission to stay pinned indefinitely or to drop a patch automatically.

Exact Git patch-ID matches and configured keyword matches flag potentially adopted fixes for human review. They never delete local patches. After behavior is verified upstream, remove the redundant patch/ledger entry in a reviewed fork PR and validate a new paired lock. Intentional adoption may also require updating the required regression filters so equivalent upstream coverage is retained rather than blindly deleting a failed gate.

Upstream workflow changes are deliberately excluded from imports: importing executable CI with a repository write token is unsafe and can require a separate workflow-write credential. Review upstream CI/toolchain contract changes separately in the trusted coordinator; source suites still use the retained upstream recipes.

## Commands

Use Python 3.11+, Git, and GitHub CLI. Only updater/publication commands need authenticated GitHub access; build/test subprocesses receive an allowlisted environment. Run from this repository.

```sh
# Read-only plans: no remote mutations.
python -m maintenance.updater --config config/products.json component \
  --product herdr --workspace /tmp/herdr-update --output out/update.json
python -m maintenance.updater --config config/products.json pair \
  --lock config/pair.lock.json --workspace /tmp/herdr-pair-update --output out/pair-update.json

# CI entrypoints, on a disposable worker without credentials.
python -m unittest discover -s tests -v
python -m maintenance.ci component --product herdr --source source --output out/component --jobs 2
python -m maintenance.ci pair --lock config/pair.lock.json --workspace sources --output out/pair --jobs 2
python -m maintenance.package build --lock config/pair.lock.json \
  --evidence out/pair/ci-evidence.json --output dist
python -m maintenance.pair_smoke run --herdr /absolute/herdr \
  --mirror /absolute/herdr-mirror --output out/local-integration.json
```

The unit suite's optional actual-binary test skips unless `HERDR_PAIR_TEST_BINARY` and `HERDR_MIRROR_PAIR_TEST_BINARY` are supplied; unit success alone is not integration proof. The `pair_smoke` command above always requires real binaries. Use a fresh `sources` workspace and empty `dist` directory. Paired CI requires a committed, clean validator checkout.

Hosted updater jobs add `--apply` with the caller's repository-scoped token. They can create update branches/PRs/issues and dispatch validation but cannot approve or merge their own PRs. Publication commands are intentionally separate from build/test:

```sh
python -m maintenance.release candidate --dist dist \
  --repository neuralyze/herdr-maintenance --output out/release.json
python -m maintenance.release promote --tag "$CANDIDATE_TAG" \
  --repository neuralyze/herdr-maintenance --output out/promotion.json
```

Use the approval-gated hosted promotion workflow for normal promotion. A privileged local operator running publication commands is exercising that operator's own GitHub authority, not obtaining an environment approval through the CLI.

## Failure handling

Read the failed workflow step and retained evidence artifact. Upstream changes, removed test filters, compiler/ABI changes, conflicts, malformed provenance, missing SSH prerequisites, fixture failures, and tampered artifacts block candidates rather than producing fallback success. Fix the relevant source/configuration in a reviewed change, then dispatch the check explicitly. No paid-model probes, production-service access, force pushes, automatic conflict resolutions, or hidden retries are part of routine maintenance.

Fork inherited upstream workflows remain present for source-contract tests but must stay disabled; only `maintenance-check.yml` and `maintenance-update.yml` are enabled there. Default workflow-token permissions are read-only; only updater/publisher jobs grant the specific writes they need. Branch protection requires review and observed validation contexts before normal merges.
