# Contributing to ZMILY Foundation

**External contribution acceptance is not yet enabled.** The CLA is a draft
for legal review. Do not sign the draft or post personal legal information in
issues or pull requests. Code reuse under the public GPL does not require a
CLA; the CLA is required only for accepting work into this dual-licensed project.

## One acceptance, not one signature per commit

Once enabled, read the final [CLA](CLA.md) and complete the maintainer-provided
private signing process before your first merge. It covers your intentionally
submitted current and future contributions in the signed capacity, including
proprietary sublicensing and transfer of the Project without re-signing.
You keep your copyright. A normal Git Signed-off-by is not a substitute.

Maintainers verify the signer/account and authority, retain the original
acceptance evidence privately, and record an opaque acceptance entry in
`.github/cla/acceptances.json` on the trusted default branch. The PR check reuses
that acceptance for subsequent submissions. There is no comment-based automatic
signing, no per-commit CLA signature, and no public storage of legal signatures.
Contact the project maintainer to arrange signing after the process is enabled;
the final privacy notice and signing contact are publication prerequisites.

If an employer or another entity owns your work, its authorized representative
must provide the necessary grant. Tell maintainers about any change of rights
holder or capacity before submitting affected work. Do not import code from
other projects unless its provenance and rights permit both distribution paths.

## Checks and review

Run `cargo fmt --all -- --check`, the tests and Clippy described in the README,
and `python scripts/test_cla_check.py`. Every PR must pass `CLA / acceptance`
and the normal source checks before merging. The CLA check uses policy and
records from the trusted default branch, never the PR's proposed edits.

All PR submitters and commit authors must have a matching acceptance or be the
identified project owner. Unknown authors and co-author trailers fail closed
until maintainers record a provenance review bound to the exact PR head SHA
and all contributor account IDs. Each of those contributors still needs an
existing acceptance; a provenance review is not a substitute signature.
Do not remove co-author attribution to make a check pass. Maintainers must
verify every actual contributor,
including imported/squashed work whose authors are not recoverable from Git.
There is no blanket bot, partner or organization-member exemption. GitHub's
commit-to-account mapping is not proof of authorship or legal ownership.

No one may self-approve an acceptance by editing its record in their own PR.
Updating verified records is a separate maintainer operation on the default
branch, followed by re-running the pending PR's CLA workflow. The check is a
technical admission check, not a legal opinion or a substitute for code review.

## Private/public synchronization

The public repository contains an independently buildable subset of the ZMILY
product. Maintainers review accepted public patches, including their signing
evidence, before importing them into the private product. Project transfers
must preserve the acceptance archive, policy history and assignment evidence,
not merely move the GitHub repository.
