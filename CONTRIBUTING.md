# Contributing to ZMILY Foundation

**CLA version 1.0 is open for maintainer-verified acceptance.** Do not post
personal legal information in issues or pull requests. Code reuse under the
public GPL does not require a CLA; the CLA is required only for accepting work
into this dual-licensed project. Project-owner approval is recorded; no
independent legal review is claimed.

## One acceptance, not one signature per commit

Read the [CLA](CLA.md) and complete the maintainer-provided
private signing process before your first merge. It covers your intentionally
submitted current and future contributions in the signed capacity, including
proprietary sublicensing and transfer of the Project without re-signing.
You keep your copyright. A normal Git Signed-off-by is not a substitute.

Maintainers verify the signer/account and authority, retain the original
acceptance evidence privately, and record an opaque acceptance entry in
`.github/cla/acceptances.json` on the trusted default branch. The PR check reuses
that acceptance for subsequent submissions. There is no comment-based automatic
signing, no per-commit CLA signature, and no public storage of legal signatures.
To start, open a [CLA signing request](https://github.com/ByronAP/zmily-foundation/issues/new?title=CLA%20signing%20request)
addressed to `@ByronAP`, containing only your GitHub handle and a request for a
private signing channel. Allen Byron Penner will arrange that channel before
you send personal information. An issue or PR comment alone is not acceptance.

The private acceptance must include your legal name, your GitHub account, the
rights holder and individual/entity capacity, the exact version and digest
from `.github/cla/policy.json`, and a dated signature or equivalent recorded
electronic assent. For an entity, identify its authorized representative and
authority. Include this statement with those identifying details:

> I have read and accept the ZMILY Contributor License Agreement version 1.0
> identified by the accompanying SHA-256 digest, including its proprietary
> sublicensing and project-transfer permissions. I have authority to grant
> those rights in the capacity identified in this acceptance.

Do not submit a generic Signed-off-by as that evidence. Maintainers verify the
account linkage and authority before adding the acceptance record. This is a
manual process; no hosted e-signature provider is configured.

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

## Signing privacy and record retention

Allen Byron Penner, operating ZMILY, administers signing records. The purpose
is to verify contribution authority, maintain evidence of the license grants,
and support licensing, compliance and project transfers. Provide only the
identity, account, capacity and assent information needed for those purposes;
do not send government ID, a home address or unrelated sensitive information.

Full acceptance evidence is kept privately with access limited to authorized
maintainers and advisers who need it for these purposes. It may transfer to a
project successor with the associated obligations. Public records expose your
GitHub numeric ID, agreement version/digest, acceptance date, signing capacity,
review/status flags and an opaque evidence reference, not the signed document.
GitHub account IDs are publicly linkable; Git history and forks may retain
public records even after a later edit or removal.

Evidence is retained while the Project relies on the grant and as reasonably
needed to establish or defend the associated rights or meet legal obligations;
deleting a signing-request issue is not a way to withdraw a granted license.
Ask the steward through the same contact route to arrange private access,
correction or deletion requests. Requests will be considered subject to
applicable law and legitimate recordkeeping needs. No contributor evidence is
collected by the CI check itself.
