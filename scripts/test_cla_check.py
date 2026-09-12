#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 Allen Byron Penner
"""Offline regression tests; no real signatures, GitHub writes or credentials."""

from copy import deepcopy
import sys
import tomllib
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
import cla_check as cla


class ClaTests(unittest.TestCase):
    def setUp(self):
        self.agreement = b"# Test agreement\nVersion: 1.0\nTest fixture only.\n"
        self.policy = {
            "schema_version": 1, "status": "active", "owner_name": "Fixture owner",
            "owner_github_id": 1, "agreement_version": "1.0",
            "agreement_sha256": cla.agreement_digest(self.agreement),
            "review_reference": "test-only-approval",
        }
        self.entry = {
            "github_id": 2, "agreement_version": "1.0",
            "agreement_sha256": self.policy["agreement_sha256"],
            "accepted_at": "2020-01-01T00:00:00Z", "evidence_reference": "test-only-evidence",
            "capacity": "individual", "authority_reviewed": True, "status": "accepted",
        }
        self.registry = {"schema_version": 1, "acceptances": [self.entry], "provenance_reviews": []}
        self.pr = {"commits": 1, "user": {"id": 2}, "head": {"sha": "a" * 40}}
        self.commits = [{"sha": "a" * 40, "author": {"id": 2}, "commit": {"message": "A fix"}}]

    def check(self):
        cla.validate(self.policy, self.registry, self.agreement)
        cla.evaluate(self.policy, self.registry, self.pr, self.commits)

    def test_one_acceptance_covers_multiple_prs_and_commits(self):
        self.check()
        self.pr["head"]["sha"] = "b" * 40
        self.pr["commits"] = 2
        self.commits.append({"sha": "b" * 40, "author": {"id": 2}, "commit": {"message": "Another fix"}})
        self.check()

    def test_account_rename_does_not_invalidate_acceptance(self):
        self.pr["user"]["login"] = "new-name"
        self.commits[0]["author"]["login"] = "old-name"
        self.check()

    def test_owner_does_not_sign_own_cla(self):
        self.pr["user"]["id"] = self.commits[0]["author"]["id"] = 1
        self.registry["acceptances"] = []
        self.check()

    def test_successor_metadata_does_not_require_contributor_resigning(self):
        self.policy["owner_name"] = "Fixture successor"
        self.policy["owner_github_id"] = 3
        self.check()

    def test_missing_acceptance(self):
        self.registry["acceptances"] = []
        with self.assertRaisesRegex(cla.Refusal, "lacks"):
            self.check()

    def test_submitter_and_each_author_checked(self):
        self.commits[0]["author"]["id"] = 99
        with self.assertRaisesRegex(cla.Refusal, "lacks"):
            self.check()

    def test_no_bot_bypass(self):
        self.commits[0]["author"] = {"id": 99, "login": "dependabot[bot]", "type": "Bot"}
        with self.assertRaisesRegex(cla.Refusal, "lacks"):
            self.check()

    def test_unmapped_author_refused(self):
        self.commits[0]["author"] = None
        with self.assertRaisesRegex(cla.Refusal, "Unmapped"):
            self.check()

    def test_coauthors_not_silently_ignored(self):
        self.commits[0]["commit"]["message"] += "\n\nCo-authored-by: Someone <test@example.invalid>"
        with self.assertRaisesRegex(cla.Refusal, "Co-authored"):
            self.check()

    def review(self):
        self.registry["provenance_reviews"] = [{
            "head_sha": self.pr["head"]["sha"], "contributor_ids": [2],
            "evidence_reference": "test-only-provenance",
        }]

    def test_review_resolves_mapping_not_signature(self):
        self.review()
        self.commits[0]["author"] = None
        self.check()
        self.registry["acceptances"] = []
        with self.assertRaisesRegex(cla.Refusal, "lacks CLA"):
            self.check()

    def test_review_does_not_cover_new_head(self):
        self.review()
        self.pr["head"]["sha"] = "b" * 40
        self.commits[0]["author"] = None
        with self.assertRaisesRegex(cla.Refusal, "Unmapped"):
            self.check()

    def test_review_cannot_omit_known_author(self):
        self.review()
        self.registry["provenance_reviews"][0]["contributor_ids"] = [1]
        with self.assertRaisesRegex(cla.Refusal, "omits"):
            self.check()

    def test_draft_blocks_even_owner(self):
        self.policy["status"] = "draft"
        self.policy["review_reference"] = None
        self.registry["acceptances"] = []
        self.pr["user"]["id"] = self.commits[0]["author"]["id"] = 1
        with self.assertRaisesRegex(cla.Refusal, "awaits legal"):
            self.check()

    def test_draft_cannot_have_signatures(self):
        self.policy["status"] = "draft"
        self.policy["review_reference"] = None
        with self.assertRaisesRegex(cla.Refusal, "Cannot accept a draft"):
            self.check()

    def test_draft_text_cannot_be_activated(self):
        self.agreement += b"DRAFT FOR LEGAL REVIEW\n"
        self.policy["agreement_sha256"] = cla.agreement_digest(self.agreement)
        with self.assertRaisesRegex(cla.Refusal, "Draft CLA"):
            self.check()

    def test_approval_required(self):
        self.policy["review_reference"] = None
        with self.assertRaisesRegex(cla.Refusal, "approval reference"):
            self.check()

    def test_changed_terms_fail_digest(self):
        self.agreement += b"Different terms\n"
        with self.assertRaisesRegex(cla.Refusal, "digest mismatch"):
            self.check()

    def test_crlf_does_not_change_agreement_identity(self):
        self.agreement = self.agreement.replace(b"\n", b"\r\n")
        self.check()

    def test_stale_acceptance_refused(self):
        self.entry["agreement_sha256"] = "0" * 64
        with self.assertRaisesRegex(cla.Refusal, "Stale"):
            self.check()

    def test_changed_version_refused(self):
        self.policy["agreement_version"] = "2.0"
        with self.assertRaisesRegex(cla.Refusal, "version mismatch"):
            self.check()

    def test_unverified_authority_refused(self):
        self.entry["authority_reviewed"] = False
        with self.assertRaisesRegex(cla.Refusal, "Authority"):
            self.check()

    def test_suspended_admission_refused(self):
        self.entry["status"] = "suspended"
        with self.assertRaisesRegex(cla.Refusal, "lacks"):
            self.check()

    def test_evidence_reference_required(self):
        self.entry["evidence_reference"] = ""
        with self.assertRaisesRegex(cla.Refusal, "evidence"):
            self.check()

    def test_future_signature_refused(self):
        self.entry["accepted_at"] = "9999-01-01T00:00:00Z"
        with self.assertRaisesRegex(cla.Refusal, "Future"):
            self.check()

    def test_duplicate_identity_refused(self):
        self.registry["acceptances"].append(deepcopy(self.entry))
        with self.assertRaisesRegex(cla.Refusal, "Duplicate"):
            self.check()

    def test_boolean_identity_refused(self):
        self.entry["github_id"] = True
        with self.assertRaisesRegex(cla.Refusal, "account ID"):
            self.check()

    def test_duplicate_json_keys_refused(self):
        with self.assertRaisesRegex(cla.Refusal, "Duplicate JSON"):
            cla.parse_json('{"status":"active","status":"draft"}')

    def test_partial_inventory_refused(self):
        self.pr["commits"] = 2
        with self.assertRaisesRegex(cla.Refusal, "Incomplete"):
            self.check()

    def test_oversized_pr_refused(self):
        self.pr["commits"] = 251
        with self.assertRaisesRegex(cla.Refusal, "review limit"):
            self.check()

    def test_duplicate_commits_refused(self):
        self.pr["commits"] = 2
        self.commits *= 2
        with self.assertRaisesRegex(cla.Refusal, "Duplicate PR"):
            self.check()

    def test_redirect_refused_before_forwarding_credentials(self):
        with self.assertRaisesRegex(cla.Refusal, "redirects"):
            cla.NoRedirect().redirect_request(None, None, 302, "", {}, "https://example.invalid")

    def test_untrusted_repository_refused(self):
        with self.assertRaisesRegex(cla.Refusal, "repository"):
            cla.GitHub("owner/repo/../../other", "test-token")

    def test_missing_token_refused(self):
        with self.assertRaisesRegex(cla.Refusal, "token"):
            cla.GitHub("owner/repo", "")

    def test_github_success_and_current_head_recheck(self):
        api = FakeGitHub(self.pr, self.commits)
        with patch.object(cla, "load", return_value=(self.policy, self.registry)):
            cla.check_pr(api, 1, cla.ROOT)
        self.assertEqual([row[1] for row in api.statuses], ["pending", "success"])
        self.assertEqual(api.pr_reads, 2)

    def test_changed_head_never_gets_success(self):
        api = FakeGitHub(self.pr, self.commits, change_head=True)
        with patch.object(cla, "load", return_value=(self.policy, self.registry)):
            with self.assertRaisesRegex(cla.Refusal, "changed"):
                cla.check_pr(api, 1, cla.ROOT)
        self.assertEqual([row[1] for row in api.statuses], ["pending", "failure"])

    def test_bad_policy_cannot_leave_old_success(self):
        api = FakeGitHub(self.pr, self.commits)
        with patch.object(cla, "load", side_effect=cla.Refusal("Broken policy")):
            with self.assertRaises(cla.Refusal):
                cla.check_pr(api, 1, cla.ROOT)
        self.assertEqual([row[1] for row in api.statuses], ["pending", "failure"])

    def test_commit_pagination(self):
        self.pr["commits"] = 201
        commits = [{"sha": f"{index:040x}", "author": {"id": 2}, "commit": {"message": "fix"}}
                   for index in range(201)]
        api = FakeGitHub(self.pr, commits)
        with patch.object(cla, "load", return_value=(self.policy, self.registry)):
            cla.check_pr(api, 1, cla.ROOT)
        self.assertEqual(api.pages, [1, 2, 3])

    def test_shipped_configuration_is_not_activated(self):
        policy, registry = cla.load(cla.ROOT)
        self.assertEqual(policy["status"], "draft")
        self.assertEqual(registry["acceptances"], [])

    def test_public_and_crate_gpl_texts_match(self):
        root = (cla.ROOT / "LICENSE").read_bytes().replace(b"\r\n", b"\n")
        workspace = cla.ROOT
        # The private source keeps the crate outside its public templates.
        if not (workspace / "crates/zmily-foundation").exists():
            workspace = cla.ROOT.parents[1]
            self.assertTrue((workspace / "publication/public-source.json").is_file())
        library = (workspace / "crates/zmily-foundation/LICENSE").read_bytes().replace(b"\r\n", b"\n")
        self.assertEqual(root, library)
        self.assertTrue(root.startswith(b"GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007"))
        self.assertIn(b"END OF TERMS AND CONDITIONS", root)
        manifest = tomllib.loads((workspace / "crates/zmily-foundation/Cargo.toml").read_text())
        self.assertEqual(manifest["package"]["license"], "GPL-3.0-only")

    def test_privileged_workflow_never_checks_out_pr_code(self):
        workflow = (cla.ROOT / ".github/workflows/cla.yml").read_text()
        self.assertIn("pull_request_target:", workflow)
        self.assertIn("ref: refs/heads/${{ github.event.repository.default_branch }}", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("contents: read", workflow)
        self.assertIn("pull-requests: read", workflow)
        self.assertIn("statuses: write", workflow)
        self.assertIn("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", workflow)
        self.assertNotIn("pull_request.head", workflow)
        self.assertNotIn("head_ref", workflow)
        self.assertNotIn("contents: write", workflow)
        self.assertNotIn("pull-requests: write", workflow)
        self.assertNotIn("secrets.", workflow)

    def test_ordinary_ci_checks_cla_policy(self):
        workflow = (cla.ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn("python scripts/cla_check.py --check-config", workflow)
        self.assertIn("python -B scripts/test_cla_check.py", workflow)


class FakeGitHub:
    def __init__(self, pr, commits, change_head=False):
        self.pr = deepcopy(pr)
        self.commits = deepcopy(commits)
        self.change_head = change_head
        self.pr_reads = 0
        self.pages = []
        self.statuses = []

    def request(self, path):
        if "/commits?" in path:
            page = int(path.rsplit("=", 1)[1])
            self.pages.append(page)
            return self.commits[(page - 1) * 100:page * 100]
        self.pr_reads += 1
        result = deepcopy(self.pr)
        if self.change_head and self.pr_reads > 1:
            result["head"]["sha"] = "b" * 40
        return result

    def status(self, sha, state, description):
        self.statuses.append((sha, state, description))


if __name__ == "__main__":
    unittest.main()
