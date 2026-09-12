#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 Allen Byron Penner
"""Trusted-base CLA admission check; never executes PR code or stores signatures."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

CONTEXT = "CLA / acceptance"
ROOT = Path(__file__).resolve().parents[1]


class Refusal(ValueError):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Refusal("GitHub API redirects are forbidden")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Refusal(message)


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON key")
        result[key] = value
    return result


def parse_json(text: str) -> object:
    return json.loads(text, object_pairs_hook=unique_object)


def agreement_digest(data: bytes) -> str:
    # Git may check text out as CRLF; the agreement identity uses UTF-8/LF.
    data.decode("utf-8")
    return hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()


def positive_id(value: object) -> bool:
    return type(value) is int and value > 0


def validate(policy: dict, registry: dict, agreement: bytes) -> None:
    require(isinstance(policy, dict) and set(policy) == {
        "schema_version", "status", "owner_name", "owner_github_id",
        "agreement_version", "agreement_sha256", "review_reference",
    }, "Invalid CLA policy fields")
    require(type(policy["schema_version"]) is int and policy["schema_version"] == 1,
            "Unsupported CLA policy schema")
    require(policy["status"] in ("draft", "active"), "Invalid CLA policy status")
    require(isinstance(policy["owner_name"], str) and bool(policy["owner_name"].strip()),
            "Missing project owner")
    require(positive_id(policy["owner_github_id"]), "Invalid owner account ID")
    require(isinstance(policy["agreement_version"], str) and bool(re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9.-]{0,63}", policy["agreement_version"])), "Invalid agreement version")
    require(policy["agreement_sha256"] == agreement_digest(agreement), "CLA digest mismatch")
    require(f"Version: {policy['agreement_version']}\n" in agreement.decode().replace("\r\n", "\n"),
            "CLA version mismatch")
    if policy["status"] == "active":
        require("draft" not in policy["agreement_version"].lower()
                and "DRAFT FOR LEGAL REVIEW" not in agreement.decode(), "Draft CLA cannot be activated")
        require(isinstance(policy["review_reference"], str) and bool(policy["review_reference"].strip()),
                "Legal review and owner approval reference required")
    else:
        require(policy["review_reference"] is None, "Draft policy must not claim approval")
    require(isinstance(registry, dict) and set(registry) == {"schema_version", "acceptances", "provenance_reviews"},
            "Invalid acceptance registry fields")
    require(type(registry["schema_version"]) is int and registry["schema_version"] == 1,
            "Unsupported acceptance schema")
    require(isinstance(registry["acceptances"], list), "Invalid acceptance list")
    require(isinstance(registry["provenance_reviews"], list), "Invalid provenance review list")
    require(policy["status"] != "draft" or not (registry["acceptances"] or registry["provenance_reviews"]),
            "Cannot accept a draft CLA")
    identities = set()
    for entry in registry["acceptances"]:
        require(isinstance(entry, dict) and set(entry) == {
            "github_id", "agreement_version", "agreement_sha256", "accepted_at",
            "evidence_reference", "capacity", "authority_reviewed", "status",
        }, "Invalid acceptance fields")
        require(positive_id(entry["github_id"]), "Invalid contributor account ID")
        require(entry["github_id"] not in identities, "Duplicate contributor acceptance")
        identities.add(entry["github_id"])
        require(entry["agreement_version"] == policy["agreement_version"]
                and entry["agreement_sha256"] == policy["agreement_sha256"], "Stale CLA acceptance")
        require(entry["capacity"] in ("individual", "entity"), "Unspecified signing capacity")
        require(entry["authority_reviewed"] is True, "Authority has not been verified")
        require(entry["status"] in ("accepted", "suspended"), "Invalid acceptance status")
        require(isinstance(entry["evidence_reference"], str) and bool(re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", entry["evidence_reference"])),
            "Missing opaque signing evidence reference")
        require(isinstance(entry["accepted_at"], str) and bool(re.fullmatch(
            r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", entry["accepted_at"])), "Invalid acceptance date")
        accepted = datetime.fromisoformat(entry["accepted_at"].replace("Z", "+00:00"))
        require(accepted <= datetime.now(timezone.utc), "Future acceptance date")
    heads = set()
    for review in registry["provenance_reviews"]:
        require(isinstance(review, dict) and set(review) == {
            "head_sha", "contributor_ids", "evidence_reference",
        }, "Invalid provenance review fields")
        require(isinstance(review["head_sha"], str) and bool(re.fullmatch(r"[0-9a-f]{40}", review["head_sha"])),
                "Invalid reviewed head SHA")
        require(review["head_sha"] not in heads, "Duplicate reviewed head")
        heads.add(review["head_sha"])
        ids = review["contributor_ids"]
        require(isinstance(ids, list) and bool(ids) and all(positive_id(value) for value in ids)
                and len(set(ids)) == len(ids), "Invalid reviewed contributor IDs")
        require(isinstance(review["evidence_reference"], str) and bool(re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", review["evidence_reference"])),
            "Missing provenance evidence reference")


def load(root: Path) -> tuple[dict, dict]:
    policy = parse_json((root / ".github/cla/policy.json").read_text(encoding="utf-8"))
    registry = parse_json((root / ".github/cla/acceptances.json").read_text(encoding="utf-8"))
    validate(policy, registry, (root / "CLA.md").read_bytes())
    return policy, registry


def evaluate(policy: dict, registry: dict, pr: dict, commits: list[dict]) -> None:
    require(policy["status"] == "active", "CLA awaits legal review and owner approval")
    require(type(pr.get("commits")) is int and 0 < pr["commits"] <= 250,
            "PR commit count outside supported review limit")
    require(len(commits) == pr["commits"], "Incomplete PR commit inventory")
    require(len({commit["sha"] for commit in commits}) == len(commits), "Duplicate PR commits")
    approved = {policy["owner_github_id"]} | {
        row["github_id"] for row in registry["acceptances"] if row["status"] == "accepted"
    }
    review = next((row for row in registry["provenance_reviews"]
                   if row["head_sha"] == pr["head"]["sha"]), None)
    if review is not None:
        require(set(review["contributor_ids"]).issubset(approved),
                "Reviewed contributor lacks CLA acceptance")
    authors = [pr.get("user")] + [commit.get("author") for commit in commits]
    for author in authors:
        if not (isinstance(author, dict) and positive_id(author.get("id"))):
            require(review is not None, "Unmapped contributor requires manual provenance review")
        else:
            require(author["id"] in approved, "Contributor lacks a verified current CLA acceptance")
            require(review is None or author["id"] in review["contributor_ids"],
                    "Provenance review omits an identified contributor")
    for commit in commits:
        message = commit.get("commit", {}).get("message")
        require(isinstance(message, str), "Missing commit provenance")
        require(review is not None or not re.search(r"(?im)^\s*co-authored-by\s*:", message),
                "Co-authored work requires manual provenance review; do not discard attribution")


class GitHub:
    def __init__(self, repository: str, token: str):
        require(bool(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository)), "Invalid repository")
        require(bool(token), "Missing GitHub token")
        self.base = f"https://api.github.com/repos/{repository}"
        self.token = token
        self.opener = build_opener(NoRedirect())

    def request(self, path: str, data: dict | None = None) -> object:
        require(path.startswith("/") and "://" not in path, "Invalid API path")
        request = Request(self.base + path, data=None if data is None else json.dumps(data).encode(), headers={
            "Authorization": f"Bearer {self.token}", "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json",
            "User-Agent": "zmily-cla-check",
        })
        with self.opener.open(request, timeout=30) as response:
            require(response.geturl() == request.full_url, "Unexpected GitHub API redirect")
            return parse_json(response.read().decode("utf-8"))

    def status(self, sha: str, state: str, description: str) -> None:
        require(bool(re.fullmatch(r"[0-9a-f]{40}", sha)), "Invalid head SHA")
        self.request(f"/statuses/{sha}", {"state": state, "context": CONTEXT,
                                        "description": description[:140]})


def check_pr(api: GitHub, number: int, root: Path) -> None:
    require(positive_id(number), "Invalid PR number")
    pr = api.request(f"/pulls/{number}")
    sha = pr["head"]["sha"]
    api.status(sha, "pending", "Checking trusted CLA policy and prior acceptances")
    try:
        policy, registry = load(root)
        require(policy["status"] == "active", "CLA awaits legal review and owner approval")
        require(type(pr.get("commits")) is int and 0 < pr["commits"] <= 250,
                "PR commit count outside supported review limit")
        commits = []
        for page in range(1, (pr["commits"] + 99) // 100 + 1):
            batch = api.request(f"/pulls/{number}/commits?per_page=100&page={page}")
            require(isinstance(batch, list), "Invalid commit response")
            commits.extend(batch)
        evaluate(policy, registry, pr, commits)
        require(api.request(f"/pulls/{number}")["head"]["sha"] == sha,
                "PR changed during evaluation; rerun for its new head")
    except Exception:
        api.status(sha, "failure", "CLA acceptance blocked; see workflow log and CONTRIBUTING.md")
        raise
    api.status(sha, "success", "Prior CLA acceptances verified; provenance review still required")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-config", action="store_true")
    args = parser.parse_args()
    try:
        if args.check_config:
            policy, _ = load(ROOT)
            print(f"CLA configuration valid; status={policy['status']}")
        else:
            require(os.environ.get("GITHUB_EVENT_NAME") == "pull_request_target", "Unsupported workflow event")
            event = parse_json(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
            repository = os.environ["GITHUB_REPOSITORY"]
            require(event["repository"]["full_name"] == repository, "Event repository mismatch")
            require(event["pull_request"]["base"]["repo"]["full_name"] == repository, "PR base mismatch")
            api = GitHub(repository, os.environ.get("CLA_GITHUB_TOKEN", ""))
            check_pr(api, event["number"], ROOT)
        return 0
    except (Refusal, ValueError, KeyError, TypeError, OSError, HTTPError, URLError) as error:
        # Do not print API response bodies, tokens or untrusted contributor content.
        print(f"CLA check refused: {error if isinstance(error, Refusal) else type(error).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
