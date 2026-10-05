#!/usr/bin/env python3
"""Read-only guard for the fixed updater branch, loaded from trusted main.

A policy-bearing bot PR is handed to reviewers, never updated by this helper.
Branch blobs are parsed as data; no branch code is checked out or executed.
"""
import argparse
import json
from pathlib import Path
import re
import runpy
import subprocess
import sys


HERE = Path(__file__).resolve().parent
BRANCH = "origin/automation/rclone-stable"
BOT_EMAIL = "41898282+github-actions[bot]@users.noreply.github.com"
MANIFEST = "rclone-version.env"
POLICY = "provider-coverage-policy.json"
MAX_POLICY = 1024 * 1024


class GuardError(Exception):
    pass


def require(condition):
    if not condition:
        raise GuardError("update_branch_refused")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def strict_json(data):
    def reject_constant(_value):
        raise GuardError("update_branch_refused")
    return json.loads(data, object_pairs_hook=unique_object, parse_constant=reject_constant)


def git(*arguments, limit=MAX_POLICY):
    result = subprocess.run(["git", "--no-pager", *arguments], stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=30, check=False)
    require(result.returncode == 0 and len(result.stdout) <= limit)
    return result.stdout


def blob(head, path, limit):
    size = git("cat-file", "-s", f"{head}:{path}", limit=32).strip()
    require(re.fullmatch(rb"[0-9]+", size) is not None and 0 < int(size) <= limit)
    data = git("cat-file", "blob", f"{head}:{path}", limit=limit)
    require(len(data) == int(size))
    return data


def disposition(head, prs):
    require(isinstance(head, str) and re.fullmatch(r"[a-f0-9]{40}", head) is not None)
    require(isinstance(prs, list) and len(prs) <= 1)
    if prs:
        pr = prs[0]
        require(isinstance(pr, dict) and type(pr.get("number")) is int and pr["number"] > 0)
        require(all(isinstance(pr.get(key), dict) for key in ("author", "headRepository", "headRepositoryOwner")))
        require(pr["author"].get("login") in ("app/github-actions", "github-actions[bot]")
                and pr.get("isCrossRepository") is False
                and pr["headRepository"].get("name") == "triage-with-rclone"
                and pr["headRepositoryOwner"].get("login") == "Donovoi"
                and pr.get("headRefOid") == head)
    require(git("rev-parse", BRANCH, limit=64).strip() == head.encode("ascii"))
    raw_paths = git("diff", "--name-only", "-z", f"origin/main...{head}", limit=4096)
    paths = raw_paths.decode("utf-8").split("\0")
    require(paths[-1] == "")
    paths.pop()
    require(len(paths) == len(set(paths)))
    changed = set(paths)
    require(changed in (set(), {MANIFEST}, {MANIFEST, POLICY}))
    checked = [MANIFEST, POLICY] if POLICY in changed else [MANIFEST]
    tree = git("ls-tree", "-z", head, "--", *checked, limit=1024)
    records = tree.decode("utf-8").split("\0")
    require(records.pop() == "" and len(records) == len(checked))
    names = set()
    for record in records:
        match = re.fullmatch(r"100644 blob [a-f0-9]{40}\t(.+)", record)
        require(match is not None)
        names.add(match.group(1))
    require(names == set(checked))
    if POLICY not in changed:
        # Preserve the bot-only orphan/reuse rule; human work is never updated.
        authors = git("log", "--format=%ae", "--max-count=1025", f"origin/main..{head}", limit=131072).decode("utf-8").splitlines()
        require(len(authors) <= 1024 and set(authors) <= {BOT_EMAIL})
        return "update"
    require(len(prs) == 1)  # A policy-bearing orphan has no bot-owned PR handoff.
    policy = strict_json(blob(head, POLICY, MAX_POLICY))
    # Both validators come from main, not from the proposed branch's tree.
    coverage = runpy.run_path(str(HERE / "provider_coverage.py"))
    coverage["validate_policy"](policy)
    updater = runpy.run_path(str(HERE / "update-rclone.py"))
    manifest = updater["parse_manifest"](blob(head, MANIFEST, 16384).decode("utf-8"))
    require(policy["reviewed_runtime_version"] == manifest["RCLONE_VERSION"])
    return "review_handoff"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--head", required=True)
    parser.add_argument("--prs", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        with args.prs.open("rb") as source:
            data = source.read(65537)
        require(len(data) <= 65536)
        action = disposition(args.head, strict_json(data))
    except (Exception, KeyboardInterrupt):
        # Git/JSON/policy failures must not publish identities or branch values.
        print("Updater branch guard refused the proposed state.", file=sys.stderr)
        return 1
    print(action)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
