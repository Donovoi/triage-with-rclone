"""Updater ownership and manual-review handoff: mocked Git, no network or writes."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("rclone_branch_guard", ROOT / "scripts/rclone-update-branch.py")
G = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(G)
HEAD = "a" * 40


def bot_pr():
    return {"number": 17, "author": {"login": "app/github-actions"}, "isCrossRepository": False,
            "headRepository": {"name": "triage-with-rclone"}, "headRepositoryOwner": {"login": "Donovoi"},
            "headRefOid": HEAD}


class BranchGuardTests(unittest.TestCase):
    def setUp(self):
        self.paths = ["provider-coverage-policy.json", "rclone-version.env"]
        self.tree = {path: ("100644", "blob") for path in self.paths}
        self.authors = [G.BOT_EMAIL, "synthetic-reviewer@example.invalid"]
        self.policy = {"schema_version": 2, "reviewed_runtime_version": "1.76.0", "providers": {},
                       "profiles": {"synthetic": {"required": {"application": ["cleanup"]}}}}
        self.blobs = {"provider-coverage-policy.json": json.dumps(self.policy).encode(),
                      "rclone-version.env": ("RCLONE_VERSION=1.76.0\n" + "\n".join(
                          f"{key}={'b' * 64}" for key in ("RCLONE_EXE_SHA256", "RCLONE_WINDOWS_ZIP_SHA256",
                                                        "RCLONE_LINUX_ZIP_SHA256", "RCLONE_LINUX_EXE_SHA256"))).encode()}
        self.calls = []
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(G, "git", side_effect=self.git))

    def git(self, *args, **kwargs):
        self.calls.append(args)
        if args == ("rev-parse", "origin/automation/rclone-stable"):
            return (HEAD + "\n").encode()
        if args == ("diff", "--name-only", "-z", f"origin/main...{HEAD}"):
            return ("\0".join(self.paths) + ("\0" if self.paths else "")).encode()
        if args[:4] == ("ls-tree", "-z", HEAD, "--"):
            return b"".join(f"{self.tree[path][0]} {self.tree[path][1]} {'b' * 40}\t{path}\0".encode()
                            for path in args[4:] if path in self.tree)
        if args == ("log", "--format=%ae", "--max-count=1025", f"origin/main..{HEAD}"):
            return ("\n".join(self.authors) + ("\n" if self.authors else "")).encode()
        if len(args) == 3 and args[0] == "cat-file" and args[2].startswith(HEAD + ":"):
            data = self.blobs[args[2].split(":", 1)[1]]
            return str(len(data)).encode() if args[1] == "-s" else data
        self.fail("Unexpected Git command")

    def test_reviewed_bot_pr_is_handed_off_without_modifying_input(self):
        before = copy.deepcopy((self.blobs, self.policy))
        self.assertEqual(G.disposition(HEAD, [bot_pr()]), "review_handoff")
        self.assertEqual((self.blobs, self.policy), before)
        self.assertTrue(all(call[0] in {"rev-parse", "diff", "ls-tree", "cat-file"} for call in self.calls))

    def test_manifest_only_bot_branch_and_interrupted_orphan_remain_updatable(self):
        self.paths = ["rclone-version.env"]
        self.authors = [G.BOT_EMAIL]
        for prs in ([], [bot_pr()]):
            with self.subTest(prs=bool(prs)):
                self.assertEqual(G.disposition(HEAD, prs), "update")
        self.paths = []
        self.authors = []
        self.assertEqual(G.disposition(HEAD, []), "update")

    def test_human_manifest_work_is_not_updated_even_on_bot_pr(self):
        self.paths = ["rclone-version.env"]
        for prs in ([], [bot_pr()]):
            with self.subTest(prs=bool(prs)), self.assertRaises(G.GuardError):
                G.disposition(HEAD, prs)

    def test_policy_bearing_orphan_is_rejected(self):
        self.authors = [G.BOT_EMAIL]
        with self.assertRaises(G.GuardError):
            G.disposition(HEAD, [])
        self.assertFalse(any(call[0] == "cat-file" for call in self.calls))

    def test_wrong_pr_owner_repository_count_type_or_head_is_rejected_before_git(self):
        mutations = [dict(bot_pr(), number=True), dict(bot_pr(), author={"login": "synthetic-human"}),
                     dict(bot_pr(), author=None), dict(bot_pr(), isCrossRepository=True),
                     dict(bot_pr(), isCrossRepository=0), dict(bot_pr(), headRefOid="c" * 40),
                     dict(bot_pr(), headRepository={"name": "other"}),
                     dict(bot_pr(), headRepositoryOwner={"login": "other"})]
        for prs in ([item] for item in mutations):
            with self.subTest(prs=prs), self.assertRaises(G.GuardError):
                G.disposition(HEAD, prs)
        for prs in (None, {}, [bot_pr(), bot_pr()]):
            with self.subTest(prs=prs), self.assertRaises(G.GuardError):
                G.disposition(HEAD, prs)
        self.assertEqual(self.calls, [])

    def test_fetched_ref_must_still_match_exact_head(self):
        with patch.object(G, "git", return_value=("c" * 40).encode()), self.assertRaises(G.GuardError):
            G.disposition(HEAD, [bot_pr()])

    def test_exact_paths_and_regular_nonexecutable_blobs_are_required(self):
        original = list(self.paths)
        for paths in (["provider-coverage-policy.json"], original + ["README.md"], original * 2,
                      ["rclone-version.env", "scripts/provider_coverage.py"]):
            with self.subTest(paths=paths), self.assertRaises(G.GuardError):
                self.paths = paths
                G.disposition(HEAD, [bot_pr()])
        self.paths = original
        for path in original:
            for mode, kind in (("120000", "blob"), ("100755", "blob"), ("160000", "commit"), ("040000", "tree")):
                with self.subTest(path=path, mode=mode), self.assertRaises(G.GuardError):
                    self.tree[path] = (mode, kind)
                    G.disposition(HEAD, [bot_pr()])
            self.tree[path] = ("100644", "blob")
        del self.tree["rclone-version.env"]
        with self.assertRaises(G.GuardError):
            G.disposition(HEAD, [bot_pr()])

    def test_policy_requires_strict_json_and_trusted_validation(self):
        valid = self.blobs["provider-coverage-policy.json"]
        for data in (b'{"schema_version":2,"schema_version":2}', b'{"x":NaN}', b'{"x":Infinity}',
                     b'[]', valid.replace(b'"1.76.0"', b'"v1.76.0"'),
                     valid.replace(b'"required":', b'"unreviewed_requirements":')):
            with self.subTest(data=data[:30]), self.assertRaises(Exception):
                self.blobs["provider-coverage-policy.json"] = data
                G.disposition(HEAD, [bot_pr()])

    def test_policy_review_must_bind_the_branch_manifest_not_latest_candidate(self):
        self.policy["reviewed_runtime_version"] = "1.77.0"
        self.blobs["provider-coverage-policy.json"] = json.dumps(self.policy).encode()
        with self.assertRaises(G.GuardError):
            G.disposition(HEAD, [bot_pr()])

    def test_blob_size_limit_is_checked_before_read(self):
        self.blobs["provider-coverage-policy.json"] = b"x" * (G.MAX_POLICY + 1)
        with self.assertRaises(G.GuardError):
            G.disposition(HEAD, [bot_pr()])
        self.assertFalse(any(call[:2] == ("cat-file", "blob") for call in self.calls))

    def test_cli_refusal_is_static_and_never_emits_dispatch_data(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "prs.json"
            path.write_text('[{"private":"CANARY"}]')
            output, error = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
                self.assertEqual(G.main(["--head", HEAD, "--prs", str(path)]), 1)
            self.assertEqual(output.getvalue(), "")
            self.assertEqual(error.getvalue(), "Updater branch guard refused the proposed state.\n")
            self.assertEqual(self.calls, [])

    def test_cli_handoff_emits_only_fixed_disposition(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "prs.json"
            path.write_text(json.dumps([bot_pr()]))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(G.main(["--head", HEAD, "--prs", str(path)]), 0)
            self.assertEqual(output.getvalue(), "review_handoff\n")


class WorkflowHandoffTests(unittest.TestCase):
    def test_handoff_precedes_branch_mutation_and_cannot_dispatch(self):
        workflow = (ROOT / ".github/workflows/rclone-update.yml").read_text(encoding="utf-8")
        guard = workflow.index("disposition=$(python3 -B scripts/rclone-update-branch.py")
        handoff = re.search(r'if \[\[ "\$disposition" == review_handoff \]\]; then\n(.*?)\n          +fi',
                            workflow, re.S).group(1)
        self.assertIn("disposition=review_handoff", handoff)
        self.assertIn("exit 0", handoff)
        self.assertNotIn("head=", handoff)
        self.assertNotRegex(handoff, r"\b(?:git|gh)\s")
        for operation in ("git checkout", "git merge", "git add", "git commit", "git push", "gh pr edit", "gh pr create"):
            self.assertGreater(workflow.index(operation), guard)
        self.assertIn("if: steps.candidate.outputs.changed == 'true' && steps.proposal.outputs.disposition == 'update'", workflow)
        self.assertIn("test_update_rclone*.py", workflow)
        self.assertIn("ref: main", workflow)
        self.assertNotIn("--force", workflow)

    def test_git_adapter_has_timeout_and_discards_raw_error(self):
        with patch.object(G.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"ok")) as run:
            self.assertEqual(G.git("rev-parse", G.BRANCH), b"ok")
        self.assertEqual(run.call_args.args[0], ["git", "--no-pager", "rev-parse", G.BRANCH])
        self.assertEqual(run.call_args.kwargs, {"stdout": subprocess.PIPE, "stderr": subprocess.DEVNULL,
                                                "timeout": 30, "check": False})


if __name__ == "__main__":
    unittest.main()
