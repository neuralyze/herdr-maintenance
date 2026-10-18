"""Reviewed squash imports and paired maintained-tip lock proposals.

No upstream program is executed. All Git work is isolated, unauthenticated except
for the single push subprocess, and candidates have only real maintained parents.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from urllib.parse import quote

from .github import GitHub, GitHubError

SHA = re.compile(r"[0-9a-f]{40}\Z")
REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
SECURITY = re.compile(r"\b(security|vulnerability|CVE-\d|remote code execution|privilege escalation)\b", re.I)


def clean_env():
    env = {k: v for k, v in os.environ.items() if not any(
        word in k.upper() for word in ("TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "API_KEY", "AUTH", "CLOUD", "AWS_", "AZURE_", "GOOGLE_", "GIT_", "GH_", "SSH_"))}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
               GIT_TERMINAL_PROMPT="0", GIT_AUTHOR_NAME="Maintenance bot",
               GIT_AUTHOR_EMAIL="maintenance@users.noreply.github.com",
               GIT_COMMITTER_NAME="Maintenance bot",
               GIT_COMMITTER_EMAIL="maintenance@users.noreply.github.com")
    return env


class GitError(RuntimeError):
    pass


def git(directory, *args, input_text=None, check=True, push=False):
    env = clean_env()
    if push:
        token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        if not token:
            raise GitError("Authenticated push requires GH_TOKEN or GITHUB_TOKEN")
        auth = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        env.update(GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="http.https://github.com/.extraheader",
                   GIT_CONFIG_VALUE_0=f"AUTHORIZATION: basic {auth}")
    result = subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
                             "-c", "credential.helper=", "-C", str(directory), *args],
                            env=env, input=input_text, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and result.returncode:
        raise GitError(f"git {args[0]} failed (exit {result.returncode}); inspect repository identities, refs and permissions")
    return result.stdout.strip() if check else result


def validate_sha(value):
    if not isinstance(value, str) or not SHA.fullmatch(value):
        raise ValueError("Expected exact lowercase 40-hex commit")
    return value


def load_config(path):
    config = json.loads(Path(path).read_text())
    if config.get("schema_version") != 1 or set(config["products"]) != {"herdr", "herdr-mirror"}:
        raise ValueError("Unsupported product configuration")
    for repo in [config["maintenance_repository"], *(p[k] for p in config["products"].values() for k in ("fork", "upstream"))]:
        if not REPO.fullmatch(repo):
            raise ValueError("Invalid configured GitHub repository")
    for product in config["products"].values():
        if product["branch"] != "maintained":
            raise ValueError("Only approved maintained branches may be polled")
    return config


def metadata(raw, name, product):
    if raw.get("schema_version") != 1 or raw.get("product") != name or raw.get("upstream_repository") != product["upstream"]:
        raise ValueError("Upstream metadata identity mismatch")
    validate_sha(raw["upstream_commit"])
    if not isinstance(raw.get("patches"), list):
        raise ValueError("Upstream metadata must preserve a patch ledger")
    return raw


def outcome(status="up_to_date", **values):
    return {"status": status, "pull_request": None, "branch": None,
            "security_update": False, "adoption_candidates": [],
            "dispatched": False, **values}


def issue(gh, repo, owner, key, title, body):
    issues = gh.api("GET", f"repos/{repo}/issues?state=open&per_page=100")
    existing = next((i for i in issues if not i.get("pull_request") and key in (i.get("body") or "")), None)
    payload = {"title": title, "body": f"{key}\n\n{body}", "assignees": [owner]}
    return gh.api("PATCH" if existing else "POST",
                  f"repos/{repo}/issues" + (f"/{existing['number']}" if existing else ""), payload)


def propose(gh, repo, owner, base, branch, title, body, workflow, publish):
    prs = gh.api("GET", f"repos/{repo}/pulls?state=open&head={quote(repo.split('/')[0] + ':' + branch)}&per_page=100")
    if prs:
        pr = prs[0]
        gh.api("PATCH", f"repos/{repo}/pulls/{pr['number']}", {"title": title, "body": body})
    else:
        publish()
        pr = gh.api("POST", f"repos/{repo}/pulls", {"head": branch, "base": base, "title": title, "body": body})
    requested = {reviewer["login"] for reviewer in pr.get("requested_reviewers", [])}
    if owner not in requested and pr.get("user", {}).get("login") != owner:
        reviews = gh.api("GET", f"repos/{repo}/pulls/{pr['number']}/reviews?per_page=100")
        if not any(review.get("user", {}).get("login") == owner for review in reviews):
            gh.api("POST", f"repos/{repo}/pulls/{pr['number']}/requested_reviewers", {"reviewers": [owner]})
    # A prior run may have created the PR but failed before dispatch. Reconcile
    # the actual immutable candidate head, without retrying completed failures.
    head = validate_sha(pr["head"]["sha"])
    runs = gh.api("GET", f"repos/{repo}/actions/workflows/{workflow}/runs?branch={quote(branch, safe='')}&per_page=100")
    dispatched = not any(run.get("head_sha") == head for run in runs["workflow_runs"])
    if dispatched:
        gh.api("POST", f"repos/{repo}/actions/workflows/{workflow}/dispatches", {"ref": branch})
    return outcome("pr_opened", pull_request=pr["html_url"], branch=branch, dispatched=dispatched)


def push_candidate(directory, repo, branch, commit):
    remote = git(directory, "ls-remote", f"https://github.com/{repo}.git", f"refs/heads/{branch}")
    if remote:
        # Existing immutable candidate may differ in commit date, but never in tree/parent.
        git(directory, "fetch", "--no-tags", f"https://github.com/{repo}.git", f"refs/heads/{branch}")
        other = git(directory, "rev-parse", "FETCH_HEAD")
        for suffix in ("^{tree}", "^"):
            if git(directory, "rev-parse", other + suffix) != git(directory, "rev-parse", commit + suffix):
                raise GitError("Existing candidate identity differs; human review required, refusing force push")
        return
    git(directory, "push", f"https://github.com/{repo}.git", f"{commit}:refs/heads/{branch}", push=True)


def prepare_import(directory, maintained, recorded, target):
    """Return (merged tree, conflicts); never mutate the maintained branch."""
    synthetic = git(directory, "commit-tree", git(directory, "rev-parse", maintained + "^{tree}"),
                    "-p", recorded, input_text="Ephemeral explicit upstream base\n")
    git(directory, "checkout", "--detach", synthetic)
    result = git(directory, "merge", "--no-commit", "--no-ff", target, check=False)
    conflicts = git(directory, "diff", "--name-only", "--diff-filter=U").splitlines()
    if result.returncode and not conflicts:
        git(directory, "merge", "--abort", check=False)
        raise GitError("Upstream merge failed without resolvable conflict list")
    # Workflow changes are explicitly excluded, including upstream deletions/additions.
    git(directory, "rm", "-r", "-f", "--ignore-unmatch", "--", ".github/workflows")
    if git(directory, "ls-tree", maintained, "--", ".github/workflows"):
        git(directory, "restore", "--source=" + maintained, "--staged", "--worktree", "--", ".github/workflows")
    conflicts = git(directory, "diff", "--name-only", "--diff-filter=U").splitlines()
    if conflicts:
        git(directory, "merge", "--abort", check=False)
        git(directory, "checkout", "--detach", maintained)
        return None, conflicts
    return git(directory, "write-tree"), []


def adoption(directory, ledger, recorded, target, notes):
    upstream = git(directory, "log", "-p", f"{recorded}..{target}")
    ids = git(directory, "patch-id", "--stable", input_text=upstream)
    upstream_ids = {line.split()[0] for line in ids.splitlines()}
    candidates = []
    for patch in ledger:
        commit = validate_sha(patch["commit"])
        diff = git(directory, "show", "--pretty=format:", commit)
        pid = git(directory, "patch-id", "--stable", input_text=diff).split()
        exact = bool(pid and pid[0] in upstream_ids)
        words = [word for word in patch.get("keywords", []) if word.casefold() in (notes + upstream).casefold()]
        if exact or words:
            candidates.append({"id": patch["id"], "exact_patch_id": exact, "keywords": words,
                               "action": "Human review only; patch retained"})
    return candidates


def component(config, product_name, workspace, apply=False, gh=None, source_urls=None):
    gh = gh or GitHub()
    product = config["products"][product_name]
    repo = product["fork"]
    if apply and os.environ.get("GITHUB_REPOSITORY", repo) != repo:
        raise ValueError("github.repository does not match configured product fork")
    release = gh.api("GET", f"repos/{product['upstream']}/releases/latest")
    if release.get("draft") or release.get("prerelease"):
        raise ValueError("Latest release must be published and stable")
    tag = release["tag_name"]
    if not isinstance(tag, str) or not tag or tag.startswith("-") or any(c in tag for c in "\n\r\0"):
        raise ValueError("Invalid release tag")
    notes = release.get("body") or ""
    security = bool(SECURITY.search(notes + " " + release.get("name", "")))
    Path(workspace).mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="component-", dir=workspace) as temporary:
        directory = Path(temporary)
        git(directory, "init")
        fork_url, upstream_url = source_urls or (f"https://github.com/{repo}.git", f"https://github.com/{product['upstream']}.git")
        git(directory, "fetch", "--no-tags", fork_url, f"refs/heads/{product['branch']}")
        maintained = git(directory, "rev-parse", "FETCH_HEAD")
        git(directory, "update-ref", "refs/heads/maintained", maintained)
        baseline = metadata(json.loads(git(directory, "show", maintained + ":.maintenance/upstream.json")), product_name, product)
        recorded = baseline["upstream_commit"]
        git(directory, "fetch", "--no-tags", upstream_url, recorded)
        git(directory, "fetch", "--no-tags", upstream_url, f"refs/tags/{tag}")
        target = validate_sha(git(directory, "rev-parse", "FETCH_HEAD^{commit}"))
        if baseline.get("upstream_tag") == tag and target != recorded:
            reason = "Recorded upstream tag was retargeted; review tag provenance before import."
        elif not git(directory, "merge-base", "--is-ancestor", target, recorded, check=False).returncode:
            return outcome(reason="Latest stable release is already included in the recorded upstream base; no downgrade")
        elif git(directory, "merge-base", "--is-ancestor", recorded, target, check=False).returncode:
            reason = "Upstream ancestry diverges from recorded base; review release provenance before import."
        else:
            reason = None
        if reason:
            if apply:
                issue(gh, repo, config["owner"], "<!-- maintenance:upstream-review -->", "Review upstream release provenance", reason + f"\nRecorded: {recorded}\nTarget: {target} ({tag})")
            return outcome("review", reason=reason, security_update=security)
        # Detect historical tag retargeting even when latest now points at a newer tag.
        if baseline.get("upstream_tag"):
            git(directory, "fetch", "--no-tags", upstream_url, "refs/tags/" + baseline["upstream_tag"])
            if git(directory, "rev-parse", "FETCH_HEAD^{commit}") != recorded:
                reason = "Previously recorded upstream tag was retargeted; human review required"
                if apply:
                    issue(gh, repo, config["owner"], "<!-- maintenance:upstream-review -->", "Review retargeted upstream tag", reason)
                return outcome("review", reason=reason)
        candidates = adoption(directory, baseline["patches"], recorded, target, notes)
        tree, conflicts = prepare_import(directory, maintained, recorded, target)
        if conflicts:
            if apply:
                issue(gh, repo, config["owner"], "<!-- maintenance:upstream-conflict -->", f"Resolve {product_name} upstream import conflicts", f"Import {tag} ({target}) onto {maintained}. Resolve manually; maintained was untouched.\n\n" + "\n".join(f"- `{p}`" for p in conflicts))
            return outcome("conflict", conflicts=conflicts, security_update=security, adoption_candidates=candidates)
        baseline.update(upstream_commit=target, upstream_tag=tag)
        path = directory / ".maintenance/upstream.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(baseline, indent=2) + "\n")
        git(directory, "add", "--", ".maintenance/upstream.json")
        tree = git(directory, "write-tree")
        commit = git(directory, "commit-tree", tree, "-p", maintained, input_text=f"Import {product_name} upstream {tag}\n")
        branch = f"maintenance/upstream-{target}-{maintained}"
        result = outcome("review", branch=branch, candidate_commit=commit, reason="Dry run; no remote state changed")
        if apply:
            body = f"Import stable upstream `{tag}` at `{target}` onto `{maintained}`.\n\nOwned workflows and local patch ledger retained. No automatic patch retirement.\n\n" + json.dumps(candidates, indent=2)
            if security:
                body = "SECURITY UPDATE: prioritize owner review.\n\n" + body
                issue(gh, repo, config["owner"], "<!-- maintenance:security-update -->", f"Prioritize {product_name} security update {tag}", notes + "\n\n" + body)
            result = propose(gh, repo, config["owner"], product["branch"], branch,
                             f"{'[security] ' if security else ''}Import upstream {tag}", body,
                             "maintenance-check.yml", lambda: push_candidate(directory, repo, branch, commit))
            labels = (["security"] if security else []) + (["adoption-review"] if candidates else [])
            for label in labels:
                try:
                    gh.api("POST", f"repos/{repo}/labels", {"name": label, "color": "b60205" if label == "security" else "fbca04"})
                except GitHubError as error:
                    if error.status != 422:
                        raise
            if labels:
                number = result["pull_request"].rstrip("/").split("/")[-1]
                gh.api("POST", f"repos/{repo}/issues/{number}/labels", {"labels": labels})
        return {**result, "security_update": security, "adoption_candidates": candidates}


def pair(config, lock_path, workspace, apply=False, gh=None):
    gh = gh or GitHub()
    repo = config["maintenance_repository"]
    if apply and os.environ.get("GITHUB_REPOSITORY", repo) != repo:
        raise ValueError("github.repository does not match coordinator")
    old = json.loads(Path(lock_path).read_text())
    if old.get("schema_version") != 1 or old.get("platform") != "linux-x86_64" or set(old["products"]) != set(config["products"]):
        raise ValueError("Invalid pair lock schema")
    updated = json.loads(json.dumps(old))
    for name, product in config["products"].items():
        previous = old["products"][name]
        if previous["repository"] != product["fork"] or previous["upstream_repository"] != product["upstream"]:
            raise ValueError("Lock repository differs from configured identity")
        validate_sha(previous["commit"])
        validate_sha(previous["upstream_commit"])
        tip = validate_sha(gh.api("GET", f"repos/{product['fork']}/git/ref/heads/{product['branch']}")["object"]["sha"])
        content = gh.api("GET", f"repos/{product['fork']}/contents/.maintenance/upstream.json?ref={tip}")
        baseline = metadata(json.loads(base64.b64decode(content["content"], validate=False)), name, product)
        updated["products"][name] = dict(repository=product["fork"], commit=tip,
            upstream_repository=product["upstream"], upstream_commit=baseline["upstream_commit"], upstream_tag=baseline.get("upstream_tag"))
    if updated == old:
        return outcome()
    branch = "maintenance/pair-" + "-".join(updated["products"][p]["commit"] for p in sorted(updated["products"]))
    if not apply:
        return outcome("review", branch=branch, lock=updated, reason="Dry run; no remote state changed")
    Path(workspace).mkdir(parents=True, exist_ok=True)
    default = gh.api("GET", f"repos/{repo}")["default_branch"]
    with tempfile.TemporaryDirectory(prefix="pair-", dir=workspace) as temporary:
        directory = Path(temporary)
        git(directory, "init")
        git(directory, "fetch", "--no-tags", f"https://github.com/{repo}.git", f"refs/heads/{default}")
        base = git(directory, "rev-parse", "FETCH_HEAD")
        git(directory, "checkout", "--detach", base)
        relative = Path(lock_path)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("Pair lock must be repository-relative")
        existing = json.loads((directory / relative).read_text())
        if existing != old:
            raise ValueError("Coordinator lock changed; rerun from approved default branch")
        (directory / relative).write_text(json.dumps(updated, indent=2) + "\n")
        git(directory, "add", "--", str(relative))
        commit = git(directory, "commit-tree", git(directory, "write-tree"), "-p", base, input_text="Update approved maintained pair pins\n")
        branch += "-" + base
        return propose(gh, repo, config["owner"], default, branch, "Validate updated maintained pair",
                       "Pins are approved maintained heads only.\n\n" + json.dumps(updated, indent=2),
                       "pair-check.yml", lambda: push_candidate(directory, repo, branch, commit))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="config/products.json")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("component", "pair"):
        command = commands.add_parser(name)
        command.add_argument("--workspace", required=True)
        command.add_argument("--output", required=True)
        command.add_argument("--apply", action="store_true")
        if name == "component":
            command.add_argument("--product", choices=("herdr", "herdr-mirror"), required=True)
        else:
            command.add_argument("--lock", required=True)
    args = parser.parse_args()
    try:
        config = load_config(args.config)
        result = component(config, args.product, args.workspace, args.apply) if args.command == "component" else pair(config, args.lock, args.workspace, args.apply)
    except (GitError, GitHubError, ValueError, KeyError, OSError) as error:
        result = outcome("review", error=str(error), reason="Action required; no automatic fallback or merge")
        code = 1
    else:
        code = 0
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
