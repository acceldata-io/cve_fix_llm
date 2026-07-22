#!/usr/bin/env python3
"""Bulk-merge open CVE fix PRs that list basapuram-kumar as reviewer.

GitHub attributes approve/merge to the owner of GITHUB_TOKEN. To merge *as*
basapuram, set GITHUB_TOKEN to basapuram's PAT (or have him run this script).

Default is dry-run (list only). Pass --apply to merge.

Examples:
  # List open CVE PRs where basapuram-kumar is a requested reviewer
  python3 merge_cve_prs.py

  # Same, limited repos
  python3 merge_cve_prs.py --repos odp-ambari,pinot,druid,zeppelin

  # Approve (as token user) then merge
  GITHUB_TOKEN=ghp_basapuram... python3 merge_cve_prs.py --apply --approve

  # Merge specific PR URLs
  python3 merge_cve_prs.py --apply --prs \\
    https://github.com/acceldata-io/odp-ambari/pull/617 \\
    https://github.com/acceldata-io/odp-ambari/pull/618
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlparse

import requests

try:
    from cve_env import load_repo_env
    load_repo_env()
except Exception:
    pass

API = "https://api.github.com"
DEFAULT_REVIEWER = "basapuram-kumar"
DEFAULT_ORG = "acceldata-io"
# Titles from our deliver scripts: "OSV-… - CVE - Bumped-up …" etc.
TITLE_HINT = re.compile(r"(CVE|OSV-\d+|Bumped-up|Bump |address)", re.I)


def token() -> str:
    t = (os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or "").strip()
    if t:
        return t
    # Fallback: gh auth token
    try:
        import subprocess
        p = subprocess.run(
            ["gh", "auth", "token"],
            capture_output=True, text=True, timeout=10,
        )
        if p.returncode == 0 and p.stdout.strip():
            return p.stdout.strip()
    except Exception:
        pass
    return ""


def headers(tok: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {tok}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def catalog_repos() -> List[str]:
    """acceldata-io/<repo> slugs from cve_profiles."""
    try:
        from cve_profiles import PROFILES
    except Exception:
        return []
    out: Set[str] = set()
    for p in PROFILES.values():
        url = (p.get("git_url") or "").rstrip("/")
        if "github.com/" not in url:
            continue
        slug = url.split("github.com/", 1)[1].replace(".git", "")
        if slug.startswith(f"{DEFAULT_ORG}/"):
            out.add(slug)
    return sorted(out)


def parse_pr_ref(ref: str) -> Tuple[str, int]:
    """Parse 'owner/repo#123' or full GitHub PR URL → (owner/repo, number)."""
    ref = ref.strip()
    m = re.match(r"^([^/\s]+/[^/\s]+)#(\d+)$", ref)
    if m:
        return m.group(1), int(m.group(2))
    m = re.match(r"^https?://github\.com/([^/]+)/([^/]+)/pull/(\d+)/?$", ref)
    if m:
        return f"{m.group(1)}/{m.group(2)}", int(m.group(3))
    raise ValueError(f"Unrecognized PR ref: {ref}")


def gh_get(tok: str, path: str, params: Optional[dict] = None) -> Any:
    r = requests.get(f"{API}{path}", headers=headers(tok), params=params or {}, timeout=60)
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return r.json()


def gh_post(tok: str, path: str, body: dict) -> Tuple[int, Any]:
    r = requests.post(
        f"{API}{path}", headers=headers(tok), json=body, timeout=60,
    )
    try:
        data = r.json()
    except Exception:
        data = {"raw": r.text[:500]}
    return r.status_code, data


def gh_put(tok: str, path: str, body: dict) -> Tuple[int, Any]:
    r = requests.put(
        f"{API}{path}", headers=headers(tok), json=body, timeout=60,
    )
    try:
        data = r.json() if r.text else {}
    except Exception:
        data = {"raw": r.text[:500]}
    return r.status_code, data


def whoami(tok: str) -> str:
    me = gh_get(tok, "/user")
    return (me or {}).get("login") or "?"


def list_open_prs(tok: str, repo: str) -> List[dict]:
    out: List[dict] = []
    page = 1
    while True:
        batch = gh_get(
            tok, f"/repos/{repo}/pulls",
            {"state": "open", "per_page": 100, "page": page},
        )
        if not batch:
            break
        out.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    return out


def requested_reviewers(pr: dict) -> Set[str]:
    names = {u.get("login", "") for u in (pr.get("requested_reviewers") or [])}
    # Also include users who already left a review (approved/commented)
    return {n for n in names if n}


def fetch_reviews(tok: str, repo: str, num: int) -> List[dict]:
    data = gh_get(tok, f"/repos/{repo}/pulls/{num}/reviews")
    return data or []


def reviewer_involved(tok: str, pr: dict, reviewer: str) -> bool:
    if reviewer in requested_reviewers(pr):
        return True
    repo = pr["base"]["repo"]["full_name"]
    for rev in fetch_reviews(tok, repo, pr["number"]):
        if (rev.get("user") or {}).get("login") == reviewer:
            return True
    return False


def title_matches(title: str, pattern: Optional[re.Pattern]) -> bool:
    if pattern is None:
        return bool(TITLE_HINT.search(title or ""))
    return bool(pattern.search(title or ""))


def mergeable_state(tok: str, repo: str, num: int) -> dict:
    """Fresh PR detail (mergeable is null until GitHub computes it)."""
    for _ in range(5):
        pr = gh_get(tok, f"/repos/{repo}/pulls/{num}")
        if not pr:
            return {}
        if pr.get("mergeable") is not None:
            return pr
        time.sleep(1.5)
    return pr or {}


def collect_candidates(
    tok: str,
    repos: Iterable[str],
    reviewer: str,
    title_re: Optional[re.Pattern],
    require_reviewer: bool,
    authors: Optional[Set[str]],
) -> List[dict]:
    found: List[dict] = []
    for repo in repos:
        try:
            prs = list_open_prs(tok, repo)
        except requests.HTTPError as e:
            print(f"  SKIP {repo}: {e}", flush=True)
            continue
        print(f"  {repo}: {len(prs)} open PR(s)", flush=True)
        for pr in prs:
            if pr.get("draft"):
                continue
            if authors and (pr.get("user") or {}).get("login") not in authors:
                continue
            if not title_matches(pr.get("title") or "", title_re):
                continue
            if require_reviewer and not reviewer_involved(tok, pr, reviewer):
                continue
            found.append(pr)
    return found


def approve_pr(tok: str, repo: str, num: int, body: str) -> Tuple[bool, str]:
    code, data = gh_post(
        tok, f"/repos/{repo}/pulls/{num}/reviews",
        {"event": "APPROVE", "body": body},
    )
    if code in (200, 201):
        return True, "approved"
    # Already approved by this user is often 422
    msg = (data.get("message") if isinstance(data, dict) else str(data)) or ""
    if code == 422 and "already" in msg.lower():
        return True, "already-approved"
    return False, f"approve HTTP {code}: {msg or data}"


def merge_pr(
    tok: str,
    repo: str,
    num: int,
    method: str,
    admin: bool,
    commit_title: Optional[str],
) -> Tuple[bool, str]:
    payload: Dict[str, Any] = {"merge_method": method}
    if commit_title:
        payload["commit_title"] = commit_title
    # Prefer merge endpoint; admin bypass via query when supported by gh CLI —
    # REST uses PUT /merges with no admin flag; use GraphQL or gh for admin.
    # For REST: if branch protection blocks, return the error clearly.
    code, data = gh_put(tok, f"/repos/{repo}/pulls/{num}/merge", payload)
    if code in (200, 201):
        sha = (data or {}).get("sha", "")[:12]
        return True, f"merged ({method}) sha={sha}"
    msg = (data.get("message") if isinstance(data, dict) else str(data)) or ""
    if admin and code in (405, 409, 422):
        # Fallback: gh pr merge --admin if available
        import subprocess
        cmd = [
            "gh", "pr", "merge", str(num),
            "--repo", repo,
            f"--{method}",
            "--admin",
        ]
        if commit_title:
            cmd.extend(["--subject", commit_title])
        env = os.environ.copy()
        env["GH_TOKEN"] = tok
        p = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=120)
        if p.returncode == 0:
            return True, f"merged-admin ({method})"
        return False, f"admin-merge failed: {(p.stderr or p.stdout)[-400:]}"
    return False, f"merge HTTP {code}: {msg or data}"


def main() -> int:
    ap = argparse.ArgumentParser(
        description="List/merge CVE fix PRs for reviewer basapuram-kumar",
    )
    ap.add_argument(
        "--reviewer", default=DEFAULT_REVIEWER,
        help=f"GitHub login that must be reviewer (default: {DEFAULT_REVIEWER})",
    )
    ap.add_argument(
        "--repos", default="",
        help="Comma-separated owner/repo or bare repo names under acceldata-io. "
             "Default: all repos from cve_profiles.",
    )
    ap.add_argument(
        "--prs", nargs="*", default=[],
        help="Explicit PR URLs or owner/repo#N (skips discovery filters except open)",
    )
    ap.add_argument(
        "--author", default="",
        help="Only PRs authored by this login (optional)",
    )
    ap.add_argument(
        "--title-regex", default="",
        help="Override title filter regex (default: CVE|OSV-|Bumped-up|…)",
    )
    ap.add_argument(
        "--any-title", action="store_true",
        help="Do not filter by title (still filter by reviewer unless --no-reviewer-filter)",
    )
    ap.add_argument(
        "--no-reviewer-filter", action="store_true",
        help="Do not require the reviewer to be requested/involved",
    )
    ap.add_argument(
        "--apply", action="store_true",
        help="Actually merge (default is dry-run list only)",
    )
    ap.add_argument(
        "--approve", action="store_true",
        help="Submit APPROVE review as the token user before merge",
    )
    ap.add_argument(
        "--merge-method", choices=("merge", "squash", "rebase"), default="merge",
    )
    ap.add_argument(
        "--admin", action="store_true",
        help="If normal merge is blocked, retry via `gh pr merge --admin`",
    )
    ap.add_argument(
        "--sleep", type=float, default=1.0,
        help="Seconds between merges (default 1)",
    )
    ap.add_argument(
        "--json-out", default="",
        help="Write results JSON to this path",
    )
    args = ap.parse_args()

    tok = token()
    if not tok:
        print("ERROR: set GITHUB_TOKEN (or GH_TOKEN / `gh auth login`).", file=sys.stderr)
        print(
            "To merge as basapuram, use basapuram's PAT:\n"
            "  GITHUB_TOKEN=ghp_... python3 merge_cve_prs.py --apply --approve",
            file=sys.stderr,
        )
        return 2

    login = whoami(tok)
    print(f"GitHub user (token): {login}", flush=True)
    if args.apply and args.approve and login.lower() != args.reviewer.lower():
        print(
            f"NOTE: approve/merge will appear as '{login}', not '{args.reviewer}'.\n"
            f"      Export basapuram's GITHUB_TOKEN if you need his identity.",
            flush=True,
        )

    title_re: Optional[re.Pattern]
    if args.any_title:
        title_re = re.compile(r".*")
    elif args.title_regex:
        title_re = re.compile(args.title_regex)
    else:
        title_re = None  # use TITLE_HINT

    authors = {args.author} if args.author else None
    candidates: List[dict] = []

    if args.prs:
        for ref in args.prs:
            repo, num = parse_pr_ref(ref)
            pr = gh_get(tok, f"/repos/{repo}/pulls/{num}")
            if not pr:
                print(f"  NOT FOUND {ref}", flush=True)
                continue
            if pr.get("state") != "open":
                print(f"  SKIP {repo}#{num} state={pr.get('state')}", flush=True)
                continue
            candidates.append(pr)
    else:
        if args.repos.strip():
            repos = []
            for part in args.repos.split(","):
                part = part.strip()
                if not part:
                    continue
                if "/" not in part:
                    part = f"{DEFAULT_ORG}/{part}"
                repos.append(part)
        else:
            repos = catalog_repos()
            if not repos:
                print("ERROR: no repos from cve_profiles; pass --repos", file=sys.stderr)
                return 2
        print(f"Scanning {len(repos)} repo(s)…", flush=True)
        candidates = collect_candidates(
            tok, repos, args.reviewer, title_re,
            require_reviewer=not args.no_reviewer_filter,
            authors=authors,
        )

    # De-dupe + stable sort
    seen: Set[str] = set()
    uniq: List[dict] = []
    for pr in candidates:
        key = f"{pr['base']['repo']['full_name']}#{pr['number']}"
        if key in seen:
            continue
        seen.add(key)
        uniq.append(pr)
    uniq.sort(key=lambda p: (p["base"]["repo"]["full_name"], p["number"]))

    print(f"\nCandidates: {len(uniq)}", flush=True)
    results: List[dict] = []
    for pr in uniq:
        repo = pr["base"]["repo"]["full_name"]
        num = pr["number"]
        title = pr.get("title") or ""
        url = pr.get("html_url") or ""
        author = (pr.get("user") or {}).get("login")
        print(f"\n• {repo}#{num}  ({author})", flush=True)
        print(f"  {title}", flush=True)
        print(f"  {url}", flush=True)

        detail = mergeable_state(tok, repo, num)
        mergeable = detail.get("mergeable")
        mstate = detail.get("mergeable_state")
        print(f"  mergeable={mergeable} state={mstate}", flush=True)

        row: Dict[str, Any] = {
            "repo": repo,
            "number": num,
            "title": title,
            "url": url,
            "author": author,
            "mergeable": mergeable,
            "mergeable_state": mstate,
        }

        if not args.apply:
            row["action"] = "dry-run"
            results.append(row)
            continue

        if mergeable is False:
            row["action"] = "skipped-conflict"
            row["ok"] = False
            print("  SKIP: not mergeable (conflict?)", flush=True)
            results.append(row)
            continue

        if args.approve:
            ok, msg = approve_pr(
                tok, repo, num,
                body=f"Approving CVE fix PR as {login} (bulk merge via merge_cve_prs.py).",
            )
            print(f"  approve: {msg}", flush=True)
            row["approve"] = msg
            if not ok:
                row["action"] = "approve-failed"
                row["ok"] = False
                results.append(row)
                continue

        ok, msg = merge_pr(
            tok, repo, num,
            method=args.merge_method,
            admin=args.admin,
            commit_title=None,
        )
        print(f"  merge: {msg}", flush=True)
        row["action"] = "merged" if ok else "merge-failed"
        row["ok"] = ok
        row["detail"] = msg
        results.append(row)
        if args.sleep > 0:
            time.sleep(args.sleep)

    merged = sum(1 for r in results if r.get("action") == "merged")
    failed = sum(1 for r in results if r.get("ok") is False)
    print(
        f"\nDone. candidates={len(uniq)} "
        f"{'merged=' + str(merged) + ' failed=' + str(failed) if args.apply else '(dry-run)'}",
        flush=True,
    )
    if args.json_out:
        with open(args.json_out, "w") as f:
            json.dump({"user": login, "results": results}, f, indent=2)
        print(f"Wrote {args.json_out}", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
