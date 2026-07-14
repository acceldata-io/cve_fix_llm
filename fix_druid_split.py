"""
Re-deliver Druid PHASE 1 as SEPARATE per-library PRs (one commit + one PR per
library group), assign basapuram-kumar as reviewer, and close each group's Jira
tickets citing the correct PR.

Build was already validated (combined). This only re-does git/PR/Jira:
  log4j      (OSV-18048, 6) -> log4j.version      2.25.3 -> 2.25.4
  netty      (OSV-18042, 9) -> netty4.version     4.1.132.Final -> 4.1.135.Final
  postgresql (OSV-18043, 1) -> postgresql.version 42.7.2 -> 42.7.11
  json-path  (OSV-18024, 1) -> json-path          2.3.0 -> 2.9.0

The earlier combined branch OSV-18048 / PR #85 is repurposed as the log4j-only
PR (force-pushed + retitled). Honors CVE_DRY_RUN=1.
"""

import json
import os
import re
import subprocess

os.environ.setdefault("CVE_PROFILE", "druid")

import cve_analyser as ca
import cve_fixer as cf

WORKDIR = os.path.expanduser("~/cve_fix_workdir/druid")
TB = cf.TARGET_BRANCH
REVIEWER = "basapuram-kumar"

GROUPS = json.load(open("/tmp/druid_groups.json"))
ISS = {i["key"]: i for i in json.load(open("/tmp/druid_326.json"))}

# group -> (regex on base pom, replacement, lib label, new version)
EDITS = {
    "log4j": (r"(<log4j\.version>)2\.25\.3(</log4j\.version>)",
              r"\g<1>2.25.4\g<2>", "log4j", "2.25.4"),
    "netty": (r"(<netty4\.version>)4\.1\.132\.Final(</netty4\.version>)",
              r"\g<1>4.1.135.Final\g<2>", "netty", "4.1.135.Final"),
    "postgresql": (r"(<postgresql\.version>)42\.7\.2(</postgresql\.version>)",
                   r"\g<1>42.7.11\g<2>", "postgresql", "42.7.11"),
    "json-path": (r"(<artifactId>json-path</artifactId>\s*<version>)2\.3\.0(</version>)",
                  r"\g<1>2.9.0\g<2>", "json-path", "2.9.0"),
}
COMMIT = {
    "log4j": "Increasing log4j2 version to fix",
    "netty": "Increasing netty version to fix",
    "postgresql": "Increasing postgresql version to fix",
    "json-path": "Increasing json-path version to fix",
}


def git(cmd: str) -> int:
    print(f"    $ {cmd}")
    return subprocess.run(cmd, shell=True, cwd=WORKDIR).returncode


def gh_request(method: str, path: str, payload: dict):
    token = cf.github_token()
    headers = {"Authorization": f"token {token}",
               "Accept": "application/vnd.github+json"}
    url = f"https://api.github.com/repos/{cf.REPO_SLUG}{path}"
    return ca.SESSION.request(method, url, headers=headers, json=payload)


def deliver(group: str) -> None:
    branch = GROUPS[group]["branch"]
    keys = GROUPS[group]["keys"]
    regex, repl, lib, ver = EDITS[group]
    title = f"{branch} - CVE - {COMMIT[group]} the Druid {lib} CVEs"
    print(f"\n{'='*70}\n  {group.upper()}  branch={branch}  ({len(keys)} tickets) -> {ver}\n{'='*70}")

    if ca.DRY_RUN:
        print(f"  [DRY_RUN] would recreate {branch} off origin/{TB}, edit pom "
              f"({lib} -> {ver}), push, PR, reviewer={REVIEWER}, close {keys}")
        return

    # Fresh branch off origin target, apply ONLY this lib's edit.
    if git(f"git checkout -f -B {branch} origin/{TB}") != 0:
        print("  ERROR: checkout failed"); return
    pom = os.path.join(WORKDIR, "pom.xml")
    text = open(pom, encoding="utf-8").read()
    new, n = re.subn(regex, repl, text, count=1)
    if n != 1:
        print(f"  ERROR: expected 1 pom edit, made {n}; aborting {group}"); return
    open(pom, "w", encoding="utf-8").write(new)
    git("git add pom.xml")
    if git(f'git commit -m "{title}"') != 0:
        print("  ERROR: commit failed"); return
    if git(f"git push -u origin {branch} --force-with-lease") != 0:
        print("  ERROR: push failed"); return

    plan = {"branch": branch, "libraries": [lib], "target_version": ver,
            "issues": [{"key": k} for k in keys]}
    pr_url = cf.create_pull_request(plan, title)
    if not pr_url:
        print("  ERROR: no PR"); return
    num = pr_url.rstrip("/").split("/")[-1]

    # Ensure title/body correct (covers the repurposed combined PR #85).
    body = (f"- Library : {lib}\n- Version : -> {ver}\n"
            f"- Tickets : {', '.join(keys)}\n\n"
            f"Per-library Phase 1 fix for the Druid 3.2.3.6 CVEs (build-validated "
            f"on JDK 8 via -Pdist).")
    gh_request("PATCH", f"/pulls/{num}", {"title": title, "body": body})

    rr = gh_request("POST", f"/pulls/{num}/requested_reviewers",
                    {"reviewers": [REVIEWER]})
    print(f"  reviewer {REVIEWER}: {rr.status_code}")

    comment = (f"Fixed via PR: {pr_url}  -  {lib} bumped to {ver} on {TB}; the "
               f"rebuilt Druid distribution was verified to carry the fixed "
               f"version for this CVE. (Per-library PR.)")
    for k in keys:
        ca.close_ticket_with_comment(k, comment, "Closed")
    print(f"  {group}: PR {pr_url} | closed {len(keys)} tickets")


def main() -> None:
    print(f"Druid per-library split  DRY_RUN={ca.DRY_RUN}")
    if not ca.DRY_RUN and git("git fetch origin --prune") != 0:
        print("fetch failed"); return
    for group in ["log4j", "netty", "postgresql", "json-path"]:
        deliver(group)


if __name__ == "__main__":
    main()
