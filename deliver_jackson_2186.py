#!/usr/bin/env python3
"""Deliver Jackson 2.18.6 bumps for components that already compiled green.

For each OK component under /root/3.3.6.5:
  - reset to nightly/ODP-3.3.6.5
  - apply jackson -> 2.18.6 (same pin discovery as compile matrix)
  - commit / push branch named after first OSV ticket
  - open PR -> nightly/ODP-3.3.6.5, reviewer basapuram-kumar
  - close matching To Do jackson2 tickets (release 3.3.6.4) that are
    actually covered by 2.18.6 (not jackson1 / not 2.19–2.20 line)

Honors CVE_DRY_RUN=1.
Skip build (CVE_SKIP_BUILD=1 default) — compile already validated.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import urllib.parse
from pathlib import Path

WORK = Path(os.environ.get("CVE_WORK", "/root/3.3.6.5"))
BASE = "nightly/ODP-3.3.6.5"
VERSION = "2.18.6"
REVIEWER = "basapuram-kumar"
ASSIGNEE = "senthil.kumar"
RELEASE = "3.3.6.4"
DRY = os.environ.get("CVE_DRY_RUN", "") not in ("", "0", "false", "False")
SKIP_BUILD = os.environ.get("CVE_SKIP_BUILD", "1") not in ("0", "false", "False")

# component -> (git repo dir name, github slug, jira cve-repo prefixes)
COMPS = [
    {
        "comp": "celeborn",
        "dir": "celeborn",
        "gh": "acceldata-io/celeborn",
        "jira_repos": ["sehajsandhu/celeborn"],
    },
    {
        "comp": "cruise-control",
        "dir": "cruise-control",
        "gh": "acceldata-io/cruise-control",
        "jira_repos": ["sehajsandhu/cruise-control", "sehajsandhu/cruise-control3"],
        "force_gradle": True,
    },
    {
        "comp": "druid",
        "dir": "druid",
        "gh": "acceldata-io/druid",
        "jira_repos": ["sehajsandhu/druid"],
    },
    {
        "comp": "hive",
        "dir": "hive",
        "gh": "acceldata-io/hive",
        "jira_repos": ["sehajsandhu/hive"],
    },
    {
        "comp": "kafka",
        "dir": "kafka",
        "gh": "acceldata-io/kafka",
        "jira_repos": ["sehajsandhu/kafka", "sehajsandhu/kafka3"],
    },
    {
        "comp": "knox",
        "dir": "knox",
        "gh": "acceldata-io/knox",
        "jira_repos": ["sehajsandhu/knox"],
    },
    {
        "comp": "nifi",
        "dir": "nifi",
        "gh": "acceldata-io/nifi",
        # nifi2 needs >=2.21.1 — do not close nifi2 tickets with 2.18.6
        "jira_repos": ["sehajsandhu/nifi"],
    },
    {
        "comp": "ozone",
        "dir": "ozone",
        "gh": "acceldata-io/ozone",
        "jira_repos": ["sehajsandhu/ozone", "sehajsandhu/ozone2"],
    },
    {
        "comp": "ranger",
        "dir": "ranger",
        "gh": "acceldata-io/ranger",
        "jira_repos": ["sehajsandhu/ranger"],
    },
    {
        "comp": "tez",
        "dir": "tez",
        "gh": "acceldata-io/tez",
        "jira_repos": ["sehajsandhu/tez"],
        "inject_xml_props": ["jackson.version", "jackson.core.version.tez", "jackson.databind.version.tez"],
    },
    {
        "comp": "hbase-connectors",
        "dir": "hbase-connectors",
        "gh": "acceldata-io/hbase-connectors",
        "jira_repos": ["sehajsandhu/hbase-connectors"],
    },
    {
        "comp": "oozie",
        "dir": "oozie",
        "gh": "acceldata-io/oozie",
        "jira_repos": ["sehajsandhu/oozie"],
    },
    {
        "comp": "flink",
        "dir": "flink",
        "gh": "acceldata-io/flink",
        "jira_repos": ["sehajsandhu/flink"],
    },
    {
        "comp": "livy",
        "dir": "livy",
        "gh": "acceldata-io/livy",
        "jira_repos": ["sehajsandhu/livy", "sehajsandhu/livy3"],
    },
    {
        "comp": "registry",
        "dir": "registry",
        "gh": "acceldata-io/registry",
        "jira_repos": ["sehajsandhu/registry"],
        "force_gradle": True,
    },
    {
        "comp": "spark3",
        "dir": "spark3",
        "gh": "acceldata-io/spark3",
        "jira_repos": ["sehajsandhu/spark3"],
        "base": "nightly/ODP-3.3.6.5",
    },
    {
        "comp": "spark3_3_3_3",
        "dir": "spark3_3_3_3",
        "gh": "acceldata-io/spark3",
        "jira_repos": ["sehajsandhu/spark3_3_3_3"],
        "base": "nightly/ODP-3.3.3.3.3.6.5",
    },
    {
        "comp": "spark3_3_5_1",
        "dir": "spark3_3_5_1",
        "gh": "acceldata-io/spark3",
        "jira_repos": ["sehajsandhu/spark3_3_5_1"],
        "base": "nightly/ODP-3.5.1.3.3.6.5",
    },
    {
        "comp": "spark4",
        "dir": "spark4",
        "gh": "acceldata-io/spark3",
        "jira_repos": ["sehajsandhu/spark4"],
        "base": "nightly/ODP-4.1.1.3.3.6.5",
        "version": "2.21.1",
    },
    {
        "comp": "spark4-hbase-connectors",
        "dir": "spark4-hbase-connectors",
        "gh": "acceldata-io/hbase-connectors",
        "jira_repos": ["sehajsandhu/spark4-hbase-connectors"],
        "base": "nightly/ODP-3.3.6.5",
        "version": "2.18.6",
    },
    {
        "comp": "zeppelin",
        "dir": "zeppelin",
        "gh": "acceldata-io/zeppelin",
        "jira_repos": ["sehajsandhu/zeppelin"],
        "drop_modules": ["zeppelin-web-angular", "zeppelin-distribution"],
    },
]

sys.path.insert(0, "/root/cve_fix_llm")
os.chdir("/root/cve_fix_llm")
import cve_env
cve_env.load_repo_env()
import cve_analyser as ca

# Reuse apply helpers from compile matrix
sys.path.insert(0, "/tmp")
from jackson_compile_matrix import (  # type: ignore
    discover_pins,
    apply_version,
    git_env,
    load_token,
)


def run(cmd: str, cwd: Path, check=True):
    print(f"+ ({cwd}) {cmd}", flush=True)
    p = subprocess.run(cmd, shell=True, cwd=str(cwd), text=True,
                       capture_output=True, env=git_env())
    if p.returncode != 0 and check:
        print(p.stdout[-2000:])
        print(p.stderr[-2000:])
        raise RuntimeError(f"cmd failed: {cmd}")
    return p


def parse_ver(v: str):
    if not v:
        return None
    m = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?", str(v).strip())
    if not m:
        return None
    return tuple(int(x or 0) for x in m.groups())


def covered_by_version(pkg: str, ver: str, path: str, summary: str, target: str) -> bool:
    """Whether bumping jackson2 to `target` addresses this ticket."""
    blob = " ".join([pkg or "", path or "", summary or ""]).lower()
    if "htrace" in blob:
        return False
    if "jackson-mapper-asl" in blob or "jackson-core-asl" in blob or "codehaus.jackson" in blob:
        return False
    if "fasterxml" not in blob and "jackson-core" not in blob and "jackson-databind" not in blob and "jackson-annotations" not in blob:
        if "com.fasterxml.jackson" not in blob:
            return False
    pv = parse_ver(ver)
    tv = parse_ver(target)
    if not pv:
        return "com.fasterxml.jackson" in blob or "jackson-core" in blob or "jackson-databind" in blob
    if pv[0] != 2 or not tv:
        return False
    if pv >= tv:
        return False
    # 2.18.6 fixes [2.0, 2.18.6); does NOT cover 2.19+
    if tv == (2, 18, 6):
        return pv[1] < 19
    # 2.21.1 covers older lines and [2.19, 2.21.1)
    if tv >= (2, 21, 1):
        return True
    return pv < tv


def covered_by_2186(pkg: str, ver: str, path: str, summary: str) -> bool:
    return covered_by_version(pkg, ver, path, summary, "2.18.6")


def advisory_id(key: str, summary: str, field_value) -> str:
    """CVE / GHSA / PRISMA from Jira CVE-ID field or summary."""
    if isinstance(field_value, dict):
        field_value = field_value.get("value") or field_value.get("name") or ""
    blob = f"{field_value or ''} {summary or ''} {key or ''}"
    m = re.search(
        r"(?:CVE-\d{4}-\d+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|PRISMA-\d{4}-\d+)",
        blob,
        re.I,
    )
    if m:
        raw = m.group(0)
        if raw.upper().startswith("CVE-") or raw.upper().startswith("PRISMA-"):
            return raw.upper()
        return "GHSA-" + raw[5:].lower()
    if str(field_value or "").strip():
        return str(field_value).strip()
    return ca.extract_cve_id(key, summary or "", str(field_value or ""))


def fetch_tickets(jira_repos: list[str], target_version: str = VERSION) -> list[dict]:
    out = {}
    for repo in jira_repos:
        jql = (
            f'project = OSV AND "cve-found-in-release-version[short text]" ~ "{RELEASE}" '
            f'AND "cve-repo[short text]" ~ "{repo}" AND status = "To Do" '
            f'AND ("cve-package[short text]" ~ "jackson" OR summary ~ "jackson") '
            f"ORDER BY key ASC"
        )
        token = None
        while True:
            url = (
                f"{ca.JIRA_BASE_URL}/rest/api/3/search/jql"
                f"?jql={urllib.parse.quote(jql)}&maxResults=100"
                f"&fields=key,summary,customfield_10875,customfield_10892,customfield_10888,customfield_10127"
            )
            if token:
                url += f"&nextPageToken={urllib.parse.quote(token)}"
            r = ca.SESSION.get(url, headers={"Accept": "application/json"},
                               auth=(ca.EMAIL, ca.API_TOKEN))
            if r.status_code != 200:
                print(f"  Jira error {repo}: {r.status_code} {r.text[:200]}")
                break
            data = r.json()
            for i in data.get("issues", []):
                f = i["fields"]
                item = {
                    "key": i["key"],
                    "summary": f.get("summary") or "",
                    "pkg": f.get("customfield_10875") or "",
                    "ver": f.get("customfield_10892") or "",
                    "path": f.get("customfield_10888") or "",
                    "cve_id": advisory_id(
                        i["key"],
                        f.get("summary") or "",
                        f.get("customfield_10127") or "",
                    ),
                    "repo": repo,
                }
                if covered_by_version(item["pkg"], item["ver"], item["path"], item["summary"], target_version):
                    out[item["key"]] = item
            if data.get("isLast", True):
                break
            token = data.get("nextPageToken")
            if not token:
                break
    return [out[k] for k in sorted(out)]


def gh(method: str, path: str, payload=None):
    import requests
    tok = os.environ.get("GITHUB_TOKEN", "")
    headers = {
        "Authorization": f"token {tok}",
        "Accept": "application/vnd.github+json",
    }
    url = f"https://api.github.com{path}"
    if method == "GET":
        return requests.get(url, headers=headers, timeout=60)
    if method == "POST":
        return requests.post(url, headers=headers, json=payload, timeout=60)
    raise ValueError(method)


def create_pr(gh_slug: str, branch: str, title: str, body: str, base: str | None = None) -> str | None:
    base = base or BASE
    if DRY:
        print(f"  [DRY_RUN] Would create PR {title} base={base}")
        return f"https://github.com/{gh_slug}/pull/DRY"
    r = gh("POST", f"/repos/{gh_slug}/pulls", {
        "title": title,
        "head": branch,
        "base": base,
        "body": body,
    })
    if r.status_code == 201:
        url = r.json()["html_url"]
        num = r.json()["number"]
        print(f"  PR created: {url}")
        rr = gh("POST", f"/repos/{gh_slug}/pulls/{num}/requested_reviewers",
                {"reviewers": [REVIEWER]})
        print(f"  reviewer {REVIEWER}: HTTP {rr.status_code}")
        return url
    if r.status_code == 422:
        q = gh("GET", f"/repos/{gh_slug}/pulls?head=acceldata-io:{branch}&state=open")
        if q.status_code == 200 and q.json():
            url = q.json()[0]["html_url"]
            num = q.json()[0]["number"]
            print(f"  PR exists: {url}")
            gh("POST", f"/repos/{gh_slug}/pulls/{num}/requested_reviewers",
               {"reviewers": [REVIEWER]})
            return url
    print(f"  ERROR PR [{r.status_code}]: {r.text[:400]}")
    return None


def deliver_one(job: dict) -> dict:
    comp = job["comp"]
    repo_dir = WORK / job["dir"]
    base = job.get("base") or BASE
    version = job.get("version") or VERSION
    print(f"\n{'='*72}\nDELIVER {comp} version={version} base={base}\n{'='*72}", flush=True)
    if not (repo_dir / ".git").is_dir():
        return {"comp": comp, "status": "NO_REPO"}

    tickets = fetch_tickets(job["jira_repos"], target_version=version)
    print(f"  tickets covered by {version}: {len(tickets)}")
    for t in tickets[:12]:
        print(f"    {t['key']} pkg={t['pkg']} ver={t['ver']} cve={t.get('cve_id')}")
    if len(tickets) > 12:
        print(f"    ... +{len(tickets)-12} more")
    if not tickets:
        return {"comp": comp, "status": "NO_TICKETS"}

    branch = tickets[0]["key"]
    keys = [t["key"] for t in tickets]
    cve_id = next(
        (t["cve_id"] for t in tickets if t.get("cve_id") and t["cve_id"] != "UNKNOWN"),
        tickets[0].get("cve_id") or "UNKNOWN",
    )
    lib_name = "Jackson"

    run(f"git remote set-url origin https://github.com/{job['gh']}.git", repo_dir)
    run(f"git fetch origin {base} --prune", repo_dir)
    run(f"git checkout -B {base} origin/{base}", repo_dir)
    run("git reset --hard HEAD && git clean -fd", repo_dir)
    run(f"git checkout -B {branch} origin/{base}", repo_dir)

    pins = discover_pins(repo_dir)
    if job.get("force_gradle") and not any(p.get("name") == "jacksonVersion" for p in pins):
        pins.append({"file": "gradle.properties", "kind": "gradle", "name": "jacksonVersion", "value": "0.0.0"})
    if job.get("inject_xml_props") and not any(p.get("name") in job["inject_xml_props"] for p in pins):
        for prop in job["inject_xml_props"]:
            pins.append({"file": "pom.xml", "kind": "xml", "name": prop, "value": "0.0.0"})

    meta = {}
    if job.get("force_gradle"):
        meta["force_gradle_prop"] = "jacksonVersion"
    if job.get("inject_xml_props"):
        meta["inject_xml_props"] = job["inject_xml_props"]
    changed = apply_version(repo_dir, pins, version, job=meta or None)
    print(f"  changed: {changed}")

    st = run("git status --porcelain", repo_dir, check=False)
    if not (st.stdout or "").strip():
        print("  no diff — skipping push")
        return {"comp": comp, "status": "NO_DIFF", "tickets": keys}

    title = f"{branch} - CVE - Bumped-up {lib_name} to {version} to address {cve_id}"
    body_lines = [
        f"- Library : {lib_name}",
        f"- Version : -> {version}",
        f"- Tickets : {', '.join(keys)}",
    ]
    commit_msg = title
    if len(keys) > 1:
        commit_msg = title + "\n\nAlso covers: " + ", ".join(keys[1:])

    if DRY:
        print(f"  [DRY_RUN] Would commit/push {branch} and PR; close {keys}")
        print(f"  [DRY_RUN] subject: {title}")
        return {"comp": comp, "status": "DRY", "branch": branch, "tickets": keys, "title": title}

    run("git add -A", repo_dir)
    p = subprocess.run(
        ["git", "commit", "-m", commit_msg],
        cwd=str(repo_dir), text=True, capture_output=True, env=git_env(),
    )
    if p.returncode != 0:
        print(p.stdout, p.stderr)
        return {"comp": comp, "status": "COMMIT_FAIL", "tickets": keys}

    run(f"git push -u origin {branch}", repo_dir)
    pr_url = create_pr(job["gh"], branch, title, "\n".join(body_lines), base=base)
    if not pr_url:
        return {"comp": comp, "status": "PR_FAIL", "branch": branch, "tickets": keys}

    comment = (
        f"Fixed via PR: {pr_url} — {lib_name} bumped to {version} on {base} "
        f"to address the linked jackson2 CVE(s)."
    )
    closed = []
    for k in keys:
        ok = ca.close_ticket_with_comment(k, comment, "Closed", assignee=ASSIGNEE)
        print(f"    {k} -> {'Closed' if ok else 'FAILED'}")
        if ok:
            closed.append(k)
    return {
        "comp": comp, "status": "OK", "branch": branch, "pr": pr_url,
        "tickets": keys, "closed": closed, "title": title, "version": version,
    }


def main():
    load_token()
    only = [x.strip() for x in os.environ.get("CVE_ONLY_COMPS", "").split(",") if x.strip()]
    jobs = [j for j in COMPS if not only or j["comp"] in only]
    print(f"DRY={DRY} SKIP_BUILD={SKIP_BUILD} jobs={len(jobs)} version={VERSION}")
    results = []
    for job in jobs:
        try:
            results.append(deliver_one(job))
        except Exception as e:
            print(f"  ERROR {job['comp']}: {e}")
            results.append({"comp": job["comp"], "status": "ERROR", "error": str(e)[:500]})
        Path("/tmp/jackson_deliver_2186.json").write_text(
            json.dumps(results, indent=2), encoding="utf-8"
        )
    print("\n===== DELIVER SUMMARY =====")
    for r in results:
        print(f"{r.get('comp'):20} {r.get('status'):10} pr={r.get('pr')} closed={len(r.get('closed') or [])}/{len(r.get('tickets') or [])}")
    print("wrote /tmp/jackson_deliver_2186.json")


if __name__ == "__main__":
    main()
