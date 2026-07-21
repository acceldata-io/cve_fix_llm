#!/usr/bin/env python3
"""Flink (sehajsandhu/flink, release 3.3.6.4) CVE routing for remaining To Dos.

Branch: nightly/ODP-3.3.6.5 (JDK 11)

Already delivered (open PRs, tickets Closed):
  - log4j 2.25.4  → https://github.com/acceldata-io/flink/pull/37
  - jackson 2.18.6 → https://github.com/acceldata-io/flink/pull/36

Remaining To Dos are Exception:
  - hadoop-common (ODP platform)
  - jetty-* inside hadoop-client-runtime (Hadoop transitive; fixes on 12.x)
  - commons-configuration2 inside hadoop-client-runtime (Hadoop transitive)
  - flink-table-planner / flink-table-runtime CVE-2026-35194:
      Official fix is Flink 1.20.4 / 2.0.2 / 2.1.2 / 2.2.1.
      ODP is on 1.19.1; Apache has no 1.19.x backport and the 1.20.4
      patches do not apply cleanly. Requires a Flink minor-line upgrade
      (out of scope for a dependency CVE bump). Exception Request (Deferred).

  CVE_DRY_RUN=1 supported
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path

ASSIGNEE = "senthil.kumar"
DRY = os.environ.get("CVE_DRY_RUN", "") not in ("", "0", "false", "False")
JIRA = "sehajsandhu/flink"
RELEASE = "3.3.6.4"
STATUS = Path("/tmp/flink_cve_route_status.json")


def write_status(**kwargs):
    cur = {}
    if STATUS.is_file():
        try:
            cur = json.loads(STATUS.read_text())
        except Exception:
            cur = {}
    cur.update(kwargs)
    cur["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    STATUS.write_text(json.dumps(cur, indent=2), encoding="utf-8")
    print(f"STATUS: {json.dumps(kwargs)[:500]}", flush=True)


def field_text(v):
    if v is None:
        return ""
    if isinstance(v, str):
        return v
    if isinstance(v, dict):
        out = []
        for c in v.get("content") or []:
            for n in c.get("content") or []:
                if n.get("type") == "text":
                    out.append(n.get("text") or "")
        return " ".join(out)
    return str(v)


def load_tickets(ca):
    jql = (
        f'project = OSV AND status = "To Do" AND summary ~ "{JIRA}" '
        "ORDER BY key ASC"
    )
    issues, token = [], None
    while True:
        params = {
            "jql": jql,
            "maxResults": 100,
            "fields": (
                "summary,customfield_10893,customfield_10875,"
                "customfield_10892,customfield_10891,customfield_10888,"
                "customfield_10127"
            ),
        }
        if token:
            params["nextPageToken"] = token
        r = ca.SESSION.get(
            f"{ca.JIRA_BASE_URL}/rest/api/3/search/jql",
            params=params,
            headers={"Accept": "application/json"},
            auth=(ca.EMAIL, ca.API_TOKEN),
        )
        data = r.json()
        issues.extend(data.get("issues") or [])
        token = data.get("nextPageToken")
        if not token:
            break
    rows = []
    for i in issues:
        f = i["fields"]
        if field_text(f.get("customfield_10893")) != RELEASE:
            continue
        summ = f.get("summary") or ""
        pkg = field_text(f.get("customfield_10875"))
        fix = (
            ca.extract_fixed_version(f.get("customfield_10891"))
            if hasattr(ca, "extract_fixed_version")
            else field_text(f.get("customfield_10891"))
        )
        cve = field_text(f.get("customfield_10127")) or ""
        if not cve:
            m = re.search(r"(CVE-\d+-\d+|GHSA-[a-z0-9-]+)", summ)
            cve = m.group(1) if m else ""
        rows.append({
            "key": i["key"],
            "pkg": pkg,
            "ver": field_text(f.get("customfield_10892")),
            "fix": fix or "",
            "path": field_text(f.get("customfield_10888")),
            "cve": cve,
            "summary": summ,
        })
    return rows


def classify(row):
    pkg = (row["pkg"] or "").lower()
    path = (row["path"] or "").lower()

    if "hadoop-common" in pkg or "hadoop_hadoop-common" in pkg:
        return "exception", (
            "hadoop-common is the ODP Hadoop platform artifact "
            f"({row.get('ver')}); remediation belongs to the Hadoop "
            "component, not a Flink-owned dependency pin. "
            "Exception Request (Deferred)."
        )

    if "jetty" in pkg:
        return "exception", (
            "Jetty is shaded/transitive inside hadoop-client-runtime "
            "(ODP Hadoop), not a Flink-managed jetty.version. Advisory fixes "
            "are on Jetty 12.x while the stack stays on 9.4.x (javax). "
            "Exception Request (Deferred)."
        )

    if "commons-configuration2" in pkg or "commons_configuration2" in pkg:
        return "exception", (
            "commons-configuration2 is pulled transitively via "
            "hadoop-client-runtime (ODP Hadoop), not managed as a Flink "
            "property. Remediation belongs to the Hadoop component. "
            "Exception Request (Deferred)."
        )

    if "flink-table" in pkg or "flink_table" in pkg:
        return "exception", (
            "CVE-2026-35194 affects Flink's own table-planner/table-runtime "
            f"at {row.get('ver')} (ODP Flink 1.19.1 line). Official fixes are "
            "only published in Flink 1.20.4 / 2.0.2 / 2.1.2 / 2.2.1; Apache "
            "has no 1.19.x backport and the 1.20.4 patches do not apply cleanly "
            "to this tree. Remediation requires a Flink minor-line upgrade, "
            "which is out of scope for a dependency CVE bump on "
            "nightly/ODP-3.3.6.5. Exception Request (Deferred)."
        )

    return "unknown", f"No routing rule for {row.get('pkg')} path={path}"


def main():
    write_status(phase="start")
    sys.path.insert(0, "/root/cve_fix_llm")
    os.chdir("/root/cve_fix_llm")
    import cve_env
    import cve_analyser as ca

    cve_env.load_repo_env()
    ca.DRY_RUN = DRY

    rows = load_tickets(ca)
    write_status(phase="loaded", count=len(rows), keys=[r["key"] for r in rows])

    excepted, unknown = [], []
    for row in rows:
        action, why = classify(row)
        key = row["key"]
        if action == "exception":
            print(f"EXCEPTION {key} {row['pkg']}", flush=True)
            if DRY:
                excepted.append(key)
            else:
                ok = ca.update_ticket_exception(
                    key, why, reason="Deferred", assignee=ASSIGNEE
                )
                (excepted if ok else unknown).append(key)
                print(f"  -> {'Exception Request' if ok else 'FAILED'}", flush=True)
        else:
            print(f"UNKNOWN {key} {row['pkg']}: {why}", flush=True)
            unknown.append(key)

    write_status(phase="DONE", excepted=excepted, unknown=unknown)
    print("DONE", json.dumps({"excepted": excepted, "unknown": unknown}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        write_status(phase="ERROR", error=str(e)[:800])
        raise
