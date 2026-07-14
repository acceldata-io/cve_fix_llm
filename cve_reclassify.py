"""
Reusable cross-component CVE reclassification.

This is the first-class version of the ad-hoc "close CVE-X across all components
with a comment (and optionally clear a field)" scripts. It is used both as a CLI
and as a tool by cve_agent.py.

Typical use (the CVE-2022-25168 / "fixed in Hadoop" pattern):

    python3 cve_reclassify.py --cve CVE-2022-25168 --to Closed \
        --comment "Fixed in Hadoop; Commit: https://github.com/acceldata-io/hadoop/commit/742f35f0" \
        --exclude-repo hbase --clear customfield_10885 --dry-run

Remove --dry-run to actually apply. Everything routes through cve_analyser's
authenticated Jira session and transition/comment helpers.
"""

from __future__ import annotations
import argparse
import urllib.parse
from typing import Dict, List, Optional

import cve_analyser as ca

# Terminal-ish states we normally do NOT touch unless explicitly asked.
TERMINAL_DEFAULT_SKIP = {"Closed"}


def find_cve_tickets(cve_id: str,
                     repo_substr: Optional[str] = None,
                     release: Optional[str] = None) -> List[Dict]:
    """Return every OSV ticket whose CVE-ID == cve_id (optionally filtered to
    a cve-repo substring and/or a release version)."""
    jql = f'project = OSV AND text ~ "{cve_id}"'
    if repo_substr:
        jql += f' AND "cve-repo[short text]" ~ "{repo_substr}"'
    if release:
        jql += f' AND "cve-found-in-release-version[short text]" ~ "{release}"'
    jql += " ORDER BY created DESC"

    fields = ("key,summary,status,customfield_10127,customfield_10870,"
              "customfield_10126,customfield_10893")
    out: List[Dict] = []
    tok = None
    while True:
        url = (f"{ca.JIRA_BASE_URL}/rest/api/3/search/jql"
               f"?jql={urllib.parse.quote(jql)}&maxResults=100&fields={fields}")
        if tok:
            url += f"&nextPageToken={urllib.parse.quote(tok)}"
        r = ca.SESSION.get(url, headers={"Accept": "application/json"},
                           auth=(ca.EMAIL, ca.API_TOKEN))
        if r.status_code != 200:
            print(f"  ERROR fetching {cve_id} [{r.status_code}]: {r.text[:200]}")
            break
        d = r.json()
        for iss in d.get("issues", []):
            f = iss["fields"]
            cid = ca.extract_cve_id(iss["key"], f.get("summary", "") or "",
                                    f.get("customfield_10127", "") or "")
            if cid != cve_id:
                continue
            out.append({
                "key": iss["key"],
                "status": (f.get("status") or {}).get("name", ""),
                "repo": f.get("customfield_10870", "") or "",
                "release": f.get("customfield_10893", "") or "",
                "severity": ca.extract_dropdown(f.get("customfield_10126")),
            })
        tok = d.get("nextPageToken")
        if d.get("isLast") or not tok:
            break
    return out


def _assign(key: str) -> bool:
    """Assign the ticket so status-specific transitions become available."""
    if ca.DRY_RUN:
        print(f"    [DRY_RUN] would assign {key}")
        return True
    url = f"{ca.JIRA_BASE_URL}/rest/api/3/issue/{key}"
    r = ca.SESSION.put(url, headers={"Accept": "application/json",
                                     "Content-Type": "application/json"},
                       auth=(ca.EMAIL, ca.API_TOKEN),
                       json={"fields": {"assignee": {"accountId": ca.ASSIGNEE_ACCOUNT_ID}}})
    if r.status_code in (200, 204):
        print(f"    assigned {key}")
        return True
    print(f"    ERROR assigning {key} [{r.status_code}]: {r.text[:200]}")
    return False


def _clear_field(key: str, field_id: str) -> bool:
    if ca.DRY_RUN:
        print(f"    [DRY_RUN] would clear {field_id} on {key}")
        return True
    url = f"{ca.JIRA_BASE_URL}/rest/api/3/issue/{key}"
    r = ca.SESSION.put(url, headers={"Accept": "application/json",
                                     "Content-Type": "application/json"},
                       auth=(ca.EMAIL, ca.API_TOKEN),
                       json={"fields": {field_id: None}})
    if r.status_code in (200, 204):
        print(f"    cleared {field_id} on {key}")
        return True
    print(f"    ERROR clearing {field_id} on {key} [{r.status_code}]: {r.text[:200]}")
    return False


def reclassify(cve_id: str,
               to_status: str,
               comment: str = "",
               include_repos: Optional[List[str]] = None,
               exclude_repos: Optional[List[str]] = None,
               only_statuses: Optional[List[str]] = None,
               clear_fields: Optional[List[str]] = None,
               skip_statuses: Optional[List[str]] = None,
               release: Optional[str] = None,
               include_keys: Optional[List[str]] = None,
               exception_reason: str = "Deferred",
               transition_details: Optional[str] = None,
               dry_run: bool = True) -> Dict:
    """
    Move every matching CVE ticket to `to_status`, adding `comment` and clearing
    `clear_fields`. Returns a summary dict. Honors dry_run (sets ca.DRY_RUN).

    Filters:
      include_repos  : only repos whose cve-repo contains one of these substrings
      exclude_repos  : skip repos whose cve-repo contains one of these substrings
      release        : only tickets whose cve-found-in-release-version matches this
                       (e.g. "3.2.3.6") — CRITICAL for release-scoped requests
      include_keys   : hard allow-list of exact OSV keys; when set, ONLY these
                       keys are eligible (strongest scoping)
      only_statuses  : only act on tickets currently in one of these statuses
      skip_statuses  : never touch tickets in these statuses
                       (defaults to {to_status} + {"Closed"} to stay idempotent)
    """
    ca.DRY_RUN = dry_run
    include_repos = include_repos or []
    exclude_repos = exclude_repos or []
    clear_fields = clear_fields or []
    include_keys = set(include_keys) if include_keys else None
    skip = set(skip_statuses) if skip_statuses is not None else set(TERMINAL_DEFAULT_SKIP)
    skip.add(to_status)

    tickets = find_cve_tickets(cve_id, release=release)
    selected, skipped = [], []
    for t in tickets:
        repo = t["repo"] or ""
        if include_keys is not None and t["key"] not in include_keys:
            skipped.append((t, "not in include_keys")); continue
        if include_repos and not any(s.lower() in repo.lower() for s in include_repos):
            skipped.append((t, "not in include_repos")); continue
        if exclude_repos and any(s.lower() in repo.lower() for s in exclude_repos):
            skipped.append((t, "excluded repo")); continue
        if release and release.lower() not in (t.get("release", "") or "").lower():
            skipped.append((t, f"release {t.get('release')} != {release}")); continue
        if only_statuses and t["status"] not in only_statuses:
            skipped.append((t, f"status {t['status']} not in only_statuses")); continue
        if t["status"] in skip:
            skipped.append((t, f"already {t['status']}")); continue
        selected.append(t)

    print(f"\n{'='*80}")
    print(f"  RECLASSIFY {cve_id} -> {to_status}   (dry_run={dry_run})"
          + (f"  release~{release}" if release else ""))
    print(f"  total tickets={len(tickets)}  selected={len(selected)}  skipped={len(skipped)}")
    print(f"{'='*80}")

    # Moving to "Exception Request" REQUIRES the CVE-Exception-Reason and
    # CVE-Transition-Details fields to be set on the same edit, otherwise the
    # transition is rejected (HTTP 400). Route those through the dedicated
    # cve_analyser.update_ticket_exception helper.
    is_exception = (to_status == ca.EXCEPTION_STATUS)

    ok = fail = 0
    for t in sorted(selected, key=lambda x: x["key"]):
        key = t["key"]
        print(f">>> {key}  [{t['status']}]  {t['repo']}  rel={t.get('release','')}")
        if is_exception:
            details = transition_details or comment or f"Exception ({exception_reason})"
            for fld in clear_fields:
                _clear_field(key, fld)
            if ca.update_ticket_exception(key, details, reason=exception_reason):
                ok += 1
            else:
                fail += 1
            continue
        if not _assign(key):
            fail += 1; continue
        if comment:
            ca.add_comment(key, comment)
        for fld in clear_fields:
            _clear_field(key, fld)
        if ca.transition_issue(key, to_status):
            ok += 1
        else:
            fail += 1

    print(f"\nDONE  ok={ok}  fail={fail}  skipped={len(skipped)}")
    return {
        "cve": cve_id, "to_status": to_status, "dry_run": dry_run,
        "release": release,
        "exception_reason": exception_reason if is_exception else None,
        "total": len(tickets),
        "selected": [f"{t['key']}({t.get('release','')})" for t in selected],
        "ok": ok, "fail": fail, "skipped": len(skipped),
        "skipped_detail": [(t["key"], t["status"], t["repo"], t.get("release", ""), why)
                           for t, why in skipped],
    }


def _main():
    ap = argparse.ArgumentParser(description="Reclassify OSV tickets for a CVE.")
    ap.add_argument("--cve", required=True)
    ap.add_argument("--to", required=True, dest="to_status",
                    help='Target status, e.g. "Closed" or "Exception Request"')
    ap.add_argument("--comment", default="")
    ap.add_argument("--include-repo", action="append", default=[], dest="include_repos")
    ap.add_argument("--exclude-repo", action="append", default=[], dest="exclude_repos")
    ap.add_argument("--only-status", action="append", default=None, dest="only_statuses")
    ap.add_argument("--skip-status", action="append", default=None, dest="skip_statuses")
    ap.add_argument("--clear", action="append", default=[], dest="clear_fields",
                    help="customfield id to clear, e.g. customfield_10885")
    ap.add_argument("--release", default=None,
                    help='scope to a release, e.g. "3.2.3.6"')
    ap.add_argument("--key", action="append", default=None, dest="include_keys",
                    help="exact OSV key allow-list (repeatable), e.g. OSV-18879")
    ap.add_argument("--exception-reason", default="Deferred", dest="exception_reason",
                    choices=["Deferred", "Not Exploitable", "Spark Transitive"],
                    help="CVE-Exception-Reason (only used when --to 'Exception Request')")
    ap.add_argument("--transition-details", default=None, dest="transition_details",
                    help="CVE-Transition-Details text (defaults to --comment)")
    grp = ap.add_mutually_exclusive_group()
    grp.add_argument("--dry-run", dest="dry_run", action="store_true", default=True)
    grp.add_argument("--apply", dest="dry_run", action="store_false")
    a = ap.parse_args()
    reclassify(a.cve, a.to_status, a.comment, a.include_repos, a.exclude_repos,
               a.only_statuses, a.clear_fields, a.skip_statuses,
               a.release, a.include_keys, a.exception_reason,
               a.transition_details, a.dry_run)


if __name__ == "__main__":
    _main()
