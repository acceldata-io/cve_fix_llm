#!/usr/bin/env python3
"""Batch CVE deliver for superset (release 3.3.6.4).

Base branch: rel/ODP-3.3.6.4-1 (no nightly/ODP-3.3.6.5 on this repo).
Pins: requirements/base.txt (+ base.in when pinned).
One PR per library.

Status: /tmp/batch14_cve_status.json
Summary: /root/cve_fix_llm/reports/batch9_status.md

  CVE_DRY_RUN=1 / CVE_ROUTE_ONLY=1
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

from packaging.version import InvalidVersion, Version

ASSIGNEE = "senthil.kumar"
REVIEWER = "basapuram-kumar"
DRY = os.environ.get("CVE_DRY_RUN", "") not in ("", "0", "false", "False")
ROUTE_ONLY = os.environ.get("CVE_ROUTE_ONLY", "") not in ("", "0", "false", "False")
RELEASE = "3.3.6.4"
WORK = Path("/root/3.3.6.5/superset")
GH = "acceldata-io/superset"
BASE = "rel/ODP-3.3.6.4-1"
JIRA = "sehajsandhu/superset"
BASE_TXT = WORK / "requirements/base.txt"
BASE_IN = WORK / "requirements/base.in"
STATUS = Path("/tmp/batch14_cve_status.json")
SUMMARY = Path("/root/cve_fix_llm/reports/batch9_status.md")
TIMEOUT = int(os.environ.get("CVE_COMPILE_TIMEOUT", "3600"))
TOKEN = ""

BUMPS = {
    "pyasn1": "0.6.3",
    "idna": "3.15",
    "urllib3": "2.7.0",
    "pyjwt": "2.12.0",
    "flask-cors": "6.0.0",
    "brotli": "1.2.0",
    "mako": "1.3.12",
    "markdown": "3.8.1",
    "marshmallow": "3.26.2",
    "pygments": "2.20.0",
    "requests": "2.33.0",
    "python-dotenv": "1.2.2",
    "pynacl": "1.6.2",
    "werkzeug": "3.1.6",
    "pyarrow": "17.0.0",
}

LIB_ORDER = list(BUMPS.keys())

PKG_TO_LIB = {k: k for k in BUMPS}
PKG_TO_LIB["pyjwt"] = "pyjwt"


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
    print(f"STATUS: {json.dumps(kwargs)[:700]}", flush=True)


def append_summary(results: dict):
    SUMMARY.parent.mkdir(parents=True, exist_ok=True)
    existing = SUMMARY.read_text(encoding="utf-8") if SUMMARY.is_file() else ""
    block = [
        "",
        f"## superset ({time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime())})",
    ]
    for _, res in results.items():
        block.append(f"- excepted: {len(res.get('excepted') or [])}")
        block.append(f"- already-fixed: {', '.join(res.get('already_fixed') or []) or '—'}")
        block.append(f"- closed: {len(res.get('closed') or [])}")
        for pr in res.get("prs") or []:
            block.append(f"- PR: {pr}")
        if res.get("errors"):
            block.append(f"- errors: {json.dumps(res['errors'])[:400]}")
        if res.get("unknown"):
            block.append(f"- unknown: {', '.join(res['unknown'])}")
    text = existing
    if "## superset" in text:
        text = re.sub(r"\n## superset.*?(?=\n## |\Z)", "", text, flags=re.S)
    text = re.sub(
        r"(## Remaining queue\n)(.*?)(?=\n## |\Z)",
        r"\1- (queue complete)\n",
        text,
        flags=re.S,
        count=1,
    )
    SUMMARY.write_text(text.rstrip() + "\n" + "\n".join(block) + "\n", encoding="utf-8")


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


def load_token():
    global TOKEN
    sys.path.insert(0, "/root/cve_fix_llm")
    os.chdir("/root/cve_fix_llm")
    import cve_env

    cve_env.load_repo_env()
    TOKEN = os.environ.get("GITHUB_TOKEN", "").strip()
    if not TOKEN:
        raise SystemExit("GITHUB_TOKEN missing")
    askpass = Path("/tmp/git-askpass-github.sh")
    askpass.write_text(
        "#!/bin/sh\ncase \"$1\" in\n*Username*) echo x-access-token ;;\n"
        "*Password*) echo \"$GITHUB_TOKEN\" ;;\nesac\n",
        encoding="utf-8",
    )
    askpass.chmod(0o700)
    os.environ["GIT_ASKPASS"] = str(askpass)
    os.environ["GIT_TERMINAL_PROMPT"] = "0"
    os.environ["GITHUB_TOKEN"] = TOKEN


def git_env():
    env = os.environ.copy()
    env["GIT_ASKPASS"] = os.environ.get("GIT_ASKPASS", "")
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GITHUB_TOKEN"] = TOKEN
    return env


def run(cmd, cwd, env=None, timeout=TIMEOUT, log_path=None):
    print(f"+ ({cwd}) {cmd}", flush=True)
    try:
        p = subprocess.run(
            cmd, shell=True, cwd=str(cwd), text=True,
            capture_output=True, env=env or git_env(), timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return 124, "", f"TIMEOUT after {timeout}s"
    out, err = p.stdout or "", p.stderr or ""
    if log_path:
        Path(log_path).write_text(out + "\n" + err, encoding="utf-8", errors="replace")
    return p.returncode, out, err


def norm_pkg(name: str) -> str:
    return re.sub(r"[-_.]+", "-", (name or "").lower())


def parse_fix_versions(fix_field: str) -> list[str]:
    if not fix_field:
        return []
    parts = re.split(r"[,;/]| and ", fix_field)
    vers = []
    for p in parts:
        m = re.search(r"\b(\d+(?:\.\d+)+(?:[a-zA-Z0-9._\-]*)?)\b", p.strip())
        if m:
            vers.append(m.group(1))
    return vers


def _major(v: str) -> int | None:
    try:
        return Version(v).major
    except InvalidVersion:
        return None


def version_ge(a: str, b: str) -> bool:
    try:
        return Version(a) >= Version(b)
    except InvalidVersion:
        return False


def load_tickets(ca):
    jql = f'project = OSV AND status = "To Do" AND summary ~ "{JIRA}" ORDER BY key ASC'
    issues, token = [], None
    while True:
        params = {
            "jql": jql,
            "maxResults": 100,
            "fields": (
                "summary,customfield_10893,customfield_10875,"
                "customfield_10892,customfield_10891,customfield_10127"
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
            "cve": cve,
            "summary": summ,
        })
    return rows


def classify(row):
    np = norm_pkg(row["pkg"])
    cands = parse_fix_versions(row["fix"])
    fix = (row["fix"] or "").lower()

    if np == "flask":
        return "exception", (
            "Flask 3.1.3 is a major upgrade; pyproject.toml constrains "
            "flask>=2.2.5,<3.0.0 for this Superset ODP line. "
            "Exception Request (Deferred)."
        )
    if np == "pillow":
        return "exception", (
            "Pillow 12.x breaks pyproject.toml constraint Pillow>=11.0.0,<12. "
            "Exception Request (Deferred)."
        )
    if np == "cryptography":
        return "exception", (
            "cryptography fix requires 46.x+; Superset ODP stays on 44.0.3 "
            "due to resolver/ABI risk. Exception Request (Deferred)."
        )
    if np == "paramiko" or (not cands and "open" in fix):
        return "exception", (
            "No published fixed version (fix=open) for this package on the "
            "current Superset ODP line. Exception Request (Deferred)."
        )
    if np == "pyarrow":
        # Prefer 17.0.0 when that satisfies; pure 23.x-only → exception
        if cands and all(
            _major(c) is not None and _major(c) >= 23 for c in cands
        ):
            return "exception", (
                "pyarrow fix requires 23.x major ABI jump from 16.x. "
                "Exception Request (Deferred)."
            )
        # has 17.x candidate
        return "fix", {"lib": "pyarrow", "name": "pyarrow", "target": BUMPS["pyarrow"]}

    lib = PKG_TO_LIB.get(np)
    if not lib or lib not in BUMPS:
        return "unknown", f"no mapping for {row['pkg']}"
    return "fix", {"lib": lib, "name": lib, "target": BUMPS[lib]}


def bump_pin(text: str, name: str, version: str) -> tuple[str, int]:
    pat = re.compile(rf"(?im)^({re.escape(name)})==([^#\s\\]+)")
    count = 0

    def repl(m):
        nonlocal count
        count += 1
        return f"{m.group(1)}=={version}"

    text2 = pat.sub(repl, text)
    return text2, count


def apply_lib(lib: str) -> list[str]:
    name = lib
    version = BUMPS[lib]
    changed = []
    for path in (BASE_TXT, BASE_IN):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        text2, n = bump_pin(text, name, version)
        if n:
            path.write_text(text2, encoding="utf-8")
            changed.append(f"{path.relative_to(WORK)}:{name}=={version}×{n}")
    return changed


def ensure_repo():
    env = git_env()
    run(f"git remote set-url origin https://github.com/{GH}.git", WORK, env=env, timeout=60)
    run(f"git fetch origin {BASE} --prune", WORK, env=env, timeout=600)
    run(f"git checkout -B {BASE} origin/{BASE}", WORK, env=env, timeout=120)
    run("git reset --hard HEAD && git clean -fdx", WORK, env=env, timeout=900)


def pip_gate(lib: str) -> bool:
    log = f"/tmp/batch14_superset_{lib}_pip.log"
    py = "python3.11" if Path("/usr/bin/python3.11").exists() else "python3"
    venv = f"/tmp/ss_gate_{lib}"
    pin = f"{lib}=={BUMPS[lib]}"
    cmd = (
        f"rm -rf {venv} && {py} -m venv {venv} && "
        f"{venv}/bin/pip install -U pip -q && "
        f"{venv}/bin/pip install --no-cache-dir {pin}"
    )
    code, out, err = run(cmd, WORK, timeout=TIMEOUT, log_path=log)
    if code != 0:
        for ln in (out + err).splitlines()[-30:]:
            print("   ", ln[:220], flush=True)
        return False
    return True


def create_pr(branch, title, body):
    import requests

    headers = {"Authorization": f"token {TOKEN}", "Accept": "application/vnd.github+json"}
    r = requests.post(
        f"https://api.github.com/repos/{GH}/pulls",
        headers=headers,
        json={"title": title, "head": branch, "base": BASE, "body": body},
        timeout=60,
    )
    if r.status_code == 201:
        url = r.json()["html_url"]
        num = r.json()["number"]
        requests.post(
            f"https://api.github.com/repos/{GH}/pulls/{num}/requested_reviewers",
            headers=headers,
            json={"reviewers": [REVIEWER]},
            timeout=60,
        )
        return url
    if r.status_code == 422:
        r2 = requests.get(
            f"https://api.github.com/repos/{GH}/pulls",
            headers=headers,
            params={"head": f"acceldata-io:{branch}", "state": "open"},
            timeout=60,
        )
        if r2.ok and r2.json():
            return r2.json()[0]["html_url"]
    print(f"PR fail {r.status_code}: {r.text[:500]}", flush=True)
    return None


def deliver_lib(ca, lib, tickets):
    meta = tickets[0]
    name, target = meta.get("name") or lib, meta.get("target")
    branch = tickets[0]["key"]
    cves = sorted({t["cve"] for t in tickets if t.get("cve")})
    title = (
        f"{branch} - CVE - Bumped-up {name} to {target} to address "
        f"{'/'.join(cves) if cves else 'CVE'}"
    )
    print(f"\n=== superset/{lib} PR branch={branch} ({len(tickets)}) ===", flush=True)
    ensure_repo()
    run(f"git checkout -B {branch} origin/{BASE}", WORK, env=git_env(), timeout=120)
    changed = apply_lib(lib)
    if not changed:
        return {"lib": lib, "ok": False, "phase": "NO_CHANGE"}
    if DRY:
        return {"lib": lib, "dry": True, "title": title, "changed": changed}
    if not pip_gate(lib):
        return {"lib": lib, "ok": False, "phase": "FAILED_PIP_GATE", "branch": branch}
    run(
        "git add requirements/base.txt requirements/base.in",
        WORK, env=git_env(), timeout=60,
    )
    p = subprocess.run(
        ["git", "commit", "-m", title],
        cwd=str(WORK), text=True, capture_output=True, env=git_env(),
    )
    if p.returncode != 0:
        return {"lib": lib, "ok": False, "commit_err": (p.stderr or p.stdout or "")[-400:]}
    code, _, err = run(f"git push -u origin {branch}", WORK, env=git_env(), timeout=300)
    if code != 0:
        return {"lib": lib, "ok": False, "push_err": err[-400:]}
    body = "\n".join([
        f"- Component: superset ({BASE}, release {RELEASE})",
        f"- Library: {name} → {target}",
        f"- Tickets: {', '.join(t['key'] for t in tickets)}",
        f"- Files: {', '.join(changed)}",
    ])
    pr = create_pr(branch, title, body)
    if not pr:
        return {"lib": lib, "ok": False, "pr": None}
    closed = []
    for t in tickets:
        ok = ca.close_ticket_with_comment(
            t["key"],
            f"Fixed via PR: {pr} — bumped {name} to {target} on {BASE}.",
            "Closed",
            assignee=ASSIGNEE,
        )
        print(f"  {t['key']} -> {'Closed' if ok else 'FAILED'}", flush=True)
        if ok:
            closed.append(t["key"])
    return {"lib": lib, "ok": True, "pr": pr, "closed": closed}


def process(ca):
    write_status(phase="superset:load")
    rows = load_tickets(ca)
    excepted, fixable, unknown = [], [], []
    for row in rows:
        action, meta = classify(row)
        if action == "exception":
            print(f"[superset] EXCEPTION {row['key']} {row['pkg']}", flush=True)
            if DRY:
                excepted.append(row["key"])
            else:
                ok = ca.update_ticket_exception(
                    row["key"], meta, reason="Deferred", assignee=ASSIGNEE,
                )
                (excepted if ok else unknown).append(row["key"])
        elif action == "fix":
            print(f"[superset] FIXABLE {row['key']} {row['pkg']} -> {meta['target']}", flush=True)
            fixable.append({**row, **meta})
        else:
            print(f"[superset] UNKNOWN {row['key']} {meta}", flush=True)
            unknown.append(row["key"])

    if ROUTE_ONLY:
        return {
            "excepted": excepted,
            "fixable": [r["key"] for r in fixable],
            "unknown": unknown,
            "prs": [],
            "fixable_detail": [
                {"key": r["key"], "lib": r.get("lib"), "target": r.get("target")}
                for r in fixable
            ],
        }

    by_lib: dict[str, list] = {}
    for r in fixable:
        by_lib.setdefault(r["lib"], []).append(r)
    prs, closed, errors = [], [], []
    for lib in LIB_ORDER:
        if lib not in by_lib:
            continue
        try:
            res = deliver_lib(ca, lib, by_lib[lib])
        except Exception as e:
            res = {"lib": lib, "ok": False, "error": str(e)[:400]}
            print(f"[superset/{lib}] ERROR {e}", flush=True)
        if res and res.get("pr"):
            prs.append(res["pr"])
            closed.extend(res.get("closed") or [])
        elif res and not res.get("ok", True) and not res.get("dry"):
            errors.append(res)
    out = {"excepted": excepted, "closed": closed, "prs": prs, "unknown": unknown}
    if errors:
        out["errors"] = errors
    return out


def main():
    write_status(phase="start")
    load_token()
    import cve_analyser as ca

    ca.DRY_RUN = DRY
    results = {"superset": process(ca)}
    append_summary(results)
    write_status(phase="DONE", results=results)
    print("DONE", json.dumps(results, indent=2), flush=True)


if __name__ == "__main__":
    main()
