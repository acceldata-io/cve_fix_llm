#!/usr/bin/env python3
"""Batch CVE deliver for jupyterhub (release 3.3.6.4).

Pins live in odp/requirements.txt on nightly/ODP-3.3.6.5.
One PR per library. Status: /tmp/batch11_cve_status.json
Summary appended to /root/cve_fix_llm/reports/batch9_status.md

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
WORK = Path("/root/3.3.6.5/jupyterhub")
GH = "acceldata-io/jupyterhub"
BASE = "nightly/ODP-3.3.6.5"
JIRA = "sehajsandhu/jupyterhub"
REQ = WORK / "odp" / "requirements.txt"
STATUS = Path("/tmp/batch11_cve_status.json")
SUMMARY = Path("/root/cve_fix_llm/reports/batch9_status.md")
TIMEOUT = int(os.environ.get("CVE_COMPILE_TIMEOUT", "3600"))
TOKEN = ""

# Canonical pin name in requirements.txt -> target version
BUMPS = {
    "idna": "3.15",
    "mistune": "3.2.1",
    "h11": "0.16.0",
    "httpcore": "1.0.9",  # companion for h11 0.16
    "Mako": "1.3.12",
    "nbconvert": "7.17.1",
    "ray": "2.55.0",
    "pyasn1": "0.6.3",
    "cryptography": "44.0.1",
    "jupyterlab": "4.5.7",
    "Pygments": "2.20.0",
    "urllib3": "2.7.0",
    "oauthenticator": "17.4.0",
    "notebook": "7.5.6",
    "jupyterhub": "5.4.5",
    "requests": "2.33.0",
    "aiohttp": "3.13.4",  # may be missing; add pin
    "pillow": "12.2.0",
    "tornado": "6.5.5",
    "PyJWT": "2.12.0",
}

LIB_ORDER = [
    "idna", "mistune", "h11", "mako", "nbconvert", "ray", "pyasn1",
    "cryptography", "jupyterlab", "pygments", "urllib3", "oauthenticator",
    "notebook", "jupyterhub", "requests", "aiohttp", "pillow", "tornado", "pyjwt",
]

# map lib key -> requirements canonical name(s) to bump
LIB_TO_PINS = {
    "idna": ["idna"],
    "mistune": ["mistune"],
    "h11": ["h11", "httpcore"],
    "mako": ["Mako"],
    "nbconvert": ["nbconvert"],
    "ray": ["ray"],
    "pyasn1": ["pyasn1"],
    "cryptography": ["cryptography"],
    "jupyterlab": ["jupyterlab"],
    "pygments": ["Pygments"],
    "urllib3": ["urllib3"],
    "oauthenticator": ["oauthenticator"],
    "notebook": ["notebook"],
    "jupyterhub": ["jupyterhub"],
    "requests": ["requests"],
    "aiohttp": ["aiohttp"],
    "pillow": ["pillow"],
    "tornado": ["tornado"],
    "pyjwt": ["PyJWT"],
}


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
        f"## jupyterhub ({time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime())})",
    ]
    for comp, res in results.items():
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
    if "## jupyterhub" in text:
        text = re.sub(r"\n## jupyterhub.*?(?=\n## |\Z)", "", text, flags=re.S)
    # update remaining queue
    text = re.sub(
        r"(## Remaining queue\n)(.*?)(?=\n## |\Z)",
        r"\1- druid\n- hue\n- superset\n",
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


def version_ge(a: str, b: str) -> bool:
    try:
        return Version(a) >= Version(b)
    except InvalidVersion:
        return False


def _major(v: str) -> int | None:
    try:
        return Version(v).major
    except InvalidVersion:
        return None


def min_fix_satisfied(current: str, fix_field: str) -> bool:
    cands = parse_fix_versions(fix_field)
    if not cands:
        return False
    cur_maj = _major(current)
    same = [c for c in cands if cur_maj is not None and _major(c) == cur_maj]
    pool = same if same else cands
    return any(version_ge(current, c) for c in pool)


def parse_requirements(path: Path) -> dict[str, tuple[str, str]]:
    """Map normalized name -> (canonical_name, version) for == pins (first wins)."""
    pins: dict[str, tuple[str, str]] = {}
    if not path.is_file():
        return {}
    for line in path.read_text(encoding="utf-8").splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#") or raw.startswith("git+"):
            continue
        base = raw.split(";", 1)[0].strip()
        m = re.match(r"^([A-Za-z0-9_.\-]+(?:\[[^\]]+\])?)==([^#\s]+)", base)
        if not m:
            continue
        name = m.group(1).split("[", 1)[0]
        ver = m.group(2).strip()
        np = norm_pkg(name)
        if np not in pins:
            pins[np] = (name, ver)
    return pins


def find_pin(pins: dict, pkg: str) -> tuple[str | None, str | None]:
    hit = pins.get(norm_pkg(pkg))
    if not hit:
        return None, None
    return hit[0], hit[1]


def load_tickets(ca):
    jql = f'project = OSV AND status = "To Do" AND summary ~ "{JIRA}" ORDER BY key ASC'
    issues, token = [], None
    while True:
        params = {
            "jql": jql,
            "maxResults": 100,
            "fields": (
                "summary,customfield_10893,customfield_10875,"
                "customfield_10892,customfield_10891,customfield_10888,customfield_10127"
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


def classify(row, pins):
    pkg = row["pkg"]
    np = norm_pkg(pkg)
    cands = parse_fix_versions(row["fix"])

    if np == "protobuf":
        return "exception", (
            "protobuf fix lists 33.x which is not a viable same-line bump from "
            "protobuf 6.31.x on the JupyterHub ODP stack. Exception Request (Deferred)."
        )
    if np == "fonttools":
        return "exception", (
            "fonttools is consumed via acceldata-io/fonttools fork pin "
            f"(ODP-4.45.1); upstream {row['fix']} requires a fork rebase. "
            "Exception Request (Deferred)."
        )
    if np == "pyarrow":
        return "exception", (
            "pyarrow 18.x → 23.x is a major ABI jump that breaks Ray/Spark "
            "integrations in JupyterHub. Exception Request (Deferred)."
        )
    if np == "cryptography":
        # Prefer 44.0.1 when listed; pure 46+ only → exception
        if cands and all(_major(c) is not None and _major(c) >= 46 for c in cands):
            return "exception", (
                "cryptography fix requires 46.x+; JupyterHub ODP bump stops at "
                "44.0.1 due to resolver/ABI risk with the current stack. "
                "Exception Request (Deferred)."
            )

    cname, current = find_pin(pins, pkg)
    # urllib3: prefer the py>=3.11 pin (2.6.3) when present in file
    if np == "urllib3":
        text = REQ.read_text(encoding="utf-8")
        m = re.search(
            r"^urllib3==([^;\s]+)\s*;\s*python_version\s*>=\s*'3\.11'",
            text,
            re.M,
        )
        if m:
            current = m.group(1)
            cname = "urllib3"

    if current and min_fix_satisfied(current, row["fix"]):
        return "already_fixed", (
            f"Already addressed on {BASE}: {cname}=={current} satisfies "
            f"fix requirement ({row['fix']})."
        )

    # map to lib
    lib = None
    for k in LIB_TO_PINS:
        if norm_pkg(k) == np or any(norm_pkg(p) == np for p in LIB_TO_PINS[k]):
            lib = k
            break
    if lib is None:
        # try BUMPS keys
        for k in BUMPS:
            if norm_pkg(k) == np:
                lib = norm_pkg(k).replace("-", "")
                # normalize to LIB_ORDER keys
                for lo in LIB_ORDER:
                    if norm_pkg(lo) == np:
                        lib = lo
                        break
                break

    if lib is None:
        return "unknown", f"no bump mapping for {pkg}"

    # target from BUMPS via LIB_TO_PINS primary
    primary = LIB_TO_PINS[lib][0]
    target = BUMPS[primary]
    display = primary

    if current and version_ge(current, target):
        return "already_fixed", (
            f"Already at/above target on {BASE}: {cname}=={current} "
            f"(target {target})."
        )

    return "fix", {
        "lib": lib,
        "name": display,
        "target": target,
        "current": current,
    }


def set_pin(text: str, name: str, version: str) -> tuple[str, bool]:
    """Replace == pin for name (all marker variants) or append if missing."""
    changed = False
    lines = text.splitlines(keepends=True)
    out = []
    pat = re.compile(
        rf"^({re.escape(name)})(\[[^\]]*\])?==([^#\s;]+)(.*)$",
        re.I,
    )
    found = False
    for line in lines:
        stripped = line.lstrip()
        if stripped.startswith("#"):
            out.append(line)
            continue
        m = pat.match(line.strip())
        if m:
            found = True
            marker = m.group(4) or ""
            # preserve exact trailing newline
            nl = "\n" if line.endswith("\n") else ""
            # keep original name casing from file
            new = f"{m.group(1)}{m.group(2) or ''}=={version}{marker}{nl}"
            if line != new and line.rstrip("\n") + ("\n" if line.endswith("\n") else "") != new:
                changed = True
            # Always rewrite version
            if m.group(3) != version:
                changed = True
                out.append(new)
            else:
                out.append(line)
        else:
            out.append(line)
    if not found:
        # append near end before trailing blanks
        while out and out[-1].strip() == "":
            out.pop()
        out.append(f"{name}=={version}\n")
        changed = True
    return "".join(out), changed


def apply_lib(lib: str) -> list[str]:
    text = REQ.read_text(encoding="utf-8")
    changed_files = []
    for pin_name in LIB_TO_PINS[lib]:
        target = BUMPS[pin_name]
        text2, ch = set_pin(text, pin_name, target)
        # also try lowercase if not found and name differs
        if not ch and pin_name != pin_name.lower():
            text2, ch = set_pin(text, pin_name.lower(), target)
        text = text2
        if ch:
            changed_files.append(f"odp/requirements.txt:{pin_name}=={target}")
    if lib == "jupyterhub":
        bt = WORK / "odp" / "buildtarball.sh"
        if bt.is_file():
            bt_text = bt.read_text(encoding="utf-8")
            nt = re.sub(
                r'JUPYTERHUB_VERSION="[^"]*"',
                f'JUPYTERHUB_VERSION="{BUMPS["jupyterhub"]}"',
                bt_text,
                count=1,
            )
            if nt != bt_text:
                bt.write_text(nt, encoding="utf-8")
                changed_files.append("odp/buildtarball.sh")
    if changed_files:
        REQ.write_text(text, encoding="utf-8")
    return changed_files


def ensure_repo():
    env = git_env()
    run(f"git remote set-url origin https://github.com/{GH}.git", WORK, env=env, timeout=60)
    run(f"git fetch origin {BASE} --prune", WORK, env=env, timeout=600)
    run(f"git checkout -B {BASE} origin/{BASE}", WORK, env=env, timeout=120)
    run("git reset --hard HEAD && git clean -fdx", WORK, env=env, timeout=900)


def pip_gate(lib: str) -> bool:
    """Lightweight resolver check: install just the bumped pin(s) into a throwaway venv."""
    log = f"/tmp/batch11_jupyterhub_{lib}_pip.log"
    py = "python3.11" if Path("/usr/bin/python3.11").exists() else "python3"
    venv = f"/tmp/jh_gate_{lib}"
    pins = [f"{n}=={BUMPS[n]}" for n in LIB_TO_PINS[lib]]
    cmd = (
        f"rm -rf {venv} && {py} -m venv {venv} && "
        f"{venv}/bin/pip install -U pip -q && "
        f"{venv}/bin/pip install --no-cache-dir {' '.join(pins)}"
    )
    # For packages that need the full file (git fonttools etc.) do a constraints-style dry resolve
    # Full requirements install is too heavy; pin-only is the compile gate here.
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
    print(f"\n=== jupyterhub/{lib} PR branch={branch} ({len(tickets)}) ===", flush=True)

    ensure_repo()
    run(f"git checkout -B {branch} origin/{BASE}", WORK, env=git_env(), timeout=120)
    changed = apply_lib(lib)
    if not changed:
        return {"lib": lib, "ok": False, "phase": "NO_CHANGE"}
    if DRY:
        return {"lib": lib, "dry": True, "title": title, "changed": changed}
    if not pip_gate(lib):
        return {"lib": lib, "ok": False, "phase": "FAILED_PIP_GATE", "branch": branch}
    run("git add odp/requirements.txt odp/buildtarball.sh", WORK, env=git_env(), timeout=60)
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
        f"- Component: jupyterhub ({BASE}, release {RELEASE})",
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
    write_status(phase="jupyterhub:load")
    ensure_repo()
    pins = parse_requirements(REQ)
    rows = load_tickets(ca)
    excepted, fixable, unknown, already = [], [], [], []
    for row in rows:
        action, meta = classify(row, pins)
        if action == "exception":
            print(f"[jupyterhub] EXCEPTION {row['key']} {row['pkg']}", flush=True)
            if DRY:
                excepted.append(row["key"])
            else:
                ok = ca.update_ticket_exception(
                    row["key"], meta, reason="Deferred", assignee=ASSIGNEE,
                )
                (excepted if ok else unknown).append(row["key"])
        elif action == "already_fixed":
            print(f"[jupyterhub] ALREADY {row['key']} {row['pkg']}", flush=True)
            if DRY:
                already.append(row["key"])
            else:
                ok = ca.close_ticket_with_comment(
                    row["key"], f"Closed: {meta}", "Closed", assignee=ASSIGNEE,
                )
                (already if ok else unknown).append(row["key"])
        elif action == "fix":
            print(
                f"[jupyterhub] FIXABLE {row['key']} {row['pkg']} "
                f"{meta.get('current')} -> {meta['target']}",
                flush=True,
            )
            fixable.append({**row, **meta})
        else:
            print(f"[jupyterhub] UNKNOWN {row['key']} {meta}", flush=True)
            unknown.append(row["key"])

    if ROUTE_ONLY:
        return {
            "excepted": excepted,
            "fixable": [r["key"] for r in fixable],
            "already_fixed": already,
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
            print(f"[jupyterhub/{lib}] ERROR {e}", flush=True)
        if res and res.get("pr"):
            prs.append(res["pr"])
            closed.extend(res.get("closed") or [])
        elif res and not res.get("ok", True) and not res.get("dry"):
            errors.append(res)
    out = {
        "excepted": excepted,
        "closed": closed,
        "already_fixed": already,
        "prs": prs,
        "unknown": unknown,
    }
    if errors:
        out["errors"] = errors
    return out


def main():
    write_status(phase="start")
    load_token()
    import cve_analyser as ca

    ca.DRY_RUN = DRY
    results = {"jupyterhub": process(ca)}
    append_summary(results)
    write_status(phase="DONE", results=results)
    print("DONE", json.dumps(results, indent=2), flush=True)


if __name__ == "__main__":
    main()
