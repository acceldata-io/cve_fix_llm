#!/usr/bin/env python3
"""Airflow (sehajsandhu/airflow, release 3.3.6.4) CVE routing + constraint bumps.

Branch: nightly/ODP-3.3.6.5 (Python 3.11 tarball via odp/)

CLOSE: ticket already satisfied by current odp/constraints-3.11.txt pin
       (often via prior #19 / nightly bumps) — comment cites nightly pin.

EXCEPTION:
  - apache-airflow 2.8.3 core CVEs (fix needs 2.10+/3.x product upgrade)
  - providers requiring major line jumps (http 4→6, common-sql 1.11→1.24)
  - Flask 2→3, Werkzeug needing 3.1.x with Flask 2.2, thrift 0.16→0.23,
    protobuf needing 5.x/6.x

FIX: bump pins in odp/constraints-3.11.txt (+ requirements.txt where pinned)

  CVE_DRY_RUN=1 / CVE_ROUTE_ONLY=1 supported
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
from packaging.specifiers import SpecifierSet

ASSIGNEE = "senthil.kumar"
REVIEWER = "basapuram-kumar"
DRY = os.environ.get("CVE_DRY_RUN", "") not in ("", "0", "false", "False")
ROUTE_ONLY = os.environ.get("CVE_ROUTE_ONLY", "") not in ("", "0", "false", "False")
DELIVER_ONLY = os.environ.get("CVE_DELIVER_ONLY", "") not in ("", "0", "false", "False")
WORK = Path("/root/3.3.6.5/airflow")
GH = "acceldata-io/airflow"
BASE = "nightly/ODP-3.3.6.5"
JIRA = "sehajsandhu/airflow"
RELEASE = "3.3.6.4"
STATUS = Path("/tmp/airflow_cve_route_status.json")
TIMEOUT = int(os.environ.get("CVE_COMPILE_TIMEOUT", "3600"))
TOKEN = ""

CONSTRAINTS = WORK / "odp" / "constraints-3.11.txt"
REQUIREMENTS = WORK / "odp" / "requirements.txt"

# Explicit bump targets (package name as in constraints, case-sensitive match via ci)
BUMPS = {
    "eventlet": "0.40.3",
    "h11": "0.16.0",
    "httpcore": "1.0.9",  # h11 0.16 requires httpcore>=1.0.9
    "httpx": "0.27.2",
    "aiohttp": "3.13.4",
    # aiohttp 3.13.x transitive floor
    "aiosignal": "1.4.0",
    "yarl": "1.17.0",
    "aiohappyeyeballs": "2.5.0",
    "propcache": "0.5.2",
    "cryptography": "43.0.1",  # 46.x/48.x need separate Exception (resolver/ABI risk)
    "urllib3": "2.7.0",  # covers 2.2.2 / 2.5.0 / 2.7.0 ticket fix lines
    "Mako": "1.3.12",
    "sqlparse": "0.5.4",
    "virtualenv": "20.36.1",
    "requests": "2.33.0",
    "filelock": "3.20.3",
    "idna": "3.15",
    "python-ldap": "3.4.5",
    "marshmallow": "3.26.2",
    "zipp": "3.19.1",
    "pyasn1": "0.6.3",
    "pyasn1-modules": "0.4.2",
    "Pygments": "2.20.0",
    "PyJWT": "2.12.0",
}

EXCEPTION_PKGS = {
    "apache-airflow": (
        "These are vulnerabilities in Apache Airflow 2.8.3 itself; published "
        "fixes require 2.10.x / 2.11.x / 3.x (product upgrade across ODP), not "
        "a dependency pin. Exception Request (Deferred)."
    ),
    "apache-airflow-providers-http": (
        "Fix requires apache-airflow-providers-http 6.0.0 (major upgrade from "
        "4.x) coordinated with Airflow 2.8.3 provider compatibility. "
        "Exception Request (Deferred)."
    ),
    "apache-airflow-providers-common-sql": (
        "Fix requires apache-airflow-providers-common-sql 1.24.1+ (large jump "
        "from 1.11.1) with Airflow 2.8.3 compatibility risk. "
        "Exception Request (Deferred)."
    ),
    "Flask-AppBuilder": (
        "Airflow 2.8.3 hard-pins flask-appbuilder==4.3.11; CVE fixes need "
        "4.5.3–4.8.1 which cannot be applied without upgrading Airflow itself. "
        "Exception Request (Deferred)."
    ),
    "flask": (
        "Flask 2.2.5 fix is only in 3.1.3 (major upgrade) which breaks "
        "Airflow 2.8.3 / Flask-AppBuilder 4.3.x. Exception Request (Deferred)."
    ),
    "werkzeug": (
        "Several Werkzeug CVEs only fix on 3.1.x; Airflow 2.8.3 pins Flask "
        "2.2.5 which requires Werkzeug <3. Exception Request (Deferred)."
    ),
    "thrift": (
        "thrift 0.16.0 fix is 0.23.0; upgrading thrift across the Airflow/"
        "Hive stack is a coordinated ODP change. Exception Request (Deferred)."
    ),
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
    print(f"STATUS: {json.dumps(kwargs)[:400]}", flush=True)


def field_text(v):
    if v is None:
        return ""
    if isinstance(v, str):
        return v
    if isinstance(v, dict):
        out = []

        def walk(n):
            if isinstance(n, dict):
                if n.get("type") == "text":
                    out.append(n.get("text") or "")
                for c in n.get("content") or []:
                    walk(c)
            elif isinstance(n, list):
                for c in n:
                    walk(c)

        walk(v)
        return " ".join(out) if out else ""
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


def parse_constraints(path: Path) -> dict[str, str]:
    pins = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "==" not in line:
            continue
        # name==ver ; ignore extras
        m = re.match(r"^([A-Za-z0-9_.\-]+)==([^#\s]+)", line)
        if m:
            pins[m.group(1)] = m.group(2)
    return pins


def norm_pkg(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def find_pin(pins: dict[str, str], pkg: str) -> tuple[str | None, str | None]:
    """Return (canonical_name, version) from constraints for pkg."""
    target = norm_pkg(pkg)
    for k, v in pins.items():
        if norm_pkg(k) == target:
            return k, v
    return None, None


def parse_fix_versions(fix_field: str) -> list[str]:
    """Extract candidate fixed versions from Jira fix text."""
    if not fix_field:
        return []
    # split on commas / 'and' / spaces carefully
    parts = re.split(r"[,;/]| and ", fix_field)
    vers = []
    for p in parts:
        p = p.strip()
        # take first token that looks like a version
        m = re.search(r"\b(\d+(?:\.\d+)+(?:[a-zA-Z0-9._\-]*)?)\b", p)
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
    """True if current meets a same-major fixed version (OR across majors).

    Scanner often lists both 1.x and 2.x fixes (e.g. urllib3 2.2.2, 1.26.19).
    Matching across majors falsely closes 2.0.7 against 1.26.19.
    """
    cands = parse_fix_versions(fix_field)
    if not cands:
        return False
    cur_maj = _major(current)
    same = [c for c in cands if cur_maj is not None and _major(c) == cur_maj]
    pool = same if same else cands
    return any(version_ge(current, c) for c in pool)


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
                "customfield_10892,customfield_10891"
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
        sev = summ.split(" - ")[0].strip()
        pkg = field_text(f.get("customfield_10875"))
        ver = field_text(f.get("customfield_10892"))
        fix = ca.extract_fixed_version(f.get("customfield_10891")) if hasattr(
            ca, "extract_fixed_version"
        ) else field_text(f.get("customfield_10891"))
        m = re.search(r"(CVE-\d+-\d+|GHSA-[a-z0-9-]+)", summ)
        rows.append({
            "key": i["key"],
            "sev": sev,
            "pkg": pkg,
            "ver": ver,
            "fix": fix or "",
            "cve": m.group(1) if m else "",
            "summary": summ,
        })
    return rows


def classify(row, pins):
    pkg = row["pkg"]
    np = norm_pkg(pkg)

    if np == "apache-airflow":
        return "exception", {"why": EXCEPTION_PKGS["apache-airflow"]}
    if np.startswith("apache-airflow-providers-"):
        why = EXCEPTION_PKGS.get(pkg) or EXCEPTION_PKGS.get(np)
        if not why:
            # match known provider keys loosely
            for k, w in EXCEPTION_PKGS.items():
                if norm_pkg(k) == np:
                    why = w
                    break
        if not why:
            why = (
                "Airflow provider package upgrade required for this CVE; "
                "provider major bumps need coordinated Airflow 2.8.3 "
                "compatibility validation. Exception Request (Deferred)."
            )
        return "exception", {"why": why}

    if np == "cryptography":
        cands = parse_fix_versions(row["fix"])
        same = [c for c in cands if _major(c) is not None and _major(c) >= 46]
        if same and not any(
            version_ge(BUMPS["cryptography"], c)
            for c in cands
            if _major(c) == 43 or (_major(c) is not None and _major(c) < 46)
        ):
            # only fixes are 46+/48+ — cannot take with Airflow 2.8.3 resolver
            if all(_major(c) is not None and _major(c) >= 46 for c in cands):
                return "exception", {"why": (
                    "cryptography fix requires 46.x+ (or 48.x); Airflow 2.8.3 "
                    "ODP constraints bump stops at 43.0.1 due to dependency "
                    "resolution / ABI risk with the 2.8.3 stack. "
                    "Exception Request (Deferred)."
                )}

    if np == "protobuf":
        cands = parse_fix_versions(row["fix"])
        if cands and all(
            c.startswith(("5.", "6.", "33.")) for c in cands
        ):
            return "exception", {"why": (
                "protobuf fix requires 5.x/6.x (or 33.x) major line; Airflow "
                "2.8.3 constraints stay on protobuf 4.25.x. "
                "Exception Request (Deferred)."
            )}

    if np in EXCEPTION_PKGS and np in (
        "werkzeug", "flask", "thrift", "flask-appbuilder"
    ):
        return "exception", {"why": EXCEPTION_PKGS[
            "Flask-AppBuilder" if np == "flask-appbuilder" else np
        ]}

    # Flask-AppBuilder keyed with capitals in EXCEPTION_PKGS
    if np == "flask-appbuilder":
        return "exception", {"why": EXCEPTION_PKGS["Flask-AppBuilder"]}

    cname, current = find_pin(pins, pkg)
    if current and min_fix_satisfied(current, row["fix"]):
        return "close", {
            "why": (
                f"Already addressed on {BASE}: {cname}=={current} satisfies "
                f"fix requirement ({row['fix']}). Prior ODP constraint bumps "
                f"(e.g. airflow#19) / nightly pins."
            ),
            "pin": f"{cname}=={current}",
        }

    bump_key = None
    for k in BUMPS:
        if norm_pkg(k) == np:
            bump_key = k
            break
    if bump_key:
        target = BUMPS[bump_key]
        if current and version_ge(current, target):
            return "close", {
                "why": (
                    f"Already at/above target on {BASE}: {cname}=={current} "
                    f"(target {target})."
                ),
                "pin": f"{cname}=={current}",
            }
        return "fix", {"bump_key": bump_key, "target": target, "current": current}

    return "unknown", {}


def route_tickets(ca, rows, pins):
    closed, excepted, fixable, unknown = [], [], [], []
    bump_needed = {}  # bump_key -> target
    for row in rows:
        action, meta = classify(row, pins)
        key = row["key"]
        if action == "close":
            comment = f"Closed: {meta['why']}"
            print(f"CLOSE {key} {row['pkg']}@{row['ver']} — {meta.get('pin','')}", flush=True)
            if not DRY:
                ok = ca.close_ticket_with_comment(key, comment, "Closed", assignee=ASSIGNEE)
                (closed if ok else unknown).append({**row, "action": "close", "ok": ok})
            else:
                closed.append({**row, "action": "close", "ok": True})
        elif action == "exception":
            print(f"EXCEPTION {key} {row['pkg']}", flush=True)
            if not DRY:
                ok = ca.update_ticket_exception(
                    key, meta["why"], reason="Deferred", assignee=ASSIGNEE
                )
                (excepted if ok else unknown).append({**row, "action": "exception", "ok": ok})
            else:
                excepted.append({**row, "action": "exception", "ok": True})
        elif action == "fix":
            print(
                f"FIXABLE {key} {row['pkg']}: {meta.get('current')} -> {meta['target']}",
                flush=True,
            )
            fixable.append({**row, "action": "fix", **meta})
            bump_needed[meta["bump_key"]] = meta["target"]
        else:
            print(f"UNKNOWN {key} pkg={row['pkg']} ver={row['ver']} fix={row['fix']}", flush=True)
            unknown.append({**row, "action": "unknown"})
    return closed, excepted, fixable, unknown, bump_needed


def ensure_repo():
    env = git_env()
    run(f"git remote set-url origin https://github.com/{GH}.git", WORK, env=env, timeout=60)
    run(f"git fetch origin {BASE} --prune", WORK, env=env, timeout=600)
    run(f"git checkout -B {BASE} origin/{BASE}", WORK, env=env, timeout=120)
    run("git reset --hard HEAD && git clean -fdx -e odp/.venv -e odp/airflow", WORK, env=env, timeout=300)
    run(f"git checkout -B {BASE} origin/{BASE}", WORK, env=env, timeout=120)
    return WORK


def apply_bumps(bump_needed: dict[str, str]) -> list[str]:
    changed = []
    text = CONSTRAINTS.read_text(encoding="utf-8", errors="replace")
    orig = text
    for name, ver in bump_needed.items():
        pattern = re.compile(
            rf"(?im)^({re.escape(name)})==([^\s#]+)",
        )
        text2, n = pattern.subn(rf"\1=={ver}", text, count=1)
        if n == 0:
            found = False
            lines = text.splitlines(keepends=True)
            out = []
            for ln in lines:
                m = re.match(r"^([A-Za-z0-9_.\-]+)==([^\s#]+)", ln.strip())
                if m and norm_pkg(m.group(1)) == norm_pkg(name):
                    out.append(
                        f"{m.group(1)}=={ver}\n"
                        if ln.endswith("\n")
                        else f"{m.group(1)}=={ver}"
                    )
                    found = True
                else:
                    out.append(ln)
            if not found:
                # New transitive pin (e.g. aiohappyeyeballs/propcache) — append
                if not text.endswith("\n"):
                    text += "\n"
                text += f"{name}=={ver}\n"
            else:
                text = "".join(out)
        else:
            text = text2
    if text != orig:
        CONSTRAINTS.write_text(text, encoding="utf-8")
        changed.append("odp/constraints-3.11.txt")

    # sync filelock/requests in requirements.txt if present
    if REQUIREMENTS.is_file():
        rtext = REQUIREMENTS.read_text(encoding="utf-8", errors="replace")
        rorig = rtext
        for name, ver in bump_needed.items():
            if norm_pkg(name) not in ("filelock", "requests"):
                continue
            rtext, n = re.subn(
                rf"(?im)^({re.escape(name)})==([^\s#]+)",
                rf"\1=={ver}",
                rtext,
                count=1,
            )
            if n == 0:
                rtext, n = re.subn(
                    rf"(?im)^(filelock|requests)==([^\s#]+)",
                    lambda m: (
                        f"{m.group(1)}=={ver}"
                        if norm_pkg(m.group(1)) == norm_pkg(name)
                        else m.group(0)
                    ),
                    rtext,
                    count=1,
                )
        if rtext != rorig:
            REQUIREMENTS.write_text(rtext, encoding="utf-8")
            changed.append("odp/requirements.txt")
    return changed


def pip_gate() -> bool:
    """Resolve check mirroring odp/buildtarball.sh constraint stripping."""
    py = "python3.11" if Path("/usr/bin/python3.11").exists() else "python3"
    venv = Path("/tmp/airflow-cve-venv")
    log = "/tmp/airflow_pip_gate.log"
    gate_c = Path("/tmp/airflow_constraints_gate.txt")
    # Mirror buildtarball.sh: drop pins that requirements.txt overrides
    strip = [
        "mysqlclient",
        "aiofiles",
        "cachetools",
        "distlib",
        "filelock",
        "google-auth",
        "kubernetes",
        "kubernetes-asyncio",
        "platformdirs",
        "requests-oauthlib",
        "websocket-client",
        "apache-airflow-providers-cncf-kubernetes",
        "google-re2",
    ]
    text = CONSTRAINTS.read_text(encoding="utf-8", errors="replace")
    lines = []
    for ln in text.splitlines(keepends=True):
        m = re.match(r"^([A-Za-z0-9_.\-]+)==", ln.strip())
        if m and norm_pkg(m.group(1)) in {norm_pkg(s) for s in strip}:
            continue
        lines.append(ln)
    gate_c.write_text("".join(lines), encoding="utf-8")

    code, out, err = run(
        f"rm -rf {venv} && {py} -m venv {venv} && "
        f"{venv}/bin/pip install -U 'pip>=24' -q && "
        f"{venv}/bin/pip install -r {REQUIREMENTS} "
        f"--constraint {gate_c} --dry-run",
        WORK / "odp",
        timeout=TIMEOUT,
        log_path=log,
    )
    if code != 0 and "no such option" in (out + err).lower():
        code, out, err = run(
            f"{venv}/bin/pip install -U pip -q && "
            f"{venv}/bin/pip install -r {REQUIREMENTS} --constraint {gate_c}",
            WORK / "odp",
            timeout=TIMEOUT,
            log_path=log,
        )
    write_status(pip_gate={"exit": code, "ok": code == 0, "log": log})
    if code != 0:
        for ln in (out + err).splitlines()[-50:]:
            if any(x in ln.lower() for x in ("error", "conflict", "could not", "resolution", "requires")):
                print("   ", ln[:220], flush=True)
    return code == 0


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
            headers=headers, json={"reviewers": [REVIEWER]}, timeout=60,
        )
        return url
    print(f"PR fail {r.status_code}: {r.text[:400]}", flush=True)
    return None


def deliver(ca, fixable, bump_needed):
    if not bump_needed:
        print("No bumps to apply", flush=True)
        return {"ok": True, "pr": None, "closed": []}

    # Include transitive companion pins from BUMPS (aiohttp/cryptography floors)
    merged = dict(BUMPS)
    merged.update(bump_needed)
    bump_needed = merged

    branch = fixable[0]["key"]
    parts = [f"{k} {v}" for k, v in sorted(bump_needed.items())]
    title = (
        f"{branch} - CVE - Bumped-up Airflow Python deps "
        f"({', '.join(parts[:4])}{'...' if len(parts)>4 else ''}) "
        f"to address ODP {RELEASE} CVEs"
    )

    ensure_repo()
    run(f"git checkout -B {branch} origin/{BASE}", WORK, env=git_env(), timeout=120)
    # re-read pins after reset and re-apply
    changed = apply_bumps(bump_needed)
    write_status(patched=changed, bumps=bump_needed)

    if not DRY:
        ok = pip_gate()
        if not ok:
            return {"ok": False, "phase": "FAILED_PIP_GATE"}

    body_lines = [
        f"- Component: airflow ({BASE}, release {RELEASE})",
        f"- Tickets: {', '.join(r['key'] for r in fixable)}",
        "- Constraint bumps:",
        *[f"  - {k}: -> {v}" for k, v in sorted(bump_needed.items())],
    ]
    if DRY:
        return {"ok": True, "dry": True, "title": title, "bumps": bump_needed}

    run("git add odp/constraints-3.11.txt odp/requirements.txt", WORK, timeout=60)
    p = subprocess.run(
        ["git", "commit", "-m", title], cwd=str(WORK),
        text=True, capture_output=True, env=git_env(),
    )
    if p.returncode != 0:
        return {"ok": False, "commit_err": (p.stderr or p.stdout or "")[-400:]}
    code, _, err = run(f"git push -u origin {branch}", WORK, timeout=300)
    if code != 0:
        return {"ok": False, "push_err": err[-400:]}
    pr = create_pr(branch, title, "\n".join(body_lines))
    if not pr:
        return {"ok": False, "pr": None}

    closed = []
    for r in fixable:
        comment = (
            f"Fixed via PR: {pr} — bumped {r.get('bump_key', r['pkg'])} "
            f"to {r.get('target')} on {BASE}."
        )
        ok = ca.close_ticket_with_comment(r["key"], comment, "Closed", assignee=ASSIGNEE)
        print(f"  {r['key']} -> {'Closed' if ok else 'FAILED'}", flush=True)
        if ok:
            closed.append(r["key"])
    return {"ok": True, "pr": pr, "closed": closed, "bumps": bump_needed}


def main():
    write_status(phase="start")
    load_token()
    import cve_analyser as ca
    ca.DRY_RUN = DRY

    if DELIVER_ONLY:
        prev = json.loads(STATUS.read_text()) if STATUS.is_file() else {}
        bump_needed = dict(prev.get("bumps") or {})
        # Always merge full BUMPS so transitive companions are applied on resume
        bump_needed.update(BUMPS)
        fix_keys = prev.get("fixable") or []
        if not bump_needed or not fix_keys:
            raise SystemExit("CVE_DELIVER_ONLY needs prior status with bumps+fixable")
        # Rebuild minimal fixable rows for PR/close
        fixable = [
            {"key": k, "pkg": "", "bump_key": "deps", "target": "see bumps"}
            for k in fix_keys
        ]
        write_status(phase="deliver_only", bumps=bump_needed, fixable=fix_keys)
        res = deliver(ca, fixable, bump_needed)
        write_status(phase="DONE", result=res)
        print("DONE", json.dumps(res, indent=2), flush=True)
        return

    ensure_repo()
    pins = parse_constraints(CONSTRAINTS)
    write_status(phase="pins_loaded", pin_count=len(pins))

    rows = load_tickets(ca)
    write_status(phase="loaded", count=len(rows))
    closed, excepted, fixable, unknown, bump_needed = route_tickets(ca, rows, pins)
    write_status(
        phase="routed",
        closed=[r["key"] for r in closed],
        excepted=[r["key"] for r in excepted],
        fixable=[r["key"] for r in fixable],
        unknown=[r["key"] for r in unknown],
        bumps=bump_needed,
    )
    if ROUTE_ONLY:
        write_status(phase="ROUTE_ONLY_DONE")
        return

    res = deliver(ca, fixable, bump_needed)
    write_status(phase="DONE", result=res)
    print("DONE", json.dumps(res, indent=2), flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        write_status(phase="ERROR", error=str(e)[:800])
        raise
