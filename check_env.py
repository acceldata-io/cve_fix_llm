#!/usr/bin/env python3
"""Portable environment check for running CVE automation on any Linux/macOS host.

Usage:
    python3 check_env.py
"""
from __future__ import annotations
import os
import shutil
import sys

import cve_env

cve_env.load_repo_env()


def ok(msg): print(f"  OK  {msg}")
def bad(msg): print(f" FAIL {msg}")
def info(msg): print(f"  ..  {msg}")


def main() -> int:
    fails = 0
    print("=== CVE automation environment ===\n")

    # Python
    v = sys.version_info
    if v >= (3, 9):
        ok(f"Python {v.major}.{v.minor}.{v.micro}")
    else:
        bad(f"Python {v.major}.{v.minor} (need 3.9+)"); fails += 1

    # Packages
    for pkg, mod in [("anthropic", "anthropic"), ("requests", "requests")]:
        try:
            __import__(mod); ok(f"package {pkg}")
        except ImportError:
            bad(f"package {pkg} missing (pip install -r requirements.txt)"); fails += 1

    # Credentials
    env_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if os.path.isfile(env_file):
        ok(f".env loaded from {env_file}")
    for k in ("ANTHROPIC_API_KEY", "CVE_JIRA_EMAIL", "CVE_JIRA_API_TOKEN",
              "GITHUB_TOKEN"):
        if os.environ.get(k) or (k == "GITHUB_TOKEN" and os.environ.get("GH_TOKEN")):
            ok(f"{k} set")
        else:
            # Jira may come from ~/.config/cve_fix/jira.env
            if k.startswith("CVE_JIRA"):
                jira_env = os.path.expanduser(
                    os.environ.get("CVE_JIRA_CRED_FILE",
                                   "~/.config/cve_fix/jira.env"))
                if os.path.isfile(jira_env):
                    ok(f"{k} via {jira_env}")
                    continue
            info(f"{k} not set (required for full runs)")

    # Portable paths
    import cve_profiles as cp
    j8, j11 = cp.resolve_java_home(8), cp.resolve_java_home(11)
    wd = os.path.expanduser(os.environ.get("CVE_WORKDIR", "~/cve_fix_workdir"))
    if j8: ok(f"JDK 8  -> {j8}")
    else:  bad("JDK 8 not found — set CVE_JAVA_HOME_8"); fails += 1
    if j11: ok(f"JDK 11 -> {j11}")
    else:  info("JDK 11 not found — set CVE_JAVA_HOME_11 if you need JDK11 comps")
    ok(f"CVE_WORKDIR -> {wd}")
    os.makedirs(wd, exist_ok=True)

    # Tools
    for t in ("git", "mvn"):
        p = shutil.which(t)
        if p: ok(f"{t} -> {p}")
        else: info(f"{t} not on PATH (needed for FIX builds)")

    # Sample profile resolution (JDK follows release baseline)
    try:
        p82 = cp.get_profile("spark2", release="3.2.3.6")
        ok(f"3.2.3.6 baseline → JDK {p82.get('jdk_version')}  "
           f"({p82.get('java_home') or 'missing'})")
        p336 = cp.get_profile("spark2", release="3.3.6.4")
        ok(f"3.3.6.4 baseline → JDK {p336.get('jdk_version')}  "
           f"({p336.get('java_home') or 'missing'})")
        if not cp.resolve_java_home(11):
            info("JDK 11 required for 3.3.6.* baselines — set CVE_JAVA_HOME_11")
    except Exception as e:
        bad(f"get_profile release JDK: {e}"); fails += 1

    print()
    if fails:
        print(f"RESULT: {fails} failure(s) — fix before remote runs")
        return 1
    print("RESULT: ready")
    return 0


if __name__ == "__main__":
    sys.exit(main())
