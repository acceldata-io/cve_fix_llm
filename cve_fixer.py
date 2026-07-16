"""
CVE auto-fixer (config-driven, multi-library).

For each fix target (see FIX_TARGETS) the pipeline:
  1. Fetches CVE tickets via cve_analyser and groups them by library.
  2. Selects one target version (ODP-aligned if configured, else pure-max).
  3. Clones/refreshes the Spark repo.
  4. SKIPS the target if it is already fixed (so re-runs don't redo work):
       - the local state file (cve_fix_state.json) records this lib already
         bumped to >= the target version, OR
       - the base-branch pom already has the lib at/above the target version
         (fix merged upstream), OR
       - any of this group's OSV branches already exist on origin (fix pushed).
  5. Otherwise creates a fix branch named after the first OSV ticket id.
  6. Patches the pom (property bump or dependency-version bump).
  7. Runs the full make-distribution build.
  8. On build success, commits with the target's message template and pushes.

Libraries that cannot be fixed in Spark2 are routed to the Jira "Exception
Request" flow instead (see LIBRARY_EXCEPTION_RULES).

SAFETY: APPLY defaults to False -> the script only PLANS (prints what it would
do) and performs NO git/build/push actions. Set APPLY = True to execute.
"""

import json
import os
import re
import subprocess
from typing import Dict, List, Optional, Tuple

import cve_analyser as ca
import cve_profiles

# -------------------------------------------------------------------
# Configuration (driven by the active profile; select with CVE_PROFILE)
# -------------------------------------------------------------------
PROFILE_NAME = cve_profiles.active_profile_name()
PROFILE = cve_profiles.get_profile(
    PROFILE_NAME, release=os.environ.get("CVE_RELEASE"))

SPARK_REPO_URL = PROFILE["git_url"]
TARGET_BRANCH = PROFILE["target_branch"]           # where fixes are applied
# Separate checkout per profile so spark2/spark3 builds don't collide.
WORKDIR = os.path.expanduser(
    PROFILE.get("workdir") or f"~/cve_fix_workdir/{PROFILE_NAME}")
POM_PATH = PROFILE["pom_path"]                      # relative to WORKDIR
JAVA_HOME = PROFILE["java_home"]
BUILD_CMD = PROFILE["build_cmd"]

# Runtime-environment constraints for this component (see cve_profiles.profile_env):
# a patched version that needs a newer JDK/Python than this component runs on is
# NOT a valid fix -> such CVEs are routed to Exception (environment/compatibility
# constraint) instead of being built. PROFILE_JDK is the major Java version
# (None for python components); PROFILE_PYTHON is the pinned interpreter (or None).
_ENV = cve_profiles.profile_env(PROFILE)
PROFILE_JDK = _ENV["jdk"]
PROFILE_PYTHON = _ENV["python"]
PROFILE_BUILD_TOOL = _ENV["build_tool"]

# Fixable library families. Each target matches a set of library groups, picks
# a single target version, and patches the pom accordingly.
#   lib_regex    : regex matched against the grouped library name
#   affected_prefix (optional): only include CVEs whose affected version starts
#                  with this (guards against same-name but different major lines)
#   aligned_key  : key into ODP_ALIGNED_VERSIONS for the canonical version
#   patch.type   : "property"   -> set <name>VER</name> for each name
#                  "dependency" -> set <version>VER</version> inside the
#                                  <dependency> block for group:artifact
#   commit_subject: template; {branch} and {cve} are filled in
#   requires_jdk (optional): the JDK the patched version needs (int major). If
#                  the component's PROFILE_JDK is lower, the fix is environment-
#                  incompatible: process_plan skips the build and routes the
#                  target's CVEs to Exception (environment/compatibility).
#   requires_python (optional): the Python version the patched package needs;
#                  same env gate applies for python components.
FIX_TARGETS = PROFILE["fix_targets"]

# Restrict this run to a single target by name (e.g. "netty"); None = all targets.
# Override per run with the CVE_ONLY_TARGET env var.
ONLY_TARGET = os.environ.get("CVE_ONLY_TARGET") or None

# Routing rule lists come from the active profile.
#
# Matching semantics (see match_rule): "match" is a case-insensitive substring
# of the affected library name; optional "affected_prefix" prefixes the ticket's
# affected version; optional "path_contains" is a regex against the CVE-Path; and
# optional "cve" is an exact CVE-ID match. Rules are evaluated per-ticket in
# order; the first whose match + all filters pass wins.
#
# Environment/compatibility rules (R9): an exception rule may also carry
# "requires_jdk" (int) and/or "requires_python" (str). Such a rule only matches
# when the component's runtime is BELOW that requirement (PROFILE_JDK <
# requires_jdk, or PROFILE_PYTHON < requires_python) -- i.e. the only patched
# version needs an incompatible JDK/Python, so the CVE is routed to Exception.
# A rule may set "reason" to override the default Exception reason ("Deferred").
#
#   LIBRARY_EXCEPTION_RULES : routed to "Exception Request" (Deferred).
#   LIBRARY_CLOSE_RULES     : commented with a fix reference and Closed.
#   SHADED_BUNDLE_RULES     : CVEs whose vulnerable class is inside a third-party
#                             fat jar; routed to exception/close ("bundle" is a
#                             substring of the jar filename; "action" is
#                             "exception" or "close").
LIBRARY_EXCEPTION_RULES = PROFILE["exception_rules"]
LIBRARY_CLOSE_RULES = PROFILE["close_rules"]
SHADED_BUNDLE_RULES = PROFILE.get("shaded_bundle_rules", [])

# Canonical versions kept in sync across ODP components. When a library has an
# entry here, this version OVERRIDES the pure-max selection so the component
# stays aligned with the rest of the platform.
ODP_ALIGNED_VERSIONS = PROFILE["aligned_versions"]

# Safety switch: when False, plan only; no git/build actions are performed.
# Flip to True (or set CVE_APPLY=1) once a profile's git/build fields are verified.
APPLY = os.environ.get("CVE_APPLY", "") not in ("", "0", "false", "False")

# After a fix branch is pushed (APPLY), open a PR against TARGET_BRANCH and close
# the linked Jira tickets with the PR link. Set CVE_SKIP_PR=1 to push only and
# handle the PR/Jira step manually.
SKIP_PR = os.environ.get("CVE_SKIP_PR", "") not in ("", "0", "false", "False")

# Skip the exception/shaded/close Jira routing passes and ONLY run the fix
# targets (build/PR/close). Useful when the exception routing is handled
# separately (e.g. a dedicated comment-aware script).
SKIP_ROUTING = os.environ.get("CVE_SKIP_ROUTING", "") not in ("", "0", "false", "False")

# owner/repo derived from the git URL, used for the GitHub PR API.
REPO_SLUG = re.sub(r"^https?://github\.com/", "", SPARK_REPO_URL)
REPO_SLUG = re.sub(r"\.git$", "", REPO_SLUG).strip("/")

# Records libraries already fixed (target name -> {version, branch, cves}) so a
# re-run does NOT recreate the branch / rebuild a fix that is already done.
# Per-profile so spark2 and spark3 states never collide.
STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          f"cve_fix_state_{PROFILE_NAME}.json")


# -------------------------------------------------------------------
# Version helpers
# -------------------------------------------------------------------
VERSION_RE = re.compile(r"\d+(?:\.\d+)+")


def parse_version(v: str) -> Tuple[int, ...]:
    """
    Turn a version into a comparable tuple of leading numeric components,
    stopping at the first non-numeric part. Handles suffixes/qualifiers:
      '2.9.9.1'         -> (2, 9, 9, 1)
      '4.1.135.Final'   -> (4, 1, 135)
      '32.0.1-jre'      -> (32, 0, 1)
    """
    parts: List[int] = []
    for p in re.split(r"[.\-_]", v.strip()):
        if p.isdigit():
            parts.append(int(p))
        else:
            break
    return tuple(parts)


def split_fix_versions(fixed_version: str) -> List[str]:
    """
    Pull all concrete version strings out of a Fixed-Version value such as
    '2.21.1, 2.18.6' or '2.9.9.1, 2.8.11.4, 2.7.9.6'. Non-versions like
    'open' are ignored.
    """
    if not fixed_version:
        return []
    return VERSION_RE.findall(fixed_version)


def pick_max_version(versions: List[str]) -> Optional[str]:
    """Return the numerically highest version, or None if the list is empty."""
    if not versions:
        return None
    return max(versions, key=parse_version)


def uncovered_issues(issues: List[Dict], target: str) -> List[Dict]:
    """
    Return issues NOT fixed by `target`. A CVE is considered fixed if `target`
    is >= the lowest version listed in its fixed-version field (fixes are
    forward-inclusive). Issues with no concrete fix version are ignored here.
    """
    if not target:
        return []
    tv = parse_version(target)
    missed = []
    for iss in issues:
        fixes = split_fix_versions(iss["fixed_version"])
        if not fixes:
            continue
        min_fix = min(parse_version(v) for v in fixes)
        if tv < min_fix:
            missed.append(iss)
    return missed


# -------------------------------------------------------------------
# Planning
# -------------------------------------------------------------------
def build_fix_plan(target: Dict, lib_map: Dict[str, List[Dict]]) -> Optional[Dict]:
    """
    Collect every library group matching this target into a single fix plan.
    All matched artifacts move to one version (ODP-aligned if configured, else
    pure-max). Returns None if the target matches no CVEs.
    """
    regex = re.compile(target["lib_regex"])
    prefix = target.get("affected_prefix")

    groups: Dict[str, List[Dict]] = {}
    for lib, entries in lib_map.items():
        if not regex.search(lib):
            continue
        if prefix:
            entries = [e for e in entries if e["affected_version"].startswith(prefix)]
        # A Spark-side version bump only fixes standalone library jars and
        # Spark-built assemblies; CVEs inside third-party fat jars (hadoop shaded
        # client, aws-java-sdk-bundle, iceberg/gcs runtimes, ...) are handled by
        # the shaded-bundle routing instead, so exclude them here.
        entries = [e for e in entries if not ca.is_thirdparty_shaded(e)]
        if entries:
            groups[lib] = entries
    if not groups:
        return None

    all_versions: List[str] = []
    issues: List[Dict] = []
    for entries in groups.values():
        issues.extend(entries)
        for iss in entries:
            all_versions.extend(split_fix_versions(iss["fixed_version"]))

    pure_max = pick_max_version(all_versions)
    aligned = ODP_ALIGNED_VERSIONS.get(target["aligned_key"])
    # ODP alignment wins over pure-max so Spark stays in sync with the platform.
    version = aligned or pure_max
    selection = "ODP-aligned" if aligned else "pure-max"

    # First OSV id (issues are already ordered "created DESC" from the fetch)
    branch_ticket = issues[0]["key"] if issues else None
    # Representative CVE for the commit message: first concrete (non-UNKNOWN) id.
    commit_cve = next((i["cve_id"] for i in issues if i["cve_id"] != "UNKNOWN"),
                      issues[0]["cve_id"] if issues else "")

    return {
        "name": target["name"],
        "patch": target["patch"],
        "commit_subject": target["commit_subject"],
        "libraries": sorted(groups.keys()),
        "issues": issues,
        "candidate_versions": sorted(set(all_versions), key=parse_version),
        "pure_max_version": pure_max,
        "target_version": version,
        "selection": selection,
        "branch": branch_ticket,
        "commit_cve": commit_cve,
        # R9 environment/compatibility gate (see process_plan): the patched
        # version's runtime requirements, if the target declares them.
        "requires_jdk": target.get("requires_jdk"),
        "requires_python": target.get("requires_python"),
    }


# -------------------------------------------------------------------
# pom.xml patching
# -------------------------------------------------------------------
def patch_pom_properties(pom_text: str, properties: List[str], new_version: str,
                         count: int = 1) -> Tuple[str, List[str]]:
    """
    Set <prop>...</prop> to new_version for each property name. Returns the
    patched text and the list of properties that were actually changed.

    `count` is the max replacements per property (passed to re.sub). The default
    of 1 only touches the first occurrence; pass 0 to replace EVERY occurrence,
    which is needed when the same version property is also redefined inside a
    build <profile> that overrides the top-level value (e.g. Livy's spark3
    profile re-declares <netty.version>).
    """
    changed: List[str] = []
    for prop in properties:
        pattern = re.compile(rf"(<{re.escape(prop)}>)(.*?)(</{re.escape(prop)}>)")

        def repl(m):
            if m.group(2) != new_version:
                changed.append(f"{prop}: {m.group(2)} -> {new_version}")
            return f"{m.group(1)}{new_version}{m.group(3)}"

        pom_text = pattern.sub(repl, pom_text, count=count)
    return pom_text, changed


def patch_pom_dependency_version(pom_text: str, group: str, artifact: str,
                                 new_version: str) -> Tuple[str, List[str]]:
    """
    Set the <version> inside the <dependency> block whose groupId/artifactId
    match (e.g. io.netty:netty-all). Returns patched text and changes made.
    """
    changed: List[str] = []
    pattern = re.compile(
        r"(<dependency>\s*"
        rf"<groupId>{re.escape(group)}</groupId>\s*"
        rf"<artifactId>{re.escape(artifact)}</artifactId>\s*"
        r"<version>)(.*?)(</version>)",
        re.DOTALL,
    )

    def repl(m):
        if m.group(2) != new_version:
            changed.append(f"{group}:{artifact}: {m.group(2)} -> {new_version}")
        return f"{m.group(1)}{new_version}{m.group(3)}"

    return pattern.sub(repl, pom_text, count=1), changed


def patch_pom_managed_dependency(pom_text: str, group: str, artifact: str,
                                 new_version: str) -> Tuple[str, List[str]]:
    """
    Ensure group:artifact is pinned to new_version in <dependencyManagement>.
    If a managed entry already exists, its version is updated; otherwise a new
    managed <dependency> is inserted into the first <dependencyManagement>'s
    <dependencies> block. Used for transitive deps not declared in the pom.
    """
    patched, changed = patch_pom_dependency_version(pom_text, group, artifact, new_version)
    if changed:
        return patched, changed

    anchor = re.search(r"<dependencyManagement>\s*<dependencies>", pom_text)
    if not anchor:
        return pom_text, []   # no managed section found; caller warns on no-op
    block = (
        f"\n      <dependency>\n"
        f"        <groupId>{group}</groupId>\n"
        f"        <artifactId>{artifact}</artifactId>\n"
        f"        <version>{new_version}</version>\n"
        f"      </dependency>"
    )
    insert_at = anchor.end()
    patched = pom_text[:insert_at] + block + pom_text[insert_at:]
    return patched, [f"{group}:{artifact}: (managed override) -> {new_version}"]


def apply_pom_patch(patch: Dict, version: str) -> List[str]:
    """Read WORKDIR/pom.xml, apply the patch for this target, write it back."""
    pom_file = os.path.join(WORKDIR, POM_PATH)
    with open(pom_file, "r", encoding="utf-8") as fh:
        text = fh.read()

    if patch["type"] == "property":
        # patch.get("all") -> replace every occurrence (e.g. a property that is
        # also redefined inside an overriding build profile); else just the first.
        patched, changed = patch_pom_properties(
            text, patch["names"], version, count=0 if patch.get("all") else 1)
    elif patch["type"] == "dependency":
        patched, changed = patch_pom_dependency_version(
            text, patch["group"], patch["artifact"], version)
    elif patch["type"] == "managed":
        patched, changed = patch_pom_managed_dependency(
            text, patch["group"], patch["artifact"], version)
    else:
        raise ValueError(f"unknown patch type: {patch['type']}")

    with open(pom_file, "w", encoding="utf-8") as fh:
        fh.write(patched)
    return changed


# -------------------------------------------------------------------
# Git / build
# -------------------------------------------------------------------
def run(cmd: str, cwd: Optional[str] = None) -> int:
    print(f"    $ {cmd}")
    return subprocess.run(cmd, shell=True, cwd=cwd).returncode


def ensure_repo() -> bool:
    """Clone the repo if missing, then fetch the latest refs from origin."""
    if not os.path.isdir(os.path.join(WORKDIR, ".git")):
        os.makedirs(os.path.dirname(WORKDIR), exist_ok=True)
        if run(f"git clone {SPARK_REPO_URL} {WORKDIR}") != 0:
            return False
    return run("git fetch origin --prune", cwd=WORKDIR) == 0


def create_fix_branch(branch_name: str) -> bool:
    """Reset to a clean origin/TARGET_BRANCH and create a fresh fix branch."""
    base = f"base-{TARGET_BRANCH.replace('/', '-')}"
    # -f discards any local edits so each fix starts clean from origin.
    if run(f"git checkout -f -B {base} origin/{TARGET_BRANCH}", cwd=WORKDIR) != 0:
        return False
    if run(f"git reset --hard origin/{TARGET_BRANCH}", cwd=WORKDIR) != 0:
        return False
    run(f"git branch -D {branch_name}", cwd=WORKDIR)
    return run(f"git checkout -b {branch_name}", cwd=WORKDIR) == 0


def base_pom_text() -> Optional[str]:
    """Read pom.xml from origin/TARGET_BRANCH without touching the working tree."""
    out = subprocess.run(f"git show origin/{TARGET_BRANCH}:{POM_PATH}",
                         shell=True, cwd=WORKDIR, capture_output=True, text=True)
    return out.stdout if out.returncode == 0 else None


def extract_pom_version(pom_text: str, patch: Dict) -> Optional[str]:
    """Read the current version a patch would change (property or dependency)."""
    if patch["type"] == "property":
        name = patch["names"][0]
        m = re.search(rf"<{re.escape(name)}>(.*?)</{re.escape(name)}>", pom_text)
        return m.group(1) if m else None
    if patch["type"] in ("dependency", "managed"):
        m = re.search(
            rf"<dependency>\s*<groupId>{re.escape(patch['group'])}</groupId>\s*"
            rf"<artifactId>{re.escape(patch['artifact'])}</artifactId>\s*"
            r"<version>(.*?)</version>",
            pom_text, re.DOTALL)
        return m.group(1) if m else None
    return None


def origin_branches() -> set:
    """Set of branch names that currently exist on origin."""
    out = subprocess.run("git ls-remote --heads origin",
                         shell=True, cwd=WORKDIR, capture_output=True, text=True)
    if out.returncode != 0:
        return set()
    return {line.split("refs/heads/")[-1]
            for line in out.stdout.splitlines() if "refs/heads/" in line}


def load_state() -> Dict:
    """Load the persisted fix-state (target name -> details)."""
    if os.path.isfile(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def record_fix(plan: Dict) -> None:
    """Persist that this target was fixed at target_version on its branch."""
    state = load_state()
    state[plan["name"]] = {
        "version": plan["target_version"],
        "branch": plan["branch"],
        "cves": [i["key"] for i in plan["issues"]],
    }
    with open(STATE_FILE, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2)
    print(f"  Recorded fix in {STATE_FILE}")


def github_token() -> Optional[str]:
    """Return a GitHub token.

    Priority: GITHUB_TOKEN / GH_TOKEN env vars (so a .env works), then the
    stored token via `git credential fill`.
    """
    tok = (os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or "").strip()
    if tok:
        return tok
    p = subprocess.run(
        "printf 'protocol=https\\nhost=github.com\\n\\n' | git credential fill",
        shell=True, capture_output=True, text=True)
    for line in p.stdout.splitlines():
        if line.startswith("password="):
            return line[len("password="):].strip()
    return None


def create_pull_request(plan: Dict, title: str) -> Optional[str]:
    """Open (or find an existing) PR for plan['branch'] -> TARGET_BRANCH.

    Returns the PR html_url, or None on failure.
    """
    token = github_token()
    if not token:
        print("  ERROR: no GitHub token from git credential; cannot open PR.")
        return None
    api = f"https://api.github.com/repos/{REPO_SLUG}/pulls"
    headers = {"Authorization": f"token {token}",
               "Accept": "application/vnd.github+json"}
    body = "\n".join([
        f"- Library : {', '.join(plan['libraries'])}",
        f"- Version : -> {plan['target_version']}",
        f"- Tickets : {', '.join(i['key'] for i in plan['issues'])}",
    ])
    payload = {"title": title, "head": plan["branch"],
               "base": TARGET_BRANCH, "body": body}
    r = ca.SESSION.post(api, headers=headers, json=payload)
    if r.status_code == 201:
        url = r.json().get("html_url")
        print(f"  PR created: {url}")
        return url
    if r.status_code == 422:  # likely already exists
        owner = REPO_SLUG.split("/")[0]
        q = ca.SESSION.get(api, headers=headers, params={
            "head": f"{owner}:{plan['branch']}", "base": TARGET_BRANCH,
            "state": "all"})
        if q.status_code == 200 and q.json():
            url = q.json()[0].get("html_url")
            print(f"  PR already exists: {url}")
            return url
    print(f"  ERROR creating PR [{r.status_code}]: {r.text[:300]}")
    return None


def close_tickets_for_plan(plan: Dict, pr_url: str) -> None:
    """Comment the PR link on each linked ticket, assign, and Close it."""
    lib = ", ".join(plan["libraries"])
    comment = (
        f"Fixed via PR: {pr_url}  -  {lib} version increased to "
        f"{plan['target_version']} on {TARGET_BRANCH} to address the linked CVE(s)."
    )
    for iss in plan["issues"]:
        ok = ca.close_ticket_with_comment(iss["key"], comment, "Closed")
        print(f"    {iss['key']} -> {'Closed' if ok else 'FAILED'}")


def already_fixed_reason(plan: Dict) -> Optional[str]:
    """
    Return a human-readable reason to SKIP this target, or None to proceed.
    Three independent signals are checked (any one triggers a skip):
      1. Local state file records this target already fixed at >= target version.
      2. The base branch pom already has the lib at/above the target version
         (i.e. the fix was merged upstream).
      3. Any of this group's OSV branches already exist on origin (we already
         created+pushed the fix branch, even if it isn't merged yet).
    Assumes the repo has been fetched.
    """
    target_v = parse_version(plan["target_version"])

    # 1. Local state file
    prev = load_state().get(plan["name"])
    if prev and prev.get("version") and parse_version(prev["version"]) >= target_v:
        return (f"state file records {plan['name']} already fixed at "
                f"{prev['version']} on branch '{prev.get('branch')}'")

    # 2. Base branch pom version
    pom = base_pom_text()
    if pom:
        current = extract_pom_version(pom, plan["patch"])
        if current:
            print(f"  Current version in {TARGET_BRANCH}: {current}")
            if parse_version(current) >= target_v:
                return (f"already at {current} (>= target {plan['target_version']}) "
                        f"in {TARGET_BRANCH}")

    # 3. Any of the group's OSV branches already on origin
    remote = origin_branches()
    pushed = [i["key"] for i in plan["issues"] if i["key"] in remote]
    if pushed:
        return f"fix branch(es) already on origin: {', '.join(pushed)}"
    return None


def build_env() -> dict:
    """Build environment with JAVA_HOME set and its bin prepended to PATH."""
    env = os.environ.copy()
    env["JAVA_HOME"] = JAVA_HOME
    env["PATH"] = os.path.join(JAVA_HOME, "bin") + os.pathsep + env.get("PATH", "")
    return env


def run_build() -> bool:
    if not os.path.isdir(JAVA_HOME):
        print(f"    ERROR: JAVA_HOME does not exist: {JAVA_HOME}")
        return False
    log = os.path.join(WORKDIR, "cve_fix_build.log")
    print(f"    Building (full distribution). JAVA_HOME={JAVA_HOME}")
    print(f"    Logging to {log}")
    with open(log, "w", encoding="utf-8") as fh:
        proc = subprocess.run(BUILD_CMD, shell=True, cwd=WORKDIR,
                              stdout=fh, stderr=subprocess.STDOUT, env=build_env())
    ok = proc.returncode == 0
    print(f"    Build {'SUCCEEDED' if ok else 'FAILED'} (exit {proc.returncode}).")
    return ok


# -------------------------------------------------------------------
# Orchestration
# -------------------------------------------------------------------
def match_exception_rule(library: str, issue: Dict) -> Optional[Dict]:
    """Return the first LIBRARY_EXCEPTION_RULES entry matching this ticket."""
    return match_rule(LIBRARY_EXCEPTION_RULES, library, issue)


def _python_below(have: Optional[str], need: str) -> bool:
    """True if the component's Python version is KNOWN and lower than `need`."""
    if not have:
        return False

    def _t(v: str) -> tuple:
        return tuple(int(x) for x in re.findall(r"\d+", v)[:3])

    try:
        return _t(have) < _t(need)
    except Exception:
        return False


def env_incompatible(requires_jdk=None, requires_python=None) -> Optional[str]:
    """
    Return a human-readable reason string when a fix cannot land on this
    component's runtime (R9 - environment/compatibility constraint), or None
    when the environment satisfies the requirement.

      - requires_jdk (int): patched version needs this Java major. Incompatible
        when the component's PROFILE_JDK is known and lower.
      - requires_python (str): patched package needs this Python. Incompatible
        when PROFILE_PYTHON is known and lower.
    """
    if requires_jdk is not None and PROFILE_JDK is not None \
            and PROFILE_JDK < int(requires_jdk):
        return (f"Patched version requires JDK {requires_jdk}, but {PROFILE_NAME} "
                f"builds/runs on JDK {PROFILE_JDK}. Upgrading would force an "
                f"incompatible JDK change; routed to Exception "
                f"(environment/compatibility constraint).")
    if requires_python is not None and _python_below(PROFILE_PYTHON, requires_python):
        return (f"Patched package requires Python >= {requires_python}, but "
                f"{PROFILE_NAME} runs on Python {PROFILE_PYTHON}; routed to "
                f"Exception (environment/compatibility constraint).")
    return None


def match_rule(rules: List[Dict], library: str, issue: Dict) -> Optional[Dict]:
    """
    Generic per-ticket rule matcher used by both the exception and close flows:
      - "match" is a case-insensitive substring of the library name, AND
      - "affected_prefix" (if set) prefixes the ticket's affected version, AND
      - "path_contains" (if set) matches the ticket's CVE-Path, AND
      - "cve" (if set) equals the ticket's CVE-ID (case-insensitive), AND
      - "requires_jdk"/"requires_python" (if set) only match when the component's
        runtime is BELOW that requirement (R9 environment/compatibility).
    """
    for rule in rules:
        if rule["match"].lower() not in library.lower():
            continue
        prefix = rule.get("affected_prefix")
        if prefix and not (issue.get("affected_version") or "").startswith(prefix):
            continue
        path_re = rule.get("path_contains")
        if path_re and not re.search(path_re, issue.get("cve_path") or "", re.IGNORECASE):
            continue
        cve = rule.get("cve")
        if cve and cve.lower() != (issue.get("cve_id") or "").lower():
            continue
        # Environment/compatibility gate: an env rule only applies when the
        # component's runtime actually violates the requirement.
        if (rule.get("requires_jdk") is not None
                or rule.get("requires_python") is not None):
            if not env_incompatible(rule.get("requires_jdk"),
                                    rule.get("requires_python")):
                continue
        return rule
    return None


def match_shaded_rule(issue: Dict) -> Optional[Dict]:
    """Return the first SHADED_BUNDLE_RULES entry whose 'bundle' substring is in
    the CVE-Path's jar filename, or None."""
    jar = ca.jar_filename(issue.get("cve_path") or "").lower()
    if not jar:
        return None
    for rule in SHADED_BUNDLE_RULES:
        if rule["bundle"].lower() in jar:
            return rule
    return None


def apply_shaded_bundle_rules(lib_map: Dict[str, List[Dict]]) -> None:
    """
    Route CVEs whose vulnerable class lives inside a THIRD-PARTY fat/shaded jar
    (not fixable by a Spark version bump) to Exception Request or Closed, per
    SHADED_BUNDLE_RULES. Any third-party-shaded CVE that matches no rule is
    reported for manual review rather than silently dropped. Honors DRY_RUN.
    """
    print(f"\n{'='*80}")
    print("  SHADED-BUNDLE PROCESSING")
    print(f"{'='*80}")
    if not SHADED_BUNDLE_RULES:
        print("  No shaded-bundle rules for this profile.")
        return
    if ca.DRY_RUN:
        print("  cve_analyser.DRY_RUN is enabled -> no Jira changes will be sent.")

    matched = 0
    unmatched: List[Dict] = []
    for lib, entries in lib_map.items():
        for iss in entries:
            if not ca.is_thirdparty_shaded(iss):
                continue
            rule = match_shaded_rule(iss)
            if not rule:
                unmatched.append(iss)
                continue
            matched += 1
            action = rule.get("action", "exception")
            jar = ca.jar_filename(iss.get("cve_path") or "")
            print(f"  {iss['key']}  {iss['cve_id']}  ({lib}) shaded in {jar} -> {action}")
            if action == "close":
                ca.close_ticket_with_comment(iss["key"], rule["comment"])
            else:
                ca.update_ticket_exception(iss["key"], rule["description"])

    if unmatched:
        print(f"\n  {len(unmatched)} third-party-shaded CVE(s) matched NO shaded "
              f"rule (need manual review / a new rule):")
        for iss in unmatched:
            jar = ca.jar_filename(iss.get("cve_path") or "")
            print(f"    - {iss['key']} {iss['cve_id']} {iss['affected_library']} in {jar}")
    if not matched:
        print("  No tickets routed by shaded-bundle rules.")
    else:
        print(f"  {matched} shaded-bundle ticket(s) routed.")


def apply_library_closures(lib_map: Dict[str, List[Dict]]) -> None:
    """
    For libraries fixed outside spark2 (LIBRARY_CLOSE_RULES), comment the fix
    reference on each matching ticket and close it. Honors cve_analyser.DRY_RUN.
    """
    print(f"\n{'='*80}")
    print("  LIBRARY CLOSE PROCESSING")
    print(f"{'='*80}")
    if ca.DRY_RUN:
        print("  cve_analyser.DRY_RUN is enabled -> no Jira changes will be sent.")

    matched = 0
    for lib, entries in lib_map.items():
        for iss in entries:
            if match_shaded_rule(iss):     # owned by shaded-bundle routing
                continue
            rule = match_rule(LIBRARY_CLOSE_RULES, lib, iss)
            if not rule:
                continue
            matched += 1
            print(f"  {iss['key']}  {iss['cve_id']}  ({lib}) -> Closed")
            ca.close_ticket_with_comment(iss["key"], rule["comment"])
    if not matched:
        print("  No tickets matched any library close rule.")
    else:
        print(f"  {matched} ticket(s) commented and closed.")


def apply_library_exceptions(lib_map: Dict[str, List[Dict]]) -> None:
    """
    For libraries that can't be fixed in Spark2 (e.g. protobuf), move every
    matching ticket to the Exception Request flow. Honors cve_analyser.DRY_RUN.
    """
    print(f"\n{'='*80}")
    print("  LIBRARY EXCEPTION PROCESSING")
    print(f"{'='*80}")
    if ca.DRY_RUN:
        print("  cve_analyser.DRY_RUN is enabled -> no Jira changes will be sent.")

    matched = 0
    for lib, entries in lib_map.items():
        for iss in entries:
            if match_shaded_rule(iss):     # owned by shaded-bundle routing
                continue
            rule = match_exception_rule(lib, iss)
            if not rule:
                continue
            matched += 1
            reason = rule.get("reason", "Deferred")
            env = "  [env/compat]" if (rule.get("requires_jdk") is not None
                                       or rule.get("requires_python") is not None) else ""
            print(f"  {iss['key']}  {iss['cve_id']}  ({lib}) -> Exception Request "
                  f"({reason}){env}")
            ca.update_ticket_exception(iss["key"], rule["description"], reason=reason)
    if not matched:
        print("  No tickets matched any library exception rule.")
    else:
        print(f"  {matched} ticket(s) routed to Exception Request.")


def process_plan(plan: Dict) -> None:
    print(f"\n{'='*80}")
    print(f"  {plan['name'].upper()} FIX PLAN")
    print(f"{'='*80}")
    print(f"  Libraries        : {', '.join(plan['libraries'])}")
    print(f"  Tickets          : {', '.join(i['key'] for i in plan['issues'])}")
    print(f"  Candidate vers   : {', '.join(plan['candidate_versions'])}")
    print(f"  Pure-max version : {plan['pure_max_version']}")
    print(f"  Target version   : {plan['target_version']}  ({plan['selection']})")
    print(f"  Patch            : {plan['patch']}")
    print(f"  Fix branch       : {plan['branch']}  (off {TARGET_BRANCH})")

    if not plan["target_version"]:
        print("  No concrete fix version found; skipping.")
        return

    # R9 environment/compatibility gate: if the patched version requires a JDK /
    # Python this component doesn't run, it is not a valid FIX. Skip the build
    # and route the plan's CVEs to Exception (honors cve_analyser.DRY_RUN).
    env_reason = env_incompatible(plan.get("requires_jdk"),
                                  plan.get("requires_python"))
    if env_reason:
        print(f"\n  ENV-INCOMPATIBLE: {env_reason}")
        for iss in plan["issues"]:
            print(f"    {iss['key']} {iss['cve_id']} -> Exception Request (Deferred) [env/compat]")
            ca.update_ticket_exception(iss["key"], env_reason, reason="Deferred")
        return

    missed = uncovered_issues(plan["issues"], plan["target_version"])
    if missed:
        print(f"\n  WARNING: target {plan['target_version']} does NOT cover "
              f"{len(missed)} CVE(s):")
        for iss in missed:
            print(f"    - {iss['key']} {iss['cve_id']} needs >= {iss['fixed_version']}")
        print("    These will remain unfixed at the chosen version.")

    commit_subject = plan["commit_subject"].format(
        branch=plan["branch"], cve=plan["commit_cve"])
    print(f"  Commit message   : {commit_subject}")

    if not APPLY:
        print("\n  APPLY is False -> plan only. No git/build/push performed.")
        return

    if not ensure_repo():
        print("  ERROR: could not clone/fetch the repo; aborting.")
        return

    # Idempotency: don't redo a fix that is already applied / already pushed.
    skip_reason = already_fixed_reason(plan)
    if skip_reason:
        print(f"  SKIP: {skip_reason}. Nothing to do for this library.")
        return

    if not create_fix_branch(plan["branch"]):
        print("  ERROR: git preparation failed; aborting.")
        return

    changes = apply_pom_patch(plan["patch"], plan["target_version"])
    if not changes:
        print("  WARNING: no pom changes made (already at target / pattern not found?).")
    else:
        print("  pom changes:")
        for c in changes:
            print(f"    - {c}")

    if not run_build():
        print("  Build failed. Branch left in place for manual inspection.")
        return

    print(f"  Committing on branch {plan['branch']}.")
    if run(f'git commit -am "{commit_subject}"', cwd=WORKDIR) != 0:
        print("  ERROR: commit failed (nothing to commit?); not pushing.")
        return
    print(f"  Pushing branch {plan['branch']} to origin.")
    if run(f"git push -u origin {plan['branch']}", cwd=WORKDIR) != 0:
        print("  ERROR: push failed. Commit is local; push manually.")
        return
    print("  SUCCESS. Branch pushed.")
    record_fix(plan)

    if SKIP_PR:
        print("  CVE_SKIP_PR set -> not opening PR / closing tickets.")
        return
    print(f"  Opening PR {plan['branch']} -> {TARGET_BRANCH} on {REPO_SLUG}.")
    pr_url = create_pull_request(plan, commit_subject)
    if not pr_url:
        print("  PR not created; tickets left open for manual handling.")
        return
    close_tickets_for_plan(plan, pr_url)


def select_targets() -> List[Dict]:
    if ONLY_TARGET:
        return [t for t in FIX_TARGETS if t["name"] == ONLY_TARGET]
    return FIX_TARGETS


if __name__ == "__main__":
    print(f"{'='*80}")
    print(f"  PROFILE: {PROFILE_NAME}  |  repo: {ca.REPO}  |  release: {ca.RELEASE_VERSION}")
    print(f"  branch : {TARGET_BRANCH}  |  APPLY={APPLY}  |  DRY_RUN={ca.DRY_RUN}")
    print(f"{'='*80}")
    print("Fetching CVE tickets ...")
    issues = ca.fetch_all_tickets()
    if not issues:
        print("No issues found or fetch failed.")
        raise SystemExit(1)

    lib_map = ca.group_by_library(issues)

    if SKIP_ROUTING:
        print("CVE_SKIP_ROUTING set -> skipping exception/shaded/close routing; "
              "running fix targets only.")
    else:
        # Route CVEs that live inside third-party fat/shaded jars (not fixable by
        # a Spark version bump) to exception/close per the profile's shaded rules.
        apply_shaded_bundle_rules(lib_map)

        # Route un-fixable libraries (e.g. protobuf) to the Exception Request flow.
        apply_library_exceptions(lib_map)

        # Close tickets for libraries already fixed in the platform (e.g. Hadoop's
        # BouncyCastle bump) with a comment linking the fix commit.
        apply_library_closures(lib_map)

    targets = select_targets()
    if not targets:
        print(f"No fix target matches ONLY_TARGET={ONLY_TARGET!r}.")
        raise SystemExit(1)

    for target in targets:
        plan = build_fix_plan(target, lib_map)
        if not plan:
            print(f"\nNo CVEs matched fix target '{target['name']}'.")
            continue
        process_plan(plan)
