import os
import requests
import urllib.parse
import re
from typing import List, Dict, Optional
from collections import defaultdict

import cve_env

cve_env.load_repo_env()

from requests.adapters import HTTPAdapter
try:
    from urllib3.util.retry import Retry
except ImportError:  # very old urllib3 bundled inside requests
    from requests.packages.urllib3.util.retry import Retry

import cve_profiles

# Configuration
#
# Credentials are NEVER hardcoded. They are read (in priority order) from:
#   1. environment variables  CVE_JIRA_EMAIL / CVE_JIRA_API_TOKEN
#   2. a git-ignored creds file (default ~/.config/cve_fix/jira.env, override
#      with CVE_JIRA_CRED_FILE) containing lines:  EMAIL=... / API_TOKEN=...
# The Jira base URL defaults to the company instance but is env-overridable.
JIRA_BASE_URL = os.environ.get("CVE_JIRA_BASE_URL", "https://accelcentral.atlassian.net")


def _load_jira_credentials():
    email = os.environ.get("CVE_JIRA_EMAIL", "").strip()
    token = os.environ.get("CVE_JIRA_API_TOKEN", "").strip()
    if not email or not token:
        path = os.environ.get(
            "CVE_JIRA_CRED_FILE", os.path.expanduser("~/.config/cve_fix/jira.env"))
        try:
            with open(path) as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if line.startswith("EMAIL=") and not email:
                        email = line[len("EMAIL="):].strip()
                    elif line.startswith("API_TOKEN=") and not token:
                        token = line[len("API_TOKEN="):].strip()
        except FileNotFoundError:
            pass
    return email, token


EMAIL, API_TOKEN = _load_jira_credentials()

# Active build-target profile (selected via CVE_PROFILE env; defaults spark2).
# REPO/RELEASE_VERSION drive the Jira JQL; the fixer reads the rest of the
# profile. Override either directly with the CVE_REPO / CVE_RELEASE env vars.
PROFILE = cve_profiles.get_profile()
RELEASE_VERSION = os.environ.get("CVE_RELEASE", PROFILE["release"])
REPO = os.environ.get("CVE_REPO", PROFILE["repo"])

# Filename prefixes of jars produced by the component's OWN build. These jars
# (e.g. spark-*.jar, or pinot's pinot-*-shaded.jar / pinot-all-*.jar assemblies)
# are rebuilt from source, so a pom version bump + rebuild fixes the libraries
# bundled inside them -- they must NOT be treated as third-party shaded jars.
# Defaults to spark's "spark-"; other components set built_jar_prefixes in their
# profile. Override with CVE_BUILT_JAR_PREFIXES (comma-separated).
_BUILT_PREFIX_ENV = os.environ.get("CVE_BUILT_JAR_PREFIXES", "")
if _BUILT_PREFIX_ENV:
    BUILT_JAR_PREFIXES = tuple(
        p.strip().lower() for p in _BUILT_PREFIX_ENV.split(",") if p.strip())
else:
    BUILT_JAR_PREFIXES = tuple(
        p.lower() for p in (PROFILE.get("built_jar_prefixes") or ("spark-",)))

# Default account that exception/closed tickets get assigned to (override via
# CVE_ASSIGNEE_ACCOUNT_ID env, or pass assignee= to reclassify / close helpers).
ASSIGNEE_ACCOUNT_ID = (
    os.environ.get("CVE_ASSIGNEE_ACCOUNT_ID", "").strip()
    or cve_profiles.ASSIGNEE_ACCOUNT_ID
)

# Optional display-name / email / login shortcuts → Atlassian accountId.
# Extend via CVE_ASSIGNEE_MAP="senthil.kumar=712020:...,alice=712020:..."
_ASSIGNEE_ALIASES: Dict[str, str] = {
    # Populate known TeamODP people here; or set CVE_ASSIGNEE_MAP / look up live.
}


def _load_assignee_aliases() -> Dict[str, str]:
    out = dict(_ASSIGNEE_ALIASES)
    raw = os.environ.get("CVE_ASSIGNEE_MAP", "").strip()
    for part in raw.split(","):
        part = part.strip()
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        if k.strip() and v.strip():
            out[k.strip().lower()] = v.strip()
    return out


def resolve_assignee(query: Optional[str] = None) -> Optional[str]:
    """Resolve a human name / email / accountId to a Jira accountId.

    Accepts:
      - bare Atlassian accountId (contains ':')
      - alias from CVE_ASSIGNEE_MAP / _ASSIGNEE_ALIASES
      - email or displayName looked up via Jira user search API

    Returns None if query is empty (caller should use ASSIGNEE_ACCOUNT_ID).
    Raises ValueError if a non-empty query cannot be resolved.
    """
    q = (query or "").strip()
    if not q:
        return None
    if ":" in q and " " not in q:
        return q  # already an accountId
    aliases = _load_assignee_aliases()
    key = q.lower().replace(" ", ".")
    if key in aliases:
        return aliases[key]
    if q.lower() in aliases:
        return aliases[q.lower()]

    # Live Jira user search
    url = (f"{JIRA_BASE_URL}/rest/api/3/user/search"
           f"?query={urllib.parse.quote(q)}&maxResults=10")
    r = SESSION.get(url, headers={"Accept": "application/json"},
                    auth=(EMAIL, API_TOKEN))
    if r.status_code != 200:
        raise ValueError(f"Jira user search failed [{r.status_code}]: {r.text[:200]}")
    users = r.json() or []
    if not users:
        raise ValueError(f"No Jira user matched {q!r}. "
                         f"Pass accountId or set CVE_ASSIGNEE_MAP.")
    # Prefer exact email / displayName / publicName match
    q_l = q.lower()
    for u in users:
        email = (u.get("emailAddress") or "").lower()
        disp = (u.get("displayName") or "").lower()
        name = (u.get("name") or "").lower()
        if q_l in (email, disp, name) or email.startswith(q_l):
            return u["accountId"]
    # Single unambiguous result
    if len(users) == 1:
        return users[0]["accountId"]
    choices = ", ".join(
        f"{u.get('displayName')} <{u.get('emailAddress') or '?'}> = {u['accountId']}"
        for u in users[:5])
    raise ValueError(f"Ambiguous assignee {q!r}. Candidates: {choices}")


def assign_issue(issue_key: str, account_id: Optional[str] = None) -> bool:
    """Assign a ticket to account_id (default ASSIGNEE_ACCOUNT_ID). Respects DRY_RUN."""
    aid = account_id or ASSIGNEE_ACCOUNT_ID
    if DRY_RUN:
        print(f"    [DRY_RUN] Would assign {issue_key} -> {aid}")
        return True
    url = f"{JIRA_BASE_URL}/rest/api/3/issue/{issue_key}"
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    payload = {"fields": {"assignee": {"accountId": aid}}}
    response = SESSION.put(url, headers=headers, auth=(EMAIL, API_TOKEN), json=payload)
    if response.status_code in (200, 204):
        print(f"    Assigned {issue_key} -> {aid}")
        return True
    print(f"    ERROR assigning {issue_key} [{response.status_code}]: {response.text}")
    return False

# Status that matching tickets are transitioned to
EXCEPTION_STATUS = "Exception Request"

# Safety switch: when True, no Jira updates are sent; matches are only reported.
# Default False (live). Set CVE_DRY_RUN=1 to preview a run without writing.
DRY_RUN = os.environ.get("CVE_DRY_RUN", "") not in ("", "0", "false", "False")


# -------------------------------------------------------------------
# Resilient HTTP session
# -------------------------------------------------------------------
# A single transient network blip (e.g. a connect timeout to Jira) must NOT
# abort a long run. Use a Session that retries connection errors, read errors
# and 429/5xx responses with exponential backoff, and applies a default
# per-request timeout. All Jira calls go through SESSION instead of requests.*.
HTTP_TIMEOUT = int(os.environ.get("CVE_HTTP_TIMEOUT", "30"))


class _TimeoutAdapter(HTTPAdapter):
    """HTTPAdapter that injects a default timeout when none is supplied."""

    def __init__(self, *args, timeout=HTTP_TIMEOUT, **kwargs):
        self._timeout = timeout
        super().__init__(*args, **kwargs)

    def send(self, request, **kwargs):
        if kwargs.get("timeout") is None:
            kwargs["timeout"] = self._timeout
        return super().send(request, **kwargs)


def _build_session() -> requests.Session:
    retry = Retry(
        total=5, connect=5, read=5, status=5,
        backoff_factor=2,  # waits 0s, 2s, 4s, 8s, 16s between attempts
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "POST", "PUT"]),
        raise_on_status=False,
    )
    sess = requests.Session()
    adapter = _TimeoutAdapter(max_retries=retry)
    sess.mount("https://", adapter)
    sess.mount("http://", adapter)
    return sess


SESSION = _build_session()

# CVE-Path patterns and their corresponding update payloads
HTRACE_EXCEPTION_REASON = (
    "This CVE is pulled from Hadoop which in-turn from htrace-core*. "
    "And htrace-core* is a non-active third party library; And hence we require exception"
)

CVE_PATH_RULES = [
    {
        "patterns": [
            r"htrace-core.*\.jar",
            r"/usr/odp/.*/htrace-core.*\.jar",
        ],
        "library": "htrace",
        "description": HTRACE_EXCEPTION_REASON,
    },
]

# -------------------------------------------------------------------
# Fetch ALL tickets matching the URL's JQL (with pagination)
# -------------------------------------------------------------------
def fetch_all_tickets(max_per_page: int = 100) -> List[Dict]:
    """
    Fetch all Jira tickets matching the JQL from the original URL.
    Fields fetched:
      - summary
      - customfield_10888  -> CVE-Path
      - customfield_10127  -> CVE-ID (CVE-XXXX-YYYY or GHSA-xxxx-xxxx-xxxx)
      - customfield_10875  -> CVE-Package (affected library/package name)
      - customfield_10892  -> CVE-Package-Version (affected version)
      - customfield_10891  -> CVE-Proposed-Fix (fixed version, rich text)
      - customfield_10126  -> CVE-Severity
    """
    jql = f'''project = OSV
AND "cve-found-in-release-version[short text]" ~ "{RELEASE_VERSION}"
AND "cve-severity[dropdown]" IN (Critical, High, Medium)
AND "cve-repo[short text]" ~ "{REPO}"
AND assignee = empty
AND status = "To Do"
ORDER BY created DESC'''

    jql_encoded = urllib.parse.quote(jql)
    fields = (
        "key,summary,status,"
        "customfield_10888,"   # CVE-Path
        "customfield_10127,"   # CVE-ID
        "customfield_10875,"   # CVE-Package (affected library/package)
        "customfield_10892,"   # CVE-Package-Version (affected version)
        "customfield_10891,"   # CVE-Proposed-Fix (fixed version)
        "customfield_10126,"   # CVE-Severity
        "customfield_10885"    # CVE-Transition-Details
    )

    all_issues = []
    next_page_token = None
    page = 0

    # The /search/jql endpoint uses token-based pagination (nextPageToken /
    # isLast); it does NOT support startAt and does not return a total.
    while True:
        url = (
            f"{JIRA_BASE_URL}/rest/api/3/search/jql"
            f"?jql={jql_encoded}"
            f"&maxResults={max_per_page}"
            f"&fields={fields}"
        )
        if next_page_token:
            url += f"&nextPageToken={urllib.parse.quote(next_page_token)}"
        headers = {"Accept": "application/json"}
        auth = (EMAIL, API_TOKEN)

        page += 1
        print(f"  Fetching page {page} ...")
        response = SESSION.get(url, headers=headers, auth=auth)

        if response.status_code != 200:
            print(f"  ERROR {response.status_code}: {response.text}")
            break

        data = response.json()
        issues = data.get("issues", [])

        for issue in issues:
            f = issue["fields"]

            # CVE-ID can be in summary or a dedicated field; try both
            cve_id = extract_cve_id(
                issue["key"],
                f.get("summary", ""),
                f.get("customfield_10127", "") or ""
            )

            all_issues.append({
                "key":              issue["key"],
                "summary":          f.get("summary", ""),
                "cve_id":           cve_id,
                "cve_path":         f.get("customfield_10888", "") or "",
                "affected_library": f.get("customfield_10875", "") or "",
                "affected_version": f.get("customfield_10892", "") or "",
                "fixed_version":    extract_fixed_version(f.get("customfield_10891")),
                "severity":         extract_dropdown(f.get("customfield_10126")),
            })

        print(f"  Fetched {len(all_issues)} issues so far.")

        next_page_token = data.get("nextPageToken")
        if data.get("isLast", True) or not next_page_token:
            break

    return all_issues


# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------
# CVE-YYYY-NNNNN or GitHub Security Advisory GHSA-xxxx-xxxx-xxxx.
# Some OSV tickets only carry a GHSA id in customfield_10127 (no CVE alias yet).
_VULN_ID_RE = re.compile(
    r"(?:CVE-\d{4}-\d+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})",
    re.IGNORECASE,
)


def normalize_vuln_id(vuln_id: str) -> str:
    """Canonical advisory id: CVE-YYYY-NNNN uppercased, or GHSA-xxxx-xxxx-xxxx
    (GHSA prefix upper, body lower — GitHub/OSV canonical form). Returns the
    stripped input unchanged when it does not look like a known id."""
    if not vuln_id:
        return ""
    s = str(vuln_id).strip()
    m = _VULN_ID_RE.search(s)
    if not m:
        return s
    raw = m.group(0)
    if raw.upper().startswith("CVE-"):
        return raw.upper()
    return "GHSA-" + raw[5:].lower()


def extract_cve_id(key: str, summary: str, field_value: str) -> str:
    """Extract CVE-XXXX-YYYY or GHSA-xxxx-xxxx-xxxx from the CVE-ID field,
    summary, or issue key. Prefer the dedicated field. Returns UNKNOWN only
    when no CVE/GHSA id is present (do not collapse GHSA tickets to UNKNOWN)."""
    for text in [field_value, summary, key]:
        if not text:
            continue
        m = _VULN_ID_RE.search(str(text))
        if m:
            return normalize_vuln_id(m.group(0))
    return "UNKNOWN"


def extract_dropdown(field) -> str:
    """Extract value from Jira dropdown custom field."""
    if isinstance(field, dict):
        return field.get("value", "")
    return field or ""


def extract_adf_text(field) -> str:
    """
    Flatten an Atlassian Document Format (ADF) rich-text field into plain text.
    Returns the field as-is if it is already a plain string.
    """
    if not field:
        return ""
    if isinstance(field, str):
        return field.strip()
    if not isinstance(field, dict):
        return str(field).strip()

    parts: List[str] = []

    def walk(node):
        if isinstance(node, dict):
            if node.get("type") == "text" and "text" in node:
                parts.append(node["text"])
            for child in node.get("content", []) or []:
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(field)
    return " ".join(p.strip() for p in parts if p.strip()).strip()


def extract_fixed_version(field) -> str:
    """
    Extract the fixed version from the CVE-Proposed-Fix rich-text field.
    Typical content: "fixed in 0.23.0" or "fixed in 3.21.7, 3.20.3, 3.19.6".
    Falls back to the full plain text when no clear version is found.
    """
    text = extract_adf_text(field)
    if not text:
        return ""
    m = re.search(r"fixed\s+in\s+([\d][\w.\-,\s]*)", text, re.IGNORECASE)
    if m:
        return m.group(1).strip().rstrip(".,")
    return text


def extract_library_from_path(cve_path: str) -> str:
    """
    Best-effort: extract jar/library name from CVE-Path.
    e.g. /usr/odp/.../jars/log4j-core-2.17.1.jar -> log4j-core
    """
    if not cve_path:
        return ""
    # grab the filename
    filename = cve_path.split("/")[-1]
    # strip .jar
    filename = re.sub(r"\.jar$", "", filename, flags=re.IGNORECASE)
    # strip version suffix like -2.17.1 or _2.11-2.4.8
    lib = re.sub(r"[-_]\d[\d.\-_]*$", "", filename)
    return lib or filename


def jar_filename(cve_path: str) -> str:
    """Return just the jar file name from a CVE-Path (or '')."""
    if not cve_path:
        return ""
    return cve_path.rstrip("/").split("/")[-1]


def affected_artifact(affected_library: str) -> str:
    """
    The artifact id portion of an affected-library value. Jira stores libraries
    as 'group_artifact' (e.g. 'com.fasterxml.jackson.core_jackson-core' or
    'io.netty_netty-codec-http'); the artifact is the part after the last '_'.
    Falls back to the whole value when there is no underscore.
    """
    lib = (affected_library or "").strip()
    return lib.rsplit("_", 1)[-1] if "_" in lib else lib


def is_spark_built_jar(cve_path: str) -> bool:
    """
    True if the containing jar is produced by the component's OWN build (e.g.
    spark-core_2.12-*.jar / the Spark assembly, or pinot-*-shaded.jar /
    pinot-all-*-jar-with-dependencies.jar). Those ARE rebuilt from source, so a
    component-side version bump + rebuild fixes the libs inside them. The set of
    recognised prefixes is profile-configurable via BUILT_JAR_PREFIXES.
    """
    name = jar_filename(cve_path).lower()
    return any(name.startswith(p) for p in BUILT_JAR_PREFIXES)


def is_thirdparty_shaded(issue: Dict) -> bool:
    """
    True when the vulnerable class lives inside a THIRD-PARTY fat/shaded jar
    (not a standalone jar of the affected library, and not a Spark-built
    assembly). Such CVEs cannot be fixed by a Spark pom version bump and must be
    routed to shaded-bundle handling.

    Heuristic: the jar's artifact name (stripped of version) does not match the
    affected library's artifact, and the jar is not a Spark-built artifact.
    """
    path = issue.get("cve_path") or ""
    if not path:
        return False
    if is_spark_built_jar(path):
        return False
    jar_art = extract_library_from_path(path).lower()
    aff_art = affected_artifact(issue.get("affected_library", "")).lower()
    if not jar_art or not aff_art:
        return False
    # standalone lib jar (jackson-core-2.x.jar for jackson-core) -> fixable
    if jar_art == aff_art or jar_art.startswith(aff_art) or aff_art.startswith(jar_art):
        return False
    return True


def group_by_library(issues: List[Dict]) -> Dict[str, List[Dict]]:
    """
    Group issues by affected library. Prefers the CVE-Package field and falls
    back to parsing the jar name out of the CVE-Path. Returns an ordered dict
    keyed by library name, preserving the issue order within each group.
    """
    lib_map: Dict[str, List[Dict]] = defaultdict(list)
    for iss in issues:
        lib = iss["affected_library"].strip()
        if not lib:
            lib = extract_library_from_path(iss["cve_path"])
        if not lib:
            lib = "(unknown)"
        lib_map[lib].append(iss)
    return lib_map


def match_path_rule(cve_path: str) -> Optional[Dict]:
    """
    Return the first CVE_PATH_RULES entry whose pattern matches the CVE-Path,
    or None if nothing matches.
    """
    if not cve_path:
        return None
    for rule in CVE_PATH_RULES:
        for pattern in rule["patterns"]:
            if re.search(pattern, cve_path, re.IGNORECASE):
                return rule
    return None


# -------------------------------------------------------------------
# Jira update
# -------------------------------------------------------------------
def transition_issue(issue_key: str, target_status: str,
                     fields: Optional[Dict] = None) -> bool:
    """
    Move the issue to the given target status by name. The matching
    transition is looked up dynamically (IDs vary by workflow). Note: in this
    workflow the status-specific transitions only appear once an assignee is
    set, so assign the ticket before calling this. Optional `fields` are sent
    with the transition (e.g. a resolution required by a "Closed" screen).
    Respects DRY_RUN.
    """
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    auth = (EMAIL, API_TOKEN)
    url = f"{JIRA_BASE_URL}/rest/api/3/issue/{issue_key}/transitions"

    resp = SESSION.get(url, headers=headers, auth=auth)
    if resp.status_code != 200:
        print(f"    ERROR listing transitions for {issue_key} [{resp.status_code}]: {resp.text}")
        return False

    transition = next(
        (t for t in resp.json().get("transitions", [])
         if t["to"]["name"].lower() == target_status.lower()),
        None,
    )
    if not transition:
        print(f"    ERROR: no transition to '{target_status}' available for {issue_key}")
        return False

    if DRY_RUN:
        print(f"    [DRY_RUN] Would transition {issue_key} -> '{target_status}' (id {transition['id']})")
        return True

    body = {"transition": {"id": transition["id"]}}
    if fields:
        body["fields"] = fields
    post = SESSION.post(url, headers=headers, auth=auth, json=body)
    if post.status_code in (200, 204):
        print(f"    Transitioned {issue_key} -> '{target_status}'")
        return True

    print(f"    ERROR transitioning {issue_key} [{post.status_code}]: {post.text}")
    return False


def add_comment(issue_key: str, text: str) -> bool:
    """Add a plain-text comment (Jira auto-links URLs). Respects DRY_RUN."""
    if DRY_RUN:
        print(f"    [DRY_RUN] Would comment on {issue_key}: {text}")
        return True

    url = f"{JIRA_BASE_URL}/rest/api/3/issue/{issue_key}/comment"
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    payload = {
        "body": {
            "version": 1,
            "type": "doc",
            "content": [
                {"type": "paragraph", "content": [{"type": "text", "text": text}]}
            ],
        }
    }
    resp = SESSION.post(url, headers=headers, auth=(EMAIL, API_TOKEN), json=payload)
    if resp.status_code in (200, 201):
        print(f"    Commented on {issue_key}")
        return True
    print(f"    ERROR commenting on {issue_key} [{resp.status_code}]: {resp.text}")
    return False


def close_ticket_with_comment(issue_key: str, comment: str,
                              status: str = "Closed",
                              assignee: Optional[str] = None) -> bool:
    """
    Assign the ticket, add `comment`, then transition it to `status`
    (default "Closed"). Used when a CVE is fixed elsewhere (e.g. a Hadoop
    commit) and the Spark2 ticket should just be closed with a reference.
    ``assignee`` may be an accountId, email, or display name (resolved via
    resolve_assignee). Respects DRY_RUN.
    """
    aid = None
    if assignee:
        try:
            aid = resolve_assignee(assignee)
        except ValueError as e:
            print(f"    ERROR resolving assignee {assignee!r}: {e}")
            return False
    if not assign_issue(issue_key, aid):
        return False

    add_comment(issue_key, comment)
    return transition_issue(issue_key, status)


def update_ticket_exception(issue_key: str, description: str,
                            reason: str = "Deferred",
                            assignee: Optional[str] = None) -> bool:
    """
    Assign the ticket, set the CVE-Exception-Reason (default "Deferred") and the
    CVE-Transition-Details description, then move it to the Exception Request
    status. These two fields are REQUIRED by the workflow for the transition.
    Respects the DRY_RUN flag.
    Returns True on success (or in dry-run mode), False otherwise.
    """
    aid = ASSIGNEE_ACCOUNT_ID
    if assignee:
        try:
            resolved = resolve_assignee(assignee)
            if resolved:
                aid = resolved
        except ValueError as e:
            print(f"    ERROR resolving assignee {assignee!r}: {e}")
            return False
    payload = {
        "fields": {
            "assignee": {"accountId": aid},
            "customfield_10885": {  # CVE-Transition-Details
                "version": 1,
                "type": "doc",
                "content": [
                    {
                        "type": "paragraph",
                        "content": [
                            {"type": "text", "text": description}
                        ],
                    }
                ],
            },
            "customfield_10882": {"value": reason},  # CVE-Exception-Reason
        }
    }

    if DRY_RUN:
        print(f"    [DRY_RUN] Would update {issue_key} -> {reason} exception "
              f"(details set), then transition to '{EXCEPTION_STATUS}'")
        return True

    url = f"{JIRA_BASE_URL}/rest/api/3/issue/{issue_key}"
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    response = SESSION.put(url, headers=headers, auth=(EMAIL, API_TOKEN), json=payload)

    if response.status_code not in (200, 204):
        print(f"    ERROR updating {issue_key} [{response.status_code}]: {response.text}")
        return False

    print(f"    Updated {issue_key} -> {reason} exception (details set)")
    # Assignee is now set, so the Exception Request transition is available.
    return transition_issue(issue_key, EXCEPTION_STATUS)


def apply_path_rules(issues: List[Dict]) -> None:
    """
    Scan all issues' CVE-Path against CVE_PATH_RULES and update matching
    tickets in Jira (assignee + Deferred exception + transition details).
    """
    print(f"\n{'─'*80}")
    print(f"  CVE-PATH RULE PROCESSING")
    print(f"{'─'*80}")
    if DRY_RUN:
        print("  DRY_RUN is enabled — no changes will be sent to Jira.")

    matched = 0
    for iss in issues:
        rule = match_path_rule(iss["cve_path"])
        if not rule:
            continue
        matched += 1
        print(f"  {iss['key']} matched rule '{rule['library']}'  path: {iss['cve_path']}")
        update_ticket_exception(iss["key"], rule["description"])

    if not matched:
        print("  No tickets matched any CVE-Path rule.")
    else:
        print(f"  {matched} ticket(s) matched CVE-Path rules.")


# -------------------------------------------------------------------
# Analysis
# -------------------------------------------------------------------
def analyze(issues: List[Dict]) -> None:
    print(f"\n{'='*80}")
    print(f"  CVE ANALYSIS  —  repo: {REPO}  |  release: {RELEASE_VERSION}")
    print(f"{'='*80}")
    print(f"  Total tickets fetched : {len(issues)}")

    # ── Unique vs Duplicate CVEs ──────────────────────────────────
    cve_to_tickets = defaultdict(list)
    for iss in issues:
        cve_to_tickets[iss["cve_id"]].append(iss["key"])

    unique_cves     = {cve: keys for cve, keys in cve_to_tickets.items() if len(keys) == 1}
    duplicate_cves  = {cve: keys for cve, keys in cve_to_tickets.items() if len(keys) > 1}
    unknown_cves    = [iss for iss in issues if iss["cve_id"] == "UNKNOWN"]

    print(f"  Unique CVEs           : {len(unique_cves)}")
    print(f"  Repeated CVEs         : {len(duplicate_cves)}")
    print(f"  Tickets w/ unknown ID : {len(unknown_cves)}")

    # ── Repeated CVEs detail ─────────────────────────────────────
    if duplicate_cves:
        print(f"\n{'─'*80}")
        print(f"  REPEATED CVEs (appear in multiple tickets)")
        print(f"{'─'*80}")
        print(f"  {'CVE ID':<25} {'Count':<8} {'Ticket Keys'}")
        print(f"  {'-'*25} {'-'*8} {'-'*40}")
        for cve, keys in sorted(duplicate_cves.items(), key=lambda x: -len(x[1])):
            print(f"  {cve:<25} {len(keys):<8} {', '.join(keys)}")

    # ── Library → CVE mapping ────────────────────────────────────
    print(f"\n{'─'*80}")
    print(f"  LIBRARIES PULLING CVEs")
    print(f"{'─'*80}")

    # Group by library (prefer affected_library field; fallback to path parsing)
    lib_map = group_by_library(issues)

    print(f"\n  {'Library':<35} {'Affected Ver':<20} {'Fixed Ver':<20} {'Severity':<10} {'CVE ID':<25} {'Ticket'}")
    print(f"  {'-'*35} {'-'*20} {'-'*20} {'-'*10} {'-'*25} {'-'*10}")

    for lib in sorted(lib_map.keys()):
        entries = lib_map[lib]
        for iss in entries:
            print(
                f"  {lib:<35} "
                f"{iss['affected_version']:<20} "
                f"{iss['fixed_version']:<20} "
                f"{iss['severity']:<10} "
                f"{iss['cve_id']:<25} "
                f"{iss['key']}"
            )

    # ── Library summary (unique CVEs per lib) ────────────────────
    print(f"\n{'─'*80}")
    print(f"  LIBRARY SUMMARY")
    print(f"{'─'*80}")
    print(f"  {'Library':<35} {'# Tickets':<12} {'Unique CVEs':<15} {'Severities'}")
    print(f"  {'-'*35} {'-'*12} {'-'*15} {'-'*30}")

    for lib in sorted(lib_map.keys()):
        entries   = lib_map[lib]
        ucves     = len({e["cve_id"] for e in entries})
        severities = ", ".join(sorted({e["severity"] for e in entries if e["severity"]}))
        print(f"  {lib:<35} {len(entries):<12} {ucves:<15} {severities}")

    # ── CVE-Path details ─────────────────────────────────────────
    print(f"\n{'─'*80}")
    print(f"  CVE-PATH DETAILS")
    print(f"{'─'*80}")
    print(f"  {'Ticket':<12} {'CVE ID':<20} {'CVE-Path'}")
    print(f"  {'-'*12} {'-'*20} {'-'*60}")
    for iss in issues:
        print(f"  {iss['key']:<12} {iss['cve_id']:<20} {iss['cve_path'] or '(none)'}")

    # ── Severity breakdown ───────────────────────────────────────
    print(f"\n{'─'*80}")
    print(f"  SEVERITY BREAKDOWN")
    print(f"{'─'*80}")
    sev_map = defaultdict(int)
    for iss in issues:
        sev_map[iss["severity"] or "Unknown"] += 1
    for sev in ["Critical", "High", "Medium", "Low", "Unknown"]:
        if sev_map[sev]:
            print(f"  {sev:<15}: {sev_map[sev]}")

    print(f"\n{'='*80}\n")


# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------
if __name__ == "__main__":
    print(f"Fetching CVE tickets for repo '{REPO}' release '{RELEASE_VERSION}' ...")
    issues = fetch_all_tickets()
    if issues:
        analyze(issues)
        apply_path_rules(issues)
    else:
        print("No issues found or fetch failed.")
