"""Load repo-local .env (and optional overrides) into os.environ."""

from __future__ import annotations

import os
from typing import Iterable, Optional


def _repo_root() -> str:
    return os.path.dirname(os.path.abspath(__file__))


def load_repo_env(extra_paths: Optional[Iterable[str]] = None,
                  override: bool = False) -> bool:
    """Load environment variables from .env files.

    Checks (in order): repo ``.env``, then any ``extra_paths``. Existing
    process env vars are kept unless ``override=True``.

    Returns True if at least one file was loaded.
    """
    try:
        from dotenv import load_dotenv
    except ImportError:
        return False

    loaded = False
    candidates = [os.path.join(_repo_root(), ".env")]
    if extra_paths:
        candidates.extend(extra_paths)
    cred = os.environ.get("CVE_ENV_FILE", "").strip()
    if cred:
        candidates.append(os.path.expanduser(cred))

    for path in candidates:
        path = os.path.expanduser(path)
        if os.path.isfile(path) and load_dotenv(path, override=override):
            loaded = True
    return loaded
